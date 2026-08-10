// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import http from 'k6/http';
import exec from 'k6/execution';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { b64encode } from 'k6/encoding';

const BASE_URL = (__ENV.REKOR_URL || 'http://localhost:3000').replace(/\/$/, '');
const WRITE_RATE = parseInt(__ENV.WRITE_RATE || '300', 10);
const READ_RATE = parseInt(__ENV.READ_RATE || '200', 10);
const DURATION_SEC = parseInt(__ENV.DURATION_SEC || '300', 10);
// Head start so the writer builds a backlog of indices before the reader starts.
const READ_START_SEC = parseInt(__ENV.READ_START_SEC || '10', 10);

const writeErrors = new Rate('write_errors');
const readErrors = new Rate('read_errors');
// Reader caught up to (or passed) the writer, or an entry was not yet servable by index.
const readMisses = new Rate('read_misses');
const writeLatency = new Trend('write_latency', true);
const readLatency = new Trend('read_latency', true);
const entriesCreated = new Counter('entries_created');
const highestLogIndex = new Trend('highest_log_index');

export const options = {
  scenarios: {
    write: {
      executor: 'constant-arrival-rate',
      exec: 'writeEntry',
      rate: WRITE_RATE,
      timeUnit: '1s',
      duration: `${DURATION_SEC}s`,
      preAllocatedVUs: 150,
      maxVUs: 900,
    },
    read: {
      executor: 'constant-arrival-rate',
      exec: 'readEntry',
      rate: READ_RATE,
      timeUnit: '1s',
      startTime: `${READ_START_SEC}s`,
      duration: `${DURATION_SEC - READ_START_SEC}s`,
      preAllocatedVUs: 50,
      maxVUs: 400,
    },
  },
  thresholds: {
    write_errors: ['rate<0.01'],
    read_errors: ['rate<0.01'],
    read_misses: ['rate<0.01'],
    'write_latency': ['p(95)<2000'],
    'read_latency': ['p(95)<1000'],
    // Non-zero means k6 could not sustain the configured rate with maxVUs.
    dropped_iterations: ['count<100'],
  },
};

// CryptoKey is not serializable through setup data, so each VU imports the
// shared JWK once and caches it at module scope.
let signingKey = null;

async function getSigningKey(privateKeyJwk) {
  if (signingKey === null) {
    signingKey = await crypto.subtle.importKey(
      'jwk',
      privateKeyJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
  }
  return signingKey;
}

function encodeAscii(s) {
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    bytes[i] = s.charCodeAt(i);
  }
  return bytes;
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

// WebCrypto emits IEEE P1363 (r||s); sigstore verifies ASN.1 DER.
function rawSignatureToDER(rawSignature) {
  const encodeInteger = (integer) => {
    let offset = 0;
    while (offset < integer.length - 1 && integer[offset] === 0) {
      offset++;
    }
    const trimmed = integer.slice(offset);
    const needsPadding = trimmed[0] >= 0x80;
    const length = trimmed.length + (needsPadding ? 1 : 0);
    const result = new Uint8Array(2 + length);
    result[0] = 0x02;
    result[1] = length;
    let pos = 2;
    if (needsPadding) {
      result[pos++] = 0x00;
    }
    result.set(trimmed, pos);
    return result;
  };

  const half = rawSignature.length / 2;
  const rDer = encodeInteger(rawSignature.slice(0, half));
  const sDer = encodeInteger(rawSignature.slice(half));
  const body = rDer.length + sDer.length;
  const result = new Uint8Array(2 + body);
  result[0] = 0x30;
  result[1] = body;
  result.set(rDer, 2);
  result.set(sDer, 2 + rDer.length);
  return result;
}

// pkg/pki/x509.NewPublicKey only accepts PEM, not bare SPKI DER.
function spkiToPem(spkiBuffer) {
  const b64 = b64encode(spkiBuffer);
  const wrapped = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${wrapped}\n-----END PUBLIC KEY-----\n`;
}

function parseLogIndex(body) {
  const entries = JSON.parse(body);
  const uuid = Object.keys(entries)[0];
  return entries[uuid].logIndex;
}

export async function setup() {
  const info = http.get(`${BASE_URL}/api/v1/log`);
  if (info.status !== 200) {
    throw new Error(`health check failed: ${info.status} ${info.body}`);
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyContent = b64encode(spkiToPem(spki));

  // Distinguishes digests between runs so a re-run against the same log does
  // not collide with its own previous entries (rekor rejects dupes with 409).
  const runNonce = `${Date.now()}-${Math.random()}`;

  // Probe write establishes the first index this run owns, which is more
  // reliable than treeSize once inactive shards are in play.
  const probe = await buildEntry(keyPair.privateKey, publicKeyContent, `${runNonce}-probe`);
  const res = http.post(`${BASE_URL}/api/v1/log/entries`, JSON.stringify(probe), {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
  });
  if (res.status !== 201) {
    throw new Error(`probe write failed: ${res.status} ${res.body}`);
  }
  const startIndex = parseLogIndex(res.body) + 1;

  console.log(`target=${BASE_URL} writeRate=${WRITE_RATE}/s readRate=${READ_RATE}/s duration=${DURATION_SEC}s startIndex=${startIndex}`);

  return { privateKeyJwk, publicKeyContent, runNonce, startIndex };
}

async function buildEntry(privateKey, publicKeyContent, uniqueTag) {
  const artifact = encodeAscii(`rekor-k6-${uniqueTag}`);
  const digest = await crypto.subtle.digest('SHA-256', artifact);
  // ECDSA/SHA-256 over the artifact yields a signature over exactly the digest
  // submitted below, which is what hashedrekord verifies.
  const raw = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, artifact);
  const signature = b64encode(rawSignatureToDER(new Uint8Array(raw)));

  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      signature: {
        content: signature,
        publicKey: { content: publicKeyContent },
      },
      data: {
        hash: { algorithm: 'sha256', value: toHex(digest) },
      },
    },
  };
}

export async function writeEntry(data) {
  const key = await getSigningKey(data.privateKeyJwk);
  const tag = `${data.runNonce}-${exec.scenario.iterationInTest}`;
  const entry = await buildEntry(key, data.publicKeyContent, tag);

  const res = http.post(`${BASE_URL}/api/v1/log/entries`, JSON.stringify(entry), {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    tags: { op: 'create_entry' },
  });

  writeLatency.add(res.timings.duration);
  const ok = check(res, { 'write: 201': (r) => r.status === 201 });
  writeErrors.add(!ok);

  if (ok) {
    entriesCreated.add(1);
    highestLogIndex.add(parseLogIndex(res.body));
  } else if (exec.scenario.iterationInTest % 100 === 0) {
    console.error(`write failed: ${res.status} ${String(res.body).slice(0, 300)}`);
  }
}

export function readEntry(data) {
  // The write scenario runs faster than the read scenario and started earlier,
  // so this sequential cursor always trails indices that have been committed.
  const logIndex = data.startIndex + exec.scenario.iterationInTest;

  const res = http.get(`${BASE_URL}/api/v1/log/entries?logIndex=${logIndex}`, {
    headers: { Accept: 'application/json' },
    tags: { op: 'get_entry_by_index' },
  });

  readLatency.add(res.timings.duration);
  readMisses.add(res.status === 404);
  const ok = check(res, {
    'read: 200': (r) => r.status === 200,
    'read: index matches': (r) => r.status !== 200 || parseLogIndex(r.body) === logIndex,
  });
  readErrors.add(!ok);
}
