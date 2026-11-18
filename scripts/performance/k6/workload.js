// Copyright 2026 The Sigstore Authors.
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
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';
import { Counter, Rate } from 'k6/metrics';

const fixtures = new SharedArray('signed fixtures', () => JSON.parse(open('./fixtures.json')));
const inactiveEntries = new SharedArray('inactive entries', () => {
  if (!__ENV.INACTIVE_FILE) return [];
  return JSON.parse(open(__ENV.INACTIVE_FILE));
});

const base = __ENV.BASE_URL || 'http://rekor:3000';
const readBase = __ENV.READ_BASE_URL || base;
const rate = Number(__ENV.RATE || 100);
const burstRate = Number(__ENV.BURST_RATE || 250);
const bgReadRate = Number(__ENV.READ_RATE || 100);
const durationSec = Number(__ENV.DURATION_SEC || 30);
const mode = __ENV.MODE || 'mixed';
const seedCount = Number(__ENV.SEED_COUNT || 100);
const fixtureOffset = Number(__ENV.FIXTURE_OFFSET || 0);
const allowOverload = __ENV.ALLOW_OVERLOAD !== 'false';

const writes = new Counter('created_entries');
const overload = new Counter('overload_responses');
const overloadWrites = new Counter('overload_write_responses');
const overloadReads = new Counter('overload_read_responses');
const rawMiss404 = new Counter('read_after_write_404');
const errors = new Rate('unexpected_response');

http.setResponseCallback(http.expectedStatuses(200, 201, 404, 503));

function buildScenarios() {
  const vus = Number(__ENV.VUS || 300);
  if (mode === 'write_burst') {
    const warmup = Math.max(5, Math.floor(durationSec / 6));
    const spike = Math.max(8, Math.floor(durationSec / 3));
    const recover = Math.max(5, durationSec - warmup - spike);
    return {
      write_burst: {
        executor: 'ramping-arrival-rate',
        exec: 'writeBurst',
        startRate: Math.max(10, Math.floor(rate / 4)),
        timeUnit: '1s',
        preAllocatedVUs: vus,
        maxVUs: Math.max(vus, burstRate * 4),
        gracefulStop: '15s',
        stages: [
          { target: Math.max(20, Math.floor(rate / 2)), duration: `${warmup}s` },
          { target: burstRate, duration: `${spike}s` },
          { target: Math.max(20, Math.floor(rate / 2)), duration: `${recover}s` },
        ],
      },
      concurrent_reads: {
        executor: 'constant-arrival-rate',
        exec: 'backgroundRead',
        rate: bgReadRate,
        timeUnit: '1s',
        duration: `${warmup + spike + recover}s`,
        preAllocatedVUs: Math.max(64, Math.floor(vus / 2)),
        maxVUs: Math.max(128, vus),
        gracefulStop: '15s',
      },
    };
  }
  return {
    traffic: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration: `${durationSec}s`,
      preAllocatedVUs: vus,
      maxVUs: vus,
      gracefulStop: '15s',
    },
  };
}

const thresholds = {
  unexpected_response: ['rate==0'],
  dropped_iterations: ['count==0'],
  read_after_write_404: ['count==0'],
  checks: ['rate==1'],
};
if (mode === 'write' || mode === 'write_burst' || mode === 'classic' || mode === 'mixed' || mode === 'read_after_write' || mode === 'sharded') {
  thresholds['http_req_duration{name:create}'] = ['p(99)>=0'];
}
if (mode === 'read' || mode === 'write_burst' || mode === 'classic' || mode === 'mixed' || mode === 'sharded') {
  thresholds['http_req_duration{name:lookup_uuid}'] = ['p(99)>=0'];
  thresholds['http_req_duration{name:lookup_index}'] = ['p(99)>=0'];
}
if (mode === 'read' || mode === 'classic' || mode === 'mixed') {
  thresholds['http_req_duration{name:log_info}'] = ['p(99)>=0'];
}
if (mode === 'mixed' || mode === 'sharded') {
  thresholds['http_req_duration{name:search_query}'] = ['p(99)>=0'];
  thresholds['http_req_duration{name:lookup_miss}'] = ['p(99)>=0'];
  thresholds['http_req_duration{name:raw_lookup}'] = ['p(99)>=0'];
}
if (mode === 'mixed') {
  thresholds['http_req_duration{name:log_proof}'] = ['p(99)>=0'];
}
if (mode === 'read_after_write') {
  thresholds['http_req_duration{name:raw_lookup}'] = ['p(99)>=0'];
}
if (inactiveEntries.length > 0 && (mode === 'mixed' || mode === 'sharded')) {
  thresholds['http_req_duration{name:lookup_inactive_uuid}'] = ['p(99)>=0'];
}

export const options = {
  scenarios: buildScenarios(),
  setupTimeout: '120s',
  batch: 64,
  batchPerHost: 64,
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  systemTags: ['status', 'method', 'name', 'scenario', 'expected_response'],
  thresholds,
};

function absentHex(n) {
  return n.toString(16).padStart(64, '0');
}

function recordOverload(response, isWrite) {
  overload.add(1);
  if (isWrite) {
    overloadWrites.add(1);
  } else {
    overloadReads.add(1);
  }
  check(response, { 'overload has Retry-After': r => r.headers['Retry-After'] === '1' });
}

function checkStatus(response, okStatus, isWrite) {
  let ok = response.status === okStatus;
  if (!ok && allowOverload && response.status === 503) {
    ok = true;
    recordOverload(response, isWrite);
  }
  errors.add(!ok);
  check(response, { 'expected response': () => ok });
  if (!ok && exec.scenario.iterationInTest < 15) {
    console.error(`${response.request.url} -> ${response.status}: ${response.body}`);
  }
  return ok;
}

export function setup() {
  const ids = [];
  const indexes = [];
  const chunkSize = 50;
  for (let start = 0; start < seedCount; start += chunkSize) {
    const end = Math.min(seedCount, start + chunkSize);
    const reqs = [];
    for (let i = start; i < end; i++) {
      const fixtureIdx = fixtureOffset + i;
      if (fixtureIdx >= fixtures.length) {
        throw new Error(`fixture set exhausted during setup at ${fixtureIdx}`);
      }
      reqs.push({
        method: 'POST',
        url: `${base}/api/v1/log/entries`,
        body: JSON.stringify(fixtures[fixtureIdx]),
        params: { headers: { 'Content-Type': 'application/json' }, tags: { name: 'seed' }, timeout: '30s' },
      });
    }
    const responses = http.batch(reqs);
    for (const r of responses) {
      if (r.status !== 201) throw new Error(`seeding failed: ${r.status} ${r.body}`);
      const parsed = r.json();
      const entryID = Object.keys(parsed)[0];
      ids.push(entryID);
      indexes.push(parsed[entryID].logIndex);
    }
  }
  console.log('REKOR_BENCHMARK_READY');
  return {
    ids,
    indexes,
    inactiveUUIDs: inactiveEntries.map(e => e.uuid),
    inactiveCount: inactiveEntries.length,
    treeSize: seedCount,
  };
}

function createEntry(iteration, tag) {
  const index = fixtureOffset + seedCount + iteration;
  if (index >= fixtures.length) throw new Error('fixture set exhausted; generate more fixtures');
  const response = http.post(`${base}/api/v1/log/entries`, JSON.stringify(fixtures[index]), {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: tag },
    timeout: '15s',
  });
  if (response.status === 201) writes.add(1);
  checkStatus(response, 201, true);
  return response;
}

function readAfterWrite(iteration) {
  const created = createEntry(iteration, 'create');
  if (created.status !== 201) return;
  const body = created.json();
  const entryID = Object.keys(body)[0];
  const logIndex = body[entryID].logIndex;
  const plainUUID = entryID.length === 80 ? entryID.slice(16) : entryID;
  const url = iteration % 2 === 0
    ? `${readBase}/api/v1/log/entries/${plainUUID}`
    : `${readBase}/api/v1/log/entries?logIndex=${logIndex}`;
  const resp = http.get(url, { tags: { name: 'raw_lookup' }, timeout: '15s' });
  if (resp.status === 404) {
    rawMiss404.add(1);
  }
  checkStatus(resp, 200, false);
}

function searchBatch(data, iteration) {
  const ids = data.ids;
  const indexes = data.indexes;
  const secondID = ids[(iteration + 1) % ids.length];
  const entryUUIDs = [
    ids[iteration % ids.length],
    secondID.length === 80 ? secondID.slice(16) : secondID, // plain UUID active hit
    absentHex(0xdead0000 + iteration),                      // plain UUID miss
    absentHex(0xbeef0000 + iteration),                      // second miss in same batch
  ];
  if (data.inactiveUUIDs.length > 0) {
    entryUUIDs.push(data.inactiveUUIDs[iteration % data.inactiveUUIDs.length]);
  }
  const logIndexes = [
    indexes[iteration % indexes.length],
    999999999, // out-of-range active index miss
  ];
  const resp = http.post(
    `${readBase}/api/v1/log/entries/retrieve`,
    JSON.stringify({ entryUUIDs, logIndexes }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'search_query' }, timeout: '15s' },
  );
  checkStatus(resp, 200, false);
}

export function writeBurst() {
  const iteration = exec.scenario.iterationInTest;
  createEntry(iteration, 'create');
}

export function backgroundRead(data) {
  const iteration = exec.scenario.iterationInTest;
  let resp;
  if (iteration % 2 === 0) {
    resp = http.get(`${readBase}/api/v1/log/entries/${data.ids[iteration % data.ids.length]}`, {
      tags: { name: 'lookup_uuid' }, timeout: '15s',
    });
  } else {
    resp = http.get(`${readBase}/api/v1/log/entries?logIndex=${data.indexes[iteration % data.indexes.length]}`, {
      tags: { name: 'lookup_index' }, timeout: '15s',
    });
  }
  checkStatus(resp, 200, false);
}

export default function (data) {
  const iteration = exec.scenario.iterationInTest;

  if (mode === 'write') {
    createEntry(iteration, 'create');
    return;
  }
  if (mode === 'read_after_write') {
    readAfterWrite(iteration);
    return;
  }
  if (mode === 'read') {
    const k = iteration % 8;
    let resp;
    if (k < 4) {
      resp = http.get(`${readBase}/api/v1/log/entries/${data.ids[iteration % data.ids.length]}`, {
        tags: { name: 'lookup_uuid' }, timeout: '15s',
      });
    } else if (k < 7) {
      resp = http.get(`${readBase}/api/v1/log/entries?logIndex=${data.indexes[iteration % data.indexes.length]}`, {
        tags: { name: 'lookup_index' }, timeout: '15s',
      });
    } else {
      resp = http.get(`${readBase}/api/v1/log`, { tags: { name: 'log_info' }, timeout: '15s' });
    }
    checkStatus(resp, 200, false);
    return;
  }
  if (mode === 'classic') {
    const kind = iteration % 10;
    if (kind < 2) {
      createEntry(iteration, 'create');
    } else if (kind < 6) {
      const resp = http.get(`${readBase}/api/v1/log/entries/${data.ids[iteration % data.ids.length]}`, {
        tags: { name: 'lookup_uuid' }, timeout: '15s',
      });
      checkStatus(resp, 200, false);
    } else if (kind < 9) {
      const resp = http.get(`${readBase}/api/v1/log/entries?logIndex=${data.indexes[iteration % data.indexes.length]}`, {
        tags: { name: 'lookup_index' }, timeout: '15s',
      });
      checkStatus(resp, 200, false);
    } else {
      const resp = http.get(`${readBase}/api/v1/log`, { tags: { name: 'log_info' }, timeout: '15s' });
      checkStatus(resp, 200, false);
    }
    return;
  }
  if (mode === 'sharded') {
    const slot = iteration % 20;
    if (slot < 2) {
      readAfterWrite(iteration);
    } else if (slot < 8 && data.inactiveUUIDs.length > 0) {
      const uuid = data.inactiveUUIDs[iteration % data.inactiveUUIDs.length];
      const resp = http.get(`${readBase}/api/v1/log/entries/${uuid}`, {
        tags: { name: 'lookup_inactive_uuid' }, timeout: '15s',
      });
      checkStatus(resp, 200, false);
    } else if (slot < 13) {
      searchBatch(data, iteration);
    } else if (slot < 16) {
      const resp = http.get(`${readBase}/api/v1/log/entries/${absentHex(0xface0000 + iteration)}`, {
        tags: { name: 'lookup_miss' }, timeout: '15s',
      });
      checkStatus(resp, 404, false);
    } else if (slot < 18) {
      const resp = http.get(`${readBase}/api/v1/log/entries/${data.ids[iteration % data.ids.length]}`, {
        tags: { name: 'lookup_uuid' }, timeout: '15s',
      });
      checkStatus(resp, 200, false);
    } else {
      const resp = http.get(`${readBase}/api/v1/log/entries?logIndex=${data.indexes[iteration % data.indexes.length]}`, {
        tags: { name: 'lookup_index' }, timeout: '15s',
      });
      checkStatus(resp, 200, false);
    }
    return;
  }

  // Default 'mixed' mode: realistic mix covering writes, read-after-write,
  // active/inactive UUID lookups, index lookups, SearchLogQuery batches,
  // 404 misses, log-info, and consistency proofs.
  const slot = iteration % 20;
  if (slot < 3) {
    createEntry(iteration, 'create');
  } else if (slot === 3) {
    readAfterWrite(iteration);
  } else if (slot < 8) {
    const resp = http.get(`${readBase}/api/v1/log/entries/${data.ids[iteration % data.ids.length]}`, {
      tags: { name: 'lookup_uuid' }, timeout: '15s',
    });
    checkStatus(resp, 200, false);
  } else if (slot < 10 && data.inactiveUUIDs.length > 0) {
    const uuid = data.inactiveUUIDs[iteration % data.inactiveUUIDs.length];
    const resp = http.get(`${readBase}/api/v1/log/entries/${uuid}`, {
      tags: { name: 'lookup_inactive_uuid' }, timeout: '15s',
    });
    checkStatus(resp, 200, false);
  } else if (slot < 14) {
    const resp = http.get(`${readBase}/api/v1/log/entries?logIndex=${data.indexes[iteration % data.indexes.length]}`, {
      tags: { name: 'lookup_index' }, timeout: '15s',
    });
    checkStatus(resp, 200, false);
  } else if (slot < 16) {
    searchBatch(data, iteration);
  } else if (slot === 16) {
    const resp = http.get(`${readBase}/api/v1/log/entries/${absentHex(0xcafe0000 + iteration)}`, {
      tags: { name: 'lookup_miss' }, timeout: '15s',
    });
    checkStatus(resp, 404, false);
  } else if (slot === 17) {
    const resp = http.get(`${readBase}/api/v1/log/proof?firstSize=1&lastSize=${data.treeSize}`, {
      tags: { name: 'log_proof' }, timeout: '15s',
    });
    checkStatus(resp, 200, false);
  } else {
    const resp = http.get(`${readBase}/api/v1/log`, { tags: { name: 'log_info' }, timeout: '15s' });
    checkStatus(resp, 200, false);
  }
}
