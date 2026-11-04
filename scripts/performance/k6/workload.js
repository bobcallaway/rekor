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
const base = __ENV.BASE_URL || 'http://127.0.0.1:13000';
const rate = Number(__ENV.RATE || 100);
const mode = __ENV.MODE || 'mixed';
const seedCount = 100;
const writes = new Counter('created_entries');
const overload = new Counter('overload_responses');
const errors = new Rate('unexpected_response');

http.setResponseCallback(http.expectedStatuses(200, 201, 503));
export const options = {
  scenarios: {
    traffic: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration: __ENV.DURATION || '30s',
      preAllocatedVUs: Number(__ENV.VUS || 300),
      maxVUs: Number(__ENV.VUS || 300),
      gracefulStop: '10s',
    },
  },
  setupTimeout: '60s',
  batch: 100,
  batchPerHost: 100,
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  systemTags: ['status', 'method', 'name', 'scenario', 'expected_response'],
  thresholds: {
    unexpected_response: ['rate==0'], dropped_iterations: ['count==0'], checks: ['rate==1'],
    'http_req_duration{name:create}': ['p(99)>=0'],
    'http_req_duration{name:lookup_uuid}': ['p(99)>=0'],
    'http_req_duration{name:lookup_index}': ['p(99)>=0'],
    'http_req_duration{name:log_info}': ['p(99)>=0'],
  },
};

export function setup() {
  const responses = http.batch(Array.from({length: seedCount}, (_, i) => ({
    method: 'POST', url: `${base}/api/v1/log/entries`, body: JSON.stringify(fixtures[i]),
    params: {headers: {'Content-Type': 'application/json'}, tags: {name: 'seed'}},
  })));
  const ids = responses.map(r => {
    if (r.status !== 201) throw new Error(`seeding failed: ${r.status} ${r.body}`);
    return Object.keys(r.json())[0];
  });
  console.log('REKOR_BENCHMARK_READY');
  return ids;
}

export default function(ids) {
  const iteration = exec.scenario.iterationInTest;
  const kind = mode === 'write' ? 0 : (mode === 'read' ? 2 + iteration % 8 : iteration % 10);
  let response;
  let expected;
  if (kind < 2) {
    const index = seedCount + iteration;
    if (index >= fixtures.length) throw new Error('fixture set exhausted; generate more fixtures');
    response = http.post(`${base}/api/v1/log/entries`, JSON.stringify(fixtures[index]), {
      headers: {'Content-Type': 'application/json'}, tags: {name: 'create'}, timeout: '10s',
    });
    expected = response.status === 201 || response.status === 503;
    if (response.status === 201) writes.add(1);
    if (response.status === 503) {
      overload.add(1);
      check(response, {'overload has Retry-After': r => r.headers['Retry-After'] === '1'});
    }
  } else if (kind < 6) {
    response = http.get(`${base}/api/v1/log/entries/${ids[iteration % seedCount]}`, {tags: {name: 'lookup_uuid'}, timeout: '10s'});
    expected = response.status === 200;
  } else if (kind < 9) {
    response = http.get(`${base}/api/v1/log/entries?logIndex=${iteration % seedCount}`, {tags: {name: 'lookup_index'}, timeout: '10s'});
    expected = response.status === 200;
  } else {
    response = http.get(`${base}/api/v1/log`, {tags: {name: 'log_info'}, timeout: '10s'});
    expected = response.status === 200;
  }
  errors.add(!expected);
  check(response, {'expected response': () => expected});
  if (!expected && iteration < 10) console.error(`${response.status}: ${response.body}`);
}
