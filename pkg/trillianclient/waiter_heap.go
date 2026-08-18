//
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

package trillianclient

import "container/heap"

type sizeWaiter struct {
	size  uint64
	done  chan struct{}
	index int
}

type sizeWaiters []*sizeWaiter

func (h sizeWaiters) Len() int           { return len(h) }
func (h sizeWaiters) Less(i, j int) bool { return h[i].size < h[j].size }
func (h sizeWaiters) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *sizeWaiters) Push(x any) {
	w := x.(*sizeWaiter)
	w.index = len(*h)
	*h = append(*h, w)
}

func (h *sizeWaiters) Pop() any {
	old := *h
	n := len(old)
	w := old[n-1]
	old[n-1] = nil
	w.index = -1
	*h = old[:n-1]
	return w
}

// addSizeWaiter adds a waiter to the heap. t.mu must be held.
func (t *cachedTrillianClient) addSizeWaiter(size uint64) *sizeWaiter {
	w := &sizeWaiter{size: size, done: make(chan struct{})}
	heap.Push(&t.waiters, w)
	return w
}

// removeSizeWaiter removes a canceled waiter. t.mu must be held.
func (t *cachedTrillianClient) removeSizeWaiter(w *sizeWaiter) {
	if w.index >= 0 {
		heap.Remove(&t.waiters, w.index)
	}
}

// notifySizeWaiters wakes only callers satisfied by size. t.mu must be held.
func (t *cachedTrillianClient) notifySizeWaiters(size uint64) {
	for len(t.waiters) > 0 && t.waiters[0].size <= size {
		w := heap.Pop(&t.waiters).(*sizeWaiter)
		close(w.done)
	}
}
