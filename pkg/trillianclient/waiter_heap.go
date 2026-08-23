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

// sizeBucket groups every caller waiting for the same tree size. Trillian
// advances in batches, so target sizes are highly clustered: at 500 QPS and a
// 100ms sequencing interval, dozens of requests commonly share one bucket.
// One channel close wakes the whole group.
type sizeBucket struct {
	size      uint64
	done      chan struct{}
	refs      int
	heapIndex int
	active    bool
}

type sizeBucketHeap []*sizeBucket

func (h sizeBucketHeap) Len() int           { return len(h) }
func (h sizeBucketHeap) Less(i, j int) bool { return h[i].size < h[j].size }
func (h sizeBucketHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}

func (h *sizeBucketHeap) Push(x any) {
	b := x.(*sizeBucket)
	b.heapIndex = len(*h)
	*h = append(*h, b)
}

func (h *sizeBucketHeap) Pop() any {
	old := *h
	n := len(old)
	b := old[n-1]
	old[n-1] = nil
	b.heapIndex = -1
	*h = old[:n-1]
	return b
}

type sizeWaiters struct {
	bySize map[uint64]*sizeBucket
	heap   sizeBucketHeap
	total  int
}

func (w *sizeWaiters) add(size uint64) *sizeBucket {
	if w.bySize == nil {
		w.bySize = make(map[uint64]*sizeBucket)
	}
	if b := w.bySize[size]; b != nil {
		b.refs++
		w.total++
		return b
	}
	b := &sizeBucket{
		size:      size,
		done:      make(chan struct{}),
		refs:      1,
		heapIndex: -1,
		active:    true,
	}
	w.bySize[size] = b
	w.total++
	heap.Push(&w.heap, b)
	return b
}

// release removes one canceled caller. The bucket itself is removed only when
// its final caller leaves before the requested size is reached.
func (w *sizeWaiters) release(b *sizeBucket) {
	if b == nil || !b.active {
		return
	}
	b.refs--
	w.total--
	if b.refs > 0 {
		return
	}
	b.active = false
	delete(w.bySize, b.size)
	if b.heapIndex >= 0 {
		heap.Remove(&w.heap, b.heapIndex)
	}
}

// satisfy detaches all buckets reached by size. The caller closes their done
// channels after releasing its mutex, so waking a large batch does not create
// lock contention inside the publication critical section.
func (w *sizeWaiters) satisfy(size uint64) []*sizeBucket {
	var ready []*sizeBucket
	for len(w.heap) > 0 && w.heap[0].size <= size {
		b := heap.Pop(&w.heap).(*sizeBucket)
		b.active = false
		delete(w.bySize, b.size)
		w.total -= b.refs
		ready = append(ready, b)
	}
	return ready
}

func (w *sizeWaiters) drain() []*sizeBucket {
	ready := make([]*sizeBucket, 0, len(w.heap))
	for len(w.heap) > 0 {
		b := heap.Pop(&w.heap).(*sizeBucket)
		b.active = false
		ready = append(ready, b)
	}
	clear(w.bySize)
	w.total = 0
	return ready
}

func (w *sizeWaiters) waiterCount() int {
	return w.total
}
