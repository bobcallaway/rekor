// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"crypto/rsa"
	"io"
)

// readFull is the same as io.ReadFull except that reading zero bytes returns
// ErrUnexpectedEOF rather than EOF.
func readFull(r io.Reader, buf []byte) (n int, err error) {
	n, err = io.ReadFull(r, buf)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

// padToKeySize left-pads a MPI with zeroes to match the length of the
// specified RSA public.
func padToKeySize(pub *rsa.PublicKey, b []byte) []byte {
	k := (pub.N.BitLen() + 7) / 8
	if len(b) >= k {
		return b
	}
	bb := make([]byte, k)
	copy(bb[len(bb)-len(b):], b)
	return bb
}
