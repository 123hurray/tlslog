// Copyright (C) 2015 RayXXZhang
// All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license.  See the LICENSE file for details.

package tlslog

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

type logRand struct {
	log            string
	originalReader io.Reader
}

func newLogRand(originalReader io.Reader) *logRand {
	return &logRand{
		log:            "",
		originalReader: originalReader,
	}
}

func (r *logRand) Read(p []byte) (n int, err error) {
	if r.originalReader != nil {
		n, err = r.originalReader.Read(p)
	} else {
		n, err = rand.Read(p)
	}
	if r.log == "" {
		r.log = fmt.Sprint(hex.EncodeToString(p))
	}
	return
}
