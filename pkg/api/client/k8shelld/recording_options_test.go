// Copyright 2025 The K8shell Authors. All rights reserved.
// Use of this source code is governed by a AGPLv3
// license that can be found in the LICENSE file.

package k8shelld

import (
	"context"
	"testing"

	sessionv1 "github.com/k8shell-io/common/pkg/api/gen/go/session/v1"
)

func TestRecorderOptionsContextOverride(t *testing.T) {
	cfgOpts := &sessionv1.RecordingOptions{Format: sessionv1.RecordingFormat_RECORDING_FORMAT_PCAPNG}
	ctxOpts := &sessionv1.RecordingOptions{Format: sessionv1.RecordingFormat_RECORDING_FORMAT_NONE}
	c := (&K8shelld{}).WithRecordingConfig(RecordingConfig{BufferBytes: 1024, Tcpip: cfgOpts})

	s := applyRecorderOptions(c.recorderOptions(context.Background(), c.recording.Tcpip))
	if s.options != cfgOpts || s.bufferBytes != 1024 {
		t.Fatalf("without override: options=%v buffer=%d", s.options, s.bufferBytes)
	}

	ctx := ContextWithRecordingOptions(context.Background(), ctxOpts)
	s = applyRecorderOptions(c.recorderOptions(ctx, c.recording.Tcpip))
	if s.options != ctxOpts || s.bufferBytes != 1024 {
		t.Fatalf("with override: options=%v buffer=%d", s.options, s.bufferBytes)
	}
}
