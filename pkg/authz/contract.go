// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// EvalRequest is the common interface for every typed policy evaluation
// request. Each policy domain (ssh, blueprint, ...) provides a concrete
// implementation.
//
// On the client side, build the concrete type with its With* builder
// and call ToProto to produce the gRPC message.
// On the server side, convert the incoming gRPC message with the domain's
// FromProto function, which validates the contract and returns the typed struct.
type EvalRequest interface {
	// Validate checks the request against its domain contract. It is called
	// automatically by Build and FromProto, but can be called explicitly if
	// the struct was mutated after construction.
	Validate() error

	// ToProto serializes the typed request into a gRPC EvaluateRequest,
	// attaching the supplied JWT token. Use this on the client side to
	// produce the wire message from the typed, validated struct.
	ToProto(token string) *authzv1.EvaluateRequest
}
