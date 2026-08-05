// SPDX-License-Identifier: Apache-2.0
//go:build !cgo
// +build !cgo

package ml

// onnxFields is empty when CGO is disabled — no ONNX runtime available.
type onnxFields struct{}

// newOnnxFields returns an empty struct when CGO is disabled.
func newOnnxFields() *onnxFields {
	return &onnxFields{}
}
