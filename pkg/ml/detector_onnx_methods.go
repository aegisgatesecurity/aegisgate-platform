// SPDX-License-Identifier: Apache-2.0
// +build cgo

package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	onnxruntime "github.com/yalue/onnxruntime_go"
)

// onnxFields holds the ONNX Runtime session and tensors.
// Only populated when CGO is enabled.
type onnxFields struct {
	session      *onnxruntime.AdvancedSession
	inputTensor  *onnxruntime.Tensor[int32]
	outputTensor *onnxruntime.Tensor[float32]
}

// newOnnxFields creates an empty onnxFields struct.
func newOnnxFields() *onnxFields {
	return &onnxFields{}
}

// loadModelONNX loads the ONNX model and creates an inference session.
func (td *ThreatDetector) loadModelONNX(path string) error {
	if td.config.ONNXRuntimeLibPath != "" {
		onnxruntime.SetSharedLibraryPath(td.config.ONNXRuntimeLibPath)
	}

	if !onnxruntime.IsInitialized() {
		if err := onnxruntime.InitializeEnvironment(); err != nil {
			return fmt.Errorf("initialize onnxruntime: %w", err)
		}
	}

	hash, err := computeFileHash(path)
	if err != nil {
		return fmt.Errorf("compute model hash: %w", err)
	}

	inputShape := onnxruntime.Shape{1, int64(MaxSeqLen)}
	inputData := make([]int32, MaxSeqLen)
	inputTensor, err := onnxruntime.NewTensor[int32](inputShape, inputData)
	if err != nil {
		return fmt.Errorf("create input tensor: %w", err)
	}

	outputShape := onnxruntime.Shape{1, 1}
	outputData := make([]float32, 1)
	outputTensor, err := onnxruntime.NewTensor[float32](outputShape, outputData)
	if err != nil {
		inputTensor.Destroy()
		return fmt.Errorf("create output tensor: %w", err)
	}

	session, err := onnxruntime.NewAdvancedSession(
		path,
		[]string{"input"},
		[]string{"threat_score"},
		[]onnxruntime.Value{inputTensor, outputTensor},
		[]onnxruntime.Value{outputTensor},
		nil,
	)
	if err != nil {
		inputTensor.Destroy()
		outputTensor.Destroy()
		return fmt.Errorf("create ONNX session: %w", err)
	}

	// Clean up previous session
	td.closeONNX()

	td.onnx.session = session
	td.onnx.inputTensor = inputTensor
	td.onnx.outputTensor = outputTensor
	td.modelHash = hash
	td.loaded = true

	return nil
}

// inferenceONNX runs the ONNX model on the encoded input.
func (td *ThreatDetector) inferenceONNX(encoded []int32) (float64, bool) {
	if td.onnx.session == nil {
		return 0, false
	}

	copy(td.onnx.inputTensor.GetData(), encoded)

	if err := td.onnx.session.Run(); err != nil {
		return 0, false
	}

	outputData := td.onnx.outputTensor.GetData()
	if len(outputData) >= 1 {
		score := float64(outputData[0])
		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}
		return score, true
	}

	return 0, false
}

// closeONNX cleans up the ONNX session and tensors.
func (td *ThreatDetector) closeONNX() error {
	var firstErr error

	if td.onnx.session != nil {
		if err := td.onnx.session.Destroy(); err != nil && firstErr == nil {
			firstErr = err
		}
		td.onnx.session = nil
	}
	if td.onnx.inputTensor != nil {
		if err := td.onnx.inputTensor.Destroy(); err != nil && firstErr == nil {
			firstErr = err
		}
		td.onnx.inputTensor = nil
	}
	if td.onnx.outputTensor != nil {
		if err := td.onnx.outputTensor.Destroy(); err != nil && firstErr == nil {
			firstErr = err
		}
		td.onnx.outputTensor = nil
	}

	return firstErr
}

// computeFileHash computes SHA256 of a file for model versioning.
func computeFileHash(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// measureInferenceLatency measures inference duration in ms.
func measureInferenceLatency(td *ThreatDetector) (float64, error) {
	encoded := td.normalizer.Encode("What is the weather today?")
	start := time.Now()
	td.inference(encoded)
	elapsed := time.Since(start)
	return float64(elapsed.Microseconds()) / 1000.0, nil
}