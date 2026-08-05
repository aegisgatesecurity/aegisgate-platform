// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ML Training Data Generator
//
// Generates JSONL training data from the Go augmentation pipeline.
// Usage: go run cmd/gen-training-data/main.go [-output-dir DIR]
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ml/training"
)

func main() {
	outputDir := "training/data"
	if len(os.Args) > 1 {
		for i, arg := range os.Args {
			if arg == "-output-dir" && i+1 < len(os.Args) {
				outputDir = os.Args[i+1]
			}
		}
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Generate all examples (adversarial + benign)
	aug := training.NewAugmentor()
	adversarialExamples := aug.GenerateAll()
	benignExamples := aug.GenerateBenign()

	// Combine
	allExamples := make([]training.Example, 0, len(adversarialExamples)+len(benignExamples))
	allExamples = append(allExamples, adversarialExamples...)
	allExamples = append(allExamples, benignExamples...)

	// Count by label
	adversarial := 0
	benign := 0
	for _, ex := range allExamples {
		if ex.Label == training.LabelAdversarial {
			adversarial++
		} else {
			benign++
		}
	}
	fmt.Printf("Generated %d examples (%d adversarial, %d benign)\n", len(allExamples), adversarial, benign)

	// Split dataset (80/10/10)
	train, val, test := training.SplitDataset(allExamples, 0.8, 0.1, 0.1)

	fmt.Printf("Split: train=%d, val=%d, test=%d\n", len(train), len(val), len(test))

	// Write JSONL files
	trainPath := filepath.Join(outputDir, "train.jsonl")
	valPath := filepath.Join(outputDir, "val.jsonl")
	testPath := filepath.Join(outputDir, "test.jsonl")
	combinedPath := filepath.Join(outputDir, "combined.jsonl")

	if err := training.WriteJSONL(train, trainPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing train.jsonl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Wrote %s (%d examples)\n", trainPath, len(train))

	if err := training.WriteJSONL(val, valPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing val.jsonl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Wrote %s (%d examples)\n", valPath, len(val))

	if err := training.WriteJSONL(test, testPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing test.jsonl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Wrote %s (%d examples)\n", testPath, len(test))

	if err := training.WriteJSONL(allExamples, combinedPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing combined.jsonl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Wrote %s (%d examples)\n", combinedPath, len(allExamples))

	fmt.Println("\n✅ Training data generation complete!")
	fmt.Printf("   Train: %d examples\n", len(train))
	fmt.Printf("   Val:   %d examples\n", len(val))
	fmt.Printf("   Test:  %d examples\n", len(test))
	fmt.Printf("   Total: %d examples\n", len(allExamples))
}