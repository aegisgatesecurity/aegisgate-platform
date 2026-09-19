// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — CI Echo Server
//
// Minimal multi-threaded echo server for k6 detection gate tests in CI.
// Responds to POST /v1/chat/completions with OpenAI-compatible echo responses.
// Responds to GET /health with a health check JSON.
//
// Usage: go run tests/echo-server/main.go [port]
// Default port: 11435

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

var requestCounter uint64

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
}

type choice struct {
	Index        int     `json:"index"`
	Message      message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "json error", http.StatusBadRequest)
		return
	}

	// Echo back the last user message
	content := "echo"
	if len(req.Messages) > 0 {
		content = req.Messages[len(req.Messages)-1].Content
	}

	id := atomic.AddUint64(&requestCounter, 1)
	resp := chatResponse{
		ID:      fmt.Sprintf("echo-cmpl-%d", id),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []choice{
			{
				Index:        0,
				Message:      message{Role: "assistant", Content: content},
				FinishReason: "stop",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"version": "echo-server-ci",
	})
}

func statsPrinter() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("Requests served: %d | Goroutines: %d\n",
			atomic.LoadUint64(&requestCounter), runtime.NumGoroutine())
	}
}

func main() {
	port := flag.String("port", "11435", "port to listen on")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChat)
	mux.HandleFunc("/health", handleHealth)
	// Also handle any other path as echo (for flexibility)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/chat/completions") {
			handleChat(w, r)
			return
		}
		handleHealth(w, r)
	})

	go statsPrinter()

	addr := ":" + *port
	log.Printf("CI Echo Server starting on %s (GOMAXPROCS=%d)\n", addr, runtime.GOMAXPROCS(0))
	log.Printf("Endpoints: POST /v1/chat/completions, GET /health\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
		os.Exit(1)
	}
}
