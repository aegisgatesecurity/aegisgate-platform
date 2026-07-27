// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// EnvProvider reads secrets from environment variables
type EnvProvider struct {
	prefix string
}

// NewEnvProvider creates a new environment variable provider
func NewEnvProvider() *EnvProvider {
	return &EnvProvider{prefix: ""}
}

func (e *EnvProvider) WithPrefix(prefix string) *EnvProvider {
	e.prefix = prefix
	return e
}

func (e *EnvProvider) Get(ctx context.Context, key string) (Secret, error) {
	fullKey := e.prefix + key
	value := os.Getenv(fullKey)
	if value == "" {
		return Secret{}, fmt.Errorf("secret not found: %s", fullKey)
	}

	return Secret{
		Value:     value,
		UpdatedAt: time.Now().UTC(),
		Metadata: map[string]string{
			"source": "env",
			"key":    fullKey,
		},
	}, nil
}

func (e *EnvProvider) Set(ctx context.Context, key string, value Secret) error {
	return fmt.Errorf("env provider is read-only")
}

func (e *EnvProvider) Delete(ctx context.Context, key string) error {
	return fmt.Errorf("env provider is read-only")
}

func (e *EnvProvider) List(ctx context.Context) ([]string, error) {
	var keys []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[0], e.prefix) {
			keys = append(keys, strings.TrimPrefix(parts[0], e.prefix))
		}
	}
	return keys, nil
}

func (e *EnvProvider) Exists(ctx context.Context, key string) bool {
	_, err := e.Get(ctx, key)
	return err == nil
}

func (e *EnvProvider) Close() error {
	return nil
}

func (e *EnvProvider) Health(ctx context.Context) error {
	return nil
}

func (e *EnvProvider) Name() string {
	return "env"
}
