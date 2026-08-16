package anomaly

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents anomaly detection configuration.
type Config struct {
	// Enabled controls whether anomaly detection is active
	Enabled bool `yaml:"enabled"`

	// Entropy configures entropy detection thresholds
	Entropy EntropyConfig `yaml:"entropy"`

	// Frequency configures frequency analysis settings
	Frequency FrequencyConfig `yaml:"frequency"`

	// Structure configures structure detection settings
	Structure StructureConfig `yaml:"structure"`

	// Scoring configures the scoring algorithm weights and thresholds
	Scoring ScorerConfig `yaml:"scoring"`

	// Performance configures performance limits
	Performance PerformanceConfig `yaml:"performance"`
}

// EntropyConfig configures entropy analysis thresholds.
type EntropyConfig struct {
	// LowThreshold is entropy below this value indicates natural language (default: 2.0)
	LowThreshold float64 `yaml:"low_threshold"`
	// MediumThreshold is entropy below this value indicates mixed content (default: 4.0)
	MediumThreshold float64 `yaml:"medium_threshold"`
	// HighThreshold is entropy below this value indicates likely token/secret (default: 6.0)
	HighThreshold float64 `yaml:"high_threshold"`
	// VeryHighThreshold is entropy above this value indicates likely encoded (default: 7.0)
	VeryHighThreshold float64 `yaml:"very_high_threshold"`
	// BoostEncodedContent when true, boosts scores for Base64/hex content (default: true)
	BoostEncodedContent bool `yaml:"boost_encoded_content"`
}

// FrequencyConfig configures frequency analysis settings.
type FrequencyConfig struct {
	// Baseline sets the comparison baseline (english, code, json, base64, hex, natural)
	Baseline string `yaml:"baseline"`
	// StrictMode when true, uses tighter thresholds (default: false)
	StrictMode bool `yaml:"strict_mode"`
}

// StructureConfig configures structure detection settings.
type StructureConfig struct {
	// KnownPrefixes lists known service prefixes for token detection
	KnownPrefixes []string `yaml:"known_prefixes"`
	// MinKeyLength is the minimum length for detected keys (default: 16)
	MinKeyLength int `yaml:"min_key_length"`
	// MaxKeyLength is the maximum length for detected keys (default: 256)
	MaxKeyLength int `yaml:"max_key_length"`
	// DetectProduction when true, identifies production vs test keys (default: true)
	DetectProduction bool `yaml:"detect_production"`
}

// PerformanceConfig configures performance limits.
type PerformanceConfig struct {
	// MaxInputSize is the maximum input size to analyze in bytes (default: 64KB)
	MaxInputSize int `yaml:"max_input_size"`
	// Timeout is the maximum time for analysis (default: 10ms)
	Timeout time.Duration `yaml:"timeout"`
	// MaxMemoryKB is the maximum memory to use per scan (default: 1MB)
	MaxMemoryKB int `yaml:"max_memory_kb"`
	// EnableMetrics when true, emits Prometheus metrics (default: true)
	EnableMetrics bool `yaml:"enable_metrics"`
}

// DefaultConfig returns production-safe default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Entropy: EntropyConfig{
			LowThreshold:        2.0,
			MediumThreshold:     4.0,
			HighThreshold:       6.0,
			VeryHighThreshold:   7.0,
			BoostEncodedContent: true,
		},
		Frequency: FrequencyConfig{
			Baseline:   "natural",
			StrictMode: false,
		},
		Structure: StructureConfig{
			KnownPrefixes: []string{
				"sk-", "sk-prod-", "sk-test-",
				"ghp_", "github_pat_", "gho_", "glpat-", "glft-",
				"sk_live_", "sk_test_", "rk_live_", "sq0atp-", "sq0csp-",
				"xoxb-", "xoxp-",
				"AKIA", "ASIA",
				"eyJ", "eyJh",
			},
			MinKeyLength:     16,
			MaxKeyLength:     256,
			DetectProduction: true,
		},
		Scoring: ScorerConfig{
			EntropyWeight:       0.3,
			FrequencyWeight:     0.3,
			StructureWeight:     0.4,
			AnomalyThreshold:    0.7,
			AlertThreshold:      0.85,
			SuspiciousThreshold: 0.5,
		},
		Performance: PerformanceConfig{
			MaxInputSize:  65536, // 64KB
			Timeout:       10 * time.Millisecond,
			MaxMemoryKB:   1024, // 1MB
			EnableMetrics: true,
		},
	}
}

// MinimalConfig returns a minimal configuration for low-resource environments.
func MinimalConfig() Config {
	config := DefaultConfig()
	config.Performance.MaxInputSize = 8192 // 8KB
	config.Performance.Timeout = 5 * time.Millisecond
	config.Performance.EnableMetrics = false
	return config
}

// EnterpriseConfig returns a configuration optimized for enterprise detection.
func EnterpriseConfig() Config {
	config := DefaultConfig()
	config.Entropy.LowThreshold = 1.5
	config.Entropy.MediumThreshold = 3.5
	config.Entropy.HighThreshold = 5.5
	config.Scoring.AnomalyThreshold = 0.6
	config.Scoring.AlertThreshold = 0.75
	config.Scoring.SuspiciousThreshold = 0.4
	config.Frequency.StrictMode = true
	return config
}

// FromYAML loads configuration from YAML bytes.
func FromYAML(data []byte) (Config, error) {
	// Initialize with defaults
	config := DefaultConfig()

	// Unmarshal with default handling
	err := yaml.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate
	if err := config.Validate(); err != nil {
		return config, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// FromYAMLFile loads configuration from a YAML file.
func FromYAMLFile(path string) (Config, error) {
	// Read file
	data, err := readFile(path)
	if err != nil {
		return DefaultConfig(), fmt.Errorf("failed to read config file: %w", err)
	}

	return FromYAML(data)
}

// Validate checks if the configuration is valid.
func (c Config) Validate() error {
	// Entropy thresholds must be in ascending order
	if c.Entropy.LowThreshold >= c.Entropy.MediumThreshold {
		return fmt.Errorf("entropy.low_threshold (%f) must be less than medium_threshold (%f)",
			c.Entropy.LowThreshold, c.Entropy.MediumThreshold)
	}
	if c.Entropy.MediumThreshold >= c.Entropy.HighThreshold {
		return fmt.Errorf("entropy.medium_threshold (%f) must be less than high_threshold (%f)",
			c.Entropy.MediumThreshold, c.Entropy.HighThreshold)
	}

	// Scoring weights must sum to 1.0 (with some tolerance)
	weightSum := c.Scoring.EntropyWeight + c.Scoring.FrequencyWeight + c.Scoring.StructureWeight
	if weightSum < 0.9 || weightSum > 1.1 {
		return fmt.Errorf("scoring weights must sum to 1.0, got %f", weightSum)
	}

	// Thresholds must be in ascending order
	if c.Scoring.SuspiciousThreshold >= c.Scoring.AnomalyThreshold {
		return fmt.Errorf("scoring.suspicious_threshold (%f) must be less than anomaly_threshold (%f)",
			c.Scoring.SuspiciousThreshold, c.Scoring.AnomalyThreshold)
	}
	if c.Scoring.AnomalyThreshold >= c.Scoring.AlertThreshold {
		return fmt.Errorf("scoring.anomaly_threshold (%f) must be less than alert_threshold (%f)",
			c.Scoring.AnomalyThreshold, c.Scoring.AlertThreshold)
	}

	// Performance limits
	if c.Performance.MaxInputSize < 1024 {
		return fmt.Errorf("performance.max_input_size must be at least 1024 bytes")
	}
	if c.Performance.MaxInputSize > 1024*1024 {
		return fmt.Errorf("performance.max_input_size must be less than 1MB")
	}
	if c.Performance.Timeout < time.Millisecond {
		return fmt.Errorf("performance.timeout must be at least 1ms")
	}

	return nil
}

// ToYAML serializes configuration to YAML bytes.
func (c Config) ToYAML() ([]byte, error) {
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	return data, nil
}

// ScorerConfig extracts scoring configuration from Config.
func (c Config) ScorerConfig() ScorerConfig {
	return c.Scoring
}

// EntropyThresholds extracts entropy thresholds from Config.
func (c Config) EntropyThresholds() EntropyThresholds {
	return EntropyThresholds{
		Low:      c.Entropy.LowThreshold,
		Medium:   c.Entropy.MediumThreshold,
		High:     c.Entropy.HighThreshold,
		VeryHigh: c.Entropy.VeryHighThreshold,
	}
}

// String returns a human-readable representation of the config.
func (c Config) String() string {
	return fmt.Sprintf("Config(enabled=%v, entropy=[%.2f,%.2f,%.2f], scoring=%.1f/%.1f/%.1f, thresholds=[%.2f,%.2f,%.2f])",
		c.Enabled,
		c.Entropy.LowThreshold, c.Entropy.MediumThreshold, c.Entropy.HighThreshold,
		c.Scoring.EntropyWeight, c.Scoring.FrequencyWeight, c.Scoring.StructureWeight,
		c.Scoring.SuspiciousThreshold, c.Scoring.AnomalyThreshold, c.Scoring.AlertThreshold,
	)
}

// MergeWith merges other config into this one, with other taking precedence.
func (c *Config) MergeWith(other Config) {
	if other.Enabled {
		c.Enabled = other.Enabled
	}

	if other.Entropy.LowThreshold > 0 {
		c.Entropy = other.Entropy
	}

	if other.Frequency.Baseline != "" {
		c.Frequency = other.Frequency
	}

	if len(other.Structure.KnownPrefixes) > 0 {
		c.Structure = other.Structure
	}

	// Always use other scoring config (more important)
	c.Scoring = other.Scoring

	c.Performance = other.Performance
}

// readFile is the file-reading hook for the config package. It defaults
// to an error-returning implementation; callers must call SetFileReader
// to wire real file I/O (keeps the package pure Go without os import).
var readFile func(path string) ([]byte, error)

// SetFileReader sets the file reading function (for testing/integration).
func SetFileReader(fn func(path string) ([]byte, error)) {
	readFile = fn
}

// init sets default file reader.
func init() {
	readFile = defaultReadFile
}

// defaultReadFile is the default file reader. Returns an error so
// callers know file I/O has not been wired via SetFileReader.
func defaultReadFile(path string) ([]byte, error) {
	// Call SetFileReader to wire real file I/O.
	return nil, fmt.Errorf("file reading not configured - use SetFileReader")
}

// ExampleConfig returns a YAML example for documentation.
func ExampleConfig() string {
	return `# AegisGate Anomaly Detection Configuration
# Place in your config.yaml under 'anomaly_detection:' section

enabled: true

entropy:
  low_threshold: 2.0        # Natural language typically < 2.0
  medium_threshold: 4.0    # Mixed content typically 2.0-4.0
  high_threshold: 6.0       # Tokens typically 4.0-6.0
  very_high_threshold: 7.0 # Encoded content typically > 7.0
  boost_encoded_content: true  # Increase score for Base64/hex

frequency:
  baseline: natural        # natural, english, code, json, base64, hex
  strict_mode: false      # Tighter thresholds for higher security

structure:
  known_prefixes:
    - "sk-"               # OpenAI
    - "ghp_"              # GitHub personal access token
    - "sk_live_"          # Stripe production
    - "xoxb-"             # Slack
    - "AKIA"              # AWS
    - "eyJ"               # JWT
  min_key_length: 16
  max_key_length: 256
  detect_production: true  # Identify prod vs test keys

scoring:
  entropy_weight: 0.3     # Weight for entropy component
  frequency_weight: 0.3    # Weight for frequency component
  structure_weight: 0.4   # Weight for structure component
  suspicious_threshold: 0.5  # Flag content above this
  anomaly_threshold: 0.7     # Consider anomalous above this
  alert_threshold: 0.85       # Alert and potentially block above this

performance:
  max_input_size: 65536   # 64KB - max input to analyze
  timeout: 10ms            # Max time for analysis
  max_memory_kb: 1024     # 1MB - max memory per scan
  enable_metrics: true    # Emit Prometheus metrics
`
}
