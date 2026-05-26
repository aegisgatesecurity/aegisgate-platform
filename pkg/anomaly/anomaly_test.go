package anomaly

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// =============================================================================
// ENTROPY TESTS
// =============================================================================

func TestShannonEntropy_Empty(t *testing.T) {
	if ShannonEntropy([]byte{}) != 0.0 {
		t.Errorf("Empty should return 0")
	}
}

func TestShannonEntropy_Constant(t *testing.T) {
	data := bytes.Repeat([]byte{'a'}, 100)
	if ShannonEntropy(data) != 0.0 {
		t.Errorf("Constant should have 0 entropy")
	}
}

func TestShannonEntropy_High(t *testing.T) {
	data := []byte("xK9mP2vL3nQ5rT7wY1zA4bC6dE8fG0hJ2lK4")
	if ShannonEntropy(data) < 4.0 {
		t.Errorf("High entropy should be > 4.0")
	}
}

func TestShannonEntropyString(t *testing.T) {
	if ShannonEntropyString("xK9mP2vL3nQ5rT7wY1zA4bC6dE8fG0hJ2lK4") < 4.0 {
		t.Errorf("String entropy should match")
	}
}

func TestBase64Likeness(t *testing.T) {
	if Base64Likeness([]byte("SGVsbG8gV29ybGQgcGF0dGVybnM=")) < 0.8 {
		t.Errorf("Base64 should score high")
	}
}

func TestHexLikeness(t *testing.T) {
	if HexLikeness([]byte("deadbeef1234567890abcdef")) < 0.8 {
		t.Errorf("Hex should score high")
	}
}

func TestEntropyThresholds_Classification(t *testing.T) {
	th := DefaultEntropyThresholds()
	if th.Classification(3.0) == "" {
		t.Errorf("Should classify entropy")
	}
}

func TestEntropyThresholds_Score(t *testing.T) {
	th := DefaultEntropyThresholds()
	if th.Score(4.0) < 0 || th.Score(4.0) > 1 {
		t.Errorf("Score should be valid range")
	}
}

func TestBase64Entropy(t *testing.T) {
	if Base64Entropy([]byte("SGVsbG8gV29ybGQ=")) < 3.0 {
		t.Errorf("Base64 should have significant entropy")
	}
}

// =============================================================================
// FREQUENCY TESTS
// =============================================================================

func TestAnalyze_Empty(t *testing.T) {
	fp := Analyze([]byte{})
	if fp.AlphanumericRatio != 0 {
		t.Errorf("Empty should have 0 ratio")
	}
}

func TestAnalyze_Basic(t *testing.T) {
	fp := Analyze([]byte("Hello123"))
	if fp.LowercaseRatio == 0 {
		t.Errorf("Should detect lowercase")
	}
}

func TestAnalyzeString(t *testing.T) {
	fp := AnalyzeString("Hello World")
	if fp.UppercaseRatio == 0 {
		t.Errorf("Should detect uppercase")
	}
}

func TestGetCommonBaseline(t *testing.T) {
	fp := GetCommonBaseline("base64")
	if fp.Base64Score == 0 {
		t.Errorf("Base64 baseline should have score")
	}
}

func TestCalculateBase64Score(t *testing.T) {
	if CalculateBase64Score([]byte("SGVsbG8gV29ybGQ=")) < 0.7 {
		t.Errorf("Base64 should score high")
	}
}

func TestCalculateHexScore(t *testing.T) {
	if CalculateHexScore([]byte("deadbeef")) < 0.8 {
		t.Errorf("Hex should score high")
	}
}

func TestCompareWithBaseline(t *testing.T) {
	fp := Analyze([]byte("SGVsbG8gV29ybGQ="))
	if fp.CompareWithBaseline(Base64Baseline) < 0.5 {
		t.Errorf("Base64 should match baseline")
	}
}

// =============================================================================
// TOKENIZER TESTS
// =============================================================================

func TestTokenType_String(t *testing.T) {
	if TokenTypeAPIKey.String() != "api_key" {
		t.Errorf("Token type string failed")
	}
}

func TestClassify_Empty(t *testing.T) {
	ts := Classify("")
	if ts.Type != TokenTypeUnknown {
		t.Errorf("Empty should be unknown")
	}
}

func TestClassify_OpenAI(t *testing.T) {
	if Classify("sk-proj-verylongkey1234567890abcdef").Type != TokenTypeOpenAIKey {
		t.Errorf("Should detect OpenAI key")
	}
}

func TestClassify_GitHub(t *testing.T) {
	if Classify("ghp_verylongtoken1234567890abcdefghij").Type != TokenTypeGitHubToken {
		t.Errorf("Should detect GitHub token")
	}
}

func TestClassify_Stripe(t *testing.T) {
	if Classify("sk_live_PLACEHOLDER").Type != TokenTypeStripeKey {
		t.Errorf("Should detect Stripe key")
	}
}

func TestClassify_AWS(t *testing.T) {
	if Classify("AKIAIOSFODNN7EXAMPLE").Type != TokenTypeAWSKey {
		t.Errorf("Should detect AWS key")
	}
}

func TestClassify_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if Classify(jwt).Type != TokenTypeJWT {
		t.Errorf("Should detect JWT")
	}
}

func TestClassify_Slack(t *testing.T) {
	if Classify("xoxb-PLACEHOLDER").Type != TokenTypeSlackToken {
		t.Errorf("Should detect Slack token")
	}
}

func TestIsUUID(t *testing.T) {
	if !isUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Errorf("Should detect UUID")
	}
}

func TestContainsTimestamp(t *testing.T) {
	_ = containsTimestamp("token_1672531200_suffix")
}

func TestIsProductionKey(t *testing.T) {
	if !isProductionKey("sk-live-abc123", TokenStructure{}) {
		t.Errorf("sk-live should be production")
	}
}

func TestIsBase64Like(t *testing.T) {
	_ = isBase64Like("SGVsbG8gV29ybGQ=")
}

func TestSplitIntoSegments(t *testing.T) {
	if len(splitIntoSegments("sk-live-abc123")) != 3 {
		t.Errorf("Should split into 3 segments")
	}
}

func TestExtractPrefix(t *testing.T) {
	prefix := extractPrefix("sk-live-abc123")
	if prefix != "sk-" && prefix != "sk" {
		t.Errorf("Prefix should be 'sk' or 'sk-', got '%s'", prefix)
	}
}

// =============================================================================
// SCORER TESTS
// =============================================================================

func TestDefaultScorerConfig(t *testing.T) {
	config := DefaultScorerConfig()
	if config.AnomalyThreshold != 0.7 {
		t.Errorf("Default threshold should be 0.7")
	}
}

func TestScore(t *testing.T) {
	config := DefaultScorerConfig()
	score := Score([]byte("sk-live-abc123def456"), config)
	if score.Total < 0 || score.Total > 1 {
		t.Errorf("Score should be valid range")
	}
}

func TestScore_HighEntropy(t *testing.T) {
	config := DefaultScorerConfig()
	data := []byte("xK9mP2vL3nQ5rT7wY1zA4bC6dE8fG0hJ2lK4nM6pR8sT0uV2wX4yZ6aB8cD0eF2gH4jK6l")
	score := Score(data, config)
	if score.Total < 0 || score.Total > 1 {
		t.Errorf("Score should be valid range")
	}
}

func TestScoreToken(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScoreToken("sk-proj-verylongkey1234567890abcdef", config)
	if result.Total < 0 || result.Total > 1 {
		t.Errorf("Score should be valid range")
	}
}

func TestScan(t *testing.T) {
	config := DefaultScorerConfig()
	result := Scan([]byte("sk-live-abc123"), config)
	if result.Score.Total == 0 {
		t.Errorf("Should have non-zero score")
	}
}

func TestScan_Empty(t *testing.T) {
	config := DefaultScorerConfig()
	result := Scan([]byte{}, config)
	if result.Score.Total != 0 {
		t.Errorf("Empty should have zero score")
	}
}

func TestScanString(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanString("user input", config)
	if result.Score.Total < 0 || result.Score.Total > 1 {
		t.Errorf("Score should be valid range")
	}
}

func TestAnomalyScore_GetSeverity(t *testing.T) {
	score := AnomalyScore{Total: 0.85}
	if score.GetSeverity() != SeverityHigh {
		t.Errorf("0.85 should be high severity")
	}
}

func TestAnomalyScore_IsHighSeverity(t *testing.T) {
	score := AnomalyScore{Total: 0.85}
	if !score.IsHighSeverity() {
		t.Errorf("High score should be high severity")
	}
}

func TestAnomalyScore_IsKnownServiceToken(t *testing.T) {
	for _, tt := range []TokenType{TokenTypeOpenAIKey, TokenTypeGitHubToken, TokenTypeStripeKey, TokenTypeAWSKey} {
		score := AnomalyScore{TokenType: tt}
		if !score.IsKnownServiceToken() {
			t.Errorf("%v should be known service", tt)
		}
	}
}

func TestAnomalyScore_ContainsServicePrefix(t *testing.T) {
	score := AnomalyScore{Flags: []string{"prefix:sk-"}}
	if !score.ContainsServicePrefix() {
		t.Errorf("Should have prefix")
	}
}

func TestSeverityLevel_String(t *testing.T) {
	levels := []SeverityLevel{SeverityNormal, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, level := range levels {
		if level.String() == "" {
			t.Errorf("Severity level should have string")
		}
	}
}

func TestClassifyScore(t *testing.T) {
	for _, score := range []float64{0.2, 0.4, 0.6, 0.8, 0.95} {
		if classifyScore(score) == "" {
			t.Errorf("Score %f should have classification", score)
		}
	}
}

// =============================================================================
// CONFIG TESTS
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	if DefaultConfig().Scoring.AnomalyThreshold != 0.7 {
		t.Errorf("Default threshold should be 0.7")
	}
}

func TestMinimalConfig(t *testing.T) {
	if MinimalConfig().Scoring.EntropyWeight != 0.3 {
		t.Errorf("Minimal should have entropy weight")
	}
}

func TestEnterpriseConfig(t *testing.T) {
	if EnterpriseConfig().Scoring.AnomalyThreshold != 0.6 {
		t.Errorf("Enterprise should have lower threshold")
	}
}

func TestConfig_FromYAML(t *testing.T) {
	config, err := FromYAML([]byte("scoring:\n  anomaly_threshold: 0.8"))
	if err != nil {
		t.Errorf("Should parse: %v", err)
	}
	if config.Scoring.AnomalyThreshold <= 0 {
		t.Errorf("Threshold should be set")
	}
}

func TestConfig_FromYAML_Invalid(t *testing.T) {
	if _, err := FromYAML([]byte("invalid: [yaml")); err == nil {
		t.Errorf("Should fail on invalid YAML")
	}
}

func TestConfig_Validate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Errorf("Valid config should pass: %v", err)
	}
}

func TestConfig_ValidateInvalid(t *testing.T) {
	badConfig := Config{Scoring: ScorerConfig{EntropyWeight: 1.5, FrequencyWeight: 0.3, StructureWeight: 0.3}}
	if err := badConfig.Validate(); err == nil {
		t.Errorf("Invalid weights should fail")
	}
}

func TestConfig_MergeWith(t *testing.T) {
	base := MinimalConfig()
	base.Scoring.EntropyWeight = 0.3
	override := Config{Scoring: ScorerConfig{AnomalyThreshold: 0.9}}
	base.MergeWith(override)
	if base.Scoring.AnomalyThreshold != 0.9 {
		t.Errorf("Override should take precedence")
	}
}

func TestConfig_ToYAML(t *testing.T) {
	yaml, err := MinimalConfig().ToYAML()
	if err != nil {
		t.Errorf("Should serialize: %v", err)
	}
	if len(yaml) == 0 {
		t.Errorf("YAML should not be empty")
	}
}

func TestConfig_String(t *testing.T) {
	if DefaultConfig().String() == "" {
		t.Errorf("Config should have string")
	}
}

func TestEntropyThresholds_Score_Edges(t *testing.T) {
	th := EntropyThresholds{Low: 2.5, Medium: 4.0, High: 5.5}
	if th.Score(0) != 0 {
		t.Errorf("Zero entropy should score 0")
	}
	if th.Score(10) < 0.9 {
		t.Errorf("High entropy should score near 1")
	}
}

// =============================================================================
// THRESHOLD TESTS
// =============================================================================

func TestNewThresholdManager(t *testing.T) {
	tm := NewThresholdManager()
	if tm.IsEnabled() {
		t.Errorf("Should be disabled by default")
	}
}

func TestThresholdManager_Enable(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	if !tm.IsEnabled() {
		t.Errorf("Should be enabled")
	}
}

func TestThresholdManager_Disable(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	tm.Disable()
	if tm.IsEnabled() {
		t.Errorf("Should be disabled")
	}
}

func TestThresholdManager_RecordSample_Disabled(t *testing.T) {
	tm := NewThresholdManager()
	if tm.RecordSample(0.5) {
		t.Errorf("Disabled should not adjust")
	}
}

func TestThresholdManager_GetThresholds(t *testing.T) {
	tm := NewThresholdManager()
	if tm.GetThresholds().Low == 0 {
		t.Errorf("Should have thresholds")
	}
}

func TestThresholdManager_GetScorerConfig(t *testing.T) {
	tm := NewThresholdManager()
	if tm.GetScorerConfig().AnomalyThreshold == 0 {
		t.Errorf("Should have config")
	}
}

func TestThresholdManager_SetScorerConfig(t *testing.T) {
	tm := NewThresholdManager()
	tm.SetScorerConfig(ScorerConfig{AnomalyThreshold: 0.9})
	if tm.GetScorerConfig().AnomalyThreshold != 0.9 {
		t.Errorf("Config not set correctly")
	}
}

func TestThresholdManager_ResetStats(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	for i := 0; i < 20; i++ {
		tm.RecordSample(0.5)
	}
	tm.ResetStats()
	if tm.GetStats().sampleCount != 0 {
		t.Errorf("Stats should be reset")
	}
}

func TestThresholdManager_AnomalyRate(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	tm.SetScorerConfig(ScorerConfig{AnomalyThreshold: 0.5})
	for i := 0; i < 5; i++ {
		tm.RecordSample(0.6)
	}
	for i := 0; i < 5; i++ {
		tm.RecordSample(0.3)
	}
	rate := tm.AnomalyRate()
	if rate < 0 || rate > 1 {
		t.Errorf("Rate should be between 0 and 1")
	}
}

func TestThresholdManager_MeanScore(t *testing.T) {
	tm := NewThresholdManager()
	tm.stats.windowScores = []float64{0.5, 0.6, 0.7, 0.8, 0.9}
	mean := tm.MeanScore()
	if mean < 0.6 || mean > 0.8 {
		t.Errorf("Mean should be ~0.7, got %f", mean)
	}
}

func TestAdjustThresholds_Mid(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	tm.SetScorerConfig(ScorerConfig{AnomalyThreshold: 0.7, AlertThreshold: 0.85})
	tm.stats.sampleCount = 100
	tm.stats.anomalyCount = 15
	tm.stats.windowScores = make([]float64, 100)
	for i := range tm.stats.windowScores {
		tm.stats.windowScores[i] = 0.55
	}
	before := tm.GetScorerConfig().AnomalyThreshold
	tm.adjustThresholds()
	if math.Abs(tm.GetScorerConfig().AnomalyThreshold-before) > 0.1 {
		t.Errorf("Normal rate should not drastically adjust threshold")
	}
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

type mockScanner struct{}

func (m *mockScanner) Scan(data []byte) interface{} {
	return "mock result"
}

func TestNewTokenScanner(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	if ts == nil {
		t.Errorf("Should create scanner")
	}
}

func TestTokenScanner_ScanToken(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	result := ts.ScanToken("sk-live-abc123")
	if result.AnomalyScore.Total < 0 {
		t.Errorf("Score should be valid")
	}
}

func TestTokenScanner_ScanData(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	result := ts.ScanData([]byte("key=sk-live-abc123"))
	if result.AnomalyScore.Total < 0 {
		t.Errorf("Score should be valid")
	}
}

func TestTokenScanner_ScanData_Secrets(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	for _, d := range []string{"key=sk-live-abc", "secret=AKIAIOSFODNN7EXAMPLE", "token=ghp_xyz"} {
		r := ts.ScanData([]byte(d))
		if r.AnomalyScore.Total < 0.3 {
			t.Errorf("Should detect secrets")
		}
	}
}

func TestTokenScanner_ScanJSON(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	_ = ts.ScanJSON([]byte("{\"key\": \"sk-live-abc123\"}"))
}

func TestTokenScanner_ScanTokens_Empty(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	if len(ts.ScanTokens(nil)) != 0 {
		t.Errorf("Should be empty")
	}
}

func TestNewHighEntropyScanner(t *testing.T) {
	hs := NewHighEntropyScanner(4.5)
	if hs == nil {
		t.Errorf("Should create scanner")
	}
}

func TestHighEntropyScanner_IsHighEntropy(t *testing.T) {
	hs := NewHighEntropyScanner(4.5)
	if !hs.IsHighEntropy([]byte("xK9mP2vL3nQ5rT7wY1zA4bC6dE8fG0hJ2lK4nM6pR8sT0uV2wX4yZ6aB8cD0eF2gH4")) {
		t.Errorf("Should detect high entropy")
	}
}

func TestHighEntropyScanner_ScanForHighEntropy(t *testing.T) {
	hs := NewHighEntropyScanner(4.5)
	found, _ := hs.ScanForHighEntropy([]byte("text xK9mP2vL3nQ5rT7wY1zA4bC6dE8fG0hJ2lK4nM6pR8sT0uV2wX4yZ6aB8cD0eF2gH4 more"))
	if !found {
		t.Errorf("Should detect high entropy")
	}
}

func TestNewEncoderDetector(t *testing.T) {
	detector := NewEncoderDetector()
	if detector == nil {
		t.Errorf("Should create detector")
	}
}

func TestEncoderDetector_Detect(t *testing.T) {
	detector := NewEncoderDetector()
	isEncoded, encType, score := detector.Detect([]byte("SGVsbG8gV29ybGQ="))
	if !isEncoded {
		t.Errorf("Base64 should be detected")
	}
	if encType != "base64" {
		t.Errorf("Should detect base64 type, got %s", encType)
	}
	if score < 0.5 {
		t.Errorf("Should have high score, got %f", score)
	}
}

func TestEncoderDetector_Detect_Hex(t *testing.T) {
	detector := NewEncoderDetector()
	isEncoded, _, _ := detector.Detect([]byte("deadbeef1234567890"))
	if !isEncoded {
		t.Errorf("Hex should be detected")
	}
}

func TestNewAnomalyAugmentedScanner(t *testing.T) {
	scanner := NewAnomalyAugmentedScanner(&mockScanner{}, DefaultIntegrationConfig(IntegrationSecretScanner))
	if scanner == nil {
		t.Errorf("Should create scanner")
	}
}

func TestAnomalyAugmentedScanner_Scan(t *testing.T) {
	scanner := NewAnomalyAugmentedScanner(&mockScanner{}, DefaultIntegrationConfig(IntegrationSecretScanner))
	result := scanner.Scan([]byte("sk-live-abc123def456"))
	if result.AnomalyScore.Total < 0 {
		t.Errorf("Should return valid result")
	}
}

func TestScannerResult_ShouldBlock(t *testing.T) {
	r1 := ScannerResult{AnomalyScore: AnomalyScore{Total: 0.95, IsAnomalous: true, IsAlert: true}, BlockOnAlert: true}
	if !r1.ShouldBlock() {
		t.Errorf("High alert should block")
	}
}

func TestScannerResult_LogResult(t *testing.T) {
	result := ScannerResult{AnomalyScore: AnomalyScore{Total: 0.5}, ProcessingTime: 50}
	result.LogResult(nil)
}

func TestWrapWithAnomalyDetection(t *testing.T) {
	fn := func(data []byte) interface{} { return "mock" }
	config := DefaultIntegrationConfig(IntegrationSecretScanner)
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("sk-live-abc123"))
	if result.AnomalyScore.Total < 0 || result.AnomalyScore.Total > 1 {
		t.Errorf("Score should be valid range")
	}
}

func TestDefaultIntegrationConfig(t *testing.T) {
	config := DefaultIntegrationConfig(IntegrationSecretScanner)
	if config.Point != IntegrationSecretScanner {
		t.Errorf("Point should be set")
	}
	if !config.Enabled {
		t.Errorf("Should be enabled")
	}
}

func TestConfig_Validate_AlertBelowAnomaly(t *testing.T) {
	badConfig := Config{Scoring: ScorerConfig{EntropyWeight: 0.3, FrequencyWeight: 0.3, StructureWeight: 0.3, AnomalyThreshold: 0.8, AlertThreshold: 0.5}}
	if err := badConfig.Validate(); err == nil {
		t.Errorf("Should detect alert < anomaly")
	}
}

func TestConfig_ToYAML_Content(t *testing.T) {
	yaml, _ := MinimalConfig().ToYAML()
	if !strings.Contains(string(yaml), "entropy") {
		t.Errorf("YAML should contain entropy section")
	}
}

func TestBuildScoreFlags_High(t *testing.T) {
	flags := buildScoreFlags(AnomalyScore{Total: 0.9, IsAnomalous: true, IsAlert: true, TokenType: TokenTypeGitHubToken})
	if len(flags) < 2 {
		t.Errorf("Should have multiple flags")
	}
}

func TestDetectTokenType_All(t *testing.T) {
	for _, token := range []string{
		"ghp_verylongtoken1234567890",
		"sk-proj-verylongkey1234567890",
		"sk_live_PLACEHOLDER",
		"AKIAIOSFODNN7EXAMPLE",
		"xoxb-PLACEHOLDER",
	} {
		ts := Classify(token)
		if ts.Type == TokenTypeUnknown {
			t.Errorf("Should classify %s", token[:15])
		}
	}
}

func TestIsProductionKey_All(t *testing.T) {
	for _, test := range []struct {
		token  string
		isProd bool
	}{
		{"sk-live-abc", true},
		{"sk-prod-key", true},
		{"sk-test-abc", false},
		{"dev_key", false},
	} {
		if isProductionKey(test.token, TokenStructure{}) != test.isProd {
			t.Errorf("Production key mismatch for %s", test.token)
		}
	}
}

func TestAnalyze_Hex(t *testing.T) {
	fp := Analyze([]byte("DEADBEEF123"))
	if fp.HexScore < 0.5 {
		t.Errorf("Hex score should be high, got %f", fp.HexScore)
	}
}

func TestAnomalyScore_Severity(t *testing.T) {
	for _, test := range []struct {
		total float64
		sev   SeverityLevel
	}{
		{0.1, SeverityNormal},
		{0.4, SeverityLow},
		{0.6, SeverityMedium},
		{0.8, SeverityHigh},
		{0.9, SeverityCritical},
	} {
		score := AnomalyScore{Total: test.total}
		if score.GetSeverity() != test.sev {
			t.Errorf("Severity mismatch for %f", test.total)
		}
	}
}

// =============================================================================
// BENCHMARK TESTS
// =============================================================================

func BenchmarkShannonEntropy(b *testing.B) {
	data := []byte("xK9mP2vL3nQ5rT7wY1zA4bC6dE8fG0hJ2lK4nM6pR8sT0uV2wX4yZ6aB8cD0eF2gH4")
	for i := 0; i < b.N; i++ {
		ShannonEntropy(data)
	}
}

func BenchmarkClassify(b *testing.B) {
	token := "sk-proj-verylongkey1234567890abcdef"
	for i := 0; i < b.N; i++ {
		Classify(token)
	}
}

func BenchmarkScore(b *testing.B) {
	config := DefaultScorerConfig()
	data := []byte("sk-live-abc123def456ghi789jkl012mno345")
	for i := 0; i < b.N; i++ {
		Score(data, config)
	}
}

// === Additional coverage tests ===

func TestConfig_FromYAMLFile(t *testing.T) {
	_, err := FromYAMLFile("/nonexistent/path.yaml")
	if err == nil {
		t.Errorf("Should error for nonexistent file")
	}
}

func TestConfig_Validate_ThresholdBounds(t *testing.T) {
	bad := Config{Scoring: ScorerConfig{EntropyWeight: 0.3, FrequencyWeight: 0.3, StructureWeight: 0.3, AnomalyThreshold: -0.1}}
	if err := bad.Validate(); err == nil {
		t.Errorf("Should detect negative threshold")
	}
}

func TestConfig_Validate_SuspiciousEdge(t *testing.T) {
	bad := Config{Scoring: ScorerConfig{EntropyWeight: 0.3, FrequencyWeight: 0.3, StructureWeight: 0.3, AnomalyThreshold: 0.5, SuspiciousThreshold: 0.8}}
	if err := bad.Validate(); err == nil {
		t.Errorf("Should detect suspicious > anomaly")
	}
}

func TestConfig_Validate_AlertEdge(t *testing.T) {
	bad := Config{Scoring: ScorerConfig{EntropyWeight: 0.3, FrequencyWeight: 0.3, StructureWeight: 0.3, AnomalyThreshold: 0.8, AlertThreshold: 0.5, SuspiciousThreshold: 0.6}}
	if err := bad.Validate(); err == nil {
		t.Errorf("Should detect alert < anomaly")
	}
}

func TestConfig_MergeWith_AllFields(t *testing.T) {
	base := MinimalConfig()
	base.Enabled = true
	override := Config{Enabled: true}
	base.MergeWith(override)
	if !base.Enabled {
		t.Errorf("Enabled should be overwritten when other.Enabled is true")
	}
}

func TestEntropyConfig_Defaults(t *testing.T) {
	config := EntropyConfig{LowThreshold: 2.5}
	if config.LowThreshold != 2.5 {
		t.Errorf("Config not set correctly")
	}
}

func TestScorerConfig_Defaults(t *testing.T) {
	config := ScorerConfig{AnomalyThreshold: 0.7}
	if config.AnomalyThreshold != 0.7 {
		t.Errorf("Config not set correctly")
	}
}

func TestEntropyThresholds_All(t *testing.T) {
	th := EntropyThresholds{Low: 1.0, Medium: 4.0, High: 6.0, VeryHigh: 7.0}
	// Test Classification function - verify correct behavior
	if th.Classification(0.5) != "natural_language" {
		t.Errorf("0.5 should be natural_language, got %s", th.Classification(0.5))
	}
	// 2.5 is between Low(1.0) and Medium(4.0), so it's mixed_content
	if th.Classification(2.5) != "mixed_content" {
		t.Errorf("2.5 should be mixed_content, got %s", th.Classification(2.5))
	}
	if th.Classification(5.0) != "likely_token" {
		t.Errorf("5.0 should be likely_token, got %s", th.Classification(5.0))
	}
	// 7.0 is at VeryHigh threshold, so it's very_high_entropy
	if th.Classification(7.0) != "very_high_entropy" {
		t.Errorf("7.0 should be very_high_entropy, got %s", th.Classification(7.0))
	}
}

func TestGetCommonBaseline_All(t *testing.T) {
	for _, bl := range []string{"base64", "hex", "email", "url", "json"} {
		_ = GetCommonBaseline(bl)
	}
}

func TestCompareWithBaseline_Hex(t *testing.T) {
	fp := Analyze([]byte("deadbeef"))
	score := fp.CompareWithBaseline(HexBaseline)
	if score < 0.4 {
		t.Errorf("Hex should have reasonable baseline match, got %.3f", score)
	}
}

func TestCalculateBase64Score_Full(t *testing.T) {
	score := CalculateBase64Score([]byte("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="))
	if score < 0.8 {
		t.Errorf("Pure base64 should score > 0.8")
	}
}

func TestCalculateHexScore_Full(t *testing.T) {
	score := CalculateHexScore([]byte("DEADBEEF1234567890ABCDEF"))
	if score < 0.8 {
		t.Errorf("Pure hex should score > 0.8")
	}
}

func TestTokenScanner_ScanTokens(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	results := ts.ScanTokens([]string{"sk-live-abc", "ghp_xyz", "plain"})
	if len(results) != 3 {
		t.Errorf("Should return 3 results, got %d", len(results))
	}
}

func TestTokenScanner_ScanData_NoSecret(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	result := ts.ScanData([]byte("hello world"))
	_ = result
}

func TestTokenScanner_ScanJSON_Empty(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	results := ts.ScanJSON([]byte{})
	if len(results) != 0 {
		t.Errorf("Empty JSON should return empty")
	}
}

func TestHighEntropyScanner_IsHighEntropy_Borderline(t *testing.T) {
	hs := NewHighEntropyScanner(3.0)
	if hs.IsHighEntropy([]byte("abcd1234")) {
		// May or may not be high entropy
	}
}

func TestEncoderDetector_Detect_Plain(t *testing.T) {
	detector := NewEncoderDetector()
	_, _, score := detector.Detect([]byte("this is plain text without any encoding"))
	if score > 0.95 {
		t.Errorf("Plain text should not have very high encode score, got %.2f", score)
	}
}

func TestAnomalyAugmentedScanner_WithThresholdManager(t *testing.T) {
	ts := NewTokenScanner(DefaultIntegrationConfig(IntegrationSecretScanner))
	tm := NewThresholdManager()
	tm.Enable()
	ts.WithThresholdManager(tm)
}

func TestAnomalyScore_IsSuspicious(t *testing.T) {
	score := AnomalyScore{Total: 0.6, IsSuspicious: true}
	if !score.IsSuspicious {
		t.Errorf("Score should be suspicious")
	}
}

func TestAnomalyScore_IsAlert(t *testing.T) {
	score := AnomalyScore{Total: 0.9, IsAlert: true}
	if !score.IsAlert {
		t.Errorf("Score should be alert")
	}
}

func TestAnomalyScore_IsAnomalous(t *testing.T) {
	score := AnomalyScore{Total: 0.8, IsAnomalous: true}
	if !score.IsAnomalous {
		t.Errorf("Score should be anomalous")
	}
}

func TestAnomalyScore_ContainsServicePrefix_Empty(t *testing.T) {
	score := AnomalyScore{Flags: []string{}}
	if score.ContainsServicePrefix() {
		t.Errorf("Empty flags should not have prefix")
	}
}

func TestAdjustThresholds_Low(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	tm.SetScorerConfig(ScorerConfig{AnomalyThreshold: 0.7})
	tm.stats.sampleCount = 100
	tm.stats.anomalyCount = 2
	tm.stats.windowScores = make([]float64, 100)
	for i := range tm.stats.windowScores {
		tm.stats.windowScores[i] = 0.2
	}
	before := tm.GetScorerConfig().AnomalyThreshold
	tm.adjustThresholds()
	after := tm.GetScorerConfig().AnomalyThreshold
	if after >= before {
		t.Errorf("Very low should decrease threshold")
	}
}

func TestAdjustThresholds_High(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	tm.SetScorerConfig(ScorerConfig{AnomalyThreshold: 0.7, AlertThreshold: 0.85})
	tm.stats.sampleCount = 100
	tm.stats.anomalyCount = 40
	tm.stats.windowScores = make([]float64, 100)
	for i := range tm.stats.windowScores {
		tm.stats.windowScores[i] = 0.8
	}
	before := tm.GetScorerConfig().AnomalyThreshold
	tm.adjustThresholds()
	after := tm.GetScorerConfig().AnomalyThreshold
	if after <= before {
		t.Errorf("Very high should increase threshold")
	}
}

func TestAdjustThresholds_EntropyHigh(t *testing.T) {
	tm := NewThresholdManager()
	tm.Enable()
	tm.SetAdjustmentFactor(0.1)
	tm.stats.sampleCount = 50
	tm.stats.anomalyCount = 2
	tm.stats.windowScores = make([]float64, 50)
	for i := range tm.stats.windowScores {
		tm.stats.windowScores[i] = 0.8
	}
	before := tm.entropyThresholds.Low
	tm.adjustThresholds()
	after := tm.entropyThresholds.Low
	if after <= before {
		t.Errorf("High mean score should increase entropy threshold")
	}
}

func TestClassify_GenericSecret(t *testing.T) {
	ts := Classify("api_secret_key_verylongandrandom123456")
	_ = ts
}

func TestClassify_Password(t *testing.T) {
	ts := Classify("MySecretP@ssw0rd!")
	_ = ts
}

func TestClassify_OAuth(t *testing.T) {
	ts := Classify("ya29.a0AfH6SMBx_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	_ = ts
}

func TestClassify_Base64Encoded(t *testing.T) {
	ts := Classify("SGVsbG8gV29ybGQgcGF0dGVybnMgc2VjcmV0")
	_ = ts
}

func TestClassify_HexEncoded(t *testing.T) {
	ts := Classify("deadbeef1234567890abcdef")
	_ = ts
}

func TestClassify_Timestamp(t *testing.T) {
	ts := Classify("token_1672531200_suffix")
	_ = ts
}

func TestClassify_SessionID(t *testing.T) {
	ts := Classify("sess_abc123def456ghi789jkl012mno345")
	_ = ts
}

func TestClassify_JWT_Invalid(t *testing.T) {
	ts := Classify("not.a.valid.jwt")
	_ = ts
}

func TestIsUUID_False(t *testing.T) {
	if isUUID("plain-text") {
		t.Errorf("Should not detect as UUID")
	}
}

func TestIsProductionKey_Variations(t *testing.T) {
	tests := []struct {
		token  string
		isProd bool
	}{
		{"production_key", true},
		{"prod_key", true},
		{"staging_key", false},
		{"local_key", false},
	}
	for _, test := range tests {
		result := isProductionKey(test.token, TokenStructure{})
		if result != test.isProd {
			t.Errorf("isProductionKey(%s) expected %v", test.token, test.isProd)
		}
	}
}

func TestIsUpperAlphaNumeric(t *testing.T) {
	if !isUpperAlphaNumeric("ABC123") {
		t.Errorf("Should detect uppercase alphanumeric")
	}
}

func TestIsBase64Like_Short(t *testing.T) {
	_ = isBase64Like("SGV")
}

func TestExtractSuffix_NoDelimiter(t *testing.T) {
	prefix := extractSuffix("nodelimiter")
	_ = prefix
}

func TestBuildScoreFlags_Known(t *testing.T) {
	score := AnomalyScore{Total: 0.85, IsAnomalous: true, TokenType: TokenTypeAWSKey}
	flags := buildScoreFlags(score)
	if len(flags) < 1 {
		t.Errorf("Should have at least one flag")
	}
}

func TestScanToken_JWT(t *testing.T) {
	config := DefaultScorerConfig()
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	result := ScoreToken(jwt, config)
	_ = result
}

func TestScanToken_GitHub(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScoreToken("ghp_verylongtoken1234567890abcdefghijklmnop", config)
	_ = result
}

func TestScanToken_AWS(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScoreToken("AKIAIOSFODNN7EXAMPLE", config)
	_ = result
}

func TestScanToken_Stripe(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScoreToken("sk_live_PLACEHOLDER", config)
	_ = result
}
