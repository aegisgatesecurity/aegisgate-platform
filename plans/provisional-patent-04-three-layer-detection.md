# UNITED STATES PROVISIONAL PATENT APPLICATION

**Title:** MULTI-LAYERED DETECTION PIPELINE FOR ARTIFICIAL INTELLIGENCE PROMPT CONTENT

**Inventor:** [INVENTOR NAME — FILL IN BEFORE FILING]
**Entity Status:** Micro Entity (under 37 CFR 1.29)
**Related Applications:** None
**Filing Date:** [FILL IN WHEN FILED]

---

## TECHNICAL FIELD

The present disclosure relates generally to cybersecurity and, more specifically, to a multi-layered detection pipeline for analyzing artificial intelligence (AI) prompt content — including user prompts, AI tool invocations, and agent communications — to detect sensitive data exfiltration, compliance violations, and adversarial techniques.

## BACKGROUND

The widespread adoption of AI tools — including LLM chat interfaces (ChatGPT, Claude, Gemini), AI coding assistants (GitHub Copilot, Cursor, Claude Code), and autonomous AI agents — has created a new content inspection domain: AI prompt content. Unlike email (inspected by traditional DLP), file uploads (inspected by malware scanners), or network traffic (inspected by firewalls/IDS), AI prompt content has unique characteristics:

1. **Free-form text with embedded structured data:** Prompts may contain prose interspersed with API keys, source code, database queries, and PII in unpredictable combinations.
2. **Adversarial obfuscation:** Users (or malicious actors) may deliberately obfuscate sensitive data using Unicode tricks, keyboard walk encoding, character substitution, and other evasion techniques.
3. **Protocol-specific structure:** AI prompts are transmitted via AI-specific protocols (MCP, A2A, HTTP API calls to LLM services) with distinct message structures.
4. **Compliance context:** AI prompts may violate healthcare (HIPAA), financial (PCI DSS), privacy (GDPR), or AI-specific (EU AI Act, NIST AI RMF) regulations depending on the content and context.

Existing security tools use single-layer detection: either regex pattern matching OR machine learning classification. Regex-only approaches are vulnerable to obfuscation. ML-only approaches have higher false positive rates and lack explainability. No existing system combines multiple detection layers specifically optimized for AI prompt content.

What is needed is a multi-layered detection pipeline that combines the precision of regex pattern matching, the regulatory coverage of compliance framework analysis, and the evasion resistance of character-level neural networks — specifically designed for and applied to AI prompt content.

## SUMMARY OF THE INVENTION

The present disclosure describes a multi-layered detection pipeline for AI prompt content. The pipeline comprises three detection layers operating sequentially and independently: (1) a pattern matching layer using AI-specific regular expressions; (2) a compliance and adversarial technique classification layer mapping detections to MITRE ATLAS techniques and compliance frameworks; and (3) a machine learning layer using a character-level convolutional neural network with bidirectional long short-term memory (CharCNN-BiLSTM).

In one embodiment, each detection layer operates independently, producing its own detection results, and the results are combined using a decision logic module to produce a final classification.

In another embodiment, the pattern matching layer applies at least 216 regular expression patterns specific to AI prompt content, including PII patterns for 24+ international jurisdictions, API key patterns for 20+ cloud providers, OT protocol patterns for industrial control systems, and harmful content patterns.

In another embodiment, the compliance and adversarial technique classification layer maps detected patterns to 52 MITRE ATLAS techniques and 33+ compliance framework controls.

In another embodiment, the machine learning layer uses a CharCNN-BiLSTM with 1,596,034 parameters, trained on a corpus of adversarial and benign AI prompts, with an evasion resistance score of 99.8 out of 100 across 2,600 adversarial test cases and a false positive rate of 0%.

In another embodiment, the pipeline applies evasion-resistant normalization before detection, including keyboard walk reverse mapping, Unicode normalization, and character substitution reversal.

## DETAILED DESCRIPTION

### 1. Pipeline Architecture

The detection pipeline processes AI prompt content through three sequential layers. Content is first normalized, then passed through each layer. Each layer produces independent results. A decision logic module combines the results for a final classification.

### 1.1 Evasion-Resistant Normalization

Before any detection layer is applied, the input content is normalized using evasion-resistant techniques:

1. **Keyboard Walk Reverse Mapping:** A mapping of 54 QWERTY keyboard pairs that reverses right-shift keyboard walk encoding. For example, the input "djj" is reversed to "ash" by mapping each character back to its left-neighbor key on the QWERTY keyboard layout. This detects cases where a user has shifted each character one key to the right to evade regex detection.

2. **Unicode Normalization:** Conversion of Unicode characters to their ASCII equivalents using Unicode Normalization Form KC (Compatibility Composition). This includes: converting fullwidth characters to halfwidth, converting mathematical symbols to their ASCII equivalents (e.g., Ａ → A), removing zero-width characters (U+200B, U+200C, U+200D, U+FEFF), and converting combining characters to their precomposed forms.

3. **Homoglyph Conversion:** Conversion of visually similar characters from different scripts to their ASCII equivalents (e.g., Cyrillic 'а' → Latin 'a', Greek 'о' → Latin 'o').

4. **Case Normalization:** Conversion to lowercase for case-insensitive pattern matching.

5. **Whitespace Normalization:** Collapsing multiple consecutive whitespace characters to a single space and trimming leading/trailing whitespace.

6. **Leet Speak Reversal:** Conversion of leet speak substitutions to their letter equivalents (e.g., '3' → 'e', '1' → 'i', '0' → 'o', '$' → 's', '@' → 'a').

The normalization is applied to a copy of the input content. Both the original and normalized versions are passed to the detection layers. The pattern matching layer processes both versions; the ML layer processes only the normalized version (by design — the model is trained on normalized input).

### 1.2 Layer 1: Pattern Matching

The pattern matching layer applies a library of regular expressions to the (normalized and original) content. The pattern library includes:

#### PII Patterns (69+ patterns)
- **US Core:** Social Security numbers (with optional dash/space formatting, with and without area group validation), US phone numbers (10-digit with optional formatting), US passport numbers, state driver's license numbers (for all 50 states + DC), US passport card numbers.
- **US Extended:** Email addresses (RFC 5322 compliant), US postal addresses (street + city + state + ZIP), dates of birth (multiple formats), employer identification numbers (EIN), ITIN numbers.
- **Financial:** Credit card numbers (Visa, Mastercard, Amex, Discover, JCB — with Luhn checksum validation), bank routing numbers (ABA, with checksum), SWIFT/BIC codes, IBAN numbers (with country-specific length validation), ACH routing numbers.
- **International:** PII patterns for 24+ jurisdictions including: UK National Insurance numbers, Canadian Social Insurance numbers, German tax IDs, French INSEE numbers, Italian fiscal codes, Spanish DNI/NIE, Dutch BSN, Australian TFN, Indian PAN/Aadhaar, Japanese My Number, Korean RRN, Chinese resident ID, Brazilian CPF, Mexican CURP, Swedish personnummer, Norwegian fødselsnummer, Finnish henkilötunnus, Danish CPR, Belgian national number, Austrian SVNR, Swiss AVS, Polish PESEL, Portuguese NIF, Greek AMKA.

#### Secret/Credential Patterns (53+ patterns)
- Cloud provider API keys: AWS (AKIA*, ASIA*), GCP (GOOG*, AIza*), Azure (account key patterns), GitHub (ghp_*, gho_*, ghs_*, ghu_*, ghr_*).
- SaaS API keys: Slack (xox[abprs]-*), Stripe (sk_live_*, sk_test_*, pk_live_*, pk_test_*), Twilio (SK*), SendGrid (SG.*), Mailgun (key-*), Discord (bot token patterns), GitLab (glpat-*), Heroku (uuid-apikey format).
- Private keys: PEM-encoded RSA private keys, ECDSA private keys, Ed25519 private keys, OpenSSH private keys.
- Database connection strings: PostgreSQL, MySQL, MongoDB, Redis, MS SQL Server connection URI formats.
- OAuth/JWT tokens: Bearer token patterns, JWT structure patterns (base64.header.signature).
- Generic high-entropy strings: Configurable threshold for detecting high-entropy strings that may be credentials.

#### XSS Patterns (11+ patterns)
- Script injection patterns adapted for AI prompt content, including: <script> tag injection, JavaScript URI schemes (javascript:), event handler attributes (onload, onerror, onclick), data URI schemes, SVG-based XSS vectors.

#### OT Protocol Patterns (9 patterns)
- Modbus: Function code patterns, register address patterns, TCP port 502 identification.
- DNP3: Data link address patterns, application layer function codes.
- OPC-UA: Node ID patterns, service call patterns, endpoint URLs.
- IEC 61850: Logical node name patterns, data object references.
- BACnet: Object identifier patterns, property identifiers.

#### Harmful Content Patterns (5+ patterns)
- Instructions for weapons/explosives synthesis, drug manufacturing instructions, self-harm methods, and content classified as illegal under applicable jurisdictions.

Each pattern match produces: pattern identifier, matched content (or hash for secure storage), confidence score, severity classification (critical/high/medium/low), and matched character positions.

### 1.3 Layer 2: Compliance and Adversarial Technique Classification

The second layer takes the pattern matches from Layer 1 and classifies them according to:

#### MITRE ATLAS Technique Mapping (52 techniques)
Each detected event is classified against MITRE ATLAS (Adversarial Threat Landscape for AI Systems) techniques, including:
- Reconnaissance techniques (T1590 series for AI system discovery).
- Initial Access techniques (T1650 series for model access).
- ML Attack Staging techniques (T1584 series for data poisoning).
- Model Attack techniques (T1529, T1599 for model evasion/extraction).
- Defense Evasion techniques (T1027 for obfuscation, T1036 for masquerading).

#### Compliance Framework Mapping (33+ frameworks)
Each detected event is mapped to relevant compliance framework controls (as described in the compliance mapping patent application).

The Layer 2 output includes: ATLAS technique IDs, compliance framework control IDs, framework violation descriptions, and regulatory references.

### 1.4 Layer 3: Machine Learning Classification

The third layer applies a character-level neural network to the normalized input content.

#### Model Architecture
- **Input:** 256-character sequence, each character mapped to a 256-dimensional vector using Latin-1 encoding (1 byte = 1 character).
- **Convolutional Layers:** Three parallel 1D convolutional layers with kernel sizes 3, 5, and 7, each with 128 filters and ReLU activation, capturing character n-grams at different scales.
- **Pooling:** Max pooling over time for each convolutional layer output.
- **Concatenation:** The three pooled outputs are concatenated into a single vector.
- **Bidirectional LSTM:** 2-layer BiLSTM with 128 units per direction (256 total per layer), processing the convolved features.
- **Dense Layer:** Fully connected layer with 64 units and ReLU activation.
- **Dropout:** 0.3 dropout rate for regularization.
- **Output:** Single sigmoid unit producing a probability score (0.0 to 1.0).
- **Threshold:** 0.50 for binary classification (safe vs. sensitive/adversarial).
- **Total Parameters:** 1,596,034.

#### Training
- **Corpus:** 70,000+ labeled AI prompts (adversarial and benign).
- **Data Augmentation:** 50 transform types including: Unicode homoglyph substitution, case variation, leet speak, keyboard walk encoding, character insertion/deletion, whitespace manipulation, URL encoding, base64 encoding, ROT13, and combinations thereof.
- **Optimizer:** Adam with learning rate 0.001.
- **Loss Function:** Binary cross-entropy.
- **Validation:** 5-fold cross-validation.
- **Final Performance:** 99.8/100 evasion resistance across 2,600 adversarial test cases (52 MITRE ATLAS payloads × 50 transforms), 0% false positive rate on benign corpus.

#### Deployment
- **Server-side:** ONNX Runtime (opset 18), deployed within the Go-based security gateway. Model hash verification ensures model integrity.
- **Browser-side:** Pure JavaScript inference module with float16 weights encoded as gzip-compressed base64 JSON, loaded into a JS-based inference engine. No external API calls.
- **Local inference:** No cloud calls, no data exfiltration. The model runs entirely on the host machine.

### 1.5 Decision Logic Module

The decision logic module combines results from all three layers:

1. **Block (highest priority):** If any Layer 1 pattern matches with high confidence, or if Layer 3 ML score exceeds 0.50, the content is classified as sensitive/adversarial and blocked.

2. **Compliance Flag:** If Layer 2 detects a compliance framework violation (even without a Layer 1 high-confidence match), the content is flagged for compliance review.

3. **Permit (lowest priority):** If no Layer 1 matches, no Layer 2 violations, and Layer 3 score is below 0.50, the content is permitted.

The decision logic is configurable: administrators may adjust thresholds, enable/disable specific layers, and define custom decision rules.

### 1.6 Independent Layer Operation

Each layer operates independently — a failure or timeout in one layer does not prevent other layers from producing results. This provides:
- **Fault tolerance:** If the ML model fails to load or times out, Layers 1 and 2 still provide detection.
- **Configurability:** Administrators may disable specific layers for specific use cases (e.g., disable ML for performance-critical paths, disable compliance for non-regulated environments).
- **Auditability:** Each layer's results are logged independently, enabling forensic analysis of detection decisions.

## CLAIMS

1. A multi-layered detection pipeline for analyzing artificial intelligence prompt content, comprising: a pattern matching layer configured to apply regular expression patterns specific to AI prompt content; a compliance and adversarial classification layer configured to map detected patterns to MITRE ATLAS techniques and compliance framework controls; and a machine learning layer configured to classify content using a character-level convolutional neural network with bidirectional long short-term memory.

2. The pipeline of claim 1, further comprising an evasion-resistant normalization module configured to apply keyboard walk reverse mapping, Unicode normalization, homoglyph conversion, and leet speak reversal before detection.

3. The pipeline of claim 1, wherein the pattern matching layer applies at least 216 regular expression patterns including PII patterns for 24+ international jurisdictions, API key patterns for 20+ cloud providers, OT protocol patterns, and harmful content patterns.

4. The pipeline of claim 1, wherein the machine learning layer uses a CharCNN-BiLSTM with approximately 1,596,000 parameters, accepting 256-character input sequences, with parallel convolutional layers of kernel sizes 3, 5, and 7.

5. The pipeline of claim 1, wherein each detection layer operates independently, and a failure or timeout in one layer does not prevent other layers from producing results.

6. The pipeline of claim 1, further comprising a decision logic module configured to combine results from all three layers to produce a final classification.

7. The pipeline of claim 1, wherein the machine learning model is deployed via ONNX Runtime for server-side inference and as a pure JavaScript module for browser-side inference, without external API calls.

8. The pipeline of claim 1, wherein the compliance classification layer maps detections to 52 MITRE ATLAS techniques and 33+ compliance frameworks.

9. The pipeline of claim 2, wherein the keyboard walk reverse mapping uses a 54-entry map reversing QWERTY right-shift encoding.

10. The pipeline of claim 4, wherein the model is trained on a corpus of 70,000+ labeled AI prompts with 50 data augmentation transform types, achieving 99.8/100 evasion resistance and 0% false positive rate.

---

**Note:** Replace [INVENTOR NAME] with the full legal name of the inventor before filing. File at https://patentscenter.uspto.gov using "Provisional" application type. Select "Micro Entity" for reduced fees ($65).