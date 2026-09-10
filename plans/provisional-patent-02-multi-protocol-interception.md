# UNITED STATES PROVISIONAL PATENT APPLICATION

**Title:** SYSTEMS AND METHODS FOR INTERCEPTING AND SCANNING ARTIFICIAL INTELLIGENCE PROTOCOL MESSAGES FOR DATA EXFILTRATION

**Inventor:** [INVENTOR NAME — FILL IN BEFORE FILING]
**Entity Status:** Micro Entity (under 37 CFR 1.29)
**Related Applications:** None
**Filing Date:** [FILL IN WHEN FILED]

---

## TECHNICAL FIELD

The present disclosure relates generally to cybersecurity and, more specifically, to systems and methods for intercepting, parsing, and scanning messages exchanged over artificial intelligence (AI) communication protocols — including the Model Context Protocol (MCP), Agent-to-Agent (A2A) Protocol, Agent Communication Protocol (ACP), and Agent Network Protocol (ANP) — for the purpose of detecting and preventing data exfiltration.

## BACKGROUND

The emergence of AI-specific communication protocols has created a new data exfiltration surface that is not addressed by existing Data Loss Prevention (DLP) or network security tools. These protocols include:

1. **Model Context Protocol (MCP):** A protocol published in 2024 that standardizes communication between AI applications and external tools, resources, and data sources. MCP messages contain tool invocation requests, resource access requests, and prompt templates that may include sensitive data.

2. **Agent-to-Agent (A2A) Protocol:** An emerging protocol for direct communication between autonomous AI agents, enabling delegation, collaboration, and information sharing between agents from different vendors or deployments.

3. **Agent Communication Protocol (ACP):** A protocol for standardizing communication between AI agents and orchestration systems.

4. **Agent Network Protocol (ANP):** A protocol for agent discovery and networking in distributed AI systems.

Existing DLP tools (e.g., Microsoft Purview, Nightfall AI) are designed to inspect email, file uploads, and HTTP traffic. They do not understand the message structures of AI-specific protocols. Existing AI security tools (e.g., Lakera Guard, Prompt Security) focus on prompt injection detection in HTTP-based API calls, not on data exfiltration within AI protocol messages.

What is needed is a system that can intercept AI protocol messages, parse their protocol-specific structures, extract content payloads, apply multi-layered data exfiltration detection, and block or redact sensitive data before it is transmitted to AI services or other agents.

## SUMMARY OF THE INVENTION

The present disclosure describes systems and methods for intercepting and scanning AI communication protocol messages for data exfiltration. The system comprises: a protocol interception module configured to intercept AI protocol messages at the transport layer; a protocol parser configured to extract content payloads from protocol-specific message structures; a detection engine configured to apply multi-layered data exfiltration detection to extracted content; and a response module configured to block, redact, or permit messages based on detection results.

In one embodiment, the protocol interception module operates as a proxy between AI client applications and AI services, intercepting MCP messages exchanged between an AI application (e.g., Claude Desktop, Cursor, GitHub Copilot) and MCP servers providing tool and resource access.

In another embodiment, the protocol interception module intercepts A2A messages exchanged between autonomous AI agents, enabling inspection of inter-agent communications for data exfiltration before delivery.

In another embodiment, the protocol parser is configured to parse MCP message structures including: tool invocation requests (extracting tool name, arguments, and embedded data), resource access requests (extracting resource URIs and content), and prompt templates (extracting template content and variables).

In another embodiment, the protocol parser is configured to parse A2A message structures including: agent delegation messages, information sharing messages, task assignment messages, and result reporting messages.

In another embodiment, the detection engine applies a multi-layered detection pipeline comprising: a first layer of pattern matching using regular expressions for known sensitive data formats; a second layer of compliance framework violation detection; and a third layer of machine learning classification using a character-level neural network.

In another embodiment, the response module is configured to: block the message entirely if high-confidence sensitive data is detected; redact specific sensitive data fields while permitting the remainder of the message; or permit the message if no sensitive data is detected, and log the transaction for audit purposes.

## DETAILED DESCRIPTION

### 1. System Architecture

The system operates as an intermediary (proxy) between AI client applications and AI services or other agents. The interception occurs at the application layer, with the proxy acting as a transparent or explicit proxy for AI protocol traffic.

### 1.1 Protocol Interception Module

The protocol interception module intercepts AI protocol messages using one or more of the following methods:

1. **Explicit Proxy:** The AI client application is configured to send protocol messages to the proxy address instead of the destination service. The proxy forwards permitted messages to the actual destination.

2. **Transparent Proxy:** The proxy intercepts traffic at the network layer using iptables rules, eBPF programs, or equivalent network interception technology, redirecting AI protocol traffic to the proxy for inspection.

3. **Sidecar Proxy:** The proxy runs as a sidecar process alongside the AI application, intercepting localhost traffic on the protocol's default port.

4. **API Gateway:** The proxy serves as an API gateway that AI applications must route through to access AI services, providing a single inspection point for all AI traffic.

The interception module identifies the protocol type by examining: the destination port, the protocol handshake message, the message content-type header, or the message structure.

### 1.2 Protocol Parser

The protocol parser is protocol-aware and extracts content from the specific message structures of each supported AI protocol.

#### 1.2.1 MCP Message Parsing

For MCP protocol messages, the parser extracts:

1. **Tool Invocation Requests:** The tool name, tool arguments (which may contain sensitive data passed from the user to the tool), and any embedded file contents or data references.

2. **Resource Access Requests:** The resource URI (which may contain sensitive identifiers), resource content (which may contain sensitive data returned from the resource), and resource metadata.

3. **Prompt Templates:** Template text (which may contain injection vectors or sensitive data), template variables (which may contain user-supplied sensitive data), and rendered prompt content (the final prompt sent to the LLM after template substitution).

4. **Sampling Requests:** Messages where the MCP client requests the MCP server to perform an LLM completion, including the prompt content and model parameters.

#### 1.2.2 A2A Message Parsing

For A2A protocol messages, the parser extracts:

1. **Agent Delegation Messages:** The delegating agent's identity, the delegated task description, any attached data or context, and the recipient agent's identity.

2. **Information Sharing Messages:** The sending agent's identity, the shared information content, the sharing context, and the receiving agent's identity.

3. **Task Assignment Messages:** The task specification, required resources, data inputs, and expected outputs.

4. **Result Reporting Messages:** The result content, which may contain processed sensitive data, status indicators, and audit information.

#### 1.2.3 ACP and ANP Message Parsing

For ACP messages, the parser extracts agent orchestration commands, state transitions, and configuration changes. For ANP messages, the parser extracts agent discovery requests, capability advertisements, and network routing information.

### 1.3 Detection Engine

The detection engine applies a multi-layered detection pipeline to the content extracted by the protocol parser.

#### Layer 1: Pattern Matching

A library of regular expression patterns is applied to the extracted content. The pattern library includes:

- **PII Patterns:** Social Security numbers, credit card numbers (with Luhn checksum validation), email addresses, phone numbers, international identity numbers (passport, national ID, driver's license for 24+ jurisdictions), postal addresses, dates of birth, financial account numbers, routing numbers, SWIFT/BIC codes, IBAN numbers, and healthcare identifiers (NPI, Medicare, Medicaid).

- **Secret/Credential Patterns:** API keys for major cloud providers (AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid, Mailgun, and others), private keys (RSA, ECDSA, Ed25519 PEM blocks), database connection strings, OAuth tokens, JWT tokens, bearer tokens, and generic high-entropy strings matching credential patterns.

- **OT Protocol Patterns:** Modbus function codes and register addresses, DNP3 data link and application layer fields, OPC-UA node identifiers and service calls, IEC 61850 logical node names, and BACnet object identifiers.

- **Harmful Content Patterns:** Patterns matching instructions for weapons, explosives, drug synthesis, self-harm methods, and content classified as illegal under applicable jurisdictions.

#### Layer 2: Compliance Framework Violation Detection

The extracted content is evaluated against compliance framework controls to detect violations. Supported frameworks include: HIPAA, PCI DSS, SOC 2, ISO 27001, ISO 42001, NIST AI RMF, EU AI Act, MITRE ATLAS, OWASP LLM Top 10, FedRAMP, GDPR, CCPA, and others.

For each framework, the system maintains a mapping from detection patterns to specific framework controls. When a pattern match is detected, the corresponding control violation is recorded.

#### Layer 3: Machine Learning Classification

A character-level convolutional neural network with bidirectional long short-term memory (CharCNN-BiLSTM) processes the extracted content. The model:

1. Accepts input sequences of up to 256 characters.
2. Maps each character to a 256-dimensional embedding using Latin-1 encoding.
3. Applies 1D convolutional layers with kernel sizes of 3, 5, and 7 to capture character n-gram features.
4. Processes the convolved features through a 2-layer bidirectional LSTM (128 units per direction).
5. Applies a dense layer with dropout (0.3) for regularization.
6. Outputs a probability score (0.0 to 1.0) indicating the likelihood that the content contains sensitive data or exfiltration attempts.
7. Uses a threshold of 0.50 for classification.

The model is trained on a corpus of adversarial and benign prompts using data augmentation techniques including Unicode normalization, case variation, character substitution, keyboard walk encoding, leet speak, homoglyph substitution, and whitespace manipulation.

The model is deployed via ONNX Runtime for Go (server-side) and as a pure JavaScript inference module (browser-side), enabling local inference without cloud calls.

#### Evasion-Resistant Normalization

Before detection, content is normalized using evasion-resistant techniques including:

1. **Keyboard Walk Reverse Mapping:** A 54-entry map that reverses QWERTY right-shift keyboard walk encoding (e.g., "djj" → "ash") to detect obfuscated patterns.

2. **Unicode Normalization:** Conversion of Unicode variants (homoglyphs, combining characters, zero-width characters) to their ASCII equivalents.

3. **Case Normalization:** Conversion to lowercase for case-insensitive matching.

4. **Whitespace Normalization:** Collapsing multiple whitespace characters and removing zero-width spaces.

### 1.4 Response Module

Based on detection results, the response module takes one of the following actions:

1. **Block:** If high-confidence sensitive data is detected (ML score > 0.50 or regex match with high confidence), the message is blocked. The AI client receives an error response indicating that the message was blocked by security policy. A security event is logged with: timestamp, protocol type, source agent, detection layer, matched pattern or ML score, and blocked content hash.

2. **Redact:** If specific sensitive data fields are detected within an otherwise permissible message, those fields are replaced with a placeholder (e.g., `[REDACTED-SSN]`). The redacted message is forwarded to the destination. A security event is logged.

3. **Permit:** If no sensitive data is detected, the message is forwarded to the destination. The transaction may be logged for audit purposes depending on configuration.

## CLAIMS

1. A system for detecting data exfiltration in artificial intelligence protocol messages, comprising: a protocol interception module configured to intercept AI communication protocol messages; a protocol parser configured to extract content payloads from protocol-specific message structures; a detection engine configured to apply data exfiltration detection to the extracted content; and a response module configured to block, redact, or permit messages based on detection results.

2. The system of claim 1, wherein the AI communication protocol is the Model Context Protocol (MCP).

3. The system of claim 1, wherein the AI communication protocol is an Agent-to-Agent (A2A) protocol.

4. The system of claim 1, wherein the protocol parser extracts content from at least: tool invocation requests, resource access requests, prompt templates, and sampling requests.

5. The system of claim 1, wherein the detection engine applies a multi-layered detection pipeline comprising: a first layer of regular expression pattern matching, a second layer of compliance framework violation detection, and a third layer of machine learning classification.

6. The system of claim 1, wherein the machine learning classification uses a character-level convolutional neural network with bidirectional long short-term memory (CharCNN-BiLSTM).

7. The system of claim 1, wherein the response module redacts specific sensitive data fields while permitting the remainder of the message.

8. The system of claim 1, wherein the detection engine applies evasion-resistant normalization including keyboard walk reverse mapping and Unicode normalization before detection.

9. The system of claim 5, wherein the compliance framework violation detection supports at least: HIPAA, PCI DSS, SOC 2, ISO 42001, NIST AI RMF, EU AI Act, MITRE ATLAS, and OWASP LLM Top 10.

10. The system of claim 1, wherein the interception module operates as an explicit proxy, transparent proxy, sidecar proxy, or API gateway.

---

**Note:** Replace [INVENTOR NAME] with the full legal name of the inventor before filing. File at https://patentscenter.uspto.gov using "Provisional" application type. Select "Micro Entity" for reduced fees ($65).