package aegisgate.threat_detection

# AG-POL-004: Block prompt injection patterns
# Maps to: MITRE ATLAS T1535.001, OWASP LLM01

default allow = true

deny {
    input.request.contains_injection == true
    input.config.ml_enabled == true
}