package aegisgate.dataprivacy

# AG-POL-003: Enforce data residency for EU AI Act
# Maps to: EU AI Act Art. 28, GDPR Art. 44-49

default allow = false

allow {
    input.config.data_residency == ""
}

allow {
    input.config.data_residency == "eu"
    input.environment.region == "eu"
}

deny {
    input.config.data_residency == "eu"
    input.environment.region != "eu"
}