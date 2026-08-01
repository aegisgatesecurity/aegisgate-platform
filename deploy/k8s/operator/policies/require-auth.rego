package aegisgate.auth

# AG-POL-001: Require authentication for professional+ tiers
# Maps to: SOC2 CC6.1, ISO 27001 A.9

default allow = false

allow {
    input.config.tier == "community"
}

allow {
    input.request.authenticated == true
}

deny {
    input.config.tier != "community"
    input.request.authenticated == false
}