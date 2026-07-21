// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SMTP Email Delivery
// =========================================================================
//
// Email sending for AegisGate license delivery, alerting, and weekly
// CISO posture digest distribution.
//
// Uses Go's net/smtp package (stdlib only, no third-party deps) for
// maximum portability. TLS STARTTLS is used for secure email delivery
// to any SMTP provider.
//
// Usage with common providers:
//
//   Gmail:
//     host: smtp.gmail.com, port: 587
//     auth: smtp.PlainAuth("", "your@gmail.com", "app-password", "smtp.gmail.com")
//
//   Amazon SES:
//     host: email-smtp.us-east-1.amazonaws.com, port: 587
//     auth: smtp.PlainAuth("", "AKI...", "secret", "email-smtp.us-east-1.amazonaws.com")
//
//   SMTP2GO / Mailgun / SendGrid:
//     Use the same pattern with your provider's SMTP credentials.
//
// Configuration via env vars:
//   AEGISGATE_SMTP_HOST, AEGISGATE_SMTP_PORT, AEGISGATE_SMTP_USER,
//   AEGISGATE_SMTP_PASSWORD, AEGISGATE_SMTP_FROM
//
// =========================================================================

package email
