// SPDX-License-Identifier: Apache-2.0
// Package email provides zero-dependency email sending via Go stdlib net/smtp.
// No external dependencies required — self-contained in the binary.

// Package email provides email sending functionality for AegisGate license delivery.
// Uses Go's net/smtp package (stdlib only) for maximum portability.
// TLS STARTTLS is used for secure email delivery to any SMTP provider.

// Usage with common providers:
//
//	Gmail:
//	  host := "smtp.gmail.com"
//	  port := 587
//	  auth := smtp.PlainAuth("", "your@gmail.com", "app-password", "smtp.gmail.com")
//
//	Amazon SES:
//	  host := "email-smtp.us-east-1.amazonaws.com"
//	  port := 587
//	  auth := smtp.PlainAuth("", "AKI...", "secret", "email-smtp.us-east-1.amazonaws.com")
//
//	SMTP2GO / Mailgun / SendGrid / etc:
//	  Use the same pattern with your provider's SMTP credentials.

package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"time"
)

// emailTemplate is the embedded HTML email template for license delivery.
// Stored as a raw string constant for zero-dependency compilation.
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your AegisGate License</title>
    <style>
        body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f4; color: #333333; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 40px 30px; text-align: center; }
        .header h1 { color: #ffffff; font-size: 24px; font-weight: 600; margin: 0; }
        .header .subtitle { color: #8892b0; font-size: 14px; margin-top: 8px; }
        .content { padding: 40px 30px; }
        .greeting { font-size: 16px; margin-bottom: 24px; }
        .license-box { background-color: #f8f9fa; border: 2px solid #e9ecef; border-radius: 8px; padding: 24px; margin: 24px 0; }
        .license-box .label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #6c757d; margin-bottom: 8px; }
        .license-box .key { font-family: 'Courier New', Courier, monospace; font-size: 14px; word-break: break-all; color: #1a1a2e; background-color: #ffffff; padding: 12px; border-radius: 4px; border: 1px solid #dee2e6; user-select: all; }
        .details { margin: 24px 0; }
        .details .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e9ecef; }
        .details .row:last-child { border-bottom: none; }
        .details .label { color: #6c757d; font-size: 14px; }
        .details .value { font-weight: 500; font-size: 14px; }
        .cta-button { display: inline-block; background-color: #1a1a2e; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 16px 4px 0 0; }
        .cta-button.secondary { background-color: transparent; border: 1px solid #1a1a2e; color: #1a1a2e; }
        .footer { background-color: #f8f9fa; padding: 24px 30px; text-align: center; font-size: 12px; color: #6c757d; }
        .footer a { color: #1a1a2e; text-decoration: none; }
        .divider { height: 1px; background-color: #e9ecef; margin: 24px 0; }
        @media (max-width: 480px) { .container { border-radius: 0; } .content { padding: 24px 20px; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AegisGate Security</h1>
            <div class="subtitle">Your license key is ready</div>
        </div>
        <div class="content">
            <p class="greeting">{{if .CustomerName}}Dear {{.CustomerName}},{{else}}Hello,{{end}}</p>
            <p>Thank you for subscribing to <strong>AegisGate {{.Tier}} Edition</strong>! Your license key is ready below.</p>
            <div class="license-box">
                <div class="label">Your License Key</div>
                <div class="key">{{.LicenseKey}}</div>
            </div>
            <div class="details">
                <div class="row"><span class="label">Tier</span><span class="value">{{.Tier}}</span></div>
                <div class="row"><span class="label">Issued</span><span class="value">{{.IssuedAt}}</span></div>
                <div class="row"><span class="label">Expires</span><span class="value">{{.ExpiresAt}}</span></div>
            </div>
            <div class="divider"></div>
            <h3 style="font-size: 16px; margin-bottom: 12px;">Quick Start</h3>
            <ol style="font-size: 14px; line-height: 1.8; padding-left: 20px;">
                <li>Copy your license key above</li>
                <li>Deploy AegisGate with Docker:</li>
            </ol>
            <pre style="background-color: #f8f9fa; padding: 12px; border-radius: 4px; font-size: 13px; overflow-x: auto;">docker run -e AEGISGATE_LICENSE_KEY="{{.LicenseKey}}" aegisgate/platform:latest</pre>
            <div style="margin-top: 24px;">
                <a href="https://aegisgatesecurity.io/docs/getting-started/" class="cta-button">Get Started</a>
                <a href="https://aegisgatesecurity.io/docs/" class="cta-button secondary">Documentation</a>
            </div>
        </div>
        <div class="footer">
            <p>Questions? Contact us at <a href="mailto:{{.SupportEmail}}">{{.SupportEmail}}</a></p>
            <p style="margin-top: 12px;">{{.CompanyName}}<br><a href="{{.CompanyURL}}">{{.CompanyURL}}</a></p>
        </div>
    </div>
</body>
</html>`

// Config holds SMTP connection settings.
// All fields are required for email delivery.
type Config struct {
	// Host is the SMTP server hostname (e.g., "smtp.gmail.com")
	Host string

	// Port is the SMTP port (typically 587 for STARTTLS, 465 for SSL)
	Port int

	// Username is the SMTP authentication username
	Username string

	// Password is the SMTP authentication password (or app password)
	Password string

	// From is the sender email address (e.g., "AegisGate <noreply@aegisgatesecurity.io>")
	From string

	// FromName is the display name for the sender
	FromName string

	// UseTLS determines whether to use TLS STARTTLS (587) or implicit TLS (465)
	// true = STARTTLS on port 587
	// false = implicit TLS on port 465
	UseTLS bool
}

// LicenseEmailData contains the data for the license delivery email template.
type LicenseEmailData struct {
	CustomerName string
	Tier         string
	LicenseKey   string
	ExpiresAt    string
	IssuedAt     string
	Features     []string
	SupportEmail string
	CompanyName  string
	CompanyURL   string
}

// EmailClient wraps SMTP functionality for sending emails.
type EmailClient struct {
	config Config
}

// NewEmailClient creates a new email client with the given SMTP configuration.
func NewEmailClient(cfg Config) *EmailClient {
	return &EmailClient{config: cfg}
}

// SendLicenseEmail sends a license key to a customer via email.
// Returns an error if the email cannot be sent.
func (c *EmailClient) SendLicenseEmail(to string, data LicenseEmailData) error {
	// Set defaults
	if data.SupportEmail == "" {
		data.SupportEmail = "support@aegisgatesecurity.io"
	}
	if data.CompanyName == "" {
		data.CompanyName = "AegisGate Security, LLC"
	}
	if data.CompanyURL == "" {
		data.CompanyURL = "https://aegisgatesecurity.io"
	}

	// Render email body
	htmlBody, err := c.renderTemplate(data)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	// Build email message
	subject := fmt.Sprintf("Your AegisGate %s License Key", data.Tier)
	msg, err := c.buildMessage(to, subject, htmlBody)
	if err != nil {
		return fmt.Errorf("failed to build email message: %w", err)
	}

	// Send email
	return c.send(to, msg)
}

// renderTemplate renders the HTML email template with the provided data.
func (c *EmailClient) renderTemplate(data LicenseEmailData) (string, error) {
	tmpl := template.Must(template.New("license").Parse(htmlTemplate))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}

	return buf.String(), nil
}

// buildMessage constructs a RFC 2822 compliant email message.
func (c *EmailClient) buildMessage(to, subject, body string) ([]byte, error) {
	from := c.config.From
	if c.config.FromName != "" {
		from = fmt.Sprintf("%s <%s>", c.config.FromName, c.config.From)
	}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""
	headers["Date"] = time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")

	var msg bytes.Buffer
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	return msg.Bytes(), nil
}

// send delivers the email via SMTP using STARTTLS or direct TLS.
func (c *EmailClient) send(to string, msg []byte) error {
	host := net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.config.Port))

	var auth smtp.Auth
	if c.config.Username != "" && c.config.Password != "" {
		auth = smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
	}

	if c.config.UseTLS {
		// STARTTLS on port 587
		err := smtp.SendMail(host, auth, c.config.From, []string{to}, msg)
		if err != nil {
			return fmt.Errorf("SMTP send failed (STARTTLS): %w", err)
		}
	} else {
		// Implicit TLS on port 465
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}

		conn, err := tls.Dial("tcp", host, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS connection failed: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, c.config.Host)
		if err != nil {
			return fmt.Errorf("SMTP client creation failed: %w", err)
		}
		defer client.Close()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %w", err)
			}
		}

		if err := client.Mail(c.config.From); err != nil {
			return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
		}

		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO failed: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA failed: %w", err)
		}

		if _, err := w.Write(msg); err != nil {
			return fmt.Errorf("SMTP write failed: %w", err)
		}

		if err := w.Close(); err != nil {
			return fmt.Errorf("SMTP DATA close failed: %w", err)
		}

		if err := client.Quit(); err != nil {
			// Quit error is non-fatal in most cases
			_ = err
		}
	}

	return nil
}

// ValidateConfig checks if the SMTP configuration has all required fields.
func ValidateConfig(cfg Config) error {
	if cfg.Host == "" {
		return fmt.Errorf("SMTP host is required")
	}
	if cfg.Port == 0 {
		return fmt.Errorf("SMTP port is required")
	}
	if cfg.From == "" {
		return fmt.Errorf("From email address is required")
	}
	return nil
}

// DefaultGmailConfig returns a pre-configured Gmail SMTP settings.
// User must provide their own Gmail address and app password.
func DefaultGmailConfig(gmailAddress, appPassword, fromName string) Config {
	return Config{
		Host:     "smtp.gmail.com",
		Port:     587,
		Username: gmailAddress,
		Password: appPassword,
		From:     gmailAddress,
		FromName: fromName,
		UseTLS:   true,
	}
}

// DefaultSMTP2GOConfig returns pre-configured SMTP2GO settings.
// User must provide their own SMTP2GO credentials.
func DefaultSMTP2GOConfig(username, apiKey, fromAddress, fromName string) Config {
	return Config{
		Host:     "mail.smtp2go.com",
		Port:     587,
		Username: username,
		Password: apiKey,
		From:     fromAddress,
		FromName: fromName,
		UseTLS:   true,
	}
}

// DefaultProtonMailConfig returns a pre-configured Proton Mail SMTP settings.
// User must provide their own Proton email address and app password.
// Note: Proton Mail requires an "App Password" for SMTP access.
// To generate one: Settings → Account → Passwords → App passwords
// Server: smtp.protonmail.ch (European domain) or smtp.protonmail.com
func DefaultProtonMailConfig(emailAddress, appPassword, fromName string) Config {
	return Config{
		Host:     "smtp.protonmail.ch",
		Port:     587,
		Username: emailAddress,
		Password: appPassword,
		From:     emailAddress,
		FromName: fromName,
		UseTLS:   true,
	}
}

// SimpleSendEmail is a convenience function for one-off emails.
// For production use, create an EmailClient for connection reuse.
func SimpleSendEmail(cfg Config, to, subject, body string) error {
	client := NewEmailClient(cfg)
	return client.SendLicenseEmail(to, LicenseEmailData{
		CustomerName: to,
		Tier:         "Developer",
		LicenseKey:   body,
		SupportEmail: cfg.From,
	})
}
