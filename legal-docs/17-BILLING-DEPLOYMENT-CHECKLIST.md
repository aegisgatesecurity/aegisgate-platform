# BILLING DEPLOYMENT CHECKLIST
## AegisGate Security Platform — Commercial Launch

**Document Version:** 1.0  
**Last Updated:** 2026-05-20  
**Purpose:** Complete checklist for deploying billing service and testing license flow

---

## EXECUTIVE SUMMARY

This document provides a complete checklist for deploying the billing service and testing the license sale → application → enforcement flow before selling to live customers.

**Goal:** Test the complete purchase-to-activation pipeline in sandbox mode before any real money changes hands.

---

## PART 1: COMPONENTS NEEDED

### 1.1 Source Code (Already Created ✅)

| Component | Location | Status |
|-----------|----------|--------|
| Stripe client | `pkg/billing/stripe.go` | ✅ Complete |
| Webhook handler | `pkg/billing/webhook/server.go` | ✅ Complete |
| License service | `pkg/license/` | ✅ Existing |
| Email service | `pkg/email/` | ✅ Existing |
| Config files | `pkg/billing/billing-config.json` | ✅ Created |

### 1.2 Website Integration (Need to Add)

| Component | Status | Notes |
|-----------|--------|-------|
| Pricing page with Stripe Checkout | 🔲 Needed | Currently static HTML |
| Purchase confirmation page | 🔲 Needed | Success URL after checkout |
| License activation page | 🔲 Needed | Where customer enters key |
| Customer dashboard | 🔲 Needed | View/manage subscription |
| Webhook endpoint deployed | 🔲 Needed | `/webhook/stripe` |

### 1.3 External Services

| Service | Status | Notes |
|---------|--------|-------|
| Stripe Account | ✅ Connected | Products configured |
| Webhook Endpoint | ⚠️ DNS Ready | `api.aegisgatesecurity.io/webhook/stripe` |
| Email (SendGrid) | 🔲 Needed | For license delivery |
| Database | 🔲 Needed | For license tracking |

---

## PART 2: WEBSITE INTEGRATION

### 2.1 Add Stripe Checkout to Pricing Page

```html
<!-- Add to pricing page, each tier button -->
<form action="/api/create-checkout-session" method="POST">
  <input type="hidden" name="tier" value="developer_annual">
  <input type="hidden" name="price_id" value="price_1TUpwnK2DQfk64XNUJsYscrS">
  <button type="submit" class="btn btn-primary">
    Subscribe - $790/year
  </button>
</form>
```

### 2.2 Create Checkout Session Endpoint

```go
// File: cmd/api/checkout.go
func createCheckoutSession(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    tier := r.FormValue("tier")
    priceID := r.FormValue("price_id")

    // Get customer email from session/form
    customerEmail := r.FormValue("email")

    client := billing.NewStripeClient()
    session, err := client.CreateCheckoutSession(
        context.Background(),
        tier,
        customerEmail,
        "https://aegisgatesecurity.io/success?session_id={CHECKOUT_SESSION_ID}",
        "https://aegisgatesecurity.io/pricing?canceled=true",
    )

    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect to Stripe Checkout
    http.Redirect(w, r, session.URL, http.StatusTemporaryRedirect)
}
```

### 2.3 Success Page

```html
<!-- /success.html -->
<!DOCTYPE html>
<html>
<head><title>Subscription Successful</title></head>
<body>
<h1>Thank you for subscribing to AegisGate!</h1>
<p>Check your email for your license key.</p>
<p>Your license key: <code id="license-key">Loading...</code></p>

<script>
// Poll for license key from backend
async function fetchLicenseKey() {
    const sessionId = new URLSearchParams(window.location.search).get('session_id');
    const response = await fetch(`/api/check-license?session_id=${sessionId}`);
    const data = await response.json();
    if (data.license_key) {
        document.getElementById('license-key').textContent = data.license_key;
    }
}
fetchLicenseKey();
</script>
</body>
</html>
```

---

## PART 3: WEBHOOK HANDLER DEPLOYMENT

### 3.1 Deploy Webhook Endpoint

```bash
# Option 1: Deploy as separate service
docker run -d \
  --name aegisgate-webhook \
  -p 8081:8080 \
  -e STRIPE_WEBHOOK_SECRET=whsec_YOUR_SECRET \
  -e STRIPE_SECRET_KEY=sk_live_YOUR_KEY \
  -e AEGISGATE_LICENSE_SERVICE=postgres://... \
  aegisgate/webhook:latest

# Option 2: Integrate into main application
# Add route to main.go:
router.HandleFunc("/webhook/stripe", webhook.HandleWebhook)
```

### 3.2 Configure Stripe Dashboard

1. Go to https://dashboard.stripe.com/webhooks
2. Add endpoint: `https://api.aegisgatesecurity.io/webhook/stripe`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Copy signing secret to environment variable

### 3.3 Test Webhook Locally

```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Login
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:8080/webhook/stripe

# Trigger test event
stripe trigger checkout.session.completed
```

---

## PART 4: LICENSE GENERATION AND DELIVERY

### 4.1 Webhook → License Flow

```go
// In webhook handler (pkg/billing/webhook/server.go)
func (s *Server) handleCheckoutCompleted(data json.RawMessage) error {
    var session CheckoutSession
    json.Unmarshal(data, &session)

    // Determine tier from metadata or amount
    tier := session.Metadata["tier"]
    if tier == "" {
        tier = s.inferTierFromAmount(session.AmountTotal)
    }

    // Generate license
    if s.licenseGen != nil {
        key, err := s.licenseGen.GenerateLicense(
            session.Customer,
            tier,
            365, // days
        )
        if err != nil {
            return fmt.Errorf("license generation failed: %w", err)
        }

        // Activate license
        s.licenseGen.ActivateLicense(key, session.CustomerEmail)

        // Send email with license key
        if s.emailService != nil {
            s.emailService.SendLicenseKey(
                session.CustomerEmail,
                key,
                tier,
                time.Now().AddDate(1, 0, 0).Format("January 2, 2006"),
            )
        }
    }

    return nil
}
```

### 4.2 License Key Structure

```
AG-{TIER}-{TIMESTAMP}-{RANDOM}
Example: AG-DEVELOPER-1701234567-XK9M2NP4QRST
```

### 4.3 Email Template

```html
Subject: Your AegisGate License Key

Hello,

Thank you for subscribing to AegisGate {TIER}!

Your License Key: AG-DEVELOPER-1701234567-XK9M2NP4QRST

To activate your license:
1. Download AegisGate from https://aegisgatesecurity.io/download
2. Run: aegisgate license activate AG-DEVELOPER-...
3. Enter your license key when prompted

Your license expires: January 1, 2027

Questions? Contact support@aegisgatesecurity.io

- The AegisGate Team
```

---

## PART 5: TEST PLAN

### 5.1 Stripe Test Mode

All testing should use Stripe **Test Mode**:
- Test card: `4242 4242 4242 4242` (always succeeds)
- Test cards: https://stripe.com/docs/testing

### 5.2 Complete Test Flow

| Step | Action | Expected Result |
|------|--------|----------------|
| 1 | Click "Subscribe" on pricing page | Redirect to Stripe Checkout |
| 2 | Enter test card `4242 4242 4242 4242` | Payment succeeds |
| 3 | Complete checkout | Redirect to success page |
| 4 | Webhook receives `checkout.session.completed` | License generated |
| 5 | Email sent with license key | Key in inbox |
| 6 | Activate license with key | License activated |
| 7 | Verify tier features enabled | Correct tier access |

### 5.3 Test Scripts

```bash
#!/bin/bash
# test_billing_flow.sh

echo "=== Billing Flow Test ==="

# 1. Create checkout session
echo "1. Creating checkout session..."
SESSION=$(curl -X POST https://api.aegisgatesecurity.io/api/create-checkout-session \
  -H "Content-Type: application/json" \
  -d '{"tier":"developer","email":"test@example.com"}' | jq -r '.url')

echo "Checkout URL: $SESSION"

# 2. Use Stripe CLI to simulate payment
echo "2. Simulating payment completion..."
stripe trigger checkout.session.completed \
  --add "checkout.session:customer_email=test@example.com" \
  --add "checkout.session:payment_status=paid"

# 3. Check license generated
echo "3. Checking license generation..."
sleep 5
LICENSE=$(curl https://api.aegisgatesecurity.io/api/check-license?email=test@example.com | jq -r '.license_key')

if [ "$LICENSE" != "null" ]; then
    echo "✅ License generated: $LICENSE"
else
    echo "❌ License not found"
fi
```

---

## PART 6: DEPLOYMENT CHECKLIST

### Pre-Launch (Complete Before Selling)

- [ ] **Stripe Account**
  - [ ] Live mode enabled
  - [ ] Products and prices configured
  - [ ] Webhook endpoint verified
  
- [ ] **Website**
  - [ ] Pricing page integrated with Stripe Checkout
  - [ ] Success page created
  - [ ] License activation page created
  - [ ] Email templates tested
  
- [ ] **Backend**
  - [ ] Webhook handler deployed
  - [ ] License generation service operational
  - [ ] Email delivery working
  
- [ ] **Testing**
  - [ ] Complete purchase flow tested (sandbox)
  - [ ] License activation tested
  - [ ] Email delivery verified
  - [ ] Tier enforcement verified

### Post-Launch

- [ ] Switch Stripe from Test to Live mode
- [ ] Monitor webhook delivery
- [ ] Test actual credit card purchase
- [ ] Verify license delivery to real email

---

## PART 7: FILES NEEDED

### Create These Files

| File | Location | Purpose |
|------|----------|---------|
| checkout handler | `cmd/api/checkout.go` | Create Stripe session |
| success page | `website/success.html` | Post-purchase page |
| activation page | `website/activate.html` | License activation |
| webhook integration | `cmd/server/webhook.go` | Main app integration |

### Modify These Files

| File | Change |
|------|--------|
| `pricing/index.html` | Add Stripe Checkout forms |
| `cmd/server/main.go` | Add webhook route |

---

## PART 8: MOCK TESTING (No Real Purchases)

### Use Stripe Test Mode

```bash
# All test transactions use test cards
# Test card numbers:
# 4242 4242 4242 4242 - Always succeeds
# 4000 0000 0000 0002 - Always declines
# 4000 0026 0000 0000 - Expired card
```

### Mock License Generation

```go
// In development, use mock license generator
type MockLicenseGenerator struct{}

func (m *MockLicenseGenerator) GenerateLicense(customerID, tier string, days int) (string, error) {
    return fmt.Sprintf("AG-%s-%d-MOCK", strings.ToUpper(tier), time.Now().Unix()), nil
}

// Switch to real implementation in production
var licenseGenerator = func() LicenseGenerator {
    if os.Getenv("MOCK_LICENSE") == "true" {
        return &MockLicenseGenerator{}
    }
    return &RealLicenseGenerator{}
}()
```

---

## SUMMARY

| Item | Status | Effort |
|------|--------|--------|
| Stripe Integration | ✅ Ready | — |
| Webhook Handler | ✅ Ready | — |
| Website Checkout | 🔲 Need to add | 4-8 hours |
| License Activation | 🔲 Need to add | 2-4 hours |
| Email Delivery | 🔲 Need to add | 2-4 hours |
| Testing | 🔲 Need to run | 2-4 hours |

**Total estimated effort:** 1-2 days

---

*This document is a working checklist. Update as items are completed.*

**Version:** 1.0  
**Last Updated:** 2026-05-20