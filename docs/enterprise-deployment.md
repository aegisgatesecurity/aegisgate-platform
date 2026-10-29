# Enterprise Deployment Guide

This guide covers deploying AegisGate Lens to managed fleets via
Group Policy (GPO), Microsoft Intune, and Jamf Pro (JAMF).

## Overview

AegisGate Lens supports enterprise-managed configuration through
Chrome's `chrome.storage.managed` API. IT administrators push
configuration via policy, which overrides individual user preferences.
Users cannot modify managed settings through the extension popup.

### What Can Be Managed?

| Policy Key | Type | Default | Description |
|---|---|---|---|
| `backendUrl` | string | `""` | AegisGate Platform URL for telemetry and IOC pull. Empty = air-gap mode. |
| `bearerToken` | string | `""` | API key for Platform authentication. Required when `backendUrl` is set. |
| `iocPullEnabled` | boolean | `false` | Enable IOC fingerprint pull from Platform. |
| `iocPullInterval` | integer | `300000` | IOC pull interval in ms (min: 60000). |
| `rampartCorrelationEnabled` | boolean | `false` | Enable detection signal correlation with local Rampart proxy. |
| `rampartBaseUrl` | string | `http://127.0.0.1:8443` | Rampart base URL for signal correlation. |
| `optInRequired` | boolean | `true` | Whether user must explicitly opt in to telemetry. Set `false` for silent deployment. |
| `facetsEnabled` | object | all `true` | Per-facet enable/disable: `pii`, `secrets`, `xss`, `compliance`, `ot`. |

### Precedence Rules

1. **Managed policy** (IT-administered) takes precedence over user preferences.
2. If a managed key is **not set** (`undefined`), the user's local preference is used.
3. If managed explicitly sets a value to `false`, that is honored — IT can disable a feature.
4. Both IOC Pull and Rampart Bridge are **OFF by default** (air-gap). IT must explicitly enable them.

## Chrome — Group Policy (GPO)

### Prerequisites

- Chrome browser (managed Chrome or Chromium-based browser with policy support)
- Group Policy Management Console (GPMC)
- Administrative templates for Chrome installed

### Steps

1. **Open Group Policy Management** → Create or edit a GPO linked to the target OU.

2. **Navigate to**:
   ```
   Computer Configuration → Policies → Administrative Templates → Google → Google Chrome → Extensions
   ```

3. **Enable extension installation**:
   - Set "Configure extension installation allow list" to Enabled.
   - Add the AegisGate Lens extension ID (from Chrome Web Store or self-hosted `.crx`).

4. **Configure managed storage**:
   - Set "Configure extension settings" to Enabled.
   - Enter the extension ID and JSON configuration:

   ```json
   {
     "backendUrl": "https://aegisgate.yourcorp.com",
     "bearerToken": "your-api-key-here",
     "iocPullEnabled": true,
     "iocPullInterval": 300000,
     "rampartCorrelationEnabled": false,
     "optInRequired": false,
     "facetsEnabled": {
       "pii": true,
       "secrets": true,
       "xss": true,
       "compliance": true,
       "ot": false
     }
   }
   ```

5. **Link the GPO** to the target OU and run `gpupdate /force` on client machines.

### Verification

On a managed machine, navigate to `chrome://policy` — the AegisGate Lens
policies should appear under "Extension policies."

## Microsoft Intune

### Prerequisites

- Microsoft Endpoint Manager admin center access
- Devices enrolled in Intune (Windows 10/11, macOS)
- Chrome browser deployed via Intune

### Steps

1. **Create a configuration profile**:
   - Go to **Devices → Configuration profiles → Create profile**.
   - Platform: Windows 10 and later.
   - Profile type: **Administrative Templates**.

2. **Configure extension installation**:
   - Search for "ExtensionInstallAllowlist".
   - Enable and add the AegisGate Lens extension ID.

3. **Configure managed storage**:
   - Search for "ExtensionSettings".
   - Enable and paste the JSON configuration (same format as GPO above).

4. **Assign** the profile to the target device group.

5. For **macOS** devices: Use a **Preferences file** (.plist) configuration profile:
   - Key path: `com.google.Chrome.extensions.<extension-id>`
   - Value: Same JSON configuration.

### Verification

On the managed device, sync with Intune (`dsregcmd /status` or check
Company Portal), then check `chrome://policy`.

## Jamf Pro (JAMF) — macOS

### Prerequisites

- Jamf Pro admin access
- Mac devices enrolled in Jamf
- Chrome browser deployed via Jamf

### Steps

1. **Create a Configuration Profile**:
   - Go to **Computers → Configuration Profiles → New**.

2. **Add Application & Custom Settings**:
   - Click **Add** → **External Application** → **com.google.Chrome**.

3. **Configure extension settings**:
   - Create a `.plist` file with the managed configuration:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
     "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>ExtensionInstallAllowlist</key>
     <array>
       <string><extension-id></string>
     </array>
     <key>ExtensionSettings</key>
     <dict>
       <key><extension-id></key>
       <dict>
         <key>backendUrl</key>
         <string>https://aegisgate.yourcorp.com</string>
         <key>bearerToken</key>
         <string>your-api-key-here</string>
         <key>iocPullEnabled</key>
         <true/>
         <key>optInRequired</key>
         <false/>
       </dict>
     </dict>
   </dict>
   </plist>
   ```

4. **Scope** the profile to the target computers or computer groups.

### Verification

On a managed Mac, run `profiles status` in Terminal to verify the
profile is installed, then check `chrome://policy` in Chrome.

## Air-Gapped Deployments

For isolated networks with no internet access:

1. **Do not set** `backendUrl` — the extension operates in standalone mode.
2. **Do not set** `iocPullEnabled` — no IOC pull without a Platform URL.
3. Set `rampartCorrelationEnabled` to `true` if a local Rampart proxy is deployed.
4. Set `rampartBaseUrl` to the Rampart proxy's local address (default: `http://127.0.0.1:8443`).
5. All detection (217 regex patterns + ML model) works locally — no cloud dependency.

Example air-gapped policy:

```json
{
  "backendUrl": "",
  "iocPullEnabled": false,
  "rampartCorrelationEnabled": true,
  "rampartBaseUrl": "http://127.0.0.1:8443",
  "optInRequired": false,
  "facetsEnabled": {
    "pii": true,
    "secrets": true,
    "xss": true,
    "compliance": true,
    "ot": true
  }
}
```

## Managed Schema File

The `managed_schema.json` file in the extension root defines the
policy schema. Chrome uses this to validate managed configuration.
The schema must be referenced in the extension's `manifest.json`:

```json
{
  "storage": {
    "managed_schema": "managed_schema.json"
  }
}
```

## Troubleshooting

### Policies not appearing in `chrome://policy`

- Verify the GPO/Intune/JAMF profile is deployed and synced.
- Check that the extension ID matches exactly.
- Ensure the JSON is valid (no trailing commas, proper escaping).

### Extension installed but features not working

- Check `chrome://policy` for the managed keys.
- Verify `backendUrl` and `bearerToken` are set if using Platform features.
- Check the browser console (`chrome://extensions` → Details → Inspect) for errors.
- Verify network connectivity to the Platform URL.

### Users can still change settings

- Managed policies override user preferences. If a user changes a setting
  in the popup, it will be overridden by the managed policy on the next
  `initSensorModules()` call (on browser startup or extension reload).
- To prevent UI confusion, set `optInRequired` to `false` for silent deployments.