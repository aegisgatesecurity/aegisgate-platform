#!/usr/bin/env python3
"""
Generate SSO integration code for main.go
Phase 3: SSO Configuration Loading and Middleware Initialization
"""

import yaml
from pathlib import Path


def generate_sso_integration():
    """Generate the SSO integration code for main.go"""
    
    code = '''// Phase 3: SSO Configuration Loading (generated)
	// Initialize SSO Manager with configuration from YAML file
	var ssoManager *sso.Manager
	var ssoErr error

	// Try to load SSO configuration from YAML file
	ssoConfig := sso.DefaultSSOConfig()
	ssoConfigPath := "configs/sso.yaml"
	if fileExists(ssoConfigPath) {
		yamlData, err := os.ReadFile(ssoConfigPath)
		if err != nil {
			log.Printf("Warning: Failed to read SSO config file %s: %v", ssoConfigPath, err)
		} else {
			var configMap map[string]interface{}
			if err := yaml.Unmarshal(yamlData, &configMap); err == nil {
				// Parse sso section
				if ssoMap, ok := configMap["sso"].(map[string]interface{}); ok {
					if enabled, ok := ssoMap["enabled"].(bool); ok {
						ssoConfig.Enabled = enabled
					}
				}

				// Parse oidc section
				if oidcMap, ok := configMap["oidc"].(map[string]interface{}); ok {
					oidcConfig := &sso.OIDCConfig{Enabled: false}
					if enabled, ok := oidcMap["enabled"].(bool); ok {
						oidcConfig.Enabled = enabled
					}
					if provider, ok := oidcMap["provider"].(string); ok {
						oidcConfig.Provider = provider
					}
					if clientID, ok := oidcMap["client_id"].(string); ok {
						oidcConfig.ClientID = clientID
					}
					if clientSecret, ok := oidcMap["client_secret"].(string); ok {
						oidcConfig.ClientSecret = clientSecret
					}
					if authURL, ok := oidcMap["auth_url"].(string); ok {
						oidcConfig.AuthURL = authURL
					}
					if tokenURL, ok := oidcMap["token_url"].(string); ok {
						oidcConfig.TokenURL = tokenURL
					}
					if userInfoURL, ok := oidcMap["user_info_url"].(string); ok {
						oidcConfig.UserInfoURL = userInfoURL
					}
					if redirectURL, ok := oidcMap["redirect_url"].(string); ok {
						oidcConfig.RedirectURL = redirectURL
					}
					ssoConfig.OIDC = oidcConfig
				}

				// Parse saml section
				if samlMap, ok := configMap["saml"].(map[string]interface{}); ok {
					samlConfig := &sso.SAMLConfig{Enabled: false}
					if enabled, ok := samlMap["enabled"].(bool); ok {
						samlConfig.Enabled = enabled
					}
					if idpMetadataURL, ok := samlMap["idp_metadata_url"].(string); ok {
						samlConfig.IDPMetadataURL = idpMetadataURL
					}
					if idpCert, ok := samlMap["idp_cert"].(string); ok {
						samlConfig.IDPCert = idpCert
					}
					if entityID, ok := samlMap["entity_id"].(string); ok {
						samlConfig.EntityID = entityID
					}
					if acsURL, ok := samlMap["acs_url"].(string); ok {
						samlConfig.ACURL = acsURL
					}
					if nameIDFormat, ok := samlMap["name_id_format"].(string); ok {
						samlConfig.NameIDFormat = nameIDFormat
					}
					ssoConfig.SAML = samlConfig
				}

				// Parse session section
				if sessionMap, ok := configMap["session"].(map[string]interface{}); ok {
					if durationHours, ok := sessionMap["duration_hours"].(float64); ok {
						ssoConfig.SessionDuration = time.Duration(durationHours) * time.Hour
					}
					if secure, ok := sessionMap["secure"].(bool); ok {
						ssoConfig.CookieSecure = secure
					}
					if sameSite, ok := sessionMap["same_site"].(string); ok {
						ssoConfig.CookieSameSite = sameSite
					}
				}
			}
		}
	}

	// Initialize SSO Manager
	ssoManager, ssoErr = sso.NewManager(&sso.ManagerConfig{
		DefaultConfig: ssoConfig,
	})

	// Create middleware with appropriate auth settings
	if ssoErr != nil || !ssoConfig.Enabled {
		log.Printf("Warning: SSO initialization failed or disabled: %v", ssoErr)
		log.Println("SSO: Using basic authentication only")
		authMiddleware = auth.NewMiddleware(authConfig)
	} else {
		authMiddleware = auth.NewMiddlewareWithSSO(authConfig, ssoManager)

		// Log enabled providers
		if ssoConfig.OIDC != nil && ssoConfig.OIDC.Enabled {
			log.Printf("SSO: OIDC provider enabled: %s", ssoConfig.OIDC.Provider)
		}
		if ssoConfig.SAML != nil && ssoConfig.SAML.Enabled {
			log.Println("SSO: SAML provider enabled")
		}
	}

	log.Printf("Auth middleware: require_auth=%v, sso_enabled=%v", authConfig.RequireAuth, ssoManager != nil)
'''
    
    return code


def generate_file_helper():
    """Generate the fileExists helper function"""
    return '''
// Helper function to check if file exists
fileExists := func(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
'''


def main():
    """Generate the complete SSO integration"""
    output_dir = Path("/home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/gen")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate main integration code
    main_code = generate_sso_integration()
    
    # Generate helper function
    helper_code = generate_file_helper()
    
    # Save to file
    output_file = output_dir / "sso_integration_code.go"
    with open(output_file, 'w') as f:
        f.write(main_code)
        f.write(helper_code)
    
    print(f"Generated SSO integration code: {output_file}")
    print("\nTo apply the integration, insert the generated code after line 373 in main.go")
    print("Replace:")
    print("  authMiddleware := auth.NewMiddleware(authConfig)")
    print("With the generated code...")


if __name__ == "__main__":
    main()
