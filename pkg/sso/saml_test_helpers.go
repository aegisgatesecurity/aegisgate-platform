// SPDX-License-Identifier: Apache-2.0
package sso

import "os"

// getTestSignedSAMLResponse retrieves a signed SAML response from environment variables
func getTestSignedSAMLResponse() string {
	return os.Getenv("TEST_SIGNED_SAML_RESPONSE")
}

// getTestSAMLResponse retrieves a standard SAML response from environment variables
func getTestSAMLResponse() string {
	return os.Getenv("TEST_SAML_RESPONSE")
}

// getTestIDPSSOURL retrieves the IdP SSO URL
func getTestIDPSSOURL() string {
	return os.Getenv("SAML_IDP_SSO_URL")
}

// getTestIDPMetadataURL retrieves the IdP Metadata URL
func getTestIDPMetadataURL() string {
	return os.Getenv("SAML_IDP_METADATA_URL")
}
