// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package setup provides an interactive setup wizard for the AegisGate
// Security Platform.
//
// The wizard guides first-time operators through initial configuration
// by detecting the deployment environment (OS, architecture, container
// runtime, cloud provider) and recommending an appropriate deploy
// profile. It then prompts for any required parameters not covered by
// the profile defaults.
//
// The wizard is invoked via the `aegisgate setup` CLI subcommand and
// outputs the selected profile name, which can then be used with
// `aegisgate --profile <name>` to start the platform.
//
// Key types:
//   - Environment: Detected system characteristics
//   - WizardOptions: Configuration for wizard behavior
//   - Run: Entry point that executes the wizard interactively
//
// =========================================================================
package setup
