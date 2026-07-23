// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 AegisGate Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package soc2 provides SOC 2 compliance types, controls, and policy templates
// for AegisGate platform audit and governance. It includes pre-written policy
// documents that map to specific SOC 2 Trust Service Criteria controls.
package soc2

import (
	"fmt"
	"time"
)

// PolicyTemplates returns a slice of PolicyDocument — one per Trust Service
// Category — containing pre-written policy templates that map to specific
// SOC 2 controls.
func PolicyTemplates() []PolicyDocument {
	now := time.Now()
	return []PolicyDocument{
		{
			ID:       "POL-SEC-001",
			Title:    "Information Security Policy",
			Category: TSCSecurity,
			Version:  "1.0",
			Content: `PURPOSE

This Information Security Policy establishes the framework for protecting AegisGate platform assets, data, and operations against unauthorized access, disclosure, alteration, or destruction. It defines the minimum security requirements that all personnel, contractors, and third parties must follow when interacting with organizational systems and data.

SCOPE

This policy applies to all employees, contractors, consultants, temporaries, and other workers at AegisGate, including all personnel affiliated with third parties who access AegisGate information systems. It covers all information assets regardless of form (electronic, physical), classification level, or storage medium, including but not limited to production systems, development environments, staging infrastructure, and corporate networks.

ACCESS CONTROL

All access to information systems must be governed by the principle of least privilege. User access rights shall be granted based on job function and business need, reviewed quarterly, and revoked promptly upon role change or termination. Access requests must be documented, approved by the data owner or designated authority, and logged for audit purposes. Shared or generic accounts are prohibited; each user must have a unique identifier for accountability.

AUTHENTICATION

All systems must enforce multi-factor authentication (MFA) for user access. Passwords must meet minimum complexity requirements: at least 14 characters, including uppercase, lowercase, numeric, and special characters. Passwords must not be reused across systems and must be changed at least every 90 days. Failed authentication attempts exceeding five consecutive failures shall trigger account lockout and generate a security alert.

AUTHORIZATION

Authorization decisions shall follow role-based access control (RBAC) principles. Roles and permissions must be formally defined, documented, and reviewed at least annually. Segregation of duties must be enforced for critical business processes to prevent fraud and error. Elevated or privileged access must be time-limited, require additional approval, and be monitored continuously.

ENCRYPTION

All data classified as confidential or above must be encrypted at rest using AES-256 or equivalent algorithms and in transit using TLS 1.2 or higher. Encryption keys must be managed through an approved key management system, rotated according to schedule, and stored separately from the data they protect. Deprecated or compromised keys must be revoked and replaced immediately.

LOGGING AND MONITORING

All systems must generate audit logs for security-relevant events, including authentication attempts, authorization changes, data access, and administrative actions. Logs must be transmitted to a centralized logging platform within 60 seconds of generation, protected from unauthorized modification, and retained for a minimum of one year. Security operations personnel must review logs daily and investigate anomalies within 24 hours.

INCIDENT RESPONSE

Security incidents must be reported immediately through established channels. The incident response team must acknowledge reported incidents within one hour and begin triage within four hours. Post-incident reviews must be conducted within five business days of incident resolution, and lessons learned must be documented and incorporated into security controls. Incident metrics must be reported to management monthly.`,
			Controls:    []string{"SOC2-CC1.1", "SOC2-CC1.4", "SOC2-CC6.1", "SOC2-CC6.2", "SOC2-CC6.3", "SOC2-CC6.6", "SOC2-CC6.7"},
			LastUpdated: now,
		},
		{
			ID:       "POL-AVAIL-001",
			Title:    "Availability and Capacity Management Policy",
			Category: TSCAvailability,
			Version:  "1.0",
			Content: `PURPOSE

This Availability and Capacity Management Policy defines the requirements for ensuring that AegisGate platform services remain accessible and operational to authorized users in accordance with service level agreements and business objectives. It establishes the standards for capacity planning, monitoring, incident management, and disaster recovery.

SCOPE

This policy applies to all production systems, supporting infrastructure, network components, and third-party services that contribute to the availability of AegisGate platform offerings. It covers both planned and unplanned availability events across all deployment regions and availability zones.

CAPACITY PLANNING

Capacity planning must be performed on a quarterly basis to forecast resource requirements based on historical trends, projected growth, and anticipated business events. Capacity assessments must evaluate compute, storage, network bandwidth, and database capacity across all tiers. Systems must maintain a minimum of 30 percent headroom above projected peak utilization to accommodate unexpected demand spikes. Capacity plans must be reviewed and approved by engineering leadership and documented in the capacity management register.

MONITORING

All production systems must be monitored continuously for availability, performance, and resource utilization. Monitoring must cover system health metrics, application performance indicators, and business-level availability signals. Alerts must be generated within five minutes of threshold breaches and routed to the appropriate on-call personnel through automated paging systems. Monitoring coverage must include all critical path dependencies, and gaps in monitoring must be remediated within one sprint cycle.

INCIDENT MANAGEMENT

Availability incidents must be classified by severity using a four-tier model: Critical (total service outage), High (major feature degradation), Medium (partial feature impact), and Low (minor or cosmetic impact). Critical incidents require an immediate response within 15 minutes, continuous status updates every 30 minutes, and a post-incident review within 48 hours. Incident commanders must be designated for all Critical and High severity incidents. Root cause analysis must be completed within five business days of incident resolution, and corrective actions must be tracked to completion.

DISASTER RECOVERY

Disaster recovery plans must be documented, tested at least annually, and updated following any significant infrastructure or application change. Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) must be defined for all critical services, with RTO not exceeding four hours and RPO not exceeding one hour for Tier 1 services. Data backup procedures must ensure automated daily backups with geographic redundancy. Backup restoration must be validated quarterly through documented restore tests. Disaster recovery procedures must be accessible to authorized personnel even during a primary system outage.`,
			Controls:    []string{"SOC2-A1.1"},
			LastUpdated: now,
		},
		{
			ID:       "POL-PI-001",
			Title:    "Processing Integrity Policy",
			Category: TSCProcessingIntegrity,
			Version:  "1.0",
			Content: `PURPOSE

This Processing Integrity Policy establishes the requirements for ensuring that AegisGate platform data processing operations are complete, valid, accurate, timely, and authorized. It defines the controls necessary to prevent, detect, and correct processing errors that could affect the integrity of business operations and data outcomes.

SCOPE

This policy applies to all data processing activities performed by AegisGate platform systems, including batch processing, real-time transaction processing, data transformation pipelines, and automated workflows. It encompasses input validation, processing logic, output verification, and error handling across all system components.

DATA VALIDATION

All data input to processing systems must be validated at the point of entry for completeness, format, range, and business rule compliance. Input validation rules must be documented, version-controlled, and tested as part of the deployment pipeline. Validation failures must be logged with sufficient detail to enable root cause analysis, including the input value, expected format, validation rule triggered, and timestamp. Invalid data must be quarantined and not propagated to downstream systems without explicit remediation and re-validation.

PROCESSING CONTROLS

Processing logic must implement appropriate checks to ensure completeness and accuracy. Reconciliation procedures must be performed for all critical processing steps, comparing input counts and totals to output counts and totals. Processing sequence controls must prevent out-of-order execution that could compromise data integrity. Automated checksums, hash comparisons, or record count validations must be implemented at each processing stage to detect data loss or corruption. All processing steps must produce audit trails that enable end-to-end traceability of data transformations.

QUALITY ASSURANCE

Quality assurance processes must be integrated into the software development lifecycle to verify processing integrity before deployment. Automated test suites must include positive tests confirming expected processing outcomes, negative tests validating proper rejection of invalid inputs, and boundary tests verifying correct behavior at data limits. Regression testing must be performed for all changes to processing logic. Production data processing must be monitored for anomalous patterns that may indicate processing errors, including unexpected volume changes, error rate spikes, or output distribution shifts.

ERROR HANDLING

Processing errors must be captured, classified, and routed to appropriate resolution workflows. Error classification must distinguish between transient errors eligible for automated retry, data quality errors requiring manual remediation, and systemic errors necessitating engineering investigation. Retry logic must implement exponential backoff with a maximum retry limit to prevent infinite retry loops. Errors that cannot be resolved through automated retry must generate alerts and be assigned to responsible teams within defined service level timeframes. All error handling must preserve the original data state and produce a complete audit trail of the error, retry attempts, and resolution.`,
			Controls:    []string{"SOC2-PI1.2"},
			LastUpdated: now,
		},
		{
			ID:       "POL-CONF-001",
			Title:    "Confidentiality and Data Protection Policy",
			Category: TSCConfidentiality,
			Version:  "1.0",
			Content: `PURPOSE

This Confidentiality and Data Protection Policy establishes the requirements for protecting information designated as confidential from unauthorized access, use, disclosure, or destruction. It defines the standards for data classification, encryption, access restrictions, and third-party management that safeguard AegisGate platform data assets.

SCOPE

This policy applies to all information assets processed, stored, or transmitted by AegisGate, regardless of format or medium. It covers data at rest, in transit, and in use across all environments including production, development, testing, and disaster recovery. All personnel who create, access, process, or manage confidential information are subject to this policy.

DATA CLASSIFICATION

All information assets must be classified according to a four-tier model: Public (no restrictions), Internal (restricted to organizational personnel), Confidential (restricted to authorized individuals with a need to know), and Restricted (highest sensitivity, requiring additional controls and explicit approval for each access). Classification must be performed by data owners at the time of creation or acquisition and reviewed annually. Data must be labeled or tagged with its classification level in metadata, filenames, or document headers. Downgrading classification requires approval from the original data owner and a documented risk assessment.

ENCRYPTION

Confidential and Restricted data must be encrypted at rest using AES-256 or equivalent encryption standards and in transit using TLS 1.2 or higher. End-to-end encryption must be used for data exchanged with external parties. Encryption keys must be generated using approved cryptographic algorithms, stored in a hardware security module or approved key management service, rotated at least annually, and revoked immediately upon compromise. Data in use within memory must be protected through access controls and, where feasible, through confidential computing technologies. Database fields containing sensitive information must implement column-level encryption in addition to storage-level encryption.

ACCESS RESTRICTIONS

Access to Confidential and Restricted data must be granted on a need-to-know basis, documented through formal access requests, and reviewed at least quarterly. Access to Restricted data requires individual approval from the data owner, time-limited access windows, and enhanced monitoring. Data access must be logged with user identity, timestamp, action performed, and data objects accessed. Physical access to storage media containing Confidential or Restricted data must be controlled through secure facilities with badge access and visitor logs.

THIRD-PARTY MANAGEMENT

Third parties with access to Confidential or Restricted data must execute non-disclosure agreements before access is granted. Third-party access must be limited to the minimum data necessary for the stated business purpose, monitored continuously, and terminated upon contract expiration or conclusion of the business need. Third-party security assessments must be performed before granting access and at least annually thereafter. Data shared with third parties must be protected through contractual obligations, technical controls, and verified through audit rights provisions. Incident notification requirements must be included in all third-party agreements, specifying notification timelines and cooperation obligations.`,
			Controls:    []string{"SOC2-C1.1", "SOC2-C2.1"},
			LastUpdated: now,
		},
		{
			ID:       "POL-PRIV-001",
			Title:    "Privacy and Personal Information Policy",
			Category: TSCPrivacy,
			Version:  "1.0",
			Content: `PURPOSE

This Privacy and Personal Information Policy establishes the requirements for the responsible collection, use, retention, and disposal of personal information by AegisGate. It defines the principles and controls necessary to protect individual privacy rights and comply with applicable privacy laws and regulations across all jurisdictions in which the organization operates.

SCOPE

This policy applies to all personal information collected, processed, stored, or transmitted by AegisGate, including but not limited to names, email addresses, identification numbers, biometric data, behavioral data, and any information that can directly or indirectly identify an individual. It covers all systems, processes, and personnel that handle personal information throughout its lifecycle.

NOTICE

AegisGate must provide clear, conspicuous, and timely notice to individuals before or at the time of collecting personal information. Privacy notices must describe the categories of data collected, the purposes for which data is used, the categories of third parties with whom data may be shared, the retention period, and the individual's rights regarding their data. Notices must be written in plain language, accessible to individuals with disabilities, and updated whenever data practices change materially. Material changes to privacy practices require renewed notice and, where applicable, updated consent.

CONSENT

Personal information must not be collected, used, or disclosed without a valid legal basis, which may include individual consent, contractual necessity, legal obligation, or legitimate interest. Where consent is the legal basis, it must be freely given, specific, informed, and unambiguous. Opt-in consent is required for sensitive personal information and for any processing beyond the original stated purpose. Individuals must be able to withdraw consent at any time without detriment, and withdrawal must be honored within 30 days. Consent records must be maintained with timestamp, scope, method of collection, and version of the notice provided.

DATA MINIMIZATION

Only personal information that is directly relevant and necessary for the specified purpose may be collected. Data collection must be proportionate to the stated purpose and must not include information that is not required. Periodic reviews must be conducted to identify and eliminate unnecessary data collection. Data fields must be evaluated against current business needs at least annually, and fields no longer required must be removed from collection forms and purged from storage. Aggregated or anonymized data must be used whenever possible in place of identifiable information.

RETENTION AND DISPOSAL

Personal information must be retained only for as long as necessary to fulfill the stated purpose, satisfy legal or regulatory requirements, or resolve disputes. Retention schedules must be defined for each category of personal information, documented in the data inventory, and enforced through automated controls where feasible. Upon expiration of the retention period, personal information must be securely disposed of using methods appropriate to the sensitivity of the data, including secure deletion for electronic data and shredding for physical records. Disposal must be verified and logged.

SUBJECT RIGHTS

Individuals have the right to access their personal information, request correction of inaccurate data, request deletion of their data, object to or restrict processing, and receive their data in a portable format. Subject rights requests must be acknowledged within five business days and fulfilled within 30 calendar days, unless a legally permissible extension applies. Identity verification must be performed before disclosing personal information in response to an access request. A complete log of subject rights requests, actions taken, and outcomes must be maintained for regulatory compliance and audit purposes.`,
			Controls:    []string{"SOC2-CC6.3", "SOC2-CC6.6"},
			LastUpdated: now,
		},
	}
}

// PolicyForCategory returns all policy documents that belong to the specified
// Trust Service Category.
func PolicyForCategory(cat TrustServiceCategory) ([]PolicyDocument, error) {
	var result []PolicyDocument
	for _, p := range PolicyTemplates() {
		if p.Category == cat {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no policies found for category: %s", cat)
	}
	return result, nil
}

// PolicyForControl returns all policy documents that cover the specified SOC 2
// control ID. A policy covers a control if the control ID appears in the
// policy's Controls list.
func PolicyForControl(controlID string) ([]PolicyDocument, error) {
	var result []PolicyDocument
	for _, p := range PolicyTemplates() {
		for _, c := range p.Controls {
			if c == controlID {
				result = append(result, p)
				break
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no policies found for control: %s", controlID)
	}
	return result, nil
}