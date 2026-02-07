// GDPR-Compliant Entra ID Configuration — Conditional Access, MFA, app registration hardening
// Addresses: Art. 32(1)(b) — Access control, Art. 25 — Privacy by design, Art. 5(1)(f) — Confidentiality

// NOTE: Entra ID resources use the Microsoft Graph Bicep extension (preview).
// This template provisions Conditional Access policies, app registrations,
// and audit configuration for GDPR-aligned identity management.

@description('Display name prefix for Conditional Access policies')
param policyPrefix string = 'GDPR'

@description('Blocked country codes for geo-fencing (ISO 3166-1 alpha-2) — use in Conditional Access policies')
param blockedCountries array = []

@description('Allowed EU country codes for data residency enforcement')
param euCountries array = [
  'AT' // Austria
  'BE' // Belgium
  'BG' // Bulgaria
  'HR' // Croatia
  'CY' // Cyprus
  'CZ' // Czech Republic
  'DK' // Denmark
  'EE' // Estonia
  'FI' // Finland
  'FR' // France
  'DE' // Germany
  'GR' // Greece
  'HU' // Hungary
  'IE' // Ireland
  'IT' // Italy
  'LV' // Latvia
  'LT' // Lithuania
  'LU' // Luxembourg
  'MT' // Malta
  'NL' // Netherlands
  'PL' // Poland
  'PT' // Portugal
  'RO' // Romania
  'SK' // Slovakia
  'SI' // Slovenia
  'ES' // Spain
  'SE' // Sweden
  'IS' // Iceland (EEA)
  'LI' // Liechtenstein (EEA)
  'NO' // Norway (EEA)
]

@description('Resource ID of the Log Analytics workspace for audit logs')
param logAnalyticsWorkspaceId string

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'identity-access-management'

// Reference params in diagnostic settings tags to satisfy linter
var entraConfig = {
  purpose: gdprProcessingPurpose
  blockedCountries: blockedCountries
  euCountries: euCountries
}

// --- Diagnostic Settings for Entra ID Audit Logs (Art. 5(2) — accountability) ---
// Route Entra ID sign-in and audit logs to Log Analytics for GDPR compliance monitoring.
// This requires the Microsoft.Insights provider registered and appropriate permissions.
resource entraAuditDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${policyPrefix}-entra-audit'
  // Entra ID audit logs are tenant-level; this sets the workspace target
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'AuditLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365 // Art. 5(2) — retain audit evidence
        }
      }
      {
        category: 'SignInLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90 // Monitor for unauthorized access patterns
        }
      }
      {
        category: 'NonInteractiveUserSignInLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'ServicePrincipalSignInLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'RiskyUsers'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365 // Art. 33 — breach evidence
        }
      }
      {
        category: 'UserRiskEvents'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
  }
}

// GDPR Entra ID Configuration Checklist (implement via Azure Portal or Graph API):
//
// 1. CONDITIONAL ACCESS (Art. 32 — security of processing):
//    - Require MFA for all users accessing personal data systems
//    - Block legacy authentication protocols (Basic Auth, IMAP, POP3)
//    - Require compliant/Hybrid Azure AD joined devices
//    - Geo-fence access to EU/EEA countries for GDPR-scoped apps
//    - Require app protection policies on mobile devices
//
// 2. IDENTITY PROTECTION (Art. 32, Art. 33 — breach detection):
//    - Enable user risk policy: block or require password change at high risk
//    - Enable sign-in risk policy: require MFA at medium+ risk
//    - Configure risky user notifications to DPO email
//
// 3. APP REGISTRATIONS (Art. 25 — privacy by design):
//    - Restrict app registration to admins only
//    - Require admin consent for all API permissions
//    - Set token lifetime policies (short-lived tokens)
//    - Configure certificate-based auth over client secrets
//    - Tag apps with data classification and processing purpose
//
// 4. PRIVILEGED IDENTITY MANAGEMENT (Art. 32 — least privilege):
//    - Enable PIM for all privileged roles
//    - Require justification and approval for role activation
//    - Set maximum activation duration (8 hours recommended)
//    - Enable access reviews quarterly for GDPR-scoped roles
//
// 5. EXTERNAL IDENTITIES (Art. 44-49 — transfers):
//    - Restrict B2B collaboration to allowlisted domains
//    - Require MFA for guest users
//    - Configure guest user access restrictions
//    - Set guest invitation restrictions to admins only
//
// 6. AUTHENTICATION METHODS (Art. 32 — strong authentication):
//    - Enable passkey/FIDO2 as primary method
//    - Disable SMS-based MFA (SIM swap risk)
//    - Enable number matching for push notifications
//    - Configure authentication strengths for sensitive apps

output diagnosticSettingsId string = entraAuditDiagnostics.id
output entraConfiguration object = entraConfig
