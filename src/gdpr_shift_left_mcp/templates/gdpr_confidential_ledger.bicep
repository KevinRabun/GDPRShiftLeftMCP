// GDPR-Compliant Azure Confidential Ledger — Tamper-proof audit trail for GDPR accountability
// Addresses: Art. 5(2) — Accountability, Art. 30 — Records of processing, Art. 33 — Breach notification records

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Confidential Ledger')
param ledgerName string

@description('Ledger type: Public (read-open) or Private (read-restricted)')
@allowed([
  'Public'
  'Private'
])
param ledgerType string = 'Private' // Art. 25 — private by default

@description('AAD-based ledger administrator object ID')
param adminObjectId string

@description('AAD-based ledger administrator tenant ID')
param adminTenantId string = subscription().tenantId

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'gdpr-audit-trail'

// --- Confidential Ledger (Art. 5(2) — accountability via tamper-proof records) ---
// Azure Confidential Ledger uses TEE (Trusted Execution Environment) backed by
// Intel SGX enclaves, providing tamper-proof, cryptographically verifiable records
// ideal for GDPR accountability obligations.
resource confidentialLedger 'Microsoft.ConfidentialLedger/ledgers@2023-06-28-preview' = {
  name: ledgerName
  location: location
  properties: {
    ledgerType: ledgerType
    // Art. 32 — AAD-based authentication; no shared keys
    aadBasedSecurityPrincipals: [
      {
        principalId: adminObjectId
        tenantId: adminTenantId
        ledgerRoleName: 'Administrator'
      }
    ]
    // Running on CCF (Confidential Consortium Framework) ensures:
    // - All writes are cryptographically signed and sequenced
    // - Transaction receipts provide non-repudiation (Art. 5(2))
    // - Enclave attestation ensures code integrity
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    gdpr_articles: 'Art.5(2),Art.30,Art.33'
    data_classification: 'audit-immutable'
    description: 'Tamper-proof GDPR audit trail and breach notification log'
  }
}

// GDPR Usage Guidance:
// 1. Log all data subject access requests (DSARs) — Art. 15 accountability
// 2. Record consent changes with timestamps — Art. 7(1) proof of consent
// 3. Store breach notification records — Art. 33(5) documentation requirement
// 4. Record processing activity changes — Art. 30 register updates
// 5. Log cross-border transfer approvals — Art. 49 derogation records

output ledgerId string = confidentialLedger.id
output ledgerName string = confidentialLedger.name
output ledgerUri string = 'https://${ledgerName}.confidential-ledger.azure.com'
