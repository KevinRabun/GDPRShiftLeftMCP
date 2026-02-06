// GDPR-Compliant Azure Policy Assignments — Enforce data residency, encryption, tagging, and audit
// Addresses: Art. 25 — Privacy by design/default, Art. 32 — Security, Art. 5(2) — Accountability

targetScope = 'subscription'

@description('Allowed Azure regions for GDPR data residency enforcement')
param allowedLocations array = [
  'westeurope'
  'northeurope'
  'germanywestcentral'
  'francecentral'
  'switzerlandnorth'
  'norwayeast'
  'swedencentral'
]

@description('Effect for encryption policies: Audit, Deny, or Disabled')
@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param encryptionPolicyEffect string = 'Deny'

@description('Effect for location and tag policies: Audit, Deny, or Disabled')
@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param tagPolicyEffect string = 'Deny'

@description('Required tags for GDPR data classification')
param requiredTags array = [
  'data_classification'
  'gdpr_processing_purpose'
]

// --- Policy 1: Restrict to EU regions (Art. 44 — data residency) ---
resource allowedLocationsPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-allowed-locations'
  properties: {
    displayName: 'GDPR: Restrict resources to EU/EEA regions'
    description: 'Ensures all resources are deployed in EU/EEA regions per GDPR Art. 44-49 transfer restrictions.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c' // Built-in: Allowed locations
    parameters: {
      listOfAllowedLocations: {
        value: allowedLocations
      }
    }
    enforcementMode: 'Default'
  }
}

// --- Policy 2: Require encryption at rest (Art. 32(1)(a)) ---
resource storageEncryptionPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-storage-encryption'
  properties: {
    displayName: 'GDPR: Storage accounts must use customer-managed keys'
    description: 'Enforces CMK encryption on storage accounts per Art. 32(1)(a) encryption requirements.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/6fac406b-40ca-413b-bf8e-0bf964659c25' // Built-in: Storage CMK
    parameters: {}
    enforcementMode: 'Default'
  }
}

// --- Policy 3: Require HTTPS only (Art. 32 — encryption in transit) ---
resource httpsOnlyPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-https-only'
  properties: {
    displayName: 'GDPR: Secure transfer (HTTPS) must be enabled'
    description: 'Enforces HTTPS for storage accounts per Art. 32 encryption in transit requirements.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9' // Built-in: Secure transfer
    parameters: {
      effect: {
        value: encryptionPolicyEffect
      }
    }
    enforcementMode: 'Default'
  }
}

// --- Policy 4: Require SQL TDE (Art. 32(1)(a) — encryption at rest) ---
resource sqlTdePolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-sql-tde'
  properties: {
    displayName: 'GDPR: SQL databases must have Transparent Data Encryption enabled'
    description: 'Enforces TDE on SQL databases per Art. 32(1)(a) encryption requirements.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/17k78e20-9358-41c9-923c-fb736d382a12' // Built-in: SQL TDE
    parameters: {}
    enforcementMode: 'Default'
  }
}

// --- Policy 5: Require diagnostic settings (Art. 5(2) — accountability) ---
resource diagnosticsPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-require-diagnostics'
  properties: {
    displayName: 'GDPR: Resources must have diagnostic settings enabled'
    description: 'Ensures diagnostic logging is enabled for accountability per Art. 5(2) and Art. 30.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/7f89b1eb-583c-429a-8828-af049802c1d9' // Built-in: Require diagnostics
    parameters: {}
    enforcementMode: 'Default'
  }
}

// --- Policy 6: Require data classification tags (Art. 30 — records of processing) ---
@batchSize(1)
resource requiredTagPolicies 'Microsoft.Authorization/policyAssignments@2024-04-01' = [for (tag, i) in requiredTags: {
  name: 'gdpr-require-tag-${i}'
  properties: {
    displayName: 'GDPR: Require \'${tag}\' tag on all resources'
    description: 'Enforces ${tag} tag for GDPR Art. 30 records of processing activities.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/871b6d14-10aa-478d-b590-94f262ecfa99' // Built-in: Require tag
    parameters: {
      tagName: {
        value: tag
      }
    }
    enforcementMode: tagPolicyEffect == 'Disabled' ? 'DoNotEnforce' : 'Default'
  }
}]

// --- Policy 7: Deny public network access by default (Art. 25 — privacy by default) ---
resource denyPublicBlobPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-deny-public-blob'
  properties: {
    displayName: 'GDPR: Storage accounts must disable public blob access'
    description: 'Prevents public blob access per Art. 25 privacy by default requirements.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751' // Built-in: No public blob
    parameters: {}
    enforcementMode: 'Default'
  }
}

// --- Policy 8: Require private endpoints (Art. 25, Art. 32 — network isolation) ---
resource privateEndpointPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'gdpr-private-endpoints'
  properties: {
    displayName: 'GDPR: Key Vaults must use private endpoints'
    description: 'Enforces private endpoint connections per Art. 32 network security requirements.'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/a6abeaec-4d90-4a02-805f-6b26c4d3fbe9' // Built-in: KV private endpoint
    parameters: {
      effect: {
        value: encryptionPolicyEffect
      }
    }
    enforcementMode: 'Default'
  }
}

// GDPR Azure Policy Best Practices:
// 1. Start with 'Audit' effect to assess current compliance posture
// 2. Move to 'Deny' effect after remediation planning
// 3. Use policy exemptions sparingly with documented justification
// 4. Assign at management group level for organization-wide enforcement
// 5. Review compliance reports quarterly aligned with DPA reviews
// 6. Integrate with Azure Monitor alerts for real-time violation detection
