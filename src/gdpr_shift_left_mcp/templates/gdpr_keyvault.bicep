// GDPR-Compliant Azure Key Vault — HSM-backed, Private Endpoint, soft-delete, purge protection
// Addresses: Art. 32(1)(a) — encryption and pseudonymisation, Art. 25 — privacy by design

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Key Vault')
param keyVaultName string

@description('Azure AD tenant ID')
param tenantId string = subscription().tenantId

@description('Resource ID of the subnet for Private Endpoint')
param subnetId string

@description('Resource ID of the Log Analytics workspace')
param logAnalyticsWorkspaceId string = ''

@description('Enable RBAC authorization (recommended over access policies)')
param enableRbacAuthorization bool = true

// --- Key Vault (Art. 32 — security of processing) ---
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'premium' // HSM-backed keys for GDPR Art. 32
    }

    // Security hardening
    enableRbacAuthorization: enableRbacAuthorization
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true // Prevent accidental key deletion

    // Network isolation
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
  tags: {
    'gdpr-purpose': 'encryption-key-management'
    'gdpr-article': 'Art-32'
  }
}

// --- Private Endpoint ---
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${keyVaultName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${keyVaultName}-plsc'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [ 'vault' ]
        }
      }
    ]
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability, audit trail) ---
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${keyVaultName}-diag'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365 // Retain audit logs for 1 year
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

output keyVaultId string = keyVault.id
output keyVaultUri string = keyVault.properties.vaultUri
output keyVaultName string = keyVault.name
