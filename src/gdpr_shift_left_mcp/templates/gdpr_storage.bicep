// GDPR-Compliant Azure Storage Account — Encryption at rest (CMK), TLS 1.2, Private Endpoint, EU region
// Addresses: Art. 5(1)(f), Art. 25, Art. 32, Arts. 44-49

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the storage account')
param storageAccountName string

@description('Resource ID of the Key Vault key for CMK encryption')
param keyVaultKeyUri string

@description('Resource ID of the User-Assigned Managed Identity for CMK access')
param userAssignedIdentityId string

@description('Resource ID of the existing Virtual Network subnet for Private Endpoint')
param subnetId string

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = ''

@description('GDPR data category tag')
param gdprDataCategory string = ''

@description('GDPR retention period in days')
param gdprRetentionDays int = 365

// --- Storage Account (Art. 32 — encryption, Art. 25 — privacy by design) ---
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_GRS' // Geo-redundant within EU
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentityId}': {}
    }
  }
  properties: {
    // Art. 32 — Encryption in transit
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'

    // Art. 32 — Encryption at rest with Customer-Managed Key
    encryption: {
      keySource: 'Microsoft.Keyvault'
      keyvaultproperties: {
        keyname: last(split(keyVaultKeyUri, '/'))
        keyvaulturi: substring(keyVaultKeyUri, 0, lastIndexOf(keyVaultKeyUri, '/keys/'))
      }
      services: {
        blob: { enabled: true, keyType: 'Account' }
        file: { enabled: true, keyType: 'Account' }
        queue: { enabled: true, keyType: 'Account' }
        table: { enabled: true, keyType: 'Account' }
      }
      requireInfrastructureEncryption: true // Double encryption
    }

    // Art. 25 — Privacy by design: no public access
    publicNetworkAccess: 'Disabled'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Force Entra ID auth only

    // Art. 5(1)(e) — Storage limitation: lifecycle management
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    'gdpr-processing-purpose': gdprProcessingPurpose
    'gdpr-data-category': gdprDataCategory
    'gdpr-retention-days': string(gdprRetentionDays)
    'gdpr-encryption': 'CMK'
    'gdpr-public-access': 'disabled'
  }
}

// --- Lifecycle Management (Art. 5(1)(e) — Storage limitation) ---
resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'gdpr-retention-policy'
          enabled: true
          type: 'Lifecycle'
          definition: {
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: gdprRetentionDays
                }
              }
              snapshot: {
                delete: {
                  daysAfterCreationGreaterThan: gdprRetentionDays
                }
              }
            }
            filters: {
              blobTypes: [ 'blockBlob', 'appendBlob' ]
            }
          }
        }
      ]
    }
  }
}

// --- Private Endpoint (Art. 25/32 — network isolation) ---
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${storageAccountName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${storageAccountName}-plsc'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [ 'blob' ]
        }
      }
    ]
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability) ---
@description('Resource ID of the Log Analytics workspace for diagnostics')
param logAnalyticsWorkspaceId string = ''

resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${storageAccountName}-diag'
  scope: storageAccount
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    metrics: [
      {
        category: 'Transaction'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
output privateEndpointId string = privateEndpoint.id
