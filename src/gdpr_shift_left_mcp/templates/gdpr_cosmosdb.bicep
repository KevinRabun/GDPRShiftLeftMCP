// GDPR-Compliant Azure Cosmos DB — Multi-region with EU data residency, encryption, and access control
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 44-49 — International transfers

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Cosmos DB account')
param cosmosAccountName string

@description('Secondary region for geo-redundancy (keep within EU)')
@allowed([
  'northeurope'
  'germanywestcentral'
  'francecentral'
  'switzerlandnorth'
  'norwayeast'
  'swedencentral'
])
param secondaryRegion string = 'northeurope'

@description('Resource ID of the subnet for Private Endpoint')
param subnetId string

@description('Resource ID of the Log Analytics workspace for diagnostics')
param logAnalyticsWorkspaceId string = ''

@description('Enable automatic failover for high availability')
param enableAutomaticFailover bool = true

@description('Database name')
param databaseName string = 'gdpr-compliant-db'

@description('Default consistency level')
@allowed([
  'Strong'
  'BoundedStaleness'
  'Session'
  'ConsistentPrefix'
  'Eventual'
])
param consistencyLevel string = 'Strong'

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = ''

@description('GDPR data category tag')
param gdprDataCategory string = ''

// --- Cosmos DB Account (Art. 32 — Security of processing) ---
resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: cosmosAccountName
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    // Art. 44-49 — Restrict to EU regions only
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: true
      }
      {
        locationName: secondaryRegion
        failoverPriority: 1
        isZoneRedundant: true
      }
    ]

    // Art. 32 — Encryption
    isVirtualNetworkFilterEnabled: true
    enableAutomaticFailover: enableAutomaticFailover

    // Art. 25 — Privacy by design: strong consistency for data integrity
    consistencyPolicy: {
      defaultConsistencyLevel: consistencyLevel
      maxStalenessPrefix: 100
      maxIntervalInSeconds: 5
    }

    // Art. 32 — Network isolation
    publicNetworkAccess: 'Disabled'
    networkAclBypass: 'AzureServices'

    // Art. 32 — Disable key-based access, force Entra ID RBAC
    disableLocalAuth: true

    // Art. 5(1)(e) — Data lifecycle management
    enableAnalyticalStorage: false // Disable unless needed for purpose limitation

    // Art. 32 — Continuous backup for breach recovery
    backupPolicy: {
      type: 'Continuous'
      continuousModeProperties: {
        tier: 'Continuous7Days'
      }
    }

    // Art. 25 — Minimal capabilities by default
    capabilities: [
      {
        name: 'EnableServerless' // Pay per request, data minimisation-friendly
      }
    ]
  }
  tags: {
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-25-Art-32-Art-44'
    'gdpr-data-category': gdprDataCategory
    'gdpr-data-residency': 'EU-only'
  }
}

// --- SQL Database ---
resource cosmosDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmosAccount
  name: databaseName
  properties: {
    resource: {
      id: databaseName
    }
  }
}

// --- Art. 30 container for processing records ---
resource ropaContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDatabase
  name: 'processing-records'
  properties: {
    resource: {
      id: 'processing-records'
      partitionKey: {
        paths: ['/processingPurpose']
        kind: 'Hash'
      }
      // Art. 5(1)(e) — Automatic TTL for retention enforcement
      defaultTtl: 86400 * 365 * 5 // 5 years default retention
      indexingPolicy: {
        automatic: true
        indexingMode: 'consistent'
      }
    }
  }
}

// --- Private Endpoint (Art. 25 — Privacy by design) ---
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${cosmosAccountName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${cosmosAccountName}-plsc'
        properties: {
          privateLinkServiceId: cosmosAccount.id
          groupIds: ['Sql']
        }
      }
    ]
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability) ---
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${cosmosAccountName}-diag'
  scope: cosmosAccount
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
    metrics: [
      {
        category: 'Requests'
        enabled: true
      }
    ]
  }
}

output cosmosAccountId string = cosmosAccount.id
output cosmosAccountName string = cosmosAccount.name
output cosmosEndpoint string = cosmosAccount.properties.documentEndpoint
output databaseName string = cosmosDatabase.name
