// GDPR-Compliant Azure PostgreSQL Flexible Server — Encrypted, isolated, audited database
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 5(1)(e) — Storage limitation

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the PostgreSQL Flexible Server')
param serverName string

@description('Administrator login name')
param administratorLogin string

@description('Administrator password')
@secure()
param administratorPassword string

@description('PostgreSQL version')
@allowed([
  '16'
  '15'
  '14'
])
param postgresVersion string = '16'

@description('SKU tier')
@allowed([
  'Burstable'
  'GeneralPurpose'
  'MemoryOptimized'
])
param skuTier string = 'GeneralPurpose'

@description('SKU name')
param skuName string = 'Standard_D2ds_v5'

@description('Storage size in GB')
param storageSizeGB int = 128

@description('Resource ID of the delegated subnet for VNet integration')
param delegatedSubnetId string = ''

@description('Resource ID of the private DNS zone')
param privateDnsZoneId string = ''

@description('Resource ID of the Log Analytics workspace for diagnostics')
param logAnalyticsWorkspaceId string = ''

@description('Backup retention period in days')
@minValue(7)
@maxValue(35)
param backupRetentionDays int = 35

@description('Enable geo-redundant backups')
param geoRedundantBackup bool = true

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = ''

@description('GDPR data category tag')
param gdprDataCategory string = ''

// --- PostgreSQL Flexible Server (Art. 32 — Security of processing) ---
resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: serverName
  location: location
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    version: postgresVersion
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorPassword

    // Art. 32 — Encryption at rest (service-managed by default)
    storage: {
      storageSizeGB: storageSizeGB
    }

    // Art. 32 — Backup and disaster recovery
    backup: {
      backupRetentionDays: backupRetentionDays
      geoRedundantBackup: geoRedundantBackup ? 'Enabled' : 'Disabled'
    }

    // Art. 25, Art. 32 — Network isolation
    network: !empty(delegatedSubnetId) ? {
      delegatedSubnetResourceId: delegatedSubnetId
      privateDnsZoneArmResourceId: privateDnsZoneId
      publicNetworkAccess: 'Disabled'
    } : {
      publicNetworkAccess: 'Disabled'
    }

    // Art. 25 — High availability for data integrity
    highAvailability: {
      mode: 'ZoneRedundant'
    }

    // Art. 5(1)(f) — Entra ID authentication
    authConfig: {
      activeDirectoryAuth: 'Enabled' // Entra ID authentication
      passwordAuth: 'Enabled' // Disable after Entra ID is fully configured
    }
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-25-Art-32'
    'gdpr-data-category': gdprDataCategory
    'gdpr-data-residency': 'EU'
  }
}

// --- Server Configuration: SSL enforcement (Art. 32 — Encryption in transit) ---
resource sslConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'require_secure_transport'
  properties: {
    value: 'on'
    source: 'user-override'
  }
}

// --- Server Configuration: TLS version (Art. 32) ---
resource tlsConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'ssl_min_protocol_version'
  properties: {
    value: 'TLSv1.2'
    source: 'user-override'
  }
}

// --- Server Configuration: Logging for accountability (Art. 5(2)) ---
resource logConnectionsConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'log_connections'
  properties: {
    value: 'on'
    source: 'user-override'
  }
}

resource logDisconnectionsConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'log_disconnections'
  properties: {
    value: 'on'
    source: 'user-override'
  }
}

resource logCheckpointsConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'log_checkpoints'
  properties: {
    value: 'on'
    source: 'user-override'
  }
}

// --- Server Configuration: Audit extension for GDPR (Art. 30) ---
resource pgAuditConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'pgaudit.log'
  properties: {
    value: 'write, ddl, role'
    source: 'user-override'
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability) ---
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${serverName}-diag'
  scope: postgresServer
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
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

output serverId string = postgresServer.id
output serverName string = postgresServer.name
output serverFqdn string = postgresServer.properties.fullyQualifiedDomainName
