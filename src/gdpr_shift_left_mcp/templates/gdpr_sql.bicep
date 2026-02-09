// GDPR-Compliant Azure SQL Database — TDE with CMK, Entra-only auth, Private Endpoint, auditing
// Addresses: Art. 5(1)(f), Art. 25, Art. 32, Art. 5(2)

@description('Azure region — use EU regions for GDPR data residency')
param location string = 'westeurope'

@description('SQL Server name')
param sqlServerName string

@description('SQL Database name')
param sqlDatabaseName string

@description('Azure AD admin object ID for Entra-only auth')
param azureAdAdminObjectId string

@description('Azure AD admin display name')
param azureAdAdminName string

@description('Subnet ID for Private Endpoint')
param subnetId string

@description('Log Analytics workspace ID for auditing')
param logAnalyticsWorkspaceId string = ''

@description('GDPR retention period in days')
param gdprRetentionDays int = 365

// --- SQL Server (Entra-only authentication — Art. 32) ---
resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    // Entra-only auth — no SQL passwords (Art. 32, Art. 25)
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true
      login: azureAdAdminName
      sid: azureAdAdminObjectId
      tenantId: subscription().tenantId
    }
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: 'personal-data-storage'
    'gdpr-encryption': 'TDE-CMK'
    'gdpr-auth': 'EntraID-only'
    'gdpr-public-access': 'disabled'
  }
}

// --- SQL Database (Art. 32 — encryption, Art. 5(1)(e) — retention) ---
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  sku: {
    name: 'GP_S_Gen5_2' // General Purpose Serverless
    tier: 'GeneralPurpose'
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
    maxSizeBytes: 34359738368 // 32 GB
    zoneRedundant: true // High availability within EU region
  }
  tags: {
    'gdpr-retention-days': string(gdprRetentionDays)
    'gdpr-data-residency': location
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability, send to Log Analytics) ---
resource sqlDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${sqlServerName}-diag'
  scope: sqlDatabase
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'SQLSecurityAuditEvents'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: gdprRetentionDays
        }
      }
    ]
  }
}

// --- Auditing (Art. 5(2) — Accountability) ---
resource sqlAuditing 'Microsoft.Sql/servers/auditingSettings@2023-08-01-preview' = {
  parent: sqlServer
  name: 'default'
  properties: {
    state: 'Enabled'
    isAzureMonitorTargetEnabled: true
    retentionDays: 90
    auditActionsAndGroups: [
      'SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP'
      'FAILED_DATABASE_AUTHENTICATION_GROUP'
      'BATCH_COMPLETED_GROUP'
      'DATABASE_OBJECT_ACCESS_GROUP'
      'DATABASE_PERMISSION_CHANGE_GROUP'
      'DATABASE_PRINCIPAL_CHANGE_GROUP'
      'SCHEMA_OBJECT_ACCESS_GROUP'
    ]
  }
}

// --- Advanced Threat Protection (Art. 32) ---
resource threatProtection 'Microsoft.Sql/servers/securityAlertPolicies@2023-08-01-preview' = {
  parent: sqlServer
  name: 'default'
  properties: {
    state: 'Enabled'
    emailAccountAdmins: true
  }
}

// --- Private Endpoint (Art. 25/32 — network isolation) ---
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${sqlServerName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${sqlServerName}-plsc'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: [ 'sqlServer' ]
        }
      }
    ]
  }
}

output sqlServerId string = sqlServer.id
output sqlServerName string = sqlServer.name
output sqlDatabaseId string = sqlDatabase.id
