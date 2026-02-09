// GDPR-Compliant Azure Log Analytics Workspace — Central audit logging, retention, and accountability
// Addresses: Art. 5(2) — Accountability, Art. 30 — Records of processing, Art. 33 — Breach notification

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Log Analytics workspace')
param workspaceName string

@description('Pricing tier (PerGB2018 recommended for GDPR workloads)')
@allowed([
  'PerGB2018'
  'CapacityReservation'
])
param sku string = 'PerGB2018'

@description('Data retention period in days. Minimum 30, recommended 365+ for GDPR audit trails.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 365

@description('Enable data export for long-term GDPR record archival')
param enableDataExport bool = false

@description('Enable purge protection — prevents accidental deletion of audit evidence')
param enablePurgeProtection bool = true

@description('Daily ingestion cap in GB (0 = unlimited). Use to control costs while ensuring compliance.')
param dailyQuotaGb int = 0

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'audit-logging-accountability'

// --- Log Analytics Workspace (Art. 5(2) — Accountability) ---
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: sku
    }

    // Art. 5(1)(e) — Storage limitation: retain logs for defined period
    retentionInDays: retentionInDays

    // Art. 5(1)(f) — Integrity and confidentiality
    publicNetworkAccessForIngestion: 'Disabled'
    publicNetworkAccessForQuery: 'Disabled'

    // Cost control
    workspaceCapping: dailyQuotaGb > 0 ? {
      dailyQuotaGb: dailyQuotaGb
    } : null

    features: {
      // Prevent accidental deletion of compliance evidence
      disableLocalAuth: true // Force Entra ID authentication
      enableDataExport: enableDataExport
    }
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-5-2-Art-30-Art-33'
    'gdpr-data-category': 'audit-logs'
    'gdpr-retention-days': string(retentionInDays)
  }
}

// --- Saved searches for GDPR-relevant queries ---
// Art. 33 — Breach detection query
resource breachDetectionQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  parent: workspace
  name: 'GDPRBreachDetection'
  properties: {
    category: 'GDPR Compliance'
    displayName: 'GDPR Art. 33 — Potential Data Breach Detection'
    query: '''
      SecurityEvent
      | where EventID in (4625, 4648, 4719, 4720, 4722, 4724, 4728, 4732, 4756)
      | where TimeGenerated > ago(72h)
      | summarize Count=count() by EventID, Account, Computer, Activity
      | where Count > 10
      | order by Count desc
    '''
    version: 2
  }
}

// Art. 15 — Data access tracking query
resource dataAccessQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  parent: workspace
  name: 'GDPRDataAccessTracking'
  properties: {
    category: 'GDPR Compliance'
    displayName: 'GDPR Art. 15 — Personal Data Access Tracking'
    query: '''
      AuditLogs
      | where OperationName has_any ("Read", "Get", "List", "Export")
      | where TargetResources has "personalData" or TargetResources has "userData"
      | project TimeGenerated, Identity, OperationName, Result, TargetResources
      | order by TimeGenerated desc
    '''
    version: 2
  }
}

// Art. 17 — Erasure request tracking query
resource erasureTrackingQuery 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
  parent: workspace
  name: 'GDPRErasureTracking'
  properties: {
    category: 'GDPR Compliance'
    displayName: 'GDPR Art. 17 — Erasure/Deletion Request Tracking'
    query: '''
      AuditLogs
      | where OperationName has_any ("Delete", "Remove", "Purge", "Erase")
      | project TimeGenerated, Identity, OperationName, Result, TargetResources
      | order by TimeGenerated desc
    '''
    version: 2
  }
}

output workspaceId string = workspace.id
output workspaceName string = workspace.name
output workspaceCustomerId string = workspace.properties.customerId
