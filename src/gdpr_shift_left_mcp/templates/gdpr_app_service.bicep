// GDPR-Compliant Azure App Service — Web application hosting with privacy by design
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 5(2) — Accountability

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the App Service')
param appName string

@description('Name of the App Service Plan')
param appServicePlanName string

@description('App Service Plan SKU (P1v3+ recommended for production GDPR workloads)')
@allowed([
  'P1v3'
  'P2v3'
  'P3v3'
  'S1'
])
param skuName string = 'P1v3'

@description('Resource ID of the subnet for VNet integration')
param vnetSubnetId string

@description('Resource ID of the subnet for Private Endpoint')
param privateEndpointSubnetId string

@description('Resource ID of the Log Analytics workspace for diagnostics')
param logAnalyticsWorkspaceId string = ''

@description('Resource ID of the Key Vault for application secrets')
param keyVaultId string = ''

@description('Application runtime stack')
@allowed([
  'PYTHON|3.12'
  'DOTNETCORE|8.0'
  'NODE|20-lts'
  'JAVA|17-java17'
])
param linuxFxVersion string = 'PYTHON|3.12'

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = ''

@description('GDPR data category tag')
param gdprDataCategory string = ''

// --- App Service Plan ---
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  kind: 'linux'
  sku: {
    name: skuName
  }
  properties: {
    reserved: true // Linux
  }
  tags: {
    'gdpr-purpose': gdprProcessingPurpose
  }
}

// --- App Service (Art. 25 — Privacy by design, Art. 32 — Security) ---
resource appService 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned' // Art. 32 — Managed identity, no stored credentials
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true // Art. 32 — Encryption in transit

    virtualNetworkSubnetId: vnetSubnetId

    siteConfig: {
      linuxFxVersion: linuxFxVersion

      // Art. 32 — TLS 1.2 minimum
      minTlsVersion: '1.2'
      ftpsState: 'Disabled' // No FTP (insecure)

      // Art. 25 — Disable unnecessary features
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      http20Enabled: true

      // Art. 32 — Security headers
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: false // No PII in error pages

      // Art. 5(1)(f) — IP restrictions (deny all, allow via Private Endpoint)
      ipSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictionsUseMain: true

      // GDPR-relevant app settings
      appSettings: [
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1' // Immutable deployment for integrity
        }
        {
          name: 'GDPR_COMPLIANCE_MODE'
          value: 'strict'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: '' // To be configured post-deployment
        }
      ]
    }
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-25-Art-32'
    'gdpr-data-category': gdprDataCategory
  }
}

// --- Staging slot for safe deployments (Art. 25 — tested before processing) ---
resource stagingSlot 'Microsoft.Web/sites/slots@2023-12-01' = {
  parent: appService
  name: 'staging'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
    }
  }
}

// --- Private Endpoint (Art. 25 — Network isolation) ---
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${appName}-pe'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${appName}-plsc'
        properties: {
          privateLinkServiceId: appService.id
          groupIds: ['sites']
        }
      }
    ]
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability, Art. 33 — Breach detection) ---
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${appName}-diag'
  scope: appService
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'AppServiceAuditLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'AppServicePlatformLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
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

output appServiceId string = appService.id
output appServiceHostName string = appService.properties.defaultHostName
output appServicePrincipalId string = appService.identity.principalId
output stagingSlotHostName string = stagingSlot.properties.defaultHostName
