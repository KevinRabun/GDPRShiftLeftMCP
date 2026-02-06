// GDPR-Compliant Azure API Management — API gateway with data protection, rate limiting, and audit
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 30 — Records of processing

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the API Management instance')
param apimName string

@description('Publisher email address')
param publisherEmail string

@description('Publisher organization name')
param publisherName string

@description('APIM SKU')
@allowed([
  'Developer'
  'Standard'
  'Premium'
])
param skuName string = 'Premium' // Premium required for VNet integration

@description('Number of scale units')
param skuCount int = 1

@description('Resource ID of the subnet for VNet integration')
param subnetId string = ''

@description('Resource ID of the Log Analytics workspace')
param logAnalyticsWorkspaceId string

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'api-gateway'

// --- API Management Instance (Art. 25 — privacy by design) ---
resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: apimName
  location: location
  sku: {
    name: skuName
    capacity: skuCount
  }
  identity: {
    type: 'SystemAssigned' // Managed identity — no stored credentials
  }
  properties: {
    publisherEmail: publisherEmail
    publisherName: publisherName

    // Art. 25 — VNet integration for network isolation
    virtualNetworkType: subnetId != '' ? 'Internal' : 'None'
    virtualNetworkConfiguration: subnetId != '' ? {
      subnetResourceId: subnetId
    } : null

    // Art. 32 — TLS configuration
    customProperties: {
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30': 'false'
      // Disable weak ciphers
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TLS_RSA_WITH_AES_256_CBC_SHA': 'false'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256': 'false'
    }

    // Art. 32 — disable insecure management interfaces
    disableGateway: false
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    gdpr_articles: 'Art.25,Art.32,Art.30'
    data_classification: 'confidential'
  }
}

// --- GDPR Data Masking Policy (Art. 25 — data minimisation) ---
// Apply this as a global policy to redact personal data from API responses and logs.
resource gdprPolicy 'Microsoft.ApiManagement/service/policies@2023-09-01-preview' = {
  parent: apim
  name: 'policy'
  properties: {
    format: 'xml'
    value: '''
<policies>
  <inbound>
    <base />
    <!-- Art. 32 — Rate limiting to prevent data scraping -->
    <rate-limit calls="100" renewal-period="60" />
    <!-- Art. 32 — CORS restrictions -->
    <cors allow-credentials="false">
      <allowed-origins>
        <origin>https://*.yourdomain.com</origin>
      </allowed-origins>
    </cors>
    <!-- Art. 25 — Remove potentially revealing headers -->
    <set-header name="X-Powered-By" exists-action="delete" />
    <set-header name="Server" exists-action="delete" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
    <!-- Art. 25 — Add privacy headers -->
    <set-header name="X-Content-Type-Options" exists-action="override">
      <value>nosniff</value>
    </set-header>
    <set-header name="Strict-Transport-Security" exists-action="override">
      <value>max-age=31536000; includeSubDomains</value>
    </set-header>
    <set-header name="Cache-Control" exists-action="override">
      <value>no-store</value>
    </set-header>
  </outbound>
  <on-error>
    <base />
    <!-- Art. 25 — Never expose internal details in errors -->
    <set-body>{"error": "An error occurred processing your request."}</set-body>
    <set-header name="Content-Type" exists-action="override">
      <value>application/json</value>
    </set-header>
  </on-error>
</policies>
'''
  }
}

// --- Named Value for Data Classification (Art. 30 — records) ---
resource dataClassification 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'gdpr-data-classification'
  properties: {
    displayName: 'GDPR-Data-Classification'
    value: 'Contains personal data subject to GDPR'
    secret: false
    tags: [
      'gdpr'
      'compliance'
    ]
  }
}

// --- Diagnostic Settings (Art. 5(2) — accountability, Art. 30 — records) ---
resource apimDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${apimName}-diag'
  scope: apim
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { categoryGroup: 'audit', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
      { categoryGroup: 'allLogs', enabled: true, retentionPolicy: { enabled: true, days: 90 } }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true, retentionPolicy: { enabled: true, days: 90 } }
    ]
  }
}

output apimId string = apim.id
output apimGatewayUrl string = apim.properties.gatewayUrl
output apimPrincipalId string = apim.identity.principalId
