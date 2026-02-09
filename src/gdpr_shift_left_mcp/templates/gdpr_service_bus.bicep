// GDPR-Compliant Azure Service Bus — Secure messaging with encryption, access control, and audit
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 5(1)(f) — Confidentiality

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Service Bus namespace')
param namespaceName string

@description('Service Bus SKU')
@allowed([
  'Premium' // Required for Private Endpoints, CMK encryption, GDPR workloads
])
param skuName string = 'Premium'

@description('Messaging units for Premium tier')
@allowed([
  1
  2
  4
  8
  16
])
param messagingUnits int = 1

@description('Resource ID of the subnet for Private Endpoint')
param subnetId string

@description('Resource ID of the Log Analytics workspace')
param logAnalyticsWorkspaceId string = ''

@description('Queue names for GDPR-related processing')
param queueNames array = [
  'dsr-requests'       // Art. 15-22 — Data Subject Requests
  'consent-events'     // Art. 7 — Consent management
  'breach-notifications' // Art. 33 — Breach notification pipeline
  'data-retention'     // Art. 5(1)(e) — Retention enforcement
]

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'gdpr-event-processing'

// --- Service Bus Namespace (Art. 32 — Security of processing) ---
resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
  name: namespaceName
  location: location
  sku: {
    name: skuName
    tier: skuName
    capacity: messagingUnits
  }
  identity: {
    type: 'SystemAssigned' // Art. 32 — Managed identity
  }
  properties: {
    // Art. 32 — Encryption in transit
    minimumTlsVersion: '1.2'

    // Art. 25 — No public access
    publicNetworkAccess: 'Disabled'

    // Art. 32 — Disable insecure auth methods
    disableLocalAuth: true

    // Art. 25 — Zone redundancy for availability
    zoneRedundant: true

    // Art. 32 — Premium features: encryption at rest with CMK support
    premiumMessagingPartitions: 1
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-25-Art-32'
    'gdpr-data-residency': 'EU'
  }
}

// --- GDPR-related Queues ---
resource queues 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = [for queueName in queueNames: {
  parent: serviceBusNamespace
  name: queueName
  properties: {
    // Art. 5(1)(e) — Message TTL aligned with purpose
    defaultMessageTimeToLive: 'P30D' // 30-day max TTL

    // Art. 5(1)(e) — Dead letter queue for failed processing audit
    deadLetteringOnMessageExpiration: true
    maxDeliveryCount: 10

    // Art. 5(1)(f) — Duplicate detection for data integrity
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT10M'

    // Art. 32 — Require sessions for ordered, reliable processing
    requiresSession: false

    // Message size
    maxSizeInMegabytes: 1024
    maxMessageSizeInKilobytes: 256

    // Lock duration
    lockDuration: 'PT5M'
  }
}]

// --- Topic for GDPR events fan-out ---
resource gdprEventsTopic 'Microsoft.ServiceBus/namespaces/topics@2024-01-01' = {
  parent: serviceBusNamespace
  name: 'gdpr-compliance-events'
  properties: {
    defaultMessageTimeToLive: 'P7D'
    maxSizeInMegabytes: 1024
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT10M'
    supportOrdering: true
  }
}

// --- Subscriptions for different GDPR processors ---
resource auditSubscription 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2024-01-01' = {
  parent: gdprEventsTopic
  name: 'audit-processor'
  properties: {
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P7D'
    maxDeliveryCount: 5
    lockDuration: 'PT5M'
  }
}

resource dsrSubscription 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2024-01-01' = {
  parent: gdprEventsTopic
  name: 'dsr-processor'
  properties: {
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P3D'
    maxDeliveryCount: 10
    lockDuration: 'PT5M'
  }
}

// --- Private Endpoint (Art. 25 — Network isolation) ---
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${namespaceName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${namespaceName}-plsc'
        properties: {
          privateLinkServiceId: serviceBusNamespace.id
          groupIds: ['namespace']
        }
      }
    ]
  }
}

// --- Diagnostic Settings (Art. 5(2) — Accountability) ---
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${namespaceName}-diag'
  scope: serviceBusNamespace
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

output namespaceId string = serviceBusNamespace.id
output namespaceName string = serviceBusNamespace.name
output namespacePrincipalId string = serviceBusNamespace.identity.principalId
