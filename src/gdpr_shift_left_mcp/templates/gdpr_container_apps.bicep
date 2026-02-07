// GDPR-Compliant Azure Container Apps — Containerised workload processing with privacy controls
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 5(1)(f) — Confidentiality

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Container Apps Environment')
param environmentName string

@description('Name of the Container App')
param containerAppName string

@description('Container image to deploy')
param containerImage string

@description('Resource ID of the Log Analytics workspace')
param logAnalyticsWorkspaceId string

@description('Log Analytics workspace shared key')
@secure()
param logAnalyticsSharedKey string

@description('Resource ID of the subnet for VNet integration')
param infrastructureSubnetId string = ''

@description('Minimum number of replicas')
param minReplicas int = 1

@description('Maximum number of replicas')
param maxReplicas int = 3

@description('CPU allocation in cores')
param cpuCores string = '0.5'

@description('Memory allocation')
param memory string = '1Gi'

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = ''

@description('GDPR data category tag')
param gdprDataCategory string = ''

// --- Container Apps Environment (Art. 25 — Isolated execution environment) ---
resource containerAppEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  properties: {
    // Art. 5(2) — Accountability: centralised logging
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: reference(logAnalyticsWorkspaceId, '2023-09-01').customerId
        sharedKey: logAnalyticsSharedKey
      }
    }

    // Art. 32 — Network isolation via VNet
    vnetConfiguration: !empty(infrastructureSubnetId) ? {
      infrastructureSubnetId: infrastructureSubnetId
      internal: true // No public ingress
    } : null

    // Art. 25 — Zone redundancy for availability
    zoneRedundant: true

    // Workload profiles for resource isolation
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
  tags: {
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-25-Art-32'
  }
}

// --- Container App (Art. 32 — Security of processing) ---
resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: containerAppName
  location: location
  identity: {
    type: 'SystemAssigned' // Art. 32 — Managed identity, no stored credentials
  }
  properties: {
    managedEnvironmentId: containerAppEnvironment.id

    configuration: {
      // Art. 32 — Ingress configuration
      ingress: {
        external: false // Internal only (Art. 25 — minimise exposure)
        targetPort: 8080
        transport: 'http2'
        // Art. 32 — Mutual TLS between containers
        clientCertificateMode: 'require'
        corsPolicy: {
          allowedOrigins: [] // No CORS by default
        }
      }

      // Art. 32 — Secret management via Key Vault references
      secrets: []

      // Art. 25 — Controlled scaling
      maxInactiveRevisions: 3
    }

    template: {
      containers: [
        {
          name: containerAppName
          image: containerImage
          resources: {
            cpu: json(cpuCores)
            memory: memory
          }
          // Art. 32 — Health probes for reliability
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/ready'
                port: 8080
              }
              periodSeconds: 10
            }
          ]
          env: [
            {
              name: 'GDPR_COMPLIANCE_MODE'
              value: 'strict'
            }
            {
              name: 'ASPNETCORE_ENVIRONMENT'
              value: 'Production'
            }
          ]
        }
      ]

      // Art. 25 — Scaling rules
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
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

output containerAppId string = containerApp.id
output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppPrincipalId string = containerApp.identity.principalId
output environmentId string = containerAppEnvironment.id
