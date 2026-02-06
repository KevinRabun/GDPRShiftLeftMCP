// GDPR-Compliant Azure Kubernetes Service — Private cluster, Azure CNI, Defender, audit logging
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 5(1)(f) — Integrity & confidentiality

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the AKS cluster')
param clusterName string

@description('Kubernetes version')
param kubernetesVersion string = '1.30'

@description('VM size for the default node pool')
param nodeVmSize string = 'Standard_DS3_v2'

@description('Number of nodes in the default node pool')
@minValue(1)
@maxValue(100)
param nodeCount int = 3

@description('Resource ID of the subnet for AKS nodes')
param subnetId string

@description('Resource ID of the Log Analytics workspace')
param logAnalyticsWorkspaceId string

@description('Enable Azure AD (Entra ID) integration for RBAC')
param enableAadAuth bool = true

@description('Azure AD admin group object IDs')
param aadAdminGroupObjectIds array = []

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'container-workloads'

// --- AKS Cluster (Art. 32 — security of processing) ---
resource aks 'Microsoft.ContainerService/managedClusters@2024-02-01' = {
  name: clusterName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: '${clusterName}-dns'
    enableRBAC: true // Art. 25 — access control by design

    // Art. 32(1)(b) — ensure ongoing confidentiality
    apiServerAccessProfile: {
      enablePrivateCluster: true // No public API endpoint
      enablePrivateClusterPublicFQDN: false
    }

    // Default node pool — private nodes only
    agentPoolProfiles: [
      {
        name: 'system'
        count: nodeCount
        vmSize: nodeVmSize
        osType: 'Linux'
        mode: 'System'
        vnetSubnetID: subnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: nodeCount * 2
        enableEncryptionAtHost: true // Art. 32(1)(a) — encryption at rest
        enableFIPS: true // FIPS 140-2 for GDPR-grade security
        osDiskType: 'Ephemeral'
        osDiskSizeGB: 128
      }
    ]

    // Art. 25 — Network isolation by design
    networkProfile: {
      networkPlugin: 'azure' // Azure CNI for network policy support
      networkPolicy: 'azure' // Enforce pod-level network policies
      outboundType: 'userDefinedRouting'
      serviceCidr: '172.16.0.0/16'
      dnsServiceIP: '172.16.0.10'
    }

    // Entra ID integration (Art. 32 — authentication security)
    aadProfile: enableAadAuth ? {
      managed: true
      enableAzureRBAC: true
      adminGroupObjectIDs: aadAdminGroupObjectIds
    } : null

    // Azure Defender for Containers (Art. 32 — threat protection)
    securityProfile: {
      defender: {
        securityMonitoring: {
          enabled: true
        }
        logAnalyticsWorkspaceResourceId: logAnalyticsWorkspaceId
      }
      workloadIdentity: {
        enabled: true // Managed identity for pods — no secrets
      }
      imageCleaner: {
        enabled: true // Remove untagged images — data minimisation
        intervalHours: 24
      }
    }

    // Monitoring (Art. 5(2) — accountability)
    addonProfiles: {
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspaceId
        }
      }
      azurepolicy: {
        enabled: true // Enforce GDPR policies via Azure Policy
      }
      azureKeyvaultSecretsProvider: {
        enabled: true // Secrets from Key Vault — no PII in config
        config: {
          enableSecretRotation: 'true'
          rotationPollInterval: '2m'
        }
      }
    }

    // Auto-upgrade for security patches (Art. 32 — ongoing security)
    autoUpgradeProfile: {
      upgradeChannel: 'stable'
    }
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    gdpr_articles: 'Art.25,Art.32,Art.5(1)(f)'
    data_classification: 'confidential'
  }
}

// --- Diagnostic Settings (Art. 5(2) — accountability, Art. 30 — records) ---
resource aksDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${clusterName}-diag'
  scope: aks
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

output aksId string = aks.id
output aksName string = aks.name
output aksFqdn string = aks.properties.privateFQDN
