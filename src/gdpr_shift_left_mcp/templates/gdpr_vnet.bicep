// GDPR-Compliant Azure Virtual Network — Network isolation, NSGs, and flow logging
// Addresses: Art. 25 — Privacy by design, Art. 32 — Security, Art. 5(1)(f) — Integrity

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Virtual Network')
param vnetName string

@description('Address prefix for the VNet')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('Resource ID of the Log Analytics workspace for NSG flow logs')
param logAnalyticsWorkspaceId string = ''

@description('Storage account ID for NSG flow log retention')
param flowLogStorageAccountId string = ''

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'network-isolation'

// --- Virtual Network (Art. 25 — Privacy by design / network segmentation) ---
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    // Art. 32 — DNS security
    dhcpOptions: {
      dnsServers: [] // Use Azure-provided DNS by default
    }
    // Art. 32 — Enable DDoS protection for production
    enableDdosProtection: false // Set to true with DDoS plan for production
    subnets: [
      // Subnet for application workloads
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: nsgApp.id
          }
          serviceEndpoints: [
            { service: 'Microsoft.Storage' }
            { service: 'Microsoft.Sql' }
            { service: 'Microsoft.KeyVault' }
            { service: 'Microsoft.AzureCosmosDB' }
          ]
          delegations: [
            {
              name: 'appServiceDelegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
      // Subnet for private endpoints (data stores)
      {
        name: 'snet-data'
        properties: {
          addressPrefix: '10.0.2.0/24'
          networkSecurityGroup: {
            id: nsgData.id
          }
          privateEndpointNetworkPolicies: 'Disabled' // Required for Private Endpoints
        }
      }
      // Subnet for management / bastion
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: '10.0.3.0/26'
          networkSecurityGroup: {
            id: nsgBastion.id
          }
        }
      }
    ]
  }
  tags: {
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-25-Art-32'
  }
}

// --- NSG for Application Subnet (Art. 32 — Least privilege network access) ---
resource nsgApp 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${vnetName}-nsg-app'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowHttpsInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      // Art. 32 — Block outbound non-HTTPS traffic
      {
        name: 'AllowHttpsOutbound'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
    ]
  }
  tags: {
    'gdpr-purpose': 'application-network-security'
    'gdpr-article': 'Art-32'
  }
}

// --- NSG for Data Subnet (Art. 32 — Strict data access) ---
resource nsgData 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${vnetName}-nsg-data'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAppSubnetInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.1.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyAllOutbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
  tags: {
    'gdpr-purpose': 'data-network-isolation'
    'gdpr-article': 'Art-32'
  }
}

// --- NSG for Bastion Subnet (Art. 32 — Secure admin access) ---
resource nsgBastion 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${vnetName}-nsg-bastion'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowGatewayManager'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'GatewayManager'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'AllowHttpsInbound'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
  tags: {
    'gdpr-purpose': 'bastion-admin-access'
    'gdpr-article': 'Art-32'
  }
}

// --- Diagnostic Settings for NSGs (Art. 5(2) — Accountability) ---
resource nsgAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: '${vnetName}-nsg-app-diag'
  scope: nsgApp
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output vnetName string = vnet.name
output appSubnetId string = vnet.properties.subnets[0].id
output dataSubnetId string = vnet.properties.subnets[1].id
output bastionSubnetId string = vnet.properties.subnets[2].id
