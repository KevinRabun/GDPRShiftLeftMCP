// GDPR-Compliant Microsoft Defender for Cloud — Threat protection, vulnerability assessment, compliance
// Addresses: Art. 32 — Security of processing, Art. 33 — Breach notification, Art. 5(2) — Accountability

@description('Enable Defender for Servers plan')
param enableServers bool = true

@description('Enable Defender for Storage plan')
param enableStorage bool = true

@description('Enable Defender for SQL plan')
param enableSql bool = true

@description('Enable Defender for Key Vault plan')
param enableKeyVault bool = true

@description('Enable Defender for Containers plan')
param enableContainers bool = true

@description('Enable Defender for App Service plan')
param enableAppService bool = true

@description('Enable Defender for ARM (Resource Manager) plan')
param enableArm bool = true

@description('Enable Defender for DNS plan')
param enableDns bool = true

@description('Enable Defender for Cosmos DB plan')
param enableCosmosDb bool = true

@description('Enable Defender for Open-Source Databases plan')
param enableOssDatabases bool = true

@description('Resource ID of the Log Analytics workspace for security data')
param logAnalyticsWorkspaceId string

@description('Email addresses for security alerts (comma-separated)')
param securityContactEmails string

@description('Phone number for critical security alerts')
param securityContactPhone string = ''

@description('DPO email for GDPR breach notifications')
param dpoEmail string = ''

// --- Defender for Cloud Pricing Tiers (Art. 32 — security of processing) ---
// Each plan provides threat detection and vulnerability assessment for its resource type.

resource defenderServers 'Microsoft.Security/pricings@2024-01-01' = if (enableServers) {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2' // Includes vulnerability assessment and JIT
  }
}

resource defenderStorage 'Microsoft.Security/pricings@2024-01-01' = if (enableStorage) {
  name: 'StorageAccounts'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'DefenderForStorageV2'
  }
}

resource defenderSql 'Microsoft.Security/pricings@2024-01-01' = if (enableSql) {
  name: 'SqlServers'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderKeyVault 'Microsoft.Security/pricings@2024-01-01' = if (enableKeyVault) {
  name: 'KeyVaults'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderContainers 'Microsoft.Security/pricings@2024-01-01' = if (enableContainers) {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderAppService 'Microsoft.Security/pricings@2024-01-01' = if (enableAppService) {
  name: 'AppServices'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderArm 'Microsoft.Security/pricings@2024-01-01' = if (enableArm) {
  name: 'Arm'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderDns 'Microsoft.Security/pricings@2024-01-01' = if (enableDns) {
  name: 'Dns'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderCosmosDb 'Microsoft.Security/pricings@2024-01-01' = if (enableCosmosDb) {
  name: 'CosmosDbs'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderOssDatabases 'Microsoft.Security/pricings@2024-01-01' = if (enableOssDatabases) {
  name: 'OpenSourceRelationalDatabases'
  properties: {
    pricingTier: 'Standard'
  }
}

// --- Security Contacts (Art. 33 — breach notification) ---
resource securityContact 'Microsoft.Security/securityContacts@2023-12-01-preview' = {
  name: 'default'
  properties: {
    emails: securityContactEmails
    phone: securityContactPhone
    notificationsByRole: {
      state: 'On'
      roles: [
        'Owner'
        'ServiceAdmin'
      ]
    }
    alertNotifications: {
      state: 'On'
      minimalSeverity: 'Medium' // Art. 33 — alert on medium+ severity
    }
  }
}

// --- Auto Provisioning (Art. 32 — automated security coverage) ---
resource autoProvisioningLA 'Microsoft.Security/autoProvisioningSettings@2017-08-01-preview' = {
  name: 'default'
  properties: {
    autoProvision: 'On'
  }
}

// --- Workspace Configuration ---
resource workspaceConfig 'Microsoft.Security/workspaceSettings@2017-08-01-preview' = {
  name: 'default'
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    scope: subscription().id
  }
}

// --- Regulatory Compliance: Enable GDPR Assessment ---
// NOTE: Regulatory compliance assessments are managed via Azure Security Benchmark.
// Ensure the "GDPR" regulatory compliance standard is enabled in Defender for Cloud.
// This provides continuous assessment against GDPR requirements mapped to Azure controls.

// GDPR Defender for Cloud Best Practices:
// 1. Enable all relevant Defender plans — each covers specific Art. 32 threat vectors
// 2. Configure security contacts to include the DPO for Art. 33 breach notification
// 3. Enable auto-provisioning to ensure new resources are immediately monitored
// 4. Review Secure Score weekly — aim for 80%+ for GDPR compliance posture
// 5. Enable GDPR regulatory compliance dashboard for continuous Art. 5(2) accountability
// 6. Configure workflow automation to create incidents from high-severity alerts
// 7. Use JIT VM access to enforce Just-in-Time access (Art. 25 — least privilege)
// 8. Enable adaptive application controls for workload hardening
// 9. Configure file integrity monitoring for sensitive data stores
// 10. Integrate with Sentinel for GDPR-focused threat hunting
