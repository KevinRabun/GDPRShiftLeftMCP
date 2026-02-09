// GDPR-Compliant Azure Confidential VM — SEV-SNP encrypted memory, vTPM, secure boot
// Addresses: Art. 32(1)(a) — Encryption, Art. 25 — Privacy by design, Art. 5(1)(f) — Confidentiality

@description('The Azure region for deployment. Use EU regions for GDPR data residency.')
param location string = 'westeurope'

@description('Name of the Virtual Machine')
param vmName string

@description('VM size — must be DCasv5/ECasv5 series for confidential computing')
@allowed([
  'Standard_DC2as_v5'
  'Standard_DC4as_v5'
  'Standard_DC8as_v5'
  'Standard_DC16as_v5'
  'Standard_EC2as_v5'
  'Standard_EC4as_v5'
  'Standard_EC8as_v5'
  'Standard_EC16as_v5'
])
param vmSize string = 'Standard_DC4as_v5'

@description('Admin username')
param adminUsername string

@description('SSH public key for authentication (password auth disabled for Art. 32)')
@secure()
param sshPublicKey string

@description('Resource ID of the subnet')
param subnetId string

@description('Resource ID of the Log Analytics workspace')
param logAnalyticsWorkspaceId string = ''

@description('Resource ID of the Disk Encryption Set for customer-managed keys')
param diskEncryptionSetId string = ''

@description('Confidential OS disk encryption type')
@allowed([
  'VMGuestStateOnly'
  'DiskWithVMGuestState'
])
param securityEncryptionType string = 'DiskWithVMGuestState' // Full disk + VM guest state encryption

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'confidential-processing'

// --- Network Interface (Art. 25 — no public IP by default) ---
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
          // No public IP — Art. 25 privacy by design
        }
      }
    ]
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
  }
}

// --- Confidential Virtual Machine (Art. 32 — encryption in use) ---
// AMD SEV-SNP provides:
// - Memory encryption: data encrypted while in use (not just at rest/in transit)
// - Hardware attestation: cryptographic proof the VM runs expected code
// - vTPM: measured boot chain ensures integrity
resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned' // Managed identity — no stored credentials
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true // Art. 32 — strong auth only
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
        patchSettings: {
          patchMode: 'AutomaticByPlatform' // Art. 32 — ongoing security
          automaticByPlatformSettings: {
            rebootSetting: 'IfRequired'
          }
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-confidential-vm-jammy'
        sku: '22_04-lts-cvm'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          // Art. 32(1)(a) — confidential disk encryption
          securityProfile: {
            securityEncryptionType: securityEncryptionType
            diskEncryptionSet: diskEncryptionSetId != '' ? {
              id: diskEncryptionSetId
            } : null
          }
          storageAccountType: 'Premium_LRS'
        }
        deleteOption: 'Delete' // Art. 17 — clean up on VM deletion
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    // Art. 32 — Confidential computing security profile
    securityProfile: {
      securityType: 'ConfidentialVM'
      uefiSettings: {
        secureBootEnabled: true // Prevent boot-level tampering
        vTpmEnabled: true // Hardware-rooted attestation
      }
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true // Art. 5(2) — accountability
      }
    }
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    gdpr_articles: 'Art.25,Art.32,Art.5(1)(f)'
    data_classification: 'highly-confidential'
    encryption_in_use: 'AMD-SEV-SNP'
  }
}

// --- VM Extension: Azure Monitor Agent (Art. 5(2) — accountability) ---
resource azureMonitorAgent 'Microsoft.Compute/virtualMachines/extensions@2024-03-01' = if (logAnalyticsWorkspaceId != '') {
  parent: vm
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

output vmId string = vm.id
output vmName string = vm.name
output vmPrincipalId string = vm.identity.principalId
