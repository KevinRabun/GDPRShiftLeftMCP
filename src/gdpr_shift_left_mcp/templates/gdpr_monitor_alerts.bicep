// GDPR-Compliant Azure Monitor Action Group & Alerts — Breach detection and 72-hour notification
// Addresses: Art. 33 — Breach notification (72h), Art. 34 — Communication to data subjects, Art. 5(2) — Accountability

@description('The Azure region for deployment.')
param location string = 'global'

@description('Name of the action group for GDPR breach notifications')
param actionGroupName string = 'gdpr-breach-alerts'

@description('Short name for the action group (max 12 chars)')
@maxLength(12)
param actionGroupShortName string = 'GDPRBreach'

@description('Email address of the Data Protection Officer')
param dpoEmail string

@description('Email address for the security/incident response team')
param securityTeamEmail string

@description('Optional SMS number for critical breach alerts (E.164 format)')
param smsPhoneNumber string = ''

@description('Country code for SMS')
param smsCountryCode string = '44'

@description('Resource ID of the Log Analytics workspace to monitor')
param logAnalyticsWorkspaceId string

@description('GDPR processing purpose tag')
param gdprProcessingPurpose string = 'breach-notification'

// --- Action Group (Art. 33 — Breach notification within 72 hours) ---
resource actionGroup 'Microsoft.Insights/actionGroups@2023-09-01-preview' = {
  name: actionGroupName
  location: location
  properties: {
    enabled: true
    groupShortName: actionGroupShortName

    emailReceivers: [
      {
        name: 'DPO Notification'
        emailAddress: dpoEmail
        useCommonAlertSchema: true
      }
      {
        name: 'Security Team'
        emailAddress: securityTeamEmail
        useCommonAlertSchema: true
      }
    ]

    smsReceivers: !empty(smsPhoneNumber) ? [
      {
        name: 'DPO SMS'
        countryCode: smsCountryCode
        phoneNumber: smsPhoneNumber
      }
    ] : []
  }
  tags: {
    gdpr_compliant: 'true'
    gdpr_processing_purpose: gdprProcessingPurpose
    'gdpr-purpose': gdprProcessingPurpose
    'gdpr-article': 'Art-33-Art-34'
  }
}

// --- Alert: Multiple Failed Sign-Ins (potential breach indicator) ---
resource failedSignInAlert 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'GDPR-Art33-FailedSignIns'
  location: location
  properties: {
    displayName: 'GDPR Art. 33 — Suspicious Failed Sign-In Activity'
    description: 'Detects multiple failed sign-in attempts that may indicate a breach attempt. Art. 33 requires notification to the supervisory authority within 72 hours.'
    severity: 1 // Critical
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT1H'
    scopes: [
      logAnalyticsWorkspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            SigninLogs
            | where ResultType != "0"
            | summarize FailedAttempts=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
            | where FailedAttempts > 10
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
  tags: {
    'gdpr-article': 'Art-33'
    'gdpr-purpose': 'breach-detection'
  }
}

// --- Alert: Unusual Data Export / Exfiltration (Art. 33 — data breach) ---
resource dataExfiltrationAlert 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'GDPR-Art33-DataExfiltration'
  location: location
  properties: {
    displayName: 'GDPR Art. 33 — Unusual Data Export Activity'
    description: 'Detects unusual data export or download patterns that may indicate a data breach requiring notification under Art. 33.'
    severity: 1
    enabled: true
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    scopes: [
      logAnalyticsWorkspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            StorageBlobLogs
            | where OperationName in ("GetBlob", "GetBlobProperties", "CopyBlob")
            | where StatusCode == 200
            | summarize TotalBytes=sum(ResponseBodySize), RequestCount=count() by CallerIpAddress, bin(TimeGenerated, 1h)
            | where TotalBytes > 1073741824 or RequestCount > 1000
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
  tags: {
    'gdpr-article': 'Art-33'
    'gdpr-purpose': 'data-exfiltration-detection'
  }
}

// --- Alert: Privilege Escalation (Art. 32 — access control breach) ---
resource privilegeEscalationAlert 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'GDPR-Art32-PrivilegeEscalation'
  location: location
  properties: {
    displayName: 'GDPR Art. 32 — Privilege Escalation Detection'
    description: 'Detects role assignment changes that may indicate unauthorised access escalation, compromising security of personal data processing.'
    severity: 2 // High
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT1H'
    scopes: [
      logAnalyticsWorkspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            AzureActivity
            | where OperationNameValue has_any (
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Authorization/roleDefinitions/write"
              )
            | where ActivityStatusValue == "Success"
            | project TimeGenerated, Caller, OperationNameValue, ResourceGroup
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
  tags: {
    'gdpr-article': 'Art-32'
    'gdpr-purpose': 'access-control-monitoring'
  }
}

// --- Alert: Encryption Key Operations (Art. 32 — key management audit) ---
resource keyOperationsAlert 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'GDPR-Art32-KeyOperations'
  location: location
  properties: {
    displayName: 'GDPR Art. 32 — Sensitive Key Vault Operations'
    description: 'Alerts on key deletion, disable, or recovery operations that may impact encryption of personal data.'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT1H'
    scopes: [
      logAnalyticsWorkspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            AzureDiagnostics
            | where ResourceProvider == "MICROSOFT.KEYVAULT"
            | where OperationName has_any ("KeyDelete", "KeyPurge", "SecretDelete", "SecretPurge", "BackupKey", "RestoreKey")
            | project TimeGenerated, CallerIPAddress, OperationName, ResultType, Resource
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
  tags: {
    'gdpr-article': 'Art-32'
    'gdpr-purpose': 'key-management-audit'
  }
}

output actionGroupId string = actionGroup.id
output actionGroupName string = actionGroup.name
