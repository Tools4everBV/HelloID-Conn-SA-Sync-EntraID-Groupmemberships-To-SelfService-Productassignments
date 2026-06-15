# HelloID-Conn-SA-Sync-EntraID-Groupmemberships-To-SelfService-Productassignments

> [!IMPORTANT]
> **Best Practice - Maximum Synchronization Frequency: Once per month**
>
> **Why this maximum?**
> This sync processes large volumes (e.g., 1,000 groups with 100 members each = 100,000 assignments) and causes significant system load. It's designed as a **one-time migration** to bring existing permissions into HelloID Service Automation as product assignments.
>
> If a higher frequency is required for your organization, please contact **Tools4ever Support**. This helps us understand your use case and provide proper guidance.

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

## Table of Contents
- [HelloID-Conn-SA-Sync-EntraID-Groupmemberships-To-SelfService-Productassignments](#helloid-conn-sa-sync-entraid-groupmemberships-to-selfservice-productassignments)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Requirements](#requirements-1)
    - [App Registration \& Certificate Setup](#app-registration--certificate-setup)
    - [HelloID-specific configuration](#helloid-specific-configuration)
    - [Convert .pfx to base64 string](#convert-pfx-to-base64-string)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Requirements
- Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
- **App ID & App Secret** for the app registration with permissions to the Microsoft Graph API.
- Make sure the sychronization is configured to meet your requirements.
- - Setup synchronization of Entra ID or local AD users and groups to HelloID.
  - This can be either the [local AD sync](https://docs.helloid.com/en/access-management/directory-sync/active-directory-sync.html) or the [Entra ID sync](https://docs.helloid.com/en/access-management/directory-sync/azure-ad-sync.html).
  > If using the [local AD sync](https://docs.helloid.com/en/access-management/directory-sync/active-directory-sync.html), make sure the userAttribute "userPrincipalName" is mapped and synced. Also make sure to change the **$taskVariableUserValue** accordingly.

## Introduction

By using this connector, you will have the ability to create and remove HelloID SelfService Productassignments based on groupmemberships in your Entra ID.

The products will be assigned to a user when they are already a member of the group that the product would make them member of. This way the product can be returned to revoke the groupmembership without having to first request all the products "you already have".

And vice versa for the removing of the productassignments. The products will be returned from a user when they are already no longer a member of the group that the product would make them member of. This way the product can be requested again without having to first return all the products "you already no longer have".

This is intended for scenarios where the groupmemberships are managed by other sources (e.g. manual actions or Provisioning) than the HelloID products to keep this in sync. This groupmembership sync is desinged to work in combination with the [Entra ID Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products).

## Getting started

### Requirements

- Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running
- **Not supported** with Cloud Agent (must run On-Premises)
- An App Registration in Microsoft Entra ID configured with certificate-based authentication
- The synchronization must be configured to meet your requirements before scheduling

### App Registration & Certificate Setup

Before implementing this scheduled task, you must configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions, and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:

- [App-only authentication with certificate (Microsoft Graph)](https://learn.microsoft.com/en-us/graph/auth-register-app-v2)

### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

**API Permissions (Application permissions):**

- `Group.Read.All` - To read group information
- `GroupMember.Read.All` - To read members from groups

**Certificate:**

- Upload the public key file (.cer) in Entra ID
- Provide the certificate as a Base64 string in HelloID

> [!NOTE]
> For more information about the required permissions, please see the Microsoft docs:
> - [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
> - [Find the permissions required to run any Microsoft Graph cmdlet](https://learn.microsoft.com/en-us/graph/permissions-reference)
> - [View and assign administrator roles in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal)

### Convert .pfx to base64 string

HelloID requires a base64 string to import the certificate. Use the example below to create a base64 string:

```powershell
$filePath = 'C:\Cert'
$pfxCertName = 'Cert.pfx'
$pfxPath = "$filePath\$pfxCertName"

$fileContentBytes = [System.IO.File]::ReadAllBytes("$pfxPath")
[System.Convert]::ToBase64String($fileContentBytes) | Set-Content "$filePath\HelloID_Cert_Base64.txt"
```

### Synchronization settings

| Variable name                                | Description                                                                                                                                                                               | Notes                                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $portalBaseUrl                               | String value of HelloID Base Url                                                                                                                                                          | (Default Global Variable)                                                                                                                                                                                                                                                                                                                                                 |
| $portalApiKey                                | String value of HelloID Api Key                                                                                                                                                           | (Default Global Variable)                                                                                                                                                                                                                                                                                                                                                 |
| $portalApiSecret                             | String value of HelloID Api Secret                                                                                                                                                        | (Default Global Variable)                                                                                                                                                                                                                                                                                                                                                 |
| $EntraIdTenantId                             | String value of Entra ID Tenant ID                                                                                                                                                        | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                                                     |
| $EntraIdAppId                                | String value of Entra ID App ID                                                                                                                                                           | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                                                     |
| $EntraIdCertificateBase64String              | Base64 string of Entra ID App Certificate                                                                                                                                                 | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                                                     |
| $EntraIdCertificatePassword                  | Password of Entra ID App Certificate                                                                                                                                                      | Recommended to set as Global Variable                                                                                                                                                                                                                                                                                                                                     |
| $entraIDGroupsSearchFilter                   | String value of seachfilter of which Entra ID groups to include                                                                                                                           | Optional, when no filter is provided ($entraIDGroupsSearchFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections                                                           |
| $ProductSkuPrefix                            | String value of prefix filter of which HelloID Self service Products to include                                                                                                           | Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried                                                                                                                                                                                                                                                                         |
| $PowerShellActionName                        | String value of name of the PowerShell action that grants the Entra ID user to the Entra ID group                                                                                         | The default value ("Add-EntraIDUserToEntraIDGroup") is set to match the value from the [Entra ID Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products)                                                                                                                                       |
| $PowerShellActionVariableCorrelationProperty | String value of name of the property of HelloID Self service Product action variables to match to Entra ID Groups (name of the variable of the PowerShell action that contains the group) | The default value ("GroupId") is set to match the value from the [Entra ID Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-EntraID-Groups-To-SelfService-Products), where Group is set as the variable name for the group for the Product actions. If your products are from a different source, change this accordingly (e.g. Group)       |
| $entraIDGroupCorrelationProperty             | String value of name of the property of Entra ID groups to match Groups in HelloID Self service Product actions (the group)                                                               | The default value ("id") is set to match the value from the [Entra ID Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-EntraID-Groups-To-SelfService-Products), where the Entra ID group SamAccountName is set as the Group value for the Product actions. If your products are from a different source, change this accordingly (e.g. Name) |
| $entraIDUserCorrelationProperty              | String value of name of the property of Entra ID users to match to HelloID users                                                                                                          | The default value `userPrincipalName`                                                                                                                                                                                                                                                                                                                                     |
| $helloIDUserCorrelationProperty              | String value of name of the property of HelloID users to match to Entra ID users                                                                                                          | The default value is `userName`                                                                                                                                                                                                                                                                                                                                           |
| $commendRequired                             | Set to `$true` if comment is configured as required                                                                                                                     |       The default value is `$false`                                                                                                                                                                                                                                                                                                                                                                    |

## Remarks
- The Productassignments are granted and revoked. Make sure your configuration is correct to avoid unwanted revokes
- This groupmembership sync is designed to work in combination with the [Entra ID Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products). If your products are from a different source, this sync task might not work and needs changes accordingly.

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
