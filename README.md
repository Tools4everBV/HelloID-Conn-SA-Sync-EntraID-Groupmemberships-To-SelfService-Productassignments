# HelloID-Conn-SA-Sync-AzureActiveDirectory-Groupmemberships-To-SelfService-Productassignments
Synchronizes Azure AD groupmemberships to HelloID Self service productassignments

<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/network/members"><img src="https://img.shields.io/github/forks/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments" alt="Forks Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/pulls"><img src="https://img.shields.io/github/issues-pr/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments" alt="Pull Requests Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/issues"><img src="https://img.shields.io/github/issues/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments" alt="Issues Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groupmemberships-To-SelfService-Productassignments?color=2b9348"></a>


| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

## Table of Contents
- [HelloID-Conn-SA-Sync-AzureActiveDirectory-Groupmemberships-To-SelfService-Productassignments](#helloid-conn-sa-sync-azureactivedirectory-groupmemberships-to-selfservice-productassignments)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
  - [Getting started](#getting-started-1)
    - [Create an API key and secret for HelloID](#create-an-api-key-and-secret-for-helloid)
    - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
      - [Application Registration](#application-registration)
      - [Configuring App Permissions](#configuring-app-permissions)
      - [Authentication and Authorization](#authentication-and-authorization)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Requirements
The requirements to run this connector, such as, an App Registration, to be run on-premises, run with concurrent sessions set to a max. of 1, etc.
An example is given below:

- Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
- **App ID & App Secret** for the app registration with permissions to the Microsoft Graph API.
- Make sure the sychronization is configured to meet your requirements.

## Introduction

By using this connector, you will have the ability to create and remove HelloID SelfService Productassignments based on groupmemberships in your Azure Active Directory.

The products will be assigned to a user when they are already a member of the group that the product would make them member of. This way the product can be returned to revoke the groupmembership without having to first request all the products "you already have".

And vice versa for the removing of the productassignments. The products will be returned from a user when they are already no longer a member of the group that the product would make them member of. This way the product can be requested again without having to first return all the products "you already no longer have".

This is intended for scenarios where the groupmemberships are managed by other sources (e.g. manual actions or Provisioning) than the HelloID products to keep this in sync. This groupmembership sync is desinged to work in combination with the [Azure Active Directory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products).

## Getting started

## Getting started

### Create an API key and secret for HelloID
1. Go to the `Manage portal > Security > API` section.
2. Click on the `Add Api key` button to create a new API key.
3. Optionally, you can add a note that will describe the purpose of this API key
4. Optionally, you can restrict the IP addresses from which this API key can be used.
5. Click on the `Save` button to save the API key.
6. Go to the `Manage portal > Automation > Variable library` section and confim that the auto variables specified in the [connection settings](#connection-settings) are available.

### Getting the Azure AD graph API access

By using this connector you will have the ability to manage Azure AD Guest accounts.

#### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

#### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read and Write all user’s full profiles by using <b><i>User.ReadWrite.All</i></b>
*	Read and Write all groups in an organization’s directory by using <b><i>Group.ReadWrite.All</i></b>
*	Read and Write data to an organization’s directory by using <b><i>Directory.ReadWrite.All</i></b>

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

#### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At last we need to get the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Overview</b>.

### Synchronization settings

| Variable name | Description   | Notes |
| ------------- | -----------   | ----- |
| $portalBaseUrl    | String value of HelloID Base Url  | (Default Global Variable) |
| $portalApiKey | String value of HelloID Api Key   | (Default Global Variable) |
| $portalApiSecret  | String value of HelloID Api Secret    | (Default Global Variable) |
| $AzureADtenantID    | String value of Azure AD Tenant ID  | Recommended to set as Global Variable |
| $AzureADAppId | String value of Azure AD App ID  | Recommended to set as Global Variable |
| $AzureADAppSecret  | String value of Azure AD App Secret  | Recommended to set as Global Variable |
| $AzureADGroupsSearchFilter   | String value of seachfilter of which Azure AD groups to include   | Optional, when no filter is provided ($AzureADGroupsSearchFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections  |
| $ProductSkuPrefix | String value of prefix filter of which HelloID Self service Products to include    | Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried |
| $PowerShellActionName | String value of name of the PowerShell action that grants the Azure AD user to the Azure AD group | The default value ("Add-AzureADUserToAzureADGroup") is set to match the value from the [Azure Active Directory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products)   |
| $PowerShellActionVariableCorrelationProperty  | String value of name of the property of HelloID Self service Product action variables to match to Azure AD Groups (name of the variable of the PowerShell action that contains the group) | The default value ("GroupId") is set to match the value from the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products), where Group is set as the variable name for the group for the Product actions. If your products are from a different source, change this accordingly (e.g. Group)   |
| $azureADGroupCorrelationProperty   | String value of name of the property of Azure AD groups to match Groups in HelloID Self service Product actions (the group) | The default value ("id") is set to match the value from the [Azure Active Directory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products), where the Azure AD group SamAccountName is set as the Group value for the Product actions. If your products are from a different source, change this accordingly (e.g. Name)   |
| $azureADUserCorrelationProperty    | String value of name of the property of Azure AD users to match to HelloID users    | The default value ("id") is set to match the value from the [Azure Active Directory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-AzureActiveDirectory-Groups-To-SelfService-Products), where the Azure AD user ID is set to the HelloID User immutableId. If your users are from a different source, change this accordingly (e.g. userPrincipalName)  |
| $helloIDUserCorrelationProperty   | String value of name of the property of HelloID users to match to Azure AD users    | The default value ("immutableId") is set to match the value from the [Azure AD Sync](https://docs.helloid.com/en/access-management/directory-sync/azure-ad-sync.html), where the Azure AD user ID is set to the HelloID User immutableId. If your users are from a different source, change this accordingly (e.g. username)   |

## Remarks
- The Productassignments are granted and revoked. Make sure your configuration is correct to avoid unwanted revokes
- This groupmembership sync is designed to work in combination with the [ActiveDirectory Groups to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-ActiveDirectory-Groups-To-SelfService-Products). If your products are from a different source, this sync task might not work and needs changes accordingly.

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/