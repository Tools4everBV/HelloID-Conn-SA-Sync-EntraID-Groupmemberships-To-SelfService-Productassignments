#####################################################
# HelloID-SA-Sync-AD-Groupmemberships-To-HelloID-Selfservice-Productassignments
#
# Version: 1.0.0
#####################################################
$VerbosePreference = "SilentlyContinue"
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
$script:PortalBaseUrl = $portalBaseUrl
$portalApiKey = $portalApiKey
$portalApiSecret = $portalApiSecret

#AzureAD Connection Configuration
$MSGraphBaseUri = "https://graph.microsoft.com/" # Fixed value
$AzureADtenantID = ""
$AzureADAppId = ""
$AzureADAppSecret = ""
$AzureADGroupsSearchFilter = "`$search=`"displayName:department_`"" # Optional, when no filter is provided ($AzureADGroupsSearchFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections

#HelloID Self service Product Configuration
$ProductSkuPrefix = 'AADGRP' # Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried
$PowerShellActionName = "Add-AzureADUserToAzureADGroup" # Define the name of the PowerShell action

#Correlation Configuration
$PowerShellActionVariableCorrelationProperty = "GroupId" # The name of the property of HelloID Self service Product action variables to match to AD Groups (name of the variable of the PowerShell action that contains the group)
$azureADGroupCorrelationProperty = "id" # The name of the property of AD groups to match Groups in HelloID Self service Product actions (the group)
$azureADUserCorrelationProperty = "id" # The name of the property of AD users to match to HelloID users
$helloIDUserCorrelationProperty = "immutableId" # The name of the property of HelloID users to match to AD users

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ""
        }

        if ($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException") {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [Parameter(Mandatory = $false)]
        $PageSize,

        [string]
        $ContentType = "application/json"
    )

    try {
        Write-Verbose "Switching to TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose "Setting authorization headers"
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatParams = @{
            Uri         = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers     = $headers
            Method      = $Method
            ErrorAction = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatParams["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatParams
                if (($response.PsObject.Properties.Match("pageData") | Measure-Object).Count -gt 0) {
                    $dataset = $response.pageData
                }
                else {
                    $dataset = $response
                }

                if ($dataset -is [array]) {
                    [void]$data.AddRange($dataset)
                }
                else {
                    [void]$data.Add($dataset)
                }
            
                $skip += $take
            }until(($dataset | Measure-Object).Count -ne $take)

            return $data
        }
        else {
            if ($Body) {
                Write-Verbose "Adding body to request"
                $splatParams["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatParams

            return $response
        }

    }
    catch {
        throw $_
    }
}

#endregion functions

#region script
Hid-Write-Status -Event Information -Message "Starting synchronization of Active Directory groupmemberships to HelloID Self service Productassignments"
Hid-Write-Status -Event Information -Message "------[HelloID]------"
try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying Self service product actions from HelloID"
    # }

    $splatParams = @{
        Method   = "GET"
        Uri      = "selfservice/actions"
        PageSize = 1000
    }
    $helloIDSelfServiceProductActions = Invoke-HIDRestMethod @splatParams

    # Filter for specified actions
    $helloIDSelfServiceProductActionsInScope = [System.Collections.ArrayList]@()
    $PowerShellActionGroupsInScope = [System.Collections.ArrayList]@()
    foreach ($helloIDSelfServiceProductAction in $helloIDSelfServiceProductActions | Where-Object { $_.name -eq "$PowerShellActionName" -and $_.executionEntry -eq "powershell-script" -and $_.executionType -eq "native" -and $_.executeOnState -ne "0" -and $_.executeOnState -ne $null }) {
        foreach ($variable in $helloIDSelfServiceProductAction.variables) {
            if ( $variable.Name -eq $PowerShellActionVariableCorrelationProperty -and $variable.Value -notlike "{{*}}") {
                if ($helloIDSelfServiceProductAction -notin $helloIDSelfServiceProductActionsInScope) {
                    [void]$helloIDSelfServiceProductActionsInScope.Add($helloIDSelfServiceProductAction)
                }

                if (-not[string]::IsNullOrEmpty($variable.Value) -and $variable.Value -notin $PowerShellActionGroupsInScope) {
                    [void]$PowerShellActionGroupsInScope.Add($variable.Value)
                }
            }
        }
    }
    
    Hid-Write-Status -Event Success -Message "Successfully queried Self service product actions from HelloID (after filtering for specified custom powershell actions). Result count: $(($helloIDSelfServiceProductActionsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service product actions from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying Self service products from HelloID"
    # }

    $splatParams = @{
        Method = "GET"
        Uri    = "selfservice/products"
    }
    $helloIDSelfServiceProducts = Invoke-HIDRestMethod @splatParams

    # Filter for products with specified Sku Prefix
    if (-not[String]::IsNullOrEmpty($ProductSkuPrefix)) {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts | Where-Object { $_.code -like "$ProductSkuPrefix*" }
    }
    else {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts
    }

    # Filter for products with specified actions
    $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProductsInScope | Where-Object { $_.selfServiceProductGUID -in $helloIDSelfServiceProductActionsInScope.objectGUID }

    Hid-Write-Status -Event Success -Message "Successfully queried Self service products from HelloID (after filtering for products with specified actions only). Result count: $(($helloIDSelfServiceProductsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service products from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying  Self service Productassignments from HelloID"
    # }

    $splatParams = @{
        Method   = "GET"
        Uri      = "product-assignment"
        PageSize = 1000
    }
    $helloIDSelfServiceProductassignments = Invoke-HIDRestMethod @splatParams

    # Filter for for productassignments of specified products
    $helloIDSelfServiceProductassignmentsInScope = $null
    $helloIDSelfServiceProductassignmentsInScope = $helloIDSelfServiceProductassignments | Where-Object { $_.productGuid -in $helloIDSelfServiceProductsInScope.selfServiceProductGUID }

    $helloIDSelfServiceProductassignmentsInScopeGrouped = $helloIDSelfServiceProductassignmentsInScope | Group-Object -Property productGuid -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Self service Productassignments from HelloID (after filtering for productassignments of specified products only). Result count: $(($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service Productassignments from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

try {
    # if ($verboseLogging -eq $true) {
    #     Hid-Write-Status -Event Information -Message "Querying Users from HelloID"
    # }

    $splatParams = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatParams

    $helloIDUsersInScope = $null
    $helloIDUsersInScope = $helloIDUsers

    $helloIDUsersInScopeGrouped = $helloIDUsersInScope | Group-Object -Property $helloIDUserCorrelationProperty -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsersInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Active Directory]-----------"  
# Get Azure AD Groups
try {  
    $headers = New-AuthorizationHeaders -TenantId $AzureADtenantID -ClientId $AzureADAppId -ClientSecret $AzureADAppSecret

    $properties = @(
        $azureADGroupCorrelationProperty
        , "displayName"
        , "description"
        , "onPremisesSyncEnabled"
        , "groupTypes"
    )
    $select = "`$select=$($properties -join ",")"

    $m365GroupFilter = "groupTypes/any(c:c+eq+'Unified')"
    $securityGroupFilter = "NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true"
    $managableGroupsFilter = "`$filter=$m365GroupFilter or $securityGroupFilter"
  
    $azureADQuerySplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups?$managableGroupsFilter&$AzureADGroupsSearchFilter&$select&`$top=999&`$count=true"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop'
    }

    $azureADGroups = [System.Collections.ArrayList]@()
    $getAzureADGroupsResponse = $null
    $getAzureADGroupsResponse = Invoke-RestMethod @azureADQuerySplatParams -Verbose:$false
    if ($getAzureADGroupsResponse.value -is [array]) {
        [void]$azureADGroups.AddRange($getAzureADGroupsResponse.value)
    }
    else {
        [void]$azureADGroups.Add($getAzureADGroupsResponse.value)
    }

    while (![string]::IsNullOrEmpty($getAzureADGroupsResponse.'@odata.nextLink')) {
        $azureADQuerySplatParams = @{
            Uri         = $getAzureADGroupsResponse.'@odata.nextLink'
            Headers     = $headers
            Method      = 'GET'
            ErrorAction = 'Stop'
        }
        $getAzureADGroupsResponse = $null
        $getAzureADGroupsResponse = Invoke-RestMethod @azureADQuerySplatParams -Verbose:$false
        if ($getAzureADGroupsResponse.value -is [array]) {
            [void]$azureADGroups.AddRange($getAzureADGroupsResponse.value)
        }
        else {
            [void]$azureADGroups.Add($getAzureADGroupsResponse.value)
        }
    }

    # Filter for groups that are in products
    $azureADGroupsInScope = $null
    $azureADGroupsInScope = $azureADGroups | Where-Object { $_.$azureADGroupCorrelationProperty -in $PowerShellActionGroupsInScope }
    
    if (($azureADGroupsInScope | Measure-Object).Count -eq 0) {
        throw "No Azure Active Directory Groups have been found"
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Azure AD groups (after filtering for groups that are in products). Result count: $(($azureADGroupsInScope | Measure-Object).Count)"

    # Get Azure AD Groupmemberships of groups
    try {
        if ($verboseLogging -eq $true) {
            Hid-Write-Status -Event Information -Message "Enhancing AD groups with members"
        }
        $azureADGroupsInScope | Add-Member -MemberType NoteProperty -Name "members" -Value $null -Force
        $totalAzureADGroupMembers = 0
        foreach ($azureADGroup in $azureADGroupsInScope) {
            try {
                # if ($verboseLogging -eq $true) {
                #     Hid-Write-Status -Event Information -Message "Querying Azure AD groupmembers of group [$($azureADGroup.id)]"
                # }
                $properties = @(
                    $azureADUserCorrelationProperty
                    , "displayName"
                )
                $select = "`$select=$($properties -join ",")"
            
                $azureADQuerySplatParams = @{
                    Uri         = "$($MSGraphBaseUri)/v1.0/groups/$($azureADGroup.id)/members?&$select&`$top=999&`$count=true"
                    Headers     = $headers
                    Method      = 'GET'
                    ErrorAction = 'Stop'
                }
            
                $azureADGroupmembers = [System.Collections.ArrayList]@()
                $getAzureADGroupmembersResponse = $null
                $getAzureADGroupmembersResponse = Invoke-RestMethod @azureADQuerySplatParams -Verbose:$false
                if ($getAzureADGroupmembersResponse.value -is [array]) {
                    [void]$azureADGroupmembers.AddRange($getAzureADGroupmembersResponse.value)
                }
                else {
                    [void]$azureADGroupmembers.Add($getAzureADGroupmembersResponse.value)
                }
            
                while (![string]::IsNullOrEmpty($getAzureADGroupmembersResponse.'@odata.nextLink')) {
                    $azureADQuerySplatParams = @{
                        Uri         = $getAzureADGroupmembersResponse.'@odata.nextLink'
                        Headers     = $headers
                        Method      = 'GET'
                        ErrorAction = 'Stop'
                    }
                    $getAzureADGroupmembersResponse = $null
                    $getAzureADGroupmembersResponse = Invoke-RestMethod @azureADQuerySplatParams -Verbose:$false
                    if ($getAzureADGroupmembersResponse.value -is [array]) {
                        [void]$azureADGroupmembers.AddRange($getAzureADGroupmembersResponse.value)
                    }
                    else {
                        [void]$azureADGroupmembers.Add($getAzureADGroupmembersResponse.value)
                    }
                }

                # # Filter for user objects
                # $azureADGroupmembers = $azureADGroupmembers | Where-Object { $_.objectClass -eq "user" }

                # Filter for users that exist in HelloID
                $azureADGroupMembersInScope = $null
                $azureADGroupMembersInScope = $azureADGroupmembers | Where-Object { $_.$azureADUserCorrelationProperty -in $helloIDUsersInScope.$helloIDUserCorrelationProperty }

                # Set property of AD group with members
                $azureADGroup.members = $azureADGroupMembersInScope

                # if ($verboseLogging -eq $true) {
                #     Hid-Write-Status -Event Success -Message "Successfully queried Azure AD groupmembers of group [$($azureADGroup.id)] (after filtering for users that exist in HelloID). Result count: $(($azureADGroupMembersInScope | Measure-Object).Count)"                
                # }

                foreach ($azureADGroupmember in $azureADGroupmembers) {
                    $totalAzureADGroupMembers++
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex

                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
                    Hid-Write-Status -Event Error -Message "Error querying Azure AD groupmembers of group [$($azureADGroup.id)]. Error Message: $($errorMessage.AuditErrorMessage)"
                }
            }
        }

        Hid-Write-Status -Event Success -Message "Successfully enhanced Azure AD groups with members (after filtering for users that exist in HelloID). Result count: $($totalAzureADGroupMembers)"
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

        throw "Error querying Azure AD groupmembers. Error Message: $($errorMessage.AuditErrorMessage)"
    }

    $azureADGroupsGrouped = $azureADGroups | Group-Object -Property $azureADGroupCorrelationProperty -AsHashTable -AsString
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Azure AD groups that match filter [$($AzureADGroupsSearchFilter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete product assignments
try {
    $newProductAssignmentObjects = [System.Collections.ArrayList]@()
    $obsoleteProductAssignmentObjects = [System.Collections.ArrayList]@()
    $existingProductAssignmentObjects = [System.Collections.ArrayList]@()
    foreach ($product in $helloIDSelfServiceProductsInScope) {
        # if ($verboseLogging -eq $true) {
        #     Hid-Write-Status -Event Information -Message "Calculating new and obsolete product assignments for Product [$($product.name)]"
        # }

        # Get Group from Product Action
        $productActionsInScope = $helloIDSelfServiceProductActionsInScope | Where-Object { $_.objectGUID -eq $product.selfServiceProductGUID }
        $variablesInScope = [PSCustomObject]$productActionsInScope | Select-Object -ExpandProperty variables
        $groupName = [PSCustomObject]$variablesInScope | Where-Object { $_.name -eq "$PowerShellActionVariableCorrelationProperty" } | Select-Object value | Sort-Object value -Unique | Select-Object -ExpandProperty value
        $azureADGroup = $null
        $azureADGroup = $azureADGroupsGrouped[$groupName]
        if (($azureADGroup | Measure-Object).Count -eq 0) {
            Hid-Write-Status -Event Error -Message "No Azure AD group found with $azureADGroupCorrelationProperty [$($groupName)] for Product [$($product.name)]"
            continue
        }
        elseif (($azureADGroup | Measure-Object).Count -gt 1) {
            Hid-Write-Status -Event Error -Message "Multiple Azure AD groups found with $azureADGroupCorrelationProperty [$($groupName)] for Product [$($product.name)]. Please correct this so the $azureADGroupCorrelationProperty of the AD group is unique"
            continue
        }

        # Get AD user objects for additional data to match to HelloID user
        $azureADUsersInScope = $azureADGroup.members
        
        # Get HelloID user objects to assign to the product
        $productUsersInScope = [System.Collections.ArrayList]@()
        foreach ($azureADUser in $azureADUsersInScope) {
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersInScopeGrouped[$azureADUser.$azureADUserCorrelationProperty]

            if (($helloIDUser | Measure-Object).Count -eq 0) {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "No HelloID user found with $helloIDUserCorrelationProperty [$($azureADUser.$azureADUserCorrelationProperty)] for AD user [$($azureADUser.distinguishedName)] for Product [$($product.name)]"
                    continue
                }
            }
            else {
                [void]$productUsersInScope.Add($helloIDUser)
            }
        }

        # Get current product assignments
        $currentProductassignments = $null
        if (($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count -ge 1) {
            $currentProductassignments = $helloIDSelfServiceProductassignmentsInScopeGrouped[$product.selfServiceProductGUID]
        }

        # Define assignments to grant
        $newProductassignments = $productUsersInScope | Where-Object { $_.userGuid -notin $currentProductassignments.userGuid }
        foreach ($newProductAssignment in $newProductassignments) {
            $newProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.selfServiceProductGUID)"
                productName            = "$($product.name)"
                userGuid               = "$($newProductAssignment.userGuid)"
                userName               = "$($newProductAssignment.userName)"
                source                 = "SyncAzureADGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }

            [void]$newProductAssignmentObjects.Add($newProductAssignmentObject)
        }

        # Define assignments to revoke
        $obsoleteProductassignments = $currentProductassignments | Where-Object { $_.userGuid -notin $productUsersInScope.userGuid }
        foreach ($obsoleteProductassignment in $obsoleteProductassignments) { 
            $obsoleteProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.selfServiceProductGUID)"
                productName            = "$($product.name)"
                userGuid               = "$($obsoleteProductassignment.userGuid)"
                userName               = "$($obsoleteProductassignment.userName)"
                source                 = "SyncADGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }
    
            [void]$obsoleteProductAssignmentObjects.Add($obsoleteProductAssignmentObject)
        }

        # Define assignments already existing
        $existingProductassignments = $currentProductassignments | Where-Object { $_.userGuid -in $productUsersInScope.userGuid }
        foreach ($existingProductassignment in $existingProductassignments) { 
            $existingProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.selfServiceProductGUID)"
                productName            = "$($product.name)"
                userGuid               = "$($existingProductassignment.userGuid)"
                userName               = "$($existingProductassignment.userName)"
                source                 = "SyncADGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }
    
            [void]$existingProductAssignmentObjects.Add($existingProductAssignmentObject)
        }

        # Define total assignments (existing + new assignments)
        $totalProductAssignments = ($(($existingProductAssignmentObjects | Measure-Object).Count) + $(($newProductAssignmentObjects | Measure-Object).Count))
    }
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete product assignments. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Summary]------"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Product(s) in scope [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) already exist (and won't be changed) [$(($existingProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) to grant [$(($newProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) to revoke [$(($obsoleteProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "------[Processing]------------------"
try {
    # Grant assignments
    $productAssigmentGrantsSuccess = 0
    $productAssigmentGrantsError = 0
    foreach ($newProductAssignmentObject in $newProductAssignmentObjects) {
        try {
            # if ($verboseLogging -eq $true) {
            #     Hid-Write-Status -Event Information -Message "Granting productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]""
            # }
        
            $body = @{
                userGuid               = "$($newProductAssignmentObject.userGuid)"
                source                 = "$($newProductAssignmentObject.source)"
                executeApprovalActions = $newProductAssignmentObject.executeApprovalActions
            } | ConvertTo-Json

            $splatParams = @{
                Method      = "POST"
                Uri         = "product-assignment/$($newProductAssignmentObject.productGuid)"
                Body        = $body # ([System.Text.Encoding]::UTF8.GetBytes($body))
                ErrorAction = "Stop"
            }
            if ($dryRun -eq $false) {
                $grantProductassignmentToUser = Invoke-HIDRestMethod @splatParams
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "Successfully granted productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]"
                }
                $productAssigmentGrantsSuccess++
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "DryRun: Would grant productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]"
                }   
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            $productAssigmentGrantsError++
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Error -Message "Error granting productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($dryRun -eq $false) {
        if ($productAssigmentGrantsSuccess -ge 1 -or $productAssigmentGrantsError -ge 1) {
            Hid-Write-Status -Event Information -Message "Granted productassignments to HelloID Self service Products. Success: $($productAssigmentGrantsSuccess). Error: $($productAssigmentGrantsError)"
            Hid-Write-Summary -Event Information -Message "Granted productassignments to HelloID Self service Products. Success: $($productAssigmentGrantsSuccess). Error: $($productAssigmentGrantsError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would grant [$(($newProductAssignmentObjects | Measure-Object).Count)] productassignments for [$(($newProductAssignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Warning "DryRun: Would grant [$(($newProductAssignmentObjects | Measure-Object).Count)] productassignments for [$(($newProductAssignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
    }

    # Revoke assignments
    $productAssigmentRevokesSuccess = 0
    $productAssigmentRevokesError = 0
    foreach ($obsoleteProductAssignmentObject in $obsoleteProductAssignmentObjects) { 
        try {
            # if ($verboseLogging -eq $true) {
            #     Hid-Write-Status -Event Information -Message "Revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]""
            # }
            
            $body = @{
                productGuid            = "$($obsoleteProductAssignmentObject.productGuid)"
                userGuid               = "$($obsoleteProductAssignmentObject.userGuid)"
                executeApprovalActions = $($obsoleteProductAssignmentObject.executeApprovalActions)
            } | ConvertTo-Json

            $splatParams = @{
                Method      = "POST"
                Uri         = "product-assignment/unassign/by-product"
                Body        = $body # ([System.Text.Encoding]::UTF8.GetBytes($body))
                ErrorAction = "Stop"
            }
            if ($dryRun -eq $false) {
                $revokeProductassignmentToUser = Invoke-HIDRestMethod @splatParams
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "Successfully revoked productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
                }
                $productAssigmentRevokesSuccess++
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "DryRun: Would revoke productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
                }   
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            $productAssigmentRevokesError++
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Error -Message "Error revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($dryRun -eq $false) {
        if ($productAssigmentRevokesSuccess -ge 1 -or $productAssigmentRevokesError -ge 1) {
            Hid-Write-Status -Event Information -Message "Revoked productassignments to HelloID Self service Products. Success: $($productAssigmentRevokesSuccess). Error: $($productAssigmentRevokesError)"
            Hid-Write-Summary -Event Information -Message "Revoked productassignments to HelloID Self service Products. Success: $($productAssigmentRevokesSuccess). Error: $($productAssigmentRevokesError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would revoke [$(($obsoleteProductassignmentObjects | Measure-Object).Count)] productassignments for [$(($obsoleteProductassignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Status -Event Warning -Message "DryRun: Would revoke [$(($obsoleteProductassignmentObjects | Measure-Object).Count)] productassignments for [$(($obsoleteProductassignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
    }

    if ($dryRun -eq $false) {
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$($totalAzureADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$($totalAzureADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$($totalAzureADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$($totalAzureADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$($totalAzureADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$($totalAzureADGroupMembers)] Active Directory groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
}
#endregion