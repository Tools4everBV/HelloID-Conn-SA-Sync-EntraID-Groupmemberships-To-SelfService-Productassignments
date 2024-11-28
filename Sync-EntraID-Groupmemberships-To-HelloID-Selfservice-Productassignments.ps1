#####################################################
# HelloID-SA-Sync-AD-Groupmemberships-To-HelloID-Selfservice-Productassignments
#
# Version: 2.0.0
#####################################################

# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

switch ($verboseLogging) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
# $script:PortalBaseUrl = "" # Set from Global Variable
# $portalApiKey ="" # Set from Global Variable
# $portalApiSecret = "" # Set from Global Variable

#EntraID Connection Configuration
$MSGraphBaseUri = "https://graph.microsoft.com/" # Fixed value
# $EntraTenantId = "" # Set from Global Variable
# $EntraAppID = "" # Set from Global Variable
# $EntraAppSecret = "" # Set from Global Variable

$entraIDGroupsSearchFilter = "`$search=`"displayName:department_`"" # Optional, when no filter is provided ($entraIDGroupsSearchFilter = $null), all groups will be queried - Only displayName and description are supported with the search filter. Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http#using-search-on-directory-object-collections

#HelloID Self service Product Configuration
$ProductSkuPrefix = 'ENTRAGRP' # Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried
$PowerShellActionName = "Add-EntraIDUserToEntraIDGroup" # Define the name of the PowerShell action

#Correlation Configuration
# The name of the property of HelloID Self service Product action variables to match to AD Groups (name of the variable of the PowerShell action that contains the group)
$PowerShellActionVariableCorrelationProperty = "GroupId"
# The name of the property of AD groups to match Groups in HelloID Self service Product actions (the group)
$entraIDGroupCorrelationProperty = "id"
# The name of the property of Entra ID users to match to HelloID users
$entraIDUserCorrelationProperty = "id" # note when using the AD sync use "userPrincipalName" in combination with $helloIDUserCorrelationProperty = "userAttributes_userprincipalname"
# The name of the property of HelloID users to match to Entra ID users
# if using userAttributes, make sure to use it like this : userAttributes_<attributename> (userAttributes. will not work!)
$helloIDUserCorrelationProperty = "immutableId" # Note, only works for Entra ID synced users. Example for local AD synced users: "userAttributes_userprincipalname"

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

        $splatWebRequest = @{
            Uri             = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers         = $headers
            Method          = $Method
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatWebRequest["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatWebRequest -Verbose:$false
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
                $splatWebRequest["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatWebRequest -Verbose:$false

            return $response
        }

    }
    catch {
        throw $_
    }
}

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $authUri = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
    }
}

#endregion functions

#region script
Hid-Write-Status -Event Information -Message "Starting synchronization of Entra ID groupmemberships to HelloID Self service Productassignments"
Hid-Write-Status -Event Information -Message "------[HelloID]------"

#region Get HelloID Products
try {
    Write-Verbose "Querying Self service products from HelloID"

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

    Hid-Write-Status -Event Success -Message "Successfully queried Self service products from HelloID (after filtering for products with specified sku prefix only). Result count: $(($helloIDSelfServiceProductsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service products from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Products

#region Get HelloID Users
try {
    Write-Verbose "Querying Users from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatWebRequest

    # Transform userAttributes and add to the user object directly
    $helloIDUsers | ForEach-Object {
        if ($null -ne $_.userAttributes) {
            foreach ($userAttribute in $_.userAttributes) {
                if (![string]::IsNullOrEmpty($userAttribute)) {
                    foreach ($property in $userAttribute.PsObject.Properties) {
                        # Add a property for each field in object
                        $_ | Add-Member -MemberType NoteProperty -Name ("userAttributes_" + $property.Name) -Value $property.Value -Force
                    }
                }
            }

            # Remove unneccesary fields from  object (to avoid unneccesary large objects)
            $_.PSObject.Properties.Remove('userAttributes')
        }
    }

    $helloIDUsersInScope = $null
    $helloIDUsersInScope = $helloIDUsers | Where-Object { -not([string]::IsNullOrEmpty($_.$helloIDUserCorrelationProperty)) }

    $helloIDUsersInScopeGrouped = $helloIDUsersInScope | Group-Object -Property $helloIDUserCorrelationProperty -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsersInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Users

#region Get actions of Product
try {
    [System.Collections.ArrayList]$helloIDSelfServiceProductsInScopeWithActions = @()
    Write-Verbose "Querying HelloID Self service Products with Actions"
    foreach ($helloIDSelfServiceProductInScope in $helloIDSelfServiceProductsInScope) {
        #region Get objects with membership to Entra ID group
        try {
            $helloIDSelfServiceProductInScopeWithActionsObject = [PSCustomObject]@{
                productId   = $helloIDSelfServiceProductInScope.selfServiceProductGUID
                name        = $helloIDSelfServiceProductInScope.name
                description = $helloIDSelfServiceProductInScope.description
                code        = $helloIDSelfServiceProductInScope.code
                actions     = [System.Collections.ArrayList]@()
            }

            Write-Verbose "Querying actions of Product [$($helloIDSelfServiceProductInScope.selfServiceProductGUID)]"

            $splatParams = @{
                Method = "GET"
                Uri    = "products/$($helloIDSelfServiceProductInScope.selfServiceProductGUID)"
            }
            $helloIDSelfServiceProduct = (Invoke-HIDRestMethod @splatParams)

            # Add actions of all "grant" states
            $helloIDSelfServiceProductActions = $helloIDSelfServiceProduct.onRequest + $helloIDSelfServiceProduct.onApprove
            foreach ($helloIDSelfServiceProductAction in $helloIDSelfServiceProductActions) {
                $helloIDSelfServiceProductActionObject = [PSCustomObject]@{
                    actionGUID = $helloIDSelfServiceProductAction.id
                    name       = $helloIDSelfServiceProductAction.name
                    objectGUID = $helloIDSelfServiceProductInScope.selfServiceProductGUID
                }
                
                Hid-Write-Status -Event Success -Message "helloIDSelfServiceProductActionObject1 $($helloIDSelfServiceProductActionObject.objectGUID)"

                [void]$helloIDSelfServiceProductInScopeWithActionsObject.actions.Add($helloIDSelfServiceProductActionObject)
            }

            [void]$helloIDSelfServiceProductsInScopeWithActions.Add($helloIDSelfServiceProductInScopeWithActionsObject)

            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Success "Successfully queried actions of Product [$($helloIDSelfServiceProductInScope.selfServiceProductGUID)]. Result count: $(($helloIDSelfServiceProduct.actions | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying actions of Product [$($helloIDSelfServiceProductInScope.productId)]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get objects with with membership to AD group
    }

    # Filter for products with specified actions
    $helloIDSelfServiceProductsInScopeWithActionsInScope = $helloIDSelfServiceProductsInScopeWithActions | Where-Object { $PowerShellActionName -in $_.actions.name }

    Hid-Write-Status -Event Success -Message "Successfully queried HelloID Self service Products with Actions (after filtering for products with specified action only). Result count: $(($helloIDSelfServiceProductsInScopeWithActionsInScope.actions | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying HelloID Self service Products with Actions. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get actions of Product

#region Get HelloID Productassignments
try {
    Write-Verbose "Querying  Self service Productassignments from HelloID"

    $splatParams = @{
        Method   = "GET"
        Uri      = "product-assignment"
        PageSize = 1000
    }
    $helloIDSelfServiceProductassignments = Invoke-HIDRestMethod @splatParams

    # Filter for for productassignments of specified products
    $helloIDSelfServiceProductassignmentsInScope = $null
    # $helloIDSelfServiceProductassignmentsInScope = $helloIDSelfServiceProductassignments | Where-Object { $_.productGuid -in $helloIDSelfServiceProductsInScope.selfServiceProductGUID }
    $helloIDSelfServiceProductassignmentsInScope = $helloIDSelfServiceProductassignments | Where-Object { $_.productGuid -in $helloIDSelfServiceProductsInScopeWithActionsInScope.productId }

    $helloIDSelfServiceProductassignmentsInScopeGrouped = $helloIDSelfServiceProductassignmentsInScope | Group-Object -Property productGuid -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Self service Productassignments from HelloID (after filtering for productassignments of specified products only). Result count: $(($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service Productassignments from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Productassignments

Hid-Write-Status -Event Information -Message "------[Entra ID]-----------"  
#region Entra ID Groups and members
try {  
    $headers = New-AuthorizationHeaders -TenantId $EntraTenantId -ClientId $EntraAppID -ClientSecret $EntraAppSecret

    $properties = @(
        $entraIDGroupCorrelationProperty
        , "displayName"
        , "description"
        , "onPremisesSyncEnabled"
        , "groupTypes"
    )
    $select = "`$select=$($properties -join ",")"

    $m365GroupFilter = "groupTypes/any(c:c+eq+'Unified')"
    $securityGroupFilter = "NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true"
    $managableGroupsFilter = "`$filter=$m365GroupFilter or $securityGroupFilter"
  
    $entraIDQuerySplatParams = @{
        Uri         = "$($MSGraphBaseUri)/v1.0/groups?$managableGroupsFilter&$entraIDGroupsSearchFilter&$select&`$top=999&`$count=true"
        Headers     = $headers
        Method      = 'GET'
        ErrorAction = 'Stop'
    }

    $entraIDGroups = [System.Collections.ArrayList]@()
    $getEntraIDGroupsResponse = $null
    $getEntraIDGroupsResponse = Invoke-RestMethod @entraIDQuerySplatParams -Verbose:$false
    if ($getEntraIDGroupsResponse.value -is [array]) {
        [void]$entraIDGroups.AddRange($getEntraIDGroupsResponse.value)
    }
    else {
        [void]$entraIDGroups.Add($getEntraIDGroupsResponse.value)
    }

    while (![string]::IsNullOrEmpty($getEntraIDGroupsResponse.'@odata.nextLink')) {
        $entraIDQuerySplatParams = @{
            Uri         = $getEntraIDGroupsResponse.'@odata.nextLink'
            Headers     = $headers
            Method      = 'GET'
            ErrorAction = 'Stop'
        }
        $getEntraIDGroupsResponse = $null
        $getEntraIDGroupsResponse = Invoke-RestMethod @entraIDQuerySplatParams -Verbose:$false
        if ($getEntraIDGroupsResponse.value -is [array]) {
            [void]$entraIDGroups.AddRange($getEntraIDGroupsResponse.value)
        }
        else {
            [void]$entraIDGroups.Add($getEntraIDGroupsResponse.value)
        }
    }

    # Filter for groups that are in products
    $entraIDGroupsInScope = $entraIDGroups
    
    if (($entraIDGroupsInScope | Measure-Object).Count -eq 0) {
        throw "No Entra ID Groups have been found"
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Entra ID groups (after filtering for groups that are in products). Result count: $(($entraIDGroupsInScope | Measure-Object).Count)"

    # Get Entra ID Groupmemberships of groups
    try {
        if ($verboseLogging -eq $true) {
            Hid-Write-Status -Event Information -Message "Enhancing AD groups with members"
        }
        $entraIDGroupsInScope | Add-Member -MemberType NoteProperty -Name "members" -Value $null -Force
        $totalEntraIDGroupMembers = 0
        foreach ($entraIDGroup in $entraIDGroupsInScope) {
            try {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Information -Message "Querying Entra ID groupmembers of group [$($entraIDGroup.id)]"
                }

                $properties = @(
                    $entraIDUserCorrelationProperty
                    , "displayName"
                )
                $select = "`$select=$($properties -join ",")"
            
                $entraIDQuerySplatParams = @{
                    Uri         = "$($MSGraphBaseUri)/v1.0/groups/$($entraIDGroup.id)/members?&$select&`$top=999&`$count=true"
                    Headers     = $headers
                    Method      = 'GET'
                    ErrorAction = 'Stop'
                }
            
                $entraIDGroupmembers = [System.Collections.ArrayList]@()
                $getEntraIDGroupmembersResponse = $null
                $getEntraIDGroupmembersResponse = Invoke-RestMethod @entraIDQuerySplatParams -Verbose:$false
                if ($getEntraIDGroupmembersResponse.value -is [array]) {
                    [void]$entraIDGroupmembers.AddRange($getEntraIDGroupmembersResponse.value)
                }
                else {
                    [void]$entraIDGroupmembers.Add($getEntraIDGroupmembersResponse.value)
                }
            
                while (![string]::IsNullOrEmpty($getEntraIDGroupmembersResponse.'@odata.nextLink')) {
                    $entraIDQuerySplatParams = @{
                        Uri         = $getEntraIDGroupmembersResponse.'@odata.nextLink'
                        Headers     = $headers
                        Method      = 'GET'
                        ErrorAction = 'Stop'
                    }
                    $getEntraIDGroupmembersResponse = $null
                    $getEntraIDGroupmembersResponse = Invoke-RestMethod @entraIDQuerySplatParams -Verbose:$false
                    if ($getEntraIDGroupmembersResponse.value -is [array]) {
                        [void]$entraIDGroupmembers.AddRange($getEntraIDGroupmembersResponse.value)
                    }
                    else {
                        [void]$entraIDGroupmembers.Add($getEntraIDGroupmembersResponse.value)
                    }
                }

                # Filter for users that exist in HelloID
                $entraIDGroupMembersInScope = $null
                $entraIDGroupMembersInScope = $entraIDGroupmembers | Where-Object { $_.$entraIDUserCorrelationProperty -in $helloIDUsersInScope.$helloIDUserCorrelationProperty }

                # Set property of Entra ID group with members
                $entraIDGroup.members = $entraIDGroupMembersInScope

                foreach ($entraIDGroupmember in $entraIDGroupMembersInScope) {
                    $totalEntraIDGroupMembers++
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex

                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
                    Hid-Write-Status -Event Error -Message "Error querying Entra ID groupmembers of group [$($entraIDGroup.id)]. Error Message: $($errorMessage.AuditErrorMessage)"
                }
            }
        }

        Hid-Write-Status -Event Success -Message "Successfully enhanced Entra ID groups with members (after filtering for users that exist in HelloID). Result count: $($totalEntraIDGroupMembers)"
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

        throw "Error querying Entra ID groupmembers. Error Message: $($errorMessage.AuditErrorMessage)"
    }

    $entraIDGroupsGrouped = $entraIDGroupsInScope | Group-Object -Property $entraIDGroupCorrelationProperty -AsHashTable -AsString
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Entra ID groups that match filter [$($entraIDGroupsSearchFilter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Entra ID Groups and members

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete product assignments
try {
    $newProductAssignmentObjects = [System.Collections.ArrayList]@()
    $obsoleteProductAssignmentObjects = [System.Collections.ArrayList]@()
    $existingProductAssignmentObjects = [System.Collections.ArrayList]@()
    foreach ($product in $helloIDSelfServiceProductsInScopeWithActionsInScope) {
        if ($verboseLogging -eq $true) {
            Hid-Write-Status -Event Information -Message "Calculating new and obsolete product assignments for Product [$($product.name)]"
        }

        $entraIDGroupGuid = [Guid]::New(($product.code.replace("$ProductSkuPrefix", "")))
        $entraIDGroup = $null
        $entraIDGroup = $entraIDGroupsGrouped["$($entraIDGroupGuid)"]
        if (($entraIDGroup | Measure-Object).Count -eq 0) {
            Hid-Write-Status -Event Error -Message "No Entra ID group found with $entraIDGroupCorrelationProperty [$($entraIDGroupGuid)] for Product [$($product.name)]"
            continue
        }
        elseif (($entraIDGroup | Measure-Object).Count -gt 1) {
            Hid-Write-Status -Event Error -Message "Multiple Entra ID groups found with $entraIDGroupCorrelationProperty [$($entraIDGroupGuid)] for Product [$($product.name)]. Please correct this so the $entraIDGroupCorrelationProperty of the AD group is unique"
            continue
        }

        # Get Entra ID user objects for additional data to match to HelloID user
        $entraIDUsersInScope = $entraIDGroup.members
        
        # Get HelloID user objects to assign to the product
        $productUsersInScope = [System.Collections.ArrayList]@()
        foreach ($entraIDUser in $entraIDUsersInScope) {
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersInScopeGrouped[$entraIDUser.$entraIDUserCorrelationProperty]

            if (($helloIDUser | Measure-Object).Count -eq 0) {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "No HelloID user found with $helloIDUserCorrelationProperty [$($entraIDUser.$entraIDUserCorrelationProperty)] for Entra ID user [$($entraIDUser.distinguishedName)] for Product [$($product.name)]"
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
            $currentProductassignments = $helloIDSelfServiceProductassignmentsInScopeGrouped[$product.productId]
        }

        # Define assignments to grant
        $newProductassignments = $productUsersInScope | Where-Object { $_.userGuid -notin $currentProductassignments.userGuid }
        foreach ($newProductAssignment in $newProductassignments) {
            $newProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.productId)"
                productName            = "$($product.name)"
                userGuid               = "$($newProductAssignment.userGuid)"
                userName               = "$($newProductAssignment.userName)"
                source                 = "SyncEntraIDGroupMemberShipsToProductAssignments"
                executeApprovalActions = $false
            }

            [void]$newProductAssignmentObjects.Add($newProductAssignmentObject)
        }

        # Define assignments to revoke
        $obsoleteProductassignments = $currentProductassignments | Where-Object { $_.userGuid -notin $productUsersInScope.userGuid }
        foreach ($obsoleteProductassignment in $obsoleteProductassignments) { 
            $obsoleteProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.productId)"
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
                productGuid            = "$($product.productId)"
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
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Information -Message "Revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
            }
            
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
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$($totalEntraIDGroupMembers)] Entra ID groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$($totalEntraIDGroupMembers)] Entra ID groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$($totalEntraIDGroupMembers)] Entra ID groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$($totalEntraIDGroupMembers)] Entra ID groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$($totalEntraIDGroupMembers)] Entra ID groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$($totalEntraIDGroupMembers)] Entra ID groupmemberships to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
}
#endregion
