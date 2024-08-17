using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Interact with query parameters or the body of the request.
$name = $Request.Query.Name
if (-not $name) {
    $name = $Request.Body.Name
}

$body = "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."

if ($name) {
    $body = "Hello, $name. This HTTP triggered function executed successfully."
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
#Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
#    StatusCode = [HttpStatusCode]::OK
#    Body       = $body
#})

# Input bindings are passed in via param block.
#param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
#if ($Timer.IsPastDue) {
#    Write-Host "PowerShell timer is running late!"
#}
function Get-AADTenantDetail {
    <#
    .Description
    Gets the tenant details using the Microsoft Graph PowerShell Module with Managed Identity
    .Functionality
    Internal
    #>
    try {
        # Connect using Managed Identity

        $AllPolicies = Get-MgBetaIdentityConditionalAccessPolicy
        $SubscribedSku = Get-MgBetaSubscribedSku
        $UserCount = Get-MgBetaUserCount -ConsistencyLevel eventual
        $AuthZPolicies = Get-MgBetaPolicyAuthorizationPolicy

        # 5.3, 5.4
        $DirectorySettings = Get-MgBetaDirectorySetting

        ##### This block of code below supports 3.3, 3.4, 3.5
        $AuthenticationMethodPolicyRootObject = Get-MgBetaPolicyAuthenticationMethodPolicy
        # Fetch organization information using Microsoft Graph API
        $OrgInfo = Get-MgBetaOrganization

        $DomainSettings = Get-MgBetaDomain

        # Retrieve the initial domain
        $InitialDomain = $OrgInfo.VerifiedDomains | Where-Object { $_.isInitial }
        if (-not $InitialDomain) {
            $InitialDomain = "AAD: Domain Unretrievable"
        }

        # Construct the output object
        $AADTenantInfo = @{
            "DisplayName" = $OrgInfo.DisplayName
            "DomainName" = $InitialDomain.Name
            "TenantId" = $OrgInfo.Id
            "AADAdditionalData" = $OrgInfo
            "Policies" = $AllPolicies
            "Sku" = $SubscribedSku
            "UserCount" = $UserCount
            "AuthZPolicies" = $AuthZPolicies
            "DirectorySettings" = $DirectorySettings
            "AuthenticationMethod" = $AuthenticationMethodPolicyRootObject
            "Domain_settings" = $DomainSettings

        }

        # Convert to JSON format
        $AADTenantInfo = ConvertTo-Json @($AADTenantInfo) -Depth 4
        return $AADTenantInfo
    }
    catch {
        Write-Warning "Error retrieving Tenant details using Get-AADTenantDetail $($_)"
        $AADTenantInfo = @{
            "DisplayName" = "Error retrieving Display name"
            "DomainName" = "Error retrieving Domain name"
            "TenantId" = "Error retrieving Tenant ID"
            "AADAdditionalData" = "Error retrieving additional data"
        }

        # Convert to JSON format
        $AADTenantInfo = ConvertTo-Json @($AADTenantInfo) -Depth 4
        return $AADTenantInfo
    }

}
function Get-PrivilegedUser {
    <#
    .Description
    Gets the array of the highly privileged users
    .Functionality
    Internal
    #>
    param (
        [ValidateNotNullOrEmpty()]
        [switch]
        $TenantHasPremiumLicense
    )

    # A hashtable of privileged users
    $PrivilegedUsers = @{}
    # Get a list of the Id values for the privileged roles in the list above.
    # The Id value is passed to other cmdlets to construct a list of users assigned to privileged roles.
    $AADRoles = Get-MgBetaDirectoryRole -All -ErrorAction Stop 

    # Construct a list of privileged users based on the Active role assignments
    foreach ($Role in $AADRoles) {

        # Get a list of all the users and groups Actively assigned to this role
        $UsersAssignedRole = Get-MgBetaDirectoryRoleMember -All -ErrorAction Stop -DirectoryRoleId $Role.Id

        foreach ($User in $UsersAssignedRole) {

            $Objecttype = $User.AdditionalProperties."@odata.type" -replace "#microsoft.graph."

            if ($Objecttype -eq "user") {
                # If the user's data has not been fetched from graph, go get it
                if (-Not $PrivilegedUsers.ContainsKey($User.Id)) {
                    $AADUser = Get-MgBetaUser -ErrorAction Stop -UserId $User.Id
                    $PrivilegedUsers[$AADUser.Id] = @{"DisplayName"=$AADUser.DisplayName; "OnPremisesImmutableId"=$AADUser.OnPremisesImmutableId; "roles"=@()}
                }
                # If the current role has not already been added to the user's roles array then add the role
                if ($PrivilegedUsers[$User.Id].roles -notcontains $Role.DisplayName) {
                    $PrivilegedUsers[$User.Id].roles += $Role.DisplayName
                }
            }

            elseif ($Objecttype -eq "group") {
                # In this context $User.Id is a group identifier
                $GroupId = $User.Id
                # Get all of the group members that are Active assigned to the current role
                $GroupMembers = Get-MgBetaGroupMember -All -ErrorAction Stop -GroupId $GroupId

                foreach ($GroupMember in $GroupMembers) {
                    $Membertype = $GroupMember.AdditionalProperties."@odata.type" -replace "#microsoft.graph."
                    if ($Membertype -eq "user") {
                        # If the user's data has not been fetched from graph, go get it
                        if (-Not $PrivilegedUsers.ContainsKey($GroupMember.Id)) {
                            $AADUser = Get-MgBetaUser -ErrorAction Stop -UserId $GroupMember.Id
                            $PrivilegedUsers[$AADUser.Id] = @{"DisplayName"=$AADUser.DisplayName; "OnPremisesImmutableId"=$AADUser.OnPremisesImmutableId; "roles"=@()}
                        }
                        # If the current role has not already been added to the user's roles array then add the role
                        if ($PrivilegedUsers[$GroupMember.Id].roles -notcontains $Role.DisplayName) {
                            $PrivilegedUsers[$GroupMember.Id].roles += $Role.DisplayName
                        }
                    }
                }

                # If the premium license for PIM is there, process the users that are "member" of the PIM group as Eligible
                if ($TenantHasPremiumLicense) {
                    # Get the users that are assigned to the PIM group as Eligible members
                    $graphArgs = @{
                        "commandlet" = "Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance"
                        "queryParams" = @{'$filter' = "groupId eq '$GroupId'"}
                    }
                    $PIMGroupMembers = Invoke-GraphDirectly @graphArgs
                    foreach ($GroupMember in $PIMGroupMembers) {
                        # If the user is not a member of the PIM group (i.e. they are an owner) then skip them
                        if ($GroupMember.AccessId -ne "member") { continue }
                        $PIMEligibleUserId = $GroupMember.PrincipalId

                        # If the user's data has not been fetched from graph, go get it
                        if (-not $PrivilegedUsers.ContainsKey($PIMEligibleUserId)) {
                            $AADUser = Get-MgBetaUser -ErrorAction Stop -UserId $PIMEligibleUserId
                            $PrivilegedUsers[$PIMEligibleUserId] = @{"DisplayName"=$AADUser.DisplayName; "OnPremisesImmutableId"=$AADUser.OnPremisesImmutableId; "roles"=@()}
                        }
                        # If the current role has not already been added to the user's roles array then add the role
                        if ($PrivilegedUsers[$PIMEligibleUserId].roles -notcontains $Role.DisplayName) {
                            $PrivilegedUsers[$PIMEligibleUserId].roles += $Role.DisplayName
                        }
                    }
                }
            }
        }
    }

    # Process the Eligible role assignments if the premium license for PIM is there
    if ($TenantHasPremiumLicense) {
        # Get a list of all the users and groups that have Eligible assignments
        $graphArgs = @{
            "commandlet" = "Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance"
        }
        $AllPIMRoleAssignments = Invoke-GraphDirectly @graphArgs

        # Add to the list of privileged users based on Eligible assignments
        foreach ($Role in $AADRoles) {
            $PrivRoleId = $Role.RoleTemplateId
            # Get a list of all the users and groups Eligible assigned to this role
            $PIMRoleAssignments = $AllPIMRoleAssignments | Where-Object { $_.RoleDefinitionId -eq $PrivRoleId }

            foreach ($PIMRoleAssignment in $PIMRoleAssignments) {
                $UserObjectId = $PIMRoleAssignment.PrincipalId
                try {
                    $UserType = "user"

                    # If the user's data has not been fetched from graph, go get it
                    if (-Not $PrivilegedUsers.ContainsKey($UserObjectId)) {
                        $AADUser = Get-MgBetaUser -ErrorAction Stop -Filter "Id eq '$UserObjectId'"
                        $PrivilegedUsers[$AADUser.Id] = @{"DisplayName"=$AADUser.DisplayName; "OnPremisesImmutableId"=$AADUser.OnPremisesImmutableId; "roles"=@()}
                    }
                    # If the current role has not already been added to the user's roles array then add the role
                    if ($PrivilegedUsers[$UserObjectId].roles -notcontains $Role.DisplayName) {
                        $PrivilegedUsers[$UserObjectId].roles += $Role.DisplayName
                    }
                }
                # Catch the specific error which indicates Get-MgBetaUser does not find the user, therefore it is a group
                catch {
                    if ($_.FullyQualifiedErrorId.Contains("Request_ResourceNotFound")) {
                        $UserType = "group"
                    }
                    else {
                        throw $_
                    }
                }

                # This if statement handles when the object eligible assigned to the current role is a Group
                if ($UserType -eq "group") {
                    # Process the the users that are directly assigned to the group (not through PIM groups)
                    $GroupMembers = Get-MgBetaGroupMember -All -ErrorAction Stop -GroupId $UserObjectId
                    foreach ($GroupMember in $GroupMembers) {
                        $Membertype = $GroupMember.AdditionalProperties."@odata.type" -replace "#microsoft.graph."
                        if ($Membertype -eq "user") {
                            # If the user's data has not been fetched from graph, go get it
                            if (-Not $PrivilegedUsers.ContainsKey($GroupMember.Id)) {
                                $AADUser = Get-MgBetaUser -ErrorAction Stop -UserId $GroupMember.Id
                                $PrivilegedUsers[$AADUser.Id] = @{"DisplayName"=$AADUser.DisplayName; "OnPremisesImmutableId"=$AADUser.OnPremisesImmutableId; "roles"=@()}
                            }
                            # If the current role has not already been added to the user's roles array then add the role
                            if ($PrivilegedUsers[$GroupMember.Id].roles -notcontains $Role.DisplayName) {
                                $PrivilegedUsers[$GroupMember.Id].roles += $Role.DisplayName
                            }
                        }
                    }

                    # Get the users that are assigned to the PIM group as Eligible members
                    $graphArgs = @{
                        "commandlet" = "Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance"
                        "queryParams" = @{'$filter' = "groupId eq '$UserObjectId'"}
                    }
                    $PIMGroupMembers = Invoke-GraphDirectly @graphArgs
                    foreach ($GroupMember in $PIMGroupMembers) {
                        # If the user is not a member of the PIM group (i.e. they are an owner) then skip them
                        if ($GroupMember.AccessId -ne "member") { continue }
                        $PIMEligibleUserId = $GroupMember.PrincipalId

                        # If the user's data has not been fetched from graph, go get it
                        if (-not $PrivilegedUsers.ContainsKey($PIMEligibleUserId)) {
                            $AADUser = Get-MgBetaUser -ErrorAction Stop -UserId $PIMEligibleUserId
                            $PrivilegedUsers[$PIMEligibleUserId] = @{"DisplayName"=$AADUser.DisplayName; "OnPremisesImmutableId"=$AADUser.OnPremisesImmutableId; "roles"=@()}
                        }
                        # If the current role has not already been added to the user's roles array then add the role
                        if ($PrivilegedUsers[$PIMEligibleUserId].roles -notcontains $Role.DisplayName) {
                            $PrivilegedUsers[$PIMEligibleUserId].roles += $Role.DisplayName
                        }
                    }
                }
            }
        }
    }
    $PrivilegedUsers = ConvertTo-Json @($PrivilegedUsers) -Depth 4
    return $PrivilegedUsers
}

Write-Host "Connect AzAccount! TIME: $currentUTCtime"
Connect-AzAccount -Identity
Write-Host "Connect MgGraph TIME: $currentUTCtime"
Connect-MgGraph -Identity
Write-Host "Get-AADTenantDetails! TIME: $currentUTCtime"
$aad = Get-AADTenantDetail
Write-Host "Get-PrivilegedUsers! TIME: $currentUTCtime"
$priv = Get-PrivilegedUser
Write-Host "Disonnect-AzAccount! TIME: $currentUTCtime"
Disconnect-AzAccount

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body       = $aad +","+ $priv
})