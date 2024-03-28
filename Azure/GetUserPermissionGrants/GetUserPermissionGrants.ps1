# Before running this script you need to call Connect-MgGraph -TenantID <Your_Tenant_ID>
# Ensure you authenticate successfully before running this script!

# We will be using the Get-MgOauth2PermissionGrant command to get this information
# Id = OAuth2PermissionGrantId
# CLientId = 

#Initialize Array to store custom object with information about each permission grant
$myArray = @()

Get-MgOauth2PermissionGrant | ForEach-Object {
	#Add objects to the initial array
	$myArray += [pscustomobject]@{clientID=$_.ClientId; principalID=$_.PrincipalId; consentType=$_.ConsentType; scope=$_.scope}
}

#Initialize a new array to convert Ids into display names
$myNewArray = @()

#iterate through each ID and add the DisplayNames to the new array
$myArray | ForEach-Object {
	$clientID = (Get-MgDirectoryObjectById -Ids $_.clientID).AdditionalProperties.displayName
	if ($_.consentType -eq "AllPrincipals") {
		$myNewArray += [pscustomobject]@{clientID=$clientID; principalID=$PrincipalID; scopes=$_.scope}
	}
	elseif ($_.consentType -eq "Principal") {
		$PrincipalID = (Get-MgDirectoryObjectById -Ids $_.principalID).AdditionalProperties.displayName
		$myNewArray += [pscustomobject]@{clientID=$clientID; principalID=$PrincipalID; scopes=$_.scope}
	}
}
#Return the array
$myNewArray
