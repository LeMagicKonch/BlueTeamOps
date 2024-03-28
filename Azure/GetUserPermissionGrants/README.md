This script will get all of your permission grants that users have given to apps and the scopes for each permission grant.

Purpose of this script is to ensure no apps have unwanted permission grants from users due to the rise in Azure environment attacks in which malicious actors create new apps and give the app permission grants to a compromised user to maintain persistance.

***NOTE: 
Before running this script you need to call Connect-MgGraph -TenantID <Your_Tenant_ID>
Ensure you authenticate successfully before running this script!
