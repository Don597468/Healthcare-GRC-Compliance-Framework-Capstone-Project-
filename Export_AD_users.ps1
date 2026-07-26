$vendorMap = @{
    "ReCloud"  = "ReCloud Systems Inc."
    "Zark"     = "Zark Device Corp."
    "SparkNet" = "SparkNet IT Services Ltd."
}

$results = foreach ($ou in $vendorMap.Keys) {
    Get-ADUser -Filter * -SearchBase "OU=$ou,DC=casptone,DC=local" -Properties DisplayName, SamAccountName, whenChanged, info, Title |
    Select-Object @{N='USER_ID'; E={$_.SamAccountName}}, @{N='NAME'; E={$_.DisplayName}}, @{N='ROLE'; E={$_.Title}}, @{N='VENDOR'; E={$vendorMap[$ou]}}, @{N='SHARED_LOGIN'; E={ if ($_.SamAccountName -like "*shared*") {"Yes"} else {"No"} }}, @{N='REMOTE_MFA_ENABLED'; E={ if ($_.info -match "MFA:Yes") {"Yes"} else {"No"} }}, @{N='LAST_ACCESS_REVIEW_DATE'; E={ $_.whenChanged.ToString("yyyy-MM-dd") }}
}

$results | Export-Csv -Path "C:\ad_users_export.csv" -NoTypeInformation
