$patchInfo = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
$bitlockerInstalled = Get-Command manage-bde -ErrorAction SilentlyContinue

$serverRow = [PSCustomObject]@{
    DEVICE_ID          = "SRV-001"
    DEVICE_NAME        = "EHR-DATABASE-SERVER"
    DEVICE_TYPE        = "Server"
    ENCRYPTION_ENABLED = if ($bitlockerInstalled) { "Unknown - check manually" } else { "No - BitLocker not installed" }
    LAST_PATCH_DATE    = $patchInfo.InstalledOn.ToString("yyyy-MM-dd")
    IN_INVENTORY       = "Yes"
    VENDOR             = "ReCloud Systems Inc."
}

$serverRow | Export-Csv -Path "C:\server_inventory.csv" -NoTypeInformation
