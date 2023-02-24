Param(
    # Add when there are multiple resource groups, for this lab only one resource group is used
    # [Parameter(Mandatory = $true)]
    # [string]
    # $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]
    $VirtualMachineName
)

######################################### SOC Constants #####################################
$subId = '9b4e5031-850b-4baf-9fd9-760e8b20060f'     # Subscription ID
$ResourceGroupName = 'cloud-forensics'              # Resource Group Name
$destSAblob = 'socdisks'                            # Storage account for BLOB (immutable)
$destSAfile = 'soctempdisks'                        # Storage account for FILE share
$destTempShare = 'disks'                            # The temporary file share mounted on the hybrid worker
$destSAContainer = 'disks'                          # Container name of $destSAblob
$destKV = 'basicvault'                              # Key vault name to store a copy of the hashes

$targetLinuxDir = "/mount/$destSAfile/$destTempShare"             # Name dir where file share is mounted on
$snapshotPrefix = (Get-Date).toString('yyyyMMddHHmm') # The prefix of the snapshot to be created

Write-Output "Running on Hybrid Worker"

############################# Authenticating to Azure #############################
Disable-AzContextAutosave -Scope Process

Connect-AzAccount -Identity
############################# Snapshot the OS disk of target VM ##############################
Write-Output "#################################"
Write-Output "Snapshot the OS Disk of target VM"
Write-Output "#################################"

Get-AzSubscription -SubscriptionId $subId | Set-AzContext

$vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VirtualMachineName

$osdisk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $vm.StorageProfile.OsDisk.Name
$snapshot = New-AzSnapshotConfig -SourceUri $osdisk.id -CreateOption Copy -Location $vm.location
$snapshotName = $snapshotPrefix + "-" + $osdisk.name.Replace("_", "-")

New-AzSnapshot -ResourceGroupName $ResourceGroupName -Snapshot $snapshot -SnapshotName $snapshotName

##################### Copy the OS snapshot from source to file share and blob container ########################
Write-Output "#################################"
Write-Output "Copy the OS snapshot from source to file share and blob container"
Write-Output "#################################"

$snapSasUrl = Grant-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotName -DurationInSecond 7200 -Access Read
$targetStorageContextBlob = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $destSAblob).Context
$targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $destSAfile).Context

Write-Output "Start Copying Blob $snapshotName"
Start-AzStorageBlobCopy -AbsoluteUri $snapSasUrl.AccessSAS -DestContainer $destSAContainer -DestContext $targetStorageContextBlob -DestBlob "$snapshotName.vhd" -Force

Write-Output "Start Copying Fileshare"
Start-AzStorageFileCopy -AbsoluteUri $snapSasUrl.AccessSAS -DestShareName $destTempShare -DestContext $targetStorageContextFile -DestFilePath $snapshotName -Force

Write-Output "Waiting Fileshare Copy End"
Get-AzStorageFileCopyState -Context $targetStorageContextFile -ShareName $destTempShare -FilePath $snapshotName -WaitForComplete

# Linux hash version if you use a Linux Hybrid Runbook Worker
$diskpath = "$targetLinuxDir/$snapshotName"
Write-Output "Start Calculating HASH for $diskpath"
$hashfull = Invoke-Expression -Command "sha256sum $diskpath"
$hash = $hashfull.split(" ")[0]
Write-Output "Computed SHA-256: $hash"

# #################### Copy the OS BEK to the SOC Key Vault  ###################################
# $BEKurl = $osdisk.EncryptionSettingsCollection.EncryptionSettings.DiskEncryptionKey.SecretUrl
# Write-Output "#################################"
# Write-Output "OS Disk Encryption Secret URL: $BEKurl"
# Write-Output "#################################"
# if ($BEKurl) {
#     $sourcekv = $BEKurl.split("/")
#     $BEK = Get-AzKeyVaultSecret -VaultName $sourcekv[2].split(".")[0] -Name $sourcekv[4] -Version $sourcekv[5]
#     Write-Output "Key value: $BEK"
#     Set-AzKeyVaultSecret -VaultName $destKV -Name $snapshotName -SecretValue $BEK.SecretValue -ContentType "BEK" -Tag $BEK.Tags
# }

######## Copy the OS disk hash value in key vault and delete disk in file share ##################
Write-Output "#################################"
Write-Output "OS disk - Put hash value in Key Vault"
Write-Output "#################################"
$secret = ConvertTo-SecureString -String $hash -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $destKV -Name "$snapshotName-sha256" -SecretValue $secret -ContentType "text/plain"
$targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $destSAfile).Context
Remove-AzStorageFile -ShareName $destTempShare -Path $snapshotName -Context $targetStorageContextFile

############################ Snapshot the data disks, store hash and BEK #####################
$dsnapshotList = @()

foreach ($dataDisk in $vm.StorageProfile.DataDisks) {
    $ddisk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $dataDisk.Name
    $dsnapshot = New-AzSnapshotConfig -SourceUri $ddisk.Id -CreateOption Copy -Location $vm.location
    $dsnapshotName = $snapshotPrefix + "-" + $ddisk.name.Replace("_", "-")
    $dsnapshotList += $dsnapshotName
    Write-Output "Snapshot data disk name: $dsnapshotName"
    New-AzSnapshot -ResourceGroupName $ResourceGroupName -Snapshot $dsnapshot -SnapshotName $dsnapshotName

    Write-Output "#################################"
    Write-Output "Copy the Data Disk $dsnapshotName snapshot from source to blob container"
    Write-Output "#################################"

    $dsnapSasUrl = Grant-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $dsnapshotName -DurationInSecond 72000 -Access Read
    $targetStorageContextBlob = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $destSAblob).Context
    $targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $destSAfile).Context

    Write-Output "Start Copying Blob $dsnapshotName"
    Start-AzStorageBlobCopy -AbsoluteUri $dsnapSasUrl.AccessSAS -DestContainer $destSAContainer -DestContext $targetStorageContextBlob -DestBlob "$dsnapshotName.vhd" -Force

    Write-Output "Start Copying Fileshare"
    Start-AzStorageFileCopy -AbsoluteUri $dsnapSasUrl.AccessSAS -DestShareName $destTempShare -DestContext $targetStorageContextFile -DestFilePath $dsnapshotName -Force

    Write-Output "Waiting Fileshare Copy End"
    Get-AzStorageFileCopyState -Context $targetStorageContextFile -ShareName $destTempShare -FilePath $dsnapshotName -WaitForComplete

    $ddiskpath = "$targetLinuxDir/$dsnapshotName"
    Write-Output "Start Calculating HASH for $ddiskpath"

    $dhashfull = Invoke-Expression -Command "sha256sum $ddiskpath"
    $dhash = $dhashfull.split(" ")[0]

    Write-Output "Computed SHA-256: $dhash"


    $BEKurl = $ddisk.EncryptionSettingsCollection.EncryptionSettings.DiskEncryptionKey.SecretUrl
    Write-Output "#################################"
    Write-Output "Disk Encryption Secret URL: $BEKurl"
    Write-Output "#################################"
    if ($BEKurl) {
        $sourcekv = $BEKurl.Split("/")
        $BEK = Get-AzKeyVaultSecret -VaultName  $sourcekv[2].split(".")[0] -Name $sourcekv[4] -Version $sourcekv[5]
        Write-Output "Key value: $BEK"
        Write-Output "Secret name: $dsnapshotName"
        Set-AzKeyVaultSecret -VaultName $destKV -Name $dsnapshotName -SecretValue $BEK.SecretValue -ContentType "BEK" -Tag $BEK.Tags
    }
    else {
        Write-Output "Disk not encrypted"
    }


    Write-Output "#################################"
    Write-Output "Data disk - Put hash value in Key Vault"
    Write-Output "#################################"
    $Secret = ConvertTo-SecureString -String $dhash -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $destKV -Name "$dsnapshotName-sha256" -SecretValue $Secret -ContentType "text/plain"
    $targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $destSAfile).Context
    Remove-AzStorageFile -ShareName $destTempShare -Path $dsnapshotName -Context $targetStorageContextFile

}

################################## Delete all source snapshots ###############################
Get-AzStorageBlobCopyState -Blob "$snapshotName.vhd" -Container $destSAContainer -Context $targetStorageContextBlob -WaitForComplete
foreach ($dsnapshotName in $dsnapshotList) {
    Get-AzStorageBlobCopyState -Blob "$dsnapshotName.vhd" -Container $destSAContainer -Context $targetStorageContextBlob -WaitForComplete
}

Revoke-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotName
Remove-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotname -Force
foreach ($dsnapshotName in $dsnapshotList) {
    Revoke-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $dsnapshotName
    Remove-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $dsnapshotname -Force
}