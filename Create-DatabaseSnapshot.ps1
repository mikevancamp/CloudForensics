Param(
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroup, # The target resource group
    
    [Parameter(Mandatory = $true)] 
    [string]
    $SQLServerName, # Only the name should be entered, not the whole URI

    [Parameter(Mandatory = $true)]
    [string]
    $SourceDatabase,

    [Parameter(Mandatory = $true)]
    [string]
    $Username,

    [Parameter(Mandatory = $true)]
    [string]
    $Password
)

Update-AzConfig -DisplayBreakingChangeWarning $false

$SnapshotPrefix = (Get-Date).toString('yyyyMMddHHmm')
$DatabaseName = "$SnapshotPrefix-$SourceDatabase"

$ReadOnlySQL = "ALTER DATABASE [$DatabaseName] SET READ_ONLY WITH NO_WAIT"
Connect-AzAccount -Identity

###### Create a database copy with timestamp ######
New-AzSqlDatabaseCopy -ResourceGroupName $ResourceGroup -ServerName $SQLServerName -DatabaseName "$SourceDatabase" `
 -CopyResourceGroupName $ResourceGroup -CopyServerName $SQLServerName -CopyDatabaseName $DatabaseName

###### Make the database read-only ######
$SQLServerInstance = "$SQLServerName.database.windows.net"
Invoke-SqlCmd -ServerInstance $SQLServerInstance -Username $Username -Password $Password -Query $ReadOnlySQL
