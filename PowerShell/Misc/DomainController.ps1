param(
    $DomainName,
    $ComputerName,
    $Password
)



$NETBIOS = $DomainName.Split(".")[0]
$DB="C:\Windows\NTDS"
$Log="C:\Windows\NTDS"
$Sysvol="C:\Windows\Sysvol"
$SecurePassword=CONVERTTO-SecureString $Password -asplaintext -force

Install-Windowsfeature AD-Domain-Services -includeallsubfeature -IncludeManagementTools
Install-WindowsFeature DSC-Service -IncludeAllSubFeature -IncludeManagementTools

Import-Module ADDSDeployment

Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath $DB `
-DomainMode "Win2012R2" -DomainName $DomainName -DomainNetbiosName $NETBIOS `
-ForestMode "Win2012R2" -InstallDns:$true -LogPath $Log `
-NoRebootOnCompletion:$false -SysvolPath $Sysvol -Force:$true `
-SafeModeAdministratorPassword $SecurePassword


