<#
.Synopsis
Deploy a full Ericom Connect enviroment 

.NOTES   
Name: EricomConnectAutomation
Author: Erez Pasternak
Version: 1.0
DateCreated: 2016-05-29
DateUpdated: 2016-06-02
#>
param (
	[switch]$PrepareSystem = $true
)

Write-Output "AutoStart: $AutoStart"

# loads the BitsTransfer Module
Import-Module BitsTransfer
Write-Host "BitsTransfer Module is loaded"

# Settings Section
# Ericom Connect installer location   
$InstallerName = "EricomConnectPOC.exe"
$EC_download_url_or_unc = "https://www.ericom.com/demos/"+ $InstallerName 
$EC_local_path = "C:\Windows\Temp\" + $InstallerName

# Active Directory 
$domainName = "test.local"
$AdminUser = "admin@test.local"
$AdminPassword = "admin"

# Ericom Connect Grid Setting
$GridName = $env:computername + (Get-Random -Minimum 0 -Maximum 999)
$HostOrIp = (Get-NetIPAddress -AddressFamily IPv4)[0].IPAddress # [System.Net.Dns]::GetHostByName((hostname)).HostName
$DatabaseServer = $env:computername+"\ERICOMCONNECTDB"
$DatabaseName = $GridName
$LookUpHosts = $HostOrIp

# E-mail Settings
$To = "erez.pasternak@ericom.com"
$externalFqdn = [System.Net.Dns]::GetHostByName((hostname)).HostName




# Internal Code - DO NOT CHANGE  
$global:adminApi = $null
$global:adminSessionId = $null

$ConnectConfigurationToolPath = "\Ericom Software\Ericom Connect Configuration Tool\EricomConnectConfigurationTool.exe"
$UseWinCredentials = "true"
$SaUser = ""
$SaPassword = ""

$emailTemplate = "WebServer\DaaS\emails\ready.html"
$From = "daas@ericom.com"
$SMTPServer = "ericom-com.mail.protection.outlook.com"
$SMTPSUser = "daas@ericom.com"
$SMTPasswordUser = "admin"
$SMTPPort = 25


function Start-EricomConnection
{
	$Assem = Import-EricomLib
	
	$regularUser = New-Object Ericom.CloudConnect.Utilities.SpaceCredentials("regularUser")
	$_adminApi = [Ericom.MegaConnect.Runtime.XapApi.AdministrationProcessingUnitClassFactory]::GetInstance($regularUser)
	
	return $_adminApi
}

function EricomConnectConnector()
{
    if ( $adminSessionId -eq $null)
    {
        $_adminSessionId = ($adminApi.CreateAdminsession($AdminUser, $AdminPassword, "rooturl", "en-us")).AdminSessionId 
        return $_adminSessionId
    }
}

function Download-EricomConnect()
{
	New-Item -Path "C:\Download-EricomConnect" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Download-EricomConnect  -- Start"
	
	#if we have an installer in the localpath we will use it and not download
	
	if (!(Test-Path $EC_local_path))
	{
		Write-Output "Downloading $EC_download_url_or_unc"
		Start-BitsTransfer -Source $EC_download_url_or_unc -Destination $EC_local_path -ErrorVariable DownloadError
	}
	
	if (!(Test-Path $EC_local_path))
	{
		$mail_error = "Failed to Download " + $EC_download_url_or_unc  + "<br><i>"+ $DownloadError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
		exit
	}
	Write-Output "Download-EricomConnect  -- End"
}

function Install-SingleMachine()
{
	New-Item -Path "C:\Install-SingleMachine" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Ericom Connect POC installation has been started."
	$exitCode = (Start-Process -Filepath $EC_local_path -NoNewWindow -ArgumentList "/silent LAUNCH_CONFIG_TOOL=False" -Wait -Passthru).ExitCode
	if ($exitCode -eq 0)
	{
		Write-Output "Ericom Connect Grid Server has been succesfuly installed."
	}
	else
	{
		$installError = "Ericom Connect Grid Server could not be installed. Exit Code: " +  $exitCode
		$mail_error = "Failed to Install " + $EC_local_path  + "<br><i>"+ $installError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
		exit
	}
	Write-Output "Ericom Connect POC installation has been endded."
}


function Config-CreateGrid()
{
	New-Item -Path "C:\Config-CreateGrid" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Ericom Connect Grid configuration has been started."
	
	$_adminUser = $AdminUser
	$_adminPass = $AdminPassword
	$_gridName = $GridName
	$_hostOrIp = $HostOrIp
	$_saUser = $SaUser
	$_saPass = $SaUser
	$_databaseServer = $DatabaseServer
	$_databaseName = $DatabaseName
	
	$configPath = Join-Path $env:ProgramFiles -ChildPath $ConnectConfigurationToolPath.Trim()
	
	# in case we have a database allready, we will delete it before creating it again
	DeleteDatabase
	
	if ($UseWinCredentials -eq $true)
	{
		Write-Output "Configuration mode: with windows credentials"
		$args = " NewGrid /AdminUser $_adminUser /AdminPassword $_adminPass /GridName $_gridName /HostOrIp $_hostOrIp /DatabaseServer $_databaseServer /DatabaseName $_databaseName /UseWinCredForDBAut /LookUpHosts $LookUpHosts /disconnect "
	}
	else
	{
		Write-Output "Configuration mode: without windows credentials"
		$args = " NewGrid /AdminUser $_adminUser /AdminPassword $_adminPass /GridName $_gridName /SaDatabaseUser $_saUser /SaDatabasePassword $_saPass /DatabaseServer $_databaseServer /LookUpHosts $LookUpHosts /disconnect /noUseWinCredForDBAut"
	}
	
	$baseFileName = [System.IO.Path]::GetFileName($configPath);
	$folder = Split-Path $configPath;
	cd $folder;
	Write-Output "List of ARGS"
	Write-Output "$args"
	Write-Output "base filename"
	Write-Output "$baseFileName"
  	
    $exitCode = (Start-Process -Filepath "$baseFileName" -ArgumentList "$args" -Wait -Passthru).ExitCode
	if ($exitCode -eq 0)
	{
		Write-Output "Ericom Connect Grid Server has been succesfuly configured."
	}
	else
	{
		$GridConfigError = "Ericom Connect Grid Server could not be configured. Exit Code: " +  $exitCode
		$mail_error = "Failed to Configure Ericom Connect Grid <br><i>"+ $GridConfigError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
        exit
	}
  
    $global:adminApi = Start-EricomConnection
    $global:adminSessionId = EricomConnectConnector
	Write-Output "Ericom Connect Grid configuration has been ended."
    
}

# Remove the security settings of IE 
function Disable-IEESC
{
	$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
	$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
	Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
	Stop-Process -Name Explorer
	Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}

# Allow Multiple Sessions Per User
function AllowMultipleSessionsPerUser
{
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fSingleSessionPerUser" -Value 0
}

# Test if admin
function Test-IsAdmin() 
{
    # Get the current ID and its security principal
    $windowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsID)
 
    # Get the Admin role security principal
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    # Are we an admin role?
    if ($windowsPrincipal.IsInRole($adminRole))
    {
        $true
    }
    else
    {
        $false
    }
}

Function Show-MessageBox{

	Param(
	[Parameter(Mandatory=$True)][Alias('M')][String]$Msg,
	[Parameter(Mandatory=$False)][Alias('T')][String]$Title = "",
	[Parameter(Mandatory=$False)][Alias('OC')][Switch]$OkCancel,
	[Parameter(Mandatory=$False)][Alias('OCI')][Switch]$AbortRetryIgnore,
	[Parameter(Mandatory=$False)][Alias('YNC')][Switch]$YesNoCancel,
	[Parameter(Mandatory=$False)][Alias('YN')][Switch]$YesNo,
	[Parameter(Mandatory=$False)][Alias('RC')][Switch]$RetryCancel,
	[Parameter(Mandatory=$False)][Alias('C')][Switch]$Critical,
	[Parameter(Mandatory=$False)][Alias('Q')][Switch]$Question,
	[Parameter(Mandatory=$False)][Alias('W')][Switch]$Warning,
	[Parameter(Mandatory=$False)][Alias('I')][Switch]$Informational,
    [Parameter(Mandatory=$False)][Alias('TM')][Switch]$TopMost)

	#Set Message Box Style
	IF($OkCancel){$Type = 1}
	Elseif($AbortRetryIgnore){$Type = 2}
	Elseif($YesNoCancel){$Type = 3}
	Elseif($YesNo){$Type = 4}
	Elseif($RetryCancel){$Type = 5}
	Else{$Type = 0}
	
	#Set Message box Icon
	If($Critical){$Icon = 16}
	ElseIf($Question){$Icon = 32}
	Elseif($Warning){$Icon = 48}
	Elseif($Informational){$Icon = 64}
	Else { $Icon = 0 }
	
	#Loads the WinForm Assembly, Out-Null hides the message while loading.
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	
	If ($TopMost)
	{
		#Creates a Form to use as a parent
		$FrmMain = New-Object 'System.Windows.Forms.Form'
		$FrmMain.TopMost = $true
		
		#Display the message with input
		$Answer = [System.Windows.Forms.MessageBox]::Show($FrmMain, $MSG, $TITLE, $Type, $Icon)
		
		#Dispose of parent form
		$FrmMain.Close()
		$FrmMain.Dispose()
	}
	Else
	{
		#Display the message with input
		$Answer = [System.Windows.Forms.MessageBox]::Show($MSG , $TITLE, $Type, $Icon)			
	}
	
	#Return Answer
	Return $Answer
}
# Get UNC path from mapped drive
function Get-UNCFromPath
{
   Param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
    [String]
    $Path)

    if ($Path.Contains([io.path]::VolumeSeparatorChar)) 
    {
        $psdrive = Get-PSDrive -Name $Path.Substring(0, 1) -PSProvider 'FileSystem'

        # Is it a mapped drive?
        if ($psdrive.DisplayRoot) 
        {
            $Path = $Path.Replace($psdrive.Name + [io.path]::VolumeSeparatorChar, $psdrive.DisplayRoot)
        }
    }

    return $Path
 }


# Relaunch the script if not admin
function Invoke-RequireAdmin
{
    Param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
    [System.Management.Automation.InvocationInfo]
    $MyInvocation)

    if (-not (Test-IsAdmin))
    {
        # Get the script path
		
        $scriptPath = $MyInvocation.MyCommand.Path
	
        $scriptPath = Get-UNCFromPath -Path $scriptPath
	
        # Need to quote the paths in case of spaces
        $scriptPath = '"' + $scriptPath + '"'
	
        # Build base arguments for powershell.exe
        [string[]]$argList = @('-NoLogo -NoProfile', '-ExecutionPolicy Bypass', '-File', $scriptPath)

        # Add 
        $argList += $MyInvocation.BoundParameters.GetEnumerator() | Foreach {"-$($_.Key)", "$($_.Value)"}
        $argList += $MyInvocation.UnboundArguments

        try
        {    
            $process = Start-Process PowerShell.exe -PassThru -Verb Runas -WorkingDirectory $pwd -ArgumentList $argList
            exit $process.ExitCode
        }
        catch {}

        # Generic failure code
        exit 1 
    }
}
Function Get-PendingReboot
{
<#
.SYNOPSIS
    Gets the pending reboot status on a local or remote computer.

.DESCRIPTION
    This function will query the registry on a local or remote computer and determine if the
    system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
    Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
    CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
    and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
	
    CBServicing = Component Based Servicing (Windows 2008+)
    WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
    CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
    PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
    PendFileRename = PendingFileRenameOperations (Windows 2003+)
    PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                     Virus leverage this key for def/dat removal, giving a false positive PendingReboot

.PARAMETER ComputerName
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER ErrorLog
    A single path to send error data to a log file.

.EXAMPLE
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
	
    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
    -------- ----------- ------------- ------------ -------------- -------------- -------------
    DC01           False         False                       False                        False
    DC02           False         False                       False                        False
    FS01           False         False                       False                        False

    This example will capture the contents of C:\ServerList.txt and query the pending reboot
    information from the systems contained in the file and display the output in a table. The
    null values are by design, since these systems do not have the SCCM 2012 client installed,
    nor was the PendingFileRenameOperations value populated.

.EXAMPLE
    PS C:\> Get-PendingReboot
	
    Computer           : WKS01
    CBServicing        : False
    WindowsUpdate      : True
    CCMClient          : False
    PendComputerRename : False
    PendFileRename     : False
    PendFileRenVal     : 
    RebootPending      : True
	
    This example will query the local machine for pending reboot information.
	
.EXAMPLE
    PS C:\> $Servers = Get-Content C:\Servers.txt
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
	
    This example will create a report that contains pending reboot information.

.LINK
    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
	
    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    SCCM 2012/CCM_ClientSDK:
    http://msdn.microsoft.com/en-us/library/jj902723.aspx

.NOTES
    Author:  Brian Wilhite
    Email:   bcwilhite (at) live.com
    Date:    29AUG2012
    PSVer:   2.0/3.0/4.0/5.0
    Updated: 27JUL2015
    UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
             Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
             Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
             Added CCMClient property - Used with SCCM 2012 Clients only
             Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
             Removed $Data variable from the PSObject - it is not needed
             Bug with the way CCMClientSDK returned null value if it was false
             Removed unneeded variables
             Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
             Removed .Net Registry connection, replaced with WMI StdRegProv
             Added ComputerPendingRename
#>

[CmdletBinding()]
param(
	[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[Alias("CN","Computer")]
	[String[]]$ComputerName="$env:COMPUTERNAME",
	[String]$ErrorLog
	)

Begin {  }## End Begin Script Block
Process {
  Foreach ($Computer in $ComputerName) {
	Try {
	    ## Setting pending values to false to cut down on the number of else statements
	    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                        
	    ## Setting CBSRebootPend to null since not all versions of Windows has this value
	    $CBSRebootPend = $null
						
	    ## Querying WMI for build version
	    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

	    ## Making registry connection to the local/remote computer
	    $HKLM = [UInt32] "0x80000002"
	    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
						
	    ## If Vista/2008 & Above query the CBS Reg Key
	    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
		    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
		    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
	    }
							
	    ## Query WUAU from the registry
	    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
	    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
	    ## Query PendingFileRenameOperations from the registry
	    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
	    $RegValuePFRO = $RegSubKeySM.sValue

	    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
	    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
	    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

	    ## Query ComputerName and ActiveComputerName from the registry
	    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
	    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

	    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
	        $CompPendRen = $true
	    }
						
	    ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
	    If ($RegValuePFRO) {
		    $PendFileRename = $true
	    }

	    ## Determine SCCM 2012 Client Reboot Pending Status
	    ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
	    $CCMClientSDK = $null
	    $CCMSplat = @{
	        NameSpace='ROOT\ccm\ClientSDK'
	        Class='CCM_ClientUtilities'
	        Name='DetermineIfRebootPending'
	        ComputerName=$Computer
	        ErrorAction='Stop'
	    }
	    ## Try CCMClientSDK
	    Try {
	        $CCMClientSDK = Invoke-WmiMethod @CCMSplat
	    } Catch [System.UnauthorizedAccessException] {
	        $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
	        If ($CcmStatus.Status -ne 'Running') {
	            Write-Warning "$Computer`: Error - CcmExec service is not running."
	            $CCMClientSDK = $null
	        }
	    } Catch {
	        $CCMClientSDK = $null
	    }

	    If ($CCMClientSDK) {
	        If ($CCMClientSDK.ReturnValue -ne 0) {
		        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
		    }
		    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
		        $SCCM = $true
		    }
	    }
            
	    Else {
	        $SCCM = $null
	    }

	    ## Creating Custom PSObject and Select-Object Splat
	    $SelectSplat = @{
	        Property=(
	            'Computer',
	            'CBServicing',
	            'WindowsUpdate',
	            'CCMClientSDK',
	            'PendComputerRename',
	            'PendFileRename',
	            'PendFileRenVal',
	            'RebootPending'
	        )}
	    New-Object -TypeName PSObject -Property @{
	        Computer=$WMI_OS.CSName
	        CBServicing=$CBSRebootPend
	        WindowsUpdate=$WUAURebootReq
	        CCMClientSDK=$SCCM
	        PendComputerRename=$CompPendRen
	        PendFileRename=$PendFileRename
	        PendFileRenVal=$RegValuePFRO
	        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
	    } | Select-Object @SelectSplat

	} Catch {
	    Write-Warning "$Computer`: $_"
	    ## If $ErrorLog, log the file to a user specified location/path
	    If ($ErrorLog) {
	        Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
	    }				
	}			
  }## End Foreach ($Computer in $ComputerName)			
}## End Process

End {  }## End End

}## End Function Get-PendingReboot
function Expand-ZIPFile($file, $destination)
{
	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($file)
	New-Item -ItemType Directory -Path $destination -Force -ErrorAction SilentlyContinue
	
	foreach ($item in $zip.items())
	{
		$shell.Namespace($destination).copyhere($item, 16 + 1024)
	}
}

function ConfigureFirewall
{
	Import-Module NetSecurity
	Set-NetFirewallProfile -Profile Domain -Enabled False
}
#David - can we fix it for single machine install - just to add the Domain users to the local RemoteDesktopUsers ?

function AddUsersToRemoteDesktopGroup
{
	$baseADGroupRDP = "Domain Users"
	Invoke-Command { param ([String]$RDPGroup) net localgroup "Remote Desktop Users" "$RDPGroup" /ADD } -computername "localhost" -ArgumentList "$baseADGroupRDP"
	
}
function DeleteDatabase
{
	#import SQL Server module
    $env:PSModulePath = $env:PSModulePath + ";C:\Program Files (x86)\Microsoft SQL Server\120\Tools\PowerShell\Modules"
	Import-Module SQLPS -DisableNameChecking
 
	#your SQL Server Instance Name
	$SQLInstanceName = "localhost\ERICOMCONNECTDB"
	
	$Server = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $SQLInstanceName
	
	#create SMO handle to your database
	$DBObject = $Server.Databases[$DatabaseName]
 
	#check database exists on server
	if ($DBObject)
	{
		Write-Output "Deleting Database named $DatabaseName"
		#instead of drop we will use KillDatabase
		#KillDatabase drops all active connections before dropping the database.
		$Server.KillDatabase($DatabaseName)
	}
}
function CheckDomainRole
{
	# Get-ComputerRole.ps1
	$ComputerName = "localhost"
	
	$role = @{
		0 = "Stand alone workstation";
		1 = "Member workstation";
		2 = "Stand alone server";
		3 = "Member server";
		4 = "Back-up domain controller";
		5 = "Primary domain controller"
	}
	[int32]$myRole = (Get-WmiObject -Class win32_ComputerSystem -ComputerName $ComputerName).DomainRole
	Write-Host "$ComputerName is a $($role[$myRole]), role type $myrole"

	$response = $true;
	if ($myRole -eq 0 -or $myRole -eq 2)
	{
		Write-Warning "The machine should be in a domain!";
		$response = $false;
		
		$mail_error = "Computer " + (hostname) + "Is not part of a Domain, Please join to a Domain and try again"
		SendErrorMail  -Error "$mail_error"
        Exit 
	}
	return $response;
}

function CheckDNSConflict 
{
	$IP = (Get-NetIPAddress -AddressFamily IPv4)[0].IPAddress
	$Name = [System.Net.Dns]::GetHostByName((hostname)).HostName
	$IP_From_Name = [System.Net.Dns]::GetHostbyAddress((Get-NetIPAddress -AddressFamily IPv4)[0].IPAddress).HostName
	if ($IP_From_Name -ne $Name)
	{
    	# we have DNS problem
    	Write-Output "IP is          : $IP"
    	Write-Output "Name is        : $Name"
    	Write-Output "IP from Nams is: $IP_From_Name"
		$mail_error = "DNS problem detacted,<br>Computer IP is: "+ $IP + "<br>Computer DNS name is: "+ $Name + "<br> Computer name by IP is: "+ $IP_From_Name +"<br> Please refresh your DNS setting and try again"
		SendErrorMail  -Error "$mail_error"
    	exit
	}	
}
function CheckDNSWithPing
{
	$test1 = (Test-Connection -ComputerName (hostname) -Count 1 -erroraction Stop).IPV4Address.IPAddressToString
	$test2 = (Test-Connection -ComputerName ([System.Net.Dns]::GetHostByName((hostname)).HostName) -Count 1 -erroraction Stop).IPV4Address.IPAddressToString

	if ($test1 -ne $test2)
	{
		$DNS_error = "DNS problem detacted,<br>Ping by short name ("+ (hostname) + ") resolved to "+ $test1 + "<br>Ping by DNS name ("+ ([System.Net.Dns]::GetHostByName((hostname)).HostName) + ") resolved to "+ $test2 +"<br> Please refresh your DNS setting and try again"
    	Write-Output "$DNS_Error"
    	SendErrorMail  -Error "$DNS_error"
		exit
	}
}
Function Import-EricomLib
{
	$XAPPath = "C:\Program Files\Ericom Software\Ericom Connect Configuration Tool\"
	
	function Get-ScriptDirectory
	{
		$Invocation = (Get-Variable MyInvocation -Scope 1).Value
		Split-Path $Invocation.MyCommand.Path
	}
	
	$MegaConnectRuntimeApiDll = Join-Path ($XAPPath)  "MegaConnectRuntimeXapApi.dll"
	$CloudConnectUtilitiesDll = Join-Path ($XAPPath)  "CloudConnectUtilities.dll"
	
	
	add-type -Path (
	$MegaConnectRuntimeApiDll,
	$CloudConnectUtilitiesDll
	)
                                                                                                                    `
	$Assem = (
	$MegaConnectRuntimeApiDll,
	$CloudConnectUtilitiesDll
	)
	
	return $Assem
}


function CreateUser
{
	param (
		[Parameter()]
		[String]$userName,
		[Parameter()]
		[String]$password,
		[Parameter()]
		[String]$domainName = $domainName
	)
	
	$baseADGroupRDP = "Domain Users"
	
	$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
	$AdminSecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
	$AdminCredentials = New-Object System.Management.Automation.PSCredential ($AdminUser, $AdminSecurePassword);
    $UserUPN = $userName + "@" + $domainName
	
	try
	{
		Write-Host "Creating new AD user <<$username>>" -ForegroundColor Green
        $current = Get-ADUser -Server $domainName -Credential $AdminCredentials -Filter {sAMAccountName -eq $userName}
        
        If ($current -eq $null)
        {
		    New-ADUser -Server $domainName -PasswordNeverExpires $true -SamAccountName $userName -Name "$userName" -UserPrincipalName $UserUPN -Credential $AdminCredentials -Enabled $true -Verbose -AccountPassword $securePassword
        }
	}
	catch
	{
		Write-Warning "Could not create AD User: $userName"
		Write-Error $_.Exception.Message
	}
	try
	{
		#  Add-ADGroupMember -Server $domainName -Identity (Get-ADGroup $baseADGroupRDP -Server $domainName -Credential $AdminCredentials ) -Members $userName -Credential $AdminCredentials
	}
	catch
	{
		Write-Warning "Could not add $userName to `"$baseADGroupRDP`" AD group"
		Write-Error $_.Exception.Message
	}
}
# addes an application into Ericom Connect
Function AddApplication
{
	param (

        [string]$DisplayName,
		[Parameter()]
        [string]$applicationName,
		[Parameter()]
		[bool]$DesktopShortcut = $true,
        [Parameter()]
		[bool]$ForceUniqeApps = $true,
        [Parameter()]
		[bool]$StartMenuShortcut = $true
	)
	
    EricomConnectConnector
	$foundApp = CheckIfAppOrDesktopAreInConnect -applicationName $applicationName
    if ($ForceUniqeApps -eq $true -And $foundApp -ne $null)
        {
            return 
        }

	$response = $null;
	
	$RemoteHostList = $adminApi.RemoteHostStatusSearch($adminSessionId, "Running", "", "100", "100", "0", "", "true", "true")
	
	function FlattenFilesForDirectory ($browsingFolder, $rremoteAgentId, $rremoteHostId)
	{
		foreach ($browsingItem in $browsingFolder.Files.Values)
		{
			if (($browsingItem.Label -eq $applicationName))
			{
				$resourceDefinition = $adminApi.CreateResourceDefinition($adminSessionId, $applicationName)
				
				$val1 = $resourceDefinition.ConnectionProperties.GetLocalPropertyValue("remoteapplicationmode")
				$val1.LocalValue = $true
				$val1.ComputeBy = "Literal"
				
				$val2 = $resourceDefinition.ConnectionProperties.GetLocalPropertyValue("alternate_S_shell")
				$val2.LocalValue = '"' + $browsingItem.Path + $browsingItem.Name + '"'
				$val2.ComputeBy = "Literal"
				$val2.LocalValue
				
				$val3 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("IconLength")
				$val3.LocalValue = $browsingItem.ApplicationString.Length
				$val3.ComputeBy = "Literal"

                $valS = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("ShortcutDesktop")
				$valS.LocalValue = $DesktopShortcut
				$valS.ComputeBy = "Literal"
				
				$val4 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("IconString")
				$val4.LocalValue = $browsingItem.ApplicationString
				$val4.ComputeBy = "Literal"
				
				$val5 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("DisplayName")
				$val5.LocalValue = $applicationName
				$val5.ComputeBy = "Literal"
				
                $val6 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("ShortcutMenuAccessPad")
				$val6.LocalValue = $StartMenuShortcut
			    $val6.ComputeBy = "Literal"

				$response = @{ }
				try
				{
					$adminApi.AddResourceDefinition($adminSessionId, $resourceDefinition, "true")
					
					$response = @{
						status = "OK"
						success = "true"
						id = $resourceDefinition.ResourceDefinitionId
						message = "The resource has been successfuly published."
					}
				}
				catch [Exception]
				{
					$response = @{
						status = "ERROR"
						message = $_.Exception.Message
					}
				}
				return $response
			}
		}
		
		foreach ($directory in $browsingFolder.SubFolders.Values)
		{
			FlattenFilesForDirectory($directory);
		}
	}
	
	
	foreach ($RH in $RemoteHostList)
	{
		""
		""
		$RH.SystemInfo.ComputerName
		"____________"
		""
		$browsingFolder = $adminApi.SendCustomRequestStandaloneServer($adminSessionId,
		$RH.RemoteAgentId,
		[Ericom.MegaConnect.Runtime.XapApi.StandaloneServerRequestType]::HostAgentApplications,
		"null",
		"false",
		"999999999")
		#$browsingFolder
		FlattenFilesForDirectory ($browsingFolder, $RH.RemoteAgentId, $RH.RemoteHostId)
		if ($goon -eq $false)
		{
			return
		}
	}
}
# addes a desktop to Ericom Connect
function AddDesktop
{
	param (
		[string]$aliasName,
		[Parameter()]
		[bool]$desktopShortcut = $false,
        [Parameter()]
		[bool]$ForceUniqeApps = $true
	)
	
	$applicationName = "Desktop"
	
    EricomConnectConnector
	$response = $null;
	
	$appName = $applicationName
	if ($aliasName.Length -gt 0)
	{
		$appName = $aliasName
	}
    
    $foundApp = CheckIfAppOrDesktopAreInConnect -applicationName $appName
    if ($ForceUniqeApps -eq $true -And $foundApp -ne $null)
    {
       return 
    }

	$resourceDefinition = $adminApi.CreateResourceDefinition($adminSessionId, $applicationName)
	
	$iconfile = "$env:windir\system32\mstsc.exe"
	
	$val1 = $resourceDefinition.ConnectionProperties.GetLocalPropertyValue("remoteapplicationmode")
	$val1.LocalValue = $false
	$val1.ComputeBy = "Literal"
	
	try
	{
		$iconstring = [System.Drawing.Icon]::ExtractAssociatedIcon($iconfile).ToString();
		$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconfile);
		$iconstream = New-Object System.IO.MemoryStream;
		$icon.ToBitmap().Save($iconstream, [System.Drawing.Imaging.ImageFormat]::Png)
		$iconbytes = $iconstream.ToArray();
		$iconbase64 = [convert]::ToBase64String($iconbytes)
		$iconstream.Flush();
		$iconstream.Dispose();
		
		
		$val3 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("IconLength")
		$val3.LocalValue = $iconbase64.Length
		$val3.ComputeBy = "Literal"
		
		$val4 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("IconString")
		$val4.LocalValue = $iconbase64
		$val4.ComputeBy = "Literal"
	}
	catch
	{
		if ($UseWriteHost -eq $true)
		{
			Write-Warning $_.Exception.Message
		}
	}
	
	$valS = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("ShortcutDesktop")
	$valS.LocalValue = $desktopShortcut
	$valS.ComputeBy = "Literal"
	
	$val5 = $resourceDefinition.DisplayProperties.GetLocalPropertyValue("DisplayName")
	$val5.LocalValue = $appName
	$val5.ComputeBy = "Literal"
	
	$response = @{ }
	try
	{
		$adminApi.AddResourceDefinition($adminSessionId, $resourceDefinition, "true") | Out-Null
		
		
	}
	catch [Exception]
	{
		
	}
	return $response
}
function CheckIfAppOrDesktopAreInConnect
{
	param (
		[string]$applicationName
	)
#	$applicationName = $applicationName.Trim();

    EricomConnectConnector
	
	$AppList = $adminApi.ResourceDefinitionSearch($adminSessionId, $null, $null)
	$foundApp = $null
	foreach ($app in $AppList)
	{
		if ($app.DisplayName -eq $applicationName)

		{
			$foundApp = $app.ResourceDefinitionId;
            break;
		}
	}
	return $foundApp

}

#erez TBD
function CreateUserGroup
{
	param (
		[Parameter()]
		[String]$GroupName,
		[Parameter()]
		[String]$BaseGroup
		
	)
	#TBD
	
}
#erez TBD
function AddUserToUserGroup
{
	param (
		[Parameter()]
		[String]$GroupName,
		[Parameter()]
		[String]$User
	)
}

function Create-RemoteHostsGroup
{
	param (
		
		[Parameter()]
		[string]$groupName,
		[Parameter()]
		[string]$pattern
	)
	
    EricomConnectConnector
    $rhmc = [Ericom.MegaConnect.Runtime.XapApi.RemoteHostMembershipComputation]::Explicit
	$rhg = $adminApi.RemoteHostGroupSearch($adminSessionId, $rhmc, 100, $groupName)
	if ($rhg.Count -eq 0)
	{
       [Ericom.MegaConnect.Runtime.XapApi.RemoteHostMembershipComputation]$rhmc = 0;
	   $rGroup = $adminApi.CreateRemoteHostGroup($adminSessionId, $groupName, $rhmc); 
    
	    [System.Collections.Generic.List[String]]$remoteHostsList = New-Object System.Collections.Generic.List[String];
	
	    [Ericom.MegaConnect.Runtime.XapApi.RemoteHostSearchConstraints]$rhsc = New-Object Ericom.MegaConnect.Runtime.XapApi.RemoteHostSearchConstraints;
	    $rhsc.HostnamePattern = $pattern; #TODO: Update HERE!
	    $rhl = $adminApi.GetRemoteHostList($adminSessionId, $rhsc)
	    foreach ($h in $rhl)
	    {
		    $remoteHostsList.Add($h.RemoteHostId)
	    }
	    $rGroup.RemoteHostIds = $remoteHostsList;
	    $adminApi.AddRemoteHostGroup($adminSessionId, $rGroup) | Out-Null
	}
}

function Create-ResourceGroup
{
	param (	
		[String]$groupName
	)
	
    EricomConnectConnector
	
	$resources = $adminApi.ResourceGroupSearch($adminSessionId, $null, $null, $null)
	
	# check if resource group already exists
	$isPresent = $false;
	foreach ($resource in $resources)
	{
		if ($resource.DisplayName -eq $groupName)
		{
			$isPresent = $true;
		}
	}
	
	# create resource group
	if ($isPresent -eq $false)
	{
		$rGroup = $adminApi.CreateResourceGroup($adminSessionId, $groupName)
		$adminApi.AddResourceGroup($adminSessionId, $rGroup) | Out-Null
	}
}
function AddAppToResourceGroup
{
	param (
		[String]$resourceGroup,
        [string]$applicationName
	)
	
    EricomConnectConnector
	
	$resources = $adminApi.ResourceGroupSearch($adminSessionId, $null, $null, $null)
	$rGroup = $null;
	# check if resource group already exists
	$isPresent = $false;
	foreach ($resource in $resources)
	{
		if ($resource.DisplayName -eq $resourceGroup)
		{
			$isPresent = $true;
			$rGroup = $resource;
		}
	}
	
	# resource group found, now check for app
	if ($isPresent)
	{
		$foundApp = CheckIfAppOrDesktopAreInConnect -applicationName $applicationName 
		# try publish it
		
		if ($foundApp -ne $null)
		{
			$rlist = $rGroup.ResourceDefinitionIds
			$rlist.Add($foundApp);
			$rGroup.ResourceDefinitionIds = $rlist
			try
			{
				$output = $adminApi.UpdateResourceGroup($adminSessionId, $rGroup) | Out-Null
			}
			catch
			{
				# Write-EventLogEricom -ErrorMessage ("Could not Update Resource Group adminSessionID `"$adminSessionId`" Group: $rGroup`n " + $app.Trim() + "`n" + $_.Exception.Message)
			}
		}
	}
}
function AddHostGroupToResourceGroup
{
	param (
		[String]$resourceGroup,
		[Parameter()]
		[string]$remoteHostGroup
	)
    EricomConnectConnector
	
	$resources = $adminApi.ResourceGroupSearch($adminSessionId, $null, $null, $null)
	$rGroup = $null;
	# check if resource group already exists
	$isPresent = $false;
	foreach ($resource in $resources)
	{
		if ($resource.DisplayName -eq $groupName)
		{
			$isPresent = $true;
			$rGroup = $resource;
		}
	}
	
	# resource group found, now check for remote host group
	if ($isPresent)
	{
		$rhmc = [Ericom.MegaConnect.Runtime.XapApi.RemoteHostMembershipComputation]::Explicit
		$rhg = $adminApi.RemoteHostGroupSearch($adminSessionId, $rhmc, 100, $remoteHostGroup)
		if ($rhg.Count -gt 0)
		{
			
			[System.Collections.Generic.List[String]]$remoteHostsGroupList = New-Object System.Collections.Generic.List[String];
			foreach ($g in $rhg)
			{
				$remoteHostsGroupList.Add($g.RemoteHostGroupId)
			}
			$rGroup.RemoteHostGroupIds = $remoteHostsGroupList
			$adminApi.UpdateResourceGroup($adminSessionId, $rGroup) | Out-Null
		}
	}
}
function AddUserGroupToResourceGroup
{
	param (
		[String]$resourceGroup,
		[Parameter()]
		[string]$adGroup
	)
	$groupName = $resourceGroup;
	
    EricomConnectConnector	
	$resources = $adminApi.ResourceGroupSearch($adminSessionId, $null, $null, $null)
	# check if resource group already exists
	$rGroup = $null;
	$isPresent = $false;
	foreach ($resource in $resources)
	{
		if ($resource.DisplayName -eq $groupName)
		{
			$isPresent = $true;
			$rGroup = $resource;
		}
	}
	
	if ($isPresent -eq $true)
	{
		[Ericom.MegaConnect.Runtime.XapApi.BindingGroupType]$adGroupBindingType = 2
		$adName = $domainName
		$rGroup.AddBindingGroup("$adGroup", $adGroupBindingType, $adName, $adGroup);
		$adminApi.UpdateResourceGroup($adminSessionId, $rGroup) | Out-Null
	}
}
function AddUserToResourceGroup
{
	param (
		[String]$resourceGroup,
		[Parameter()]
		[string]$adUser
	)
	$groupName = $resourceGroup;
	
    EricomConnectConnector	
	$resources = $adminApi.ResourceGroupSearch($adminSessionId, $null, $null, $null)
	# check if resource group already exists
	$rGroup = $null;
	$isPresent = $false;
	foreach ($resource in $resources)
	{
		if ($resource.DisplayName -eq $groupName)
		{
			$isPresent = $true;
			$rGroup = $resource;
		}
	}
	
	if ($isPresent -eq $true)
	{
		[Ericom.MegaConnect.Runtime.XapApi.BindingGroupType]$adGroupBindingType = 1
		$adName = $domainName
		$adDomainId = $adUser + "@" + $adName;
		$rGroup.AddBindingGroup("$adUser", $adGroupBindingType, $adName, $adDomainId);
		$adminApi.UpdateResourceGroup($adminSessionId, $rGroup) | Out-Null
	}
}
function Publish
{
    param (
		[string]$GroupName,
		[string]$AppName,
		[string]$HostGroupName,
		[string]$User,
        [string]$UserGroup
	)

	Create-ResourceGroup -groupName $GroupName
    
	if (![string]::IsNullOrWhiteSpace($AppName))
    {
        AddAppToResourceGroup -resourceGroup $GroupName -applicationName $AppName
    }
   
    if (![string]::IsNullOrWhiteSpace($HostGroupName))
    {
        AddHostGroupToResourceGroup -resourceGroup $GroupName -remoteHostGroup $HostGroupName
    }

    if (![string]::IsNullOrWhiteSpace($User))
    {
        $UserFull = $User + "@" + $domainName
        AddUserToResourceGroup -resourceGroup $GroupName -adUser $UserFull
    }
    
    if (![string]::IsNullOrWhiteSpace($UserGroup))
    {
        AddUserGroupToResourceGroup -resourceGroup $GroupName -adGroup $UserGroup
    }
}

function Setup-Bginfo ()
{
	New-Item -Path "C:\Setup-Bginfo" -ItemType Directory -Force -ErrorAction SilentlyContinue
	$LocalPath = "C:\BgInfo"
	$GITBase = "https://raw.githubusercontent.com/ErezPasternak/azure-quickstart-templates/EricomConnect/EricomConnectAutomation/BGinfo/"
	$GITBginfo = $GITBase + "BGInfo.zip"
	$GITBgConfig = $GITBase + "bginfo_config.bgi"
	$LocalBgConfig = Join-Path $LocalPath  "bginfo_config.bgi"
	$GITBgWall = $GITBase + "wall.jpg"
	$localWall = Join-Path $LocalPath "wall.jpg"
	
	Start-BitsTransfer -Source $GITBginfo -Destination "C:\BGInfo.zip"
	Expand-ZIPFile -File "C:\BGInfo.zip" -Destination $LocalPath
	
	Start-BitsTransfer -Source $GITBgConfig -Destination $LocalBgConfig
	Start-BitsTransfer -Source $GITBgWall -Destination $localWall
	
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name BgInfo -Force -PropertyType String -Value "C:\BgInfo\bginfo.exe C:\BgInfo\bginfo_config.bgi /silent /accepteula /timer:0" | Out-Null
	C:\BgInfo\bginfo.exe C:\BgInfo\bginfo_config.bgi /silent /accepteula /timer:0
}

function AutomationDownload
{
    $HttpBase = "http://tswc.ericom.com:501/erez/751/"
	$DaaSZip = $HttpBase + "DaaSService.zip"
    $TragetFolder = "C:\Program Files\Ericom Software\Ericom Automation Service"
	
	Start-BitsTransfer -Source $DaaSZip -Destination "C:\DaaSService.zip" -ErrorVariable DownloadError
    if (!(Test-Path $EC_local_path))
	{
		$mail_error = "Failed to Download " + $DaaSZip  + "<br><i>"+ $DownloadError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
		
	}
    Remove-Item -Recurse -Force $TragetFolder -ErrorAction SilentlyContinue -ErrorVariable DeleteError

    Write-Output "$DeleteError"
	Expand-ZIPFile –File "C:\DaaSService.zip" –Destination "C:\Program Files\Ericom Software\Ericom Automation Service"
}

function AutomationSetup ()
{
	New-Item -Path "C:\AutomationService" -ItemType Directory -Force -ErrorAction SilentlyContinue

    $portNumber = 2244; # DaaS WebService port number
    $baseRDPGroup = "DaaS-RDP"           
    $workingDirectory = "C:\Program Files\Ericom Software\Ericom Automation Service\"
    $ServiceName = "AutomationWebService.exe"                  
    $ServicePath = Join-Path $workingDirectory -ChildPath $ServiceName
    $rdshpattern = $HostOrIp
    $fqdn = "PortalSettings/FQDN $externalFqdn";
    $port = "PortalSettings/Port $portNumber";
    $adDomain = "ADSettings/Domain $domainName";
    $adAdmin = "ADSettings/Administrator $AdminUser";
    $adPassword = "ADSettings/Password $AdminPassword";
    $adBaseGroup = "ADSettings/BaseADGroup $baseRDPGroup";
    $rhp = "ADSettings/RemoteHostPattern $rdshpattern";
    $ec_admin = "ConnectSettings/EC_AdminUser $AdminUser"; # EC_Admin User
    $ec_pass = "ConnectSettings/EC_AdminPass $AdminUser"; # EC_Admin Pass
    $RDCB_GridName = "ConnectSettings/EC_GridName $GridName"; # RDCB info - gridname
    $run_boot_strap = "appSettings/LoadBootstrapData True"; # Run bootstrap code
               
    $MAilTemplate = "EmailSettings/EmailTemplatePath $emailTemplate";
    $MAilServer   = "EmailSettings/SMTPServer $SMTPServer";
    $MAilPort = "EmailSettings/SMTPPort $SMTPPort";
    $MAilFrom = "EmailSettings/SMTPFrom $From";
    $MAilUser = "EmailSettings/SMTPUsername $SMTPSUser";
    $MAilPassword = "EmailSettings/SMTPPassword $SMTPassword";
  #  $MAilBCC = "EmailSettings/ListOfBcc $BCCList";
    
    # register the service            
    $argumentsService = "/install";
                
    $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
    if ($exitCodeCli -eq 0) {
        Write-Verbose "DaaSService: Service has been succesfuly registerd."
    } else {
        Write-Verbose "$ServicePath $argumentsService"
        Write-Verbose ("DaaSService: Service could not be registerd.. Exit Code: " + $exitCode)
    }        
    # configure the service
    $argumentsService = "/changesettings $fqdn $port $adDomain $adAdmin $adPassword $ec_admin $ec_pass $rhp $RDCB_GridName $adBaseGroup $MAilTemplate $MAilServer $MAilPort $MAilFrom $MAilUser $MAilPassword";
    Write-Verbose "$ServicePath $argumentsService"           
    $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
    if ($exitCodeCli -eq 0) {
           Write-Verbose "DaaSService: Service has been succesfuly updated."
    } else {
           
           Write-Verbose ("DaaSService: Service could not be updated.. Exit Code: " + $exitCode)
    }
    # start the service            
    $argumentsService = "/start";
                
    $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
    if ($exitCodeCli -eq 0) {
        Write-Verbose "DaaSService: Service has been succesfuly started."
    } else {
        Write-Verbose "$ServicePath $argumentsService"
        Write-Verbose ("DaaSService: Service could not be started.. Exit Code: " + $exitCode)
    } 

    # run bootstrap
    $argumentsService = "/changesettings $run_boot_strap";
    $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
    if ($exitCodeCli -eq 0) {
        Write-Verbose "DaaSService: Service has been succesfuly bootstrap."
    } else {
        Write-Verbose "$ServicePath $argumentsService"
        Write-Verbose ("DaaSService: Service could not be bootstrap.. Exit Code: " + $exitCode)
    } 

}
function AutomationDesktopShortcut
{
    $DaaSUrl = "http://" + "localhost" + ":2244/EricomAutomation/DaaS/index.html#/register"
    $ws  = New-Object -comObject WScript.Shell
    $Dt  = $ws.SpecialFolders.item("Desktop")
    $URL = $ws.CreateShortcut($Dt + "\DaaS Portal.url")
    $URL.TargetPath = $DaaSUrl
    $URL.Save()    
}
function EricomAutomaion
{
    AutomationDownload
    AutomationSetup
    AutomationDesktopShortcut
}

function SendAdminMail ()
{
	New-Item -Path "C:\SendAdminMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$Subject = "Ericom Connect Deployment on " + (hostname) + " is now Ready"
	
    $AdminSecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
	$AdminCredentials = New-Object System.Management.Automation.PSCredential ($AdminUser, $AdminSecurePassword);
    $MailPassword = ((Get-ADUser $SMTPasswordUser -Server $domainName -Credential $AdminCredentials -Properties HomePage | Select HomePage).HomePage | Out-String).Trim()
	
    $securePassword = ConvertTo-SecureString -String $MailPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	
	Write-Verbose "Ericom Connect Grid Server has been succesfuly configured."

	$Message = '<h1>Congratulations! Your Ericom Connect Environment is now Ready!</h1><p>Dear ' + $ToName + ',<br><br>Thank you for deploying <a href="http://www.ericom.com/connect-enterprise.asp">Ericom Connect</a> on <b>'+ [System.Net.Dns]::GetHostByName((hostname)).HostName +'</b>.<br><br>Your deployment is now complete and you can start using the system with these links:<br><br>1. <a href="http://' + $externalFqdn + ':8033/EricomXml/AccessPortal/Start.html#/login">Ericom Connect Access Portal.</a><br>2. <a href="https://' + $externalFqdn + ':8022/Admin">Ericom Connect management console.</a><br><br>Below are your system information. Please make sure you save them for future use:<br><br><b>Server Name:</b><a href="http://' + $externalFqdn + ':8080/AccessNow/Start.html?username='+ $AdminUser+'&password='+ $AdminPassword +'&autostart=true">'+ [System.Net.Dns]::GetHostByName((hostname)).HostName + '</a><br><b>Username:</b> ' + $AdminUser + ' <br><b>Password:</b> ' + $AdminPassword + '<br><br><br>Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'
	if ($To -ne "nobody")
	{
		try
		{
			Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" -ErrorAction SilentlyContinue
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\sendmailmessageend.txt"
		}
	}

}

function SendErrorMail ()
{
	param (
		[string]$Error
	)
	
	$Subject = "Ericom Connect Deployment have failed on " + (hostname)	
	$Message = '<h1>Ericom Connect Deployment have failed!</h1><p>Dear Customer ,<br><br> Ericom Connect Deployment on ' + [System.Net.Dns]::GetHostByName((hostname)).HostName +' have failed with this error: <br><br><i>"' + $Error + '"</i> <br><br> Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'

	New-Item -Path "C:\SendProblemMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
    
    $AdminSecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
	$AdminCredentials = New-Object System.Management.Automation.PSCredential ($AdminUser, $AdminSecurePassword);
    $MailPassword = ((Get-ADUser $SMTPasswordUser -Server $domainName -Credential $AdminCredentials -Properties HomePage | Select HomePage).HomePage | Out-String).Trim()	

	$securePassword = ConvertTo-SecureString -String $MailPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	
	Write-Verbose "Ericom Connect Deployment have started."
		
	if ($To -ne "nobody")
	{
		try
		{
			Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" -ErrorAction SilentlyContinue
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\SendProblemMail.txt"
		}
	}	
}

function SendStartMail ()
{
	New-Item -Path "C:\SendStartMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$Subject = "Ericom Connect Deployment on " + (hostname) +" have started"
	
	
    $AdminSecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
	$AdminCredentials = New-Object System.Management.Automation.PSCredential ($AdminUser, $AdminSecurePassword);
    $MailPassword = ((Get-ADUser $SMTPasswordUser -Server $domainName -Credential $AdminCredentials -Properties HomePage | Select HomePage).HomePage | Out-String).Trim()	

	$securePassword = ConvertTo-SecureString -String $MailPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	
	Write-Verbose "Ericom Connect Deployment have started."

	$Message = '<h1>You have successfully started your Ericom Connect Deployment!</h1><p>Dear ' + $ToName + ',<br><br>Thank you for using <a href="http://www.ericom.com/connect-enterprise.asp">Ericom Connect</a>.<br><br>Your Ericom Connect Deployment on <b>'+ [System.Net.Dns]::GetHostByName((hostname)).HostName +'</b> is now in process.<br><br>We will send you a confirmation e-mail once the deployment is complete and your system is ready.<br><br>Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'
	
	if ($To -ne "nobody")
	{
		try
		{
			Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" -ErrorAction SilentlyContinue
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\sendmailmessageend.txt"
		}
	}
}
function CheckPrerequisite
{
	# make sure that this machine is part of a domain
	CheckDomainRole

	# make sure that this machine name can be found in DNS
	CheckDNSConflict
	
	# check DNS using ping
	CheckDNSWithPing
}

function Install-Apps
{
	# list of possilbe apps (4000) can be found here - https://chocolatey.org/packages
	New-Item -Path "C:\Install-Apps" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Apps installation has been started."
	
	iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
	
	Write-Output "Installing fireofx"
	choco install -y firefox
	
	Write-Output "Installing powerpoint.viewer"
	choco install -y powerpoint.viewer
	
	Write-Output "Installing excel.viewer"
	choco install -y excel.viewer
	
	Write-Output "Installing notepadplusplus.install"
	choco install -y notepadplusplus.install
	
	#Write-Output "Installing Libre Office"
	#choco install -y libreoffice
	
	Write-Output "Apps installation has been ended."
}
function Install-WindowsFeatures
{
	# list of Windows Features can be found here - https://blogs.technet.microsoft.com/canitpro/2013/04/23/windows-server-2012-roles-features/
	New-Item -Path "C:\Install-WindowsFeatures" -ItemType Directory -Force -ErrorAction SilentlyContinue
	DISM /Online /Enable-Feature /FeatureName:NetFx3 /All  
	#Install-WindowsFeature Net-Framework-Core
	Install-WindowsFeature RDS-RD-Server
	Install-WindowsFeature Web-Server -IncludeManagementTools
	Install-WindowsFeature RSAT-AD-PowerShell
	Install-WindowsFeature Net-Framework-45-Core
	Install-WindowsFeature Desktop-Experience
	
	$needReboot = Get-PendingReboot
	if ($needReboot.RebootPending -eq $true)
	{
        $UserSelection = Show-MessageBox -Msg "In Order to continue a restart is requierd, Press OK to Restart or Canel to abort" -OC -T "Ericom Connect Deploy" -Q 
  
         
        if ($UserSelection -eq "OK" )  
        { 
            $fileExec = $MyInvocation.MyCommand.Path
		    $argumentList =""
		    if ($fileExec.length -gt 0)
		    {
			    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name "ScriptContinueOnReboot" -Force -PropertyType String -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File "' + $fileExec + '"' + " " + $argumentList) |Out-Null
		    }
		    Restart-Computer -Force
        }  
        else  
        {  
            exit
        }  
		
	} 
	
}

function PopulateWithUsers
{
	CreateUser -userName "user1" -password "P@55w0rd"
	CreateUser -userName "user2" -password "P@55w0rd"
	CreateUser -userName "user3" -password "P@55w0rd"
	
	CreateUserGroup -GroupName "Group1" -BaseGroup "Domain Users"
	AddUserToUserGroup -GroupName "Group1" -User "user1"
}

function PopulateWithRemoteHostGroups
{
	Create-RemoteHostsGroup -groupName "Allservers" -pattern "*"
    Create-RemoteHostsGroup -groupName "MyServer" -pattern "*"
}

function AddAppsAndDesktopsToConnect
{
	AddApplication -DisplayName "Notepad" -applicationName "Notepad" -DesktopShortcut $true
    AddApplication -DisplayName "Firefox" -applicationName "Mozilla Firefox" -DesktopShortcut $true
    AddApplication -DisplayName "Notepad++" -applicationName "Notepad++" -DesktopShortcut $true
    AddApplication -DisplayName "PowerPoint" -applicationName "Microsoft PowerPoint Viewer " -DesktopShortcut $true
    AddApplication -DisplayName "Excel" -applicationName "Microsoft Office Excel Viewer" -DesktopShortcut $true
    AddDesktop -aliasName "MyDesktop" -desktopShortcut $false
    AddDesktop -aliasName "HisDesktop" -desktopShortcut $true
}


function PublishAppsAndDesktops
{
	Publish -GroupName "AppGroup1" -AppName "Notepad" -HostGroupName "Allservers" -User "user1" -UserGroup "QA"
    Publish -GroupName "AppGroup2" -AppName "Mozilla Firefox" -HostGroupName "Allservers" 
    Publish -GroupName "AppGroup2" -AppName "Notepad" -HostGroupName "Allservers" -User "user1" 
	Publish -GroupName "DesktopGroup" -AppName "MyDesktop" -HostGroupName "Allserver" -User "user2"
	
	Publish -GroupName "AppGroup1"  -User "admin" 
    Publish -GroupName "AppGroup2"  -User "admin"
    Publish -GroupName "DesktopGroup"  -User "admin"
}

function CreateEricomConnectShortcuts
{
    # open browser for both Admin and Portal
	$AdminUrl = "https://" + $externalFqdn + ":8022/Admin/index.html#/connect"
    $PortalUrl  = "http://" + $externalFqdn + ":8033/EricomXml/AccessPortal/Start.html#/login"
 
    $ws = New-Object -comObject WScript.Shell
    $Dt = $ws.SpecialFolders.item("Desktop")
    $URL = $ws.CreateShortcut($Dt + "\Ericom Connect Admin.url")
    $URL.TargetPath = $AdminUrl
    $URL.Save()

    $URL1 = $ws.CreateShortcut($Dt + "\Ericom Connect AccessPortal.url")
    $URL1.TargetPath = $PortalUrl
    $URL1.Save()

    Start-Process -FilePath $AdminUrl
    Start-Sleep -s 5
    Start-Process -FilePath $PortalUrl
}

function Windows-Configuration
{
	#Configure firwall 
	ConfigureFirewall
	
	#change IE Security
	Disable-IEESC
	
	# Allow Multiple RDP Sessions Per User
	AllowMultipleSessionsPerUser
	
	# Add Domain Users To local Remote Desktop Group
	AddUsersToRemoteDesktopGroup
}

function PostInstall
{
    # Create users and groups in AD
    PopulateWithUsers
	
    # Install varius applications on the machine
	Install-Apps
    
    # Create the needed Remote Host groups in Ericom Connect
    PopulateWithRemoteHostGroups
		
	# Adds apps and desktops To Ericon Connect
	AddAppsAndDesktopsToConnect
	
	# Now we actuly publish apps and desktops to users
	PublishAppsAndDesktops
	
	# Setup background bitmap and user date using BGinfo
	Setup-Bginfo 
	
    # Create Desktop shortcuts for Admin and Portal
    CreateEricomConnectShortcuts

    #Send Admin mail
	SendAdminMail

}


Function New-ConnectServer {

$inputXml = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:NanoFinal"
        Title="Ericom Connect Builder 0.9" Height="400" Width="525" ResizeMode="CanMinimize" WindowStartupLocation="CenterScreen" Cursor="Arrow" FontFamily="Tahoma">
    <Grid Background="{DynamicResource {x:Static SystemColors.ActiveCaptionBrushKey}}" OpacityMask="{DynamicResource {x:Static SystemColors.GrayTextBrushKey}}">
        <Label Name="IntroLabel" Content="Please fill in the required information. Then, press Deploy." HorizontalAlignment="Left" Margin="14,11,0,0" VerticalAlignment="Top" Width="349"/>
        <TextBox Name="DomainName" HorizontalAlignment="Left" Height="23" Margin="129,41,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="193"/>
        <TextBox Name="AdminName" HorizontalAlignment="Left" Height="23" Margin="129,69,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="193" RenderTransformOrigin="0.495,0.524"/>
        <TextBox Name="AdminPassword" HorizontalAlignment="Left" Height="23" Margin="129,98,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="193"/>
        <TextBox Name="GridName" HorizontalAlignment="Left" Height="23" Margin="129,126,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="193"/>
        <TextBox Name="DatabaseServer" HorizontalAlignment="Left" Height="23" Margin="129,154,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="193"/>
        <TextBox Name="DatabaseName" HorizontalAlignment="Left" Margin="129,182,0,0" VerticalAlignment="Top" Width="193" Height="23"/>
        <TextBox Name="EMail" HorizontalAlignment="Left" Margin="129,210,0,0" VerticalAlignment="Top" Width="193" Height="23"/>
        <TextBox Name="DownloadPath" HorizontalAlignment="Left" Height="23" Margin="129,250,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="333"/>
        <TextBox Name="LocalPath" HorizontalAlignment="Left" Height="23" Margin="129,278,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="333"/>
        <TextBox Name="MSIName" HorizontalAlignment="Left" Height="23" Margin="129,306,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="333"/>
        <Label Name="DomainNameLabel" Content="Domain Name" HorizontalAlignment="Left" Margin="26,39,0,0" VerticalAlignment="Top"/>
        <Label Name="NameLabel" Content="Admin Name" HorizontalAlignment="Left" Margin="26,68,0,0" VerticalAlignment="Top"/>
        <Label Name="PasswordLabel" Content="Admin Password" HorizontalAlignment="Left" Margin="26,95,0,0" VerticalAlignment="Top"/>
        <Label Name="GridLabel" Content="Grid Name" HorizontalAlignment="Left" Margin="26,124,0,0" VerticalAlignment="Top"/>
        <Label Name="DBServerLabel" Content="Database Server" HorizontalAlignment="Left" Margin="26,153,0,0" VerticalAlignment="Top"/>
        <Label Name="DNNameLabel" Content="Database Name" HorizontalAlignment="Left" Margin="26,181,0,0" VerticalAlignment="Top" Width="99"/>
        <Label Name="MailLabel" Content="E-Mail" HorizontalAlignment="Left" Margin="26,210,0,0" VerticalAlignment="Top" Width="99"/>
        <Label Name="DownloadPathLabel" Content="Download Path" HorizontalAlignment="Left" Margin="26,250,0,0" VerticalAlignment="Top"/>
        <Label Name="LocalPathLabel" Content="Local Path" HorizontalAlignment="Left" Margin="26,279,0,0" VerticalAlignment="Top"/>
        <Label Name="MSINameLabel" Content="Target Path" HorizontalAlignment="Left" Margin="26,306,0,0" VerticalAlignment="Top"/>
        <Border BorderThickness="1" HorizontalAlignment="Left" Height="101" Margin="26,240,0,0" VerticalAlignment="Top" Width="447" Opacity="0.8">
            <Border.BorderBrush>
                <LinearGradientBrush EndPoint="0.5,1" StartPoint="0.5,0">
                    <GradientStop Color="Black" Offset="0"/>
                    <GradientStop Color="#FF3C618D" Offset="1"/>
                </LinearGradientBrush>
            </Border.BorderBrush>
        </Border>
        <CheckBox Name="checkBoxConfigureWindows" Content="Configure Windows" HorizontalAlignment="Left" Margin="381,55,0,0" VerticalAlignment="Top"/>
        <CheckBox Name="checkBoxInstallEC" Content="InstallEC" HorizontalAlignment="Left" Margin="381,75,0,0" VerticalAlignment="Top"/>
        <CheckBox Name="checkBoxCreateGrid" Content="CreateGrid" HorizontalAlignment="Left" Margin="381,95,0,0" VerticalAlignment="Top"/>
        <CheckBox Name="checkBoxCreateUser" Content="Create Users" HorizontalAlignment="Left" Margin="381,115,0,0" VerticalAlignment="Top"/>
        <CheckBox Name="checkBoxInstallApps" Content="Install Apps" HorizontalAlignment="Left" Margin="381,135,0,0" VerticalAlignment="Top"/>
        <CheckBox Name="checkBoxPublishApps" Content="Publish Apps" HorizontalAlignment="Left" Margin="381,156,0,0" VerticalAlignment="Top"/>
        <CheckBox Name="checkBoxSystem" Content="System Test" HorizontalAlignment="Left" Margin="381,176,0,0" VerticalAlignment="Top"/>
        <Border BorderThickness="1" HorizontalAlignment="Left" Height="157" Margin="378,48,0,0" VerticalAlignment="Top" Width="130">
            <Border.BorderBrush>
                <LinearGradientBrush EndPoint="0.5,1" StartPoint="0.5,0">
                    <GradientStop Color="Black" Offset="0"/>
                    <GradientStop Color="#FF213A64" Offset="1"/>
                </LinearGradientBrush>
            </Border.BorderBrush>
        </Border>
        <Label Name="label" Content="Actions" HorizontalAlignment="Left" Margin="409,24,0,0" VerticalAlignment="Top" Width="63"/>
        <Button Name="Deploy" Content="Deploy" HorizontalAlignment="Left" Margin="434,350,0,0" VerticalAlignment="Top" Width="75"/>
    </Grid>
</Window>
"@

    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [xml]$XAML = $inputXML
    $reader=(New-Object System.Xml.XmlNodeReader $xaml) 
    $Form=[Windows.Markup.XamlReader]::Load( $reader )
    $xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name)}

    $WPFDomainName.text = $domainName
    $WPFAdminName.text = $AdminUser
    $WPFAdminPassword.text = $AdminPassword
    $WPFGridName.text = $GridName
    $WPFDatabaseServer.text = $DatabaseServer 
    $WPFDatabaseName.text = $DatabaseName
    $WPFDownloadPath.text = $EC_download_url_or_unc 
    $WPFLocalPath.text    = $EC_local_path
    $WPFMSIName.text      = $InstallerName
    $WPFEMail.text        = $To
    
    #Button
    $WPFDeploy.Add_Click({
    
    $global:domainName     = $WPFDomainName.text 
    $global:AdminUser      = $WPFAdminName.text  
    $global:AdminPassword  = $WPFAdminPassword.SecurePassword 
    $global:GridName       = $WPFGridName.text  
    $global:DatabaseServer = $WPFDatabaseServer.text  
    $global:DatabaseName   = $WPFDatabaseName.text 
    $global:EC_download_url_or_unc = $WPFDownloadPath.text  
    $global:EC_local_path  = $WPFLocalPath.text    
    $global:InstallerName  = $WPFMSIName.text       
    $global:To             = $WPFEMail.text  
    
   
    #Actions
    $Actions = (((Get-Variable -Name *Checkbox*).Value -match "IsChecked:True")).Name

    $ToInstall = Switch ($Actions){

    "CHECKBOXSTORAGE" { "Microsoft-NanoServer-Storage-Package" }
    "CHECKBOXCOMPUTE" { "Microsoft-NanoServer-Compute-Package"}
    "CHECKBOXDEFENDER" { "Microsoft-NanoServer-Defender-Package"}
    "CHECKBOXCLUSTERING" { "Microsoft-NanoServer-FailoverCluster-Package"}
    "CHECKBOXCONTAINER" { "Microsoft-NanoServer-Containers-Package"}
    "CHECKBOXDSC" { "Microsoft-NanoServer-DSC-Package"}
    "CHECKBOXIIS" { "Microsoft-NanoServer-IIS-Package"}

    }
  

    $form.Close()

    })

    $Form.ShowDialog() | Out-Null 

}











# Main Code
#New-ConnectServer
# Relaunch if we are not running as admin

Invoke-RequireAdmin $script:MyInvocation

# Prerequisite check 
CheckPrerequisite 

# Install the needed Windows Features 
Install-WindowsFeatures

# Windows Configuration
Windows-Configuration

# Send inital mail 
SendStartMail

# Download Ericom Offical Installer from the Ericom Web site or network path 
Download-EricomConnect

# Install EC in a single machine mode including SQL express   
Install-SingleMachine

# We can stop here with a system ready and connected installed and not cofigured 
if ($PrepareSystem -eq $true)
{
	# Configure Ericom Connect Grid
	Config-CreateGrid 
	
	# Run PostInstall Creating users,apps,desktops and publish them
	PostInstall
}