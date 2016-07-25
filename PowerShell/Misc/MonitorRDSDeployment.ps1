﻿<#
.Synopsis
Monitor RDS enviroment 

.NOTES   
Name: MonitorRDSDeployment
Author: Erez Pasternak
Version: 1.0
DateCreated: 2016-06-23
DateUpdated: 2016-07-05
#>
param (
	[switch]$PrepareSystem = $true
)

# Connect Variables

$RDWEb = "https://RDWEB.test.local"
$ServerToMonitor = "localhost"
$NetworkAdmin = "admin@test.local"
$NetworkPassword = "password"

$AdminSecurePassword = ConvertTo-SecureString -String $NetworkPassword -AsPlainText -Force
$AdminCredentials = New-Object System.Management.Automation.PSCredential ($NetworkAdmin, $AdminSecurePassword);

# E-mail Settings
$To = "erez.pasternak@ericom.com"
$externalFqdn = [System.Net.Dns]::GetHostByName((hostname)).HostName

$From = "daas@ericom.com"
$SMTPServer = "ericom-com.mail.protection.outlook.com"
$SMTPSUser = "daas@ericom.com"
$SMTPassword = "password"

$SMTPPort = 25

if (!([System.Diagnostics.EventLog]::SourceExists("RDS Monitoring")))
{
	New-EventLog -LogName Application -Source "RDS Monitoring" 
}

function Write-RDSEventLog
{
	[CmdletBinding()]
	[OutputType([int])]
	Param (
		[Parameter(Mandatory = $true)]
		[string]$Message,
        [Parameter()]
        [string]$EventID
	)
	$LogName = "Application"
	$SourceName = "RDS Monitoring"
	Write-EventLog -LogName $LogName -source $SourceName -EventId $EventID -message "$Message" -EntryType Information
}

function Write-RDSEventLogError
{
	[CmdletBinding()]
	[OutputType([int])]
	Param (
		[Parameter(Mandatory = $true)]
		[string]$Message,
        [Parameter()]
        [string]$EventID
	)
	$LogName = "Application"
	$SourceName = "RDS Monitoring"
	
	Write-EventLog -LogName $LogName -source $SourceName -EventId $EventID -message "$Message" -EntryType Error
}


function Ignore-SelfSignedCerts
{
	add-type -ErrorAction SilentlyContinue -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
}
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
} #function


Function PingURL ($url)
{
	Ignore-SelfSignedCerts
	$result = Invoke-WebRequest -Uri $url -Method GET -ErrorAction SilentlyContinue -ErrorVariable ErrorText
	
	[pscustomobject]@{
		ErrorText = $ErrorText
		StatusCode = $result.StatusCode
	}
	
}

Function Execute-Command ($commandPath, $commandArguments)
{
	$pinfo = New-Object System.Diagnostics.ProcessStartInfo
	$pinfo.FileName = $commandPath
	$pinfo.RedirectStandardError = $true
	$pinfo.RedirectStandardOutput = $true
	$pinfo.UseShellExecute = $false
	$pinfo.Arguments = $commandArguments
	$p = New-Object System.Diagnostics.Process
	$p.StartInfo = $pinfo
	$p.Start() | Out-Null
	$stdout = $p.StandardOutput.ReadToEnd()
	$stderr = $p.StandardError.ReadToEnd()
	$p.WaitForExit()
	Write-Host "stdout: $stdout"
	#Write-Host "stderr: $stderr"
	[pscustomobject]@{
		Output = $stdout
		ExitCode = $p.ExitCode
	}
}


function TestSystem {

	# for remote machine
    $AdminSecurePassword = ConvertTo-SecureString -String $NetworkPassword -AsPlainText -Force
	$AdminCredentials = New-Object System.Management.Automation.PSCredential ($NetworkAdmin, $AdminSecurePassword);
 
  
	
	$PingResult = PingURL -url $RDWEb
  $ErrorForMail = $PingResult.ErrorText[0].Message
	if ($PingResult.StatusCode -eq 200)
	{
		Write-RDSEventLog -Message "RDWeb  is ok.`n" -EventID 6
	}
	else
	{
    Get-RDSEventLogs -Computername $ServerToMonitor -credentials $AdminCredentials
		Write-RDSEventLogError -Message ("RDWeb is not responding. Result of ping was:`n" + $PingResult.ErrorText) -EventID 16
		SendErrorMail -ErrorText $ErrorForMail -TestName RDWeb;
	}
		
}

function SendMonitorMail ()
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$Text,
		[Parameter(Mandatory = $true)]
		[string]$TestName
	)
	
	$Subject = "RDS Server " + $TestName + " On " + (hostname)
	$Message = '<h1>RDS server ' + $TestName + ' was raised at '+ (Get-Date) +'.</h1><p>Dear Customer ,<br><br>  ' + $TestName + ' on ' + [System.Net.Dns]::GetHostByName((hostname)).HostName + ' have happend with this info: <br><br><i>"' + $Text + '"</i> <br><br> Regards,<br>Automation Team'
	
	New-Item -Path "C:\SendMonitorMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$securePassword = ConvertTo-SecureString -String $SMTPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ($SMTPSUser, $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	if ($To -ne "nobody")
	{
		try
		{
            if (Get-LastLogArchiveFilePath -ne $null) {
                Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -Attachments (Get-LastLogArchiveFilePath)  -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" 
            } else {
                Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com"
            }
			
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\SendMonitorMail.txt"
		}
	}
}

function SendErrorMail()
{
	param (
		[Parameter(Mandatory = $true)]
		$ErrorText,
		[Parameter(Mandatory = $true)]
		[string]$TestName
	)
	
	$Subject = "Warning: " + $TestName + " is not Responding On " + (hostname)
	$Message = '<h1>Warning:  ' + $TestName + ' is not responding at '+ (Get-Date) +'.</h1><p>Dear Customer ,<br><br> ' + $TestName + ' on ' + [System.Net.Dns]::GetHostByName((hostname)).HostName + ' have failed with this error: <br><br><i>"' + $ErrorText + '"</i> <br><br> Regards,<br> Automation Team'
	
	New-Item -Path "C:\SendErrorMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$securePassword = ConvertTo-SecureString -String $SMTPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ($SMTPSUser, $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	if ($To -ne "nobody")
	{
		try
		{
            if (Get-LastLogArchiveFilePath -ne $null) {
			    Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -Attachments (Get-LastLogArchiveFilePath) -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" 
            } else {
                Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" 
            }
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\SendErrorMail.txt"
		}
	}
}


Function Start-Monitoring
{
	While ($true)
	{
		# Do things lots
		TestSystem
		
		# Add a pause so the loop doesn't run super fast and use lots of CPU        
		Start-Sleep -s 60
	}
}

 
Function Get-RDSEventLogs{

Param(
 [Parameter(Mandatory=$True,Position=0)][string[]]$Computername,
 [System.Management.Automation.PSCredential] $credentials
)

#--------------------------------------------------------------------------------------
# Global Variables
#--------------------------------------------------------------------------------------
# The location where the CM Agent log files are stored, will make this dynamic in a future release
# currently this relates to the CM12 Agent

$ThisComputer = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
#The folder where the log archive files are stored to
$localtmpfolder = "$env:USERPROFILE\Documents\RDSLogs"
 
#Check if the RemoteCMlogs folder already exists othrwise create it
If (!(Test-path $localtmpfolder)) {New-Item -ItemType directory -Path $localtmpfolder}
 
$cred = $credentials
 
Function ZIP-EClogs  ($Computername, $ThisComputer, $cred, $localtmpfolder) {
 
#--------------------------------------------------------------------------------------
# ZIP File Function. Credits for this function go to Kenneth D. Sweet
 
# http://gallery.technet.microsoft.com/ZIP-Files-script-b5374a5d/view/Discussions#content
#--------------------------------------------------------------------------------------
Function Zip-File () {
  <#
    .SYNOPSIS
      Add, Removes, and Extracts files and folders to a Zip Archive
    .DESCRIPTION
      Add, Removes, and Extracts files and folders to a Zip Archive
    .PARAMETER ZipFile
      Name os Zip Archive
    .PARAMETER Add
      Names of Files or Folders to Add to Zip Archive
      Will not overwrite existing Files in the Zip Archive
      Will only add in Files from Sub Folders to the Zip Archive when you add a Folder
    .PARAMETER Remove
      Names of Files or Folders to Remove from Zip Archive
      If "Display Delete Confirmation" is enable you will be prompted confirm to Remove each File
    .PARAMETER Extract
      Names of Files or Folders to Extract from Zip Archive
      Recreates Folders structure when extracting Files, even Folders that have no Matching Files to Extract 
    .PARAMETER Destination
      Destination Folder to Extract Files or Folders to
    .PARAMETER Folders
      Add, Remove, or Extract Folders instead of Files from the Zip Archive
    .PARAMETER List
      List the Contents of the Zip Archive
    .INPUTS
    .OUTPUTS
    .NOTES
      Written by Kenneth D. Sweet CopyRight (c) 2012
      Add, Removes, and Extracts files and folders to a Zip Archive
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -Add "C:\Temp\Temp_01.txt", "C:\Temp\Temp_02.txt"
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -Add "C:\Temp_01", "C:\Temp_02" -Folders
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -Remove "*.xls", "*.xlsx"
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -Remove "Temp_01" -Folders
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -Extract "*.doc", "*.docx"-Destination "C:\Temp" 
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -Extract "Temp_02" -Destination "C:\Temp" -Folders
    .EXAMPLE
      Zip-File -ZipFile "C:\Test.zip" -List
    .LINK
      Ken Sweet Rules the MultiVerse
  #>
  [CmdletBinding(DefaultParameterSetName="Add")]
  Param(
    [Parameter(Mandatory=$True, ParameterSetName="Add")]
    [Parameter(Mandatory=$True, ParameterSetName="Remove")]
    [Parameter(Mandatory=$True, ParameterSetName="Extract")]
    [Parameter(Mandatory=$True, ParameterSetName="List")]
    [String]$ZipFile,
    [Parameter(Mandatory=$True, ParameterSetName="Add")]
    [String[]]$Add,
    [Parameter(Mandatory=$False, ParameterSetName="Add")]
    [Switch]$Recurse,
    [Parameter(Mandatory=$True, ParameterSetName="Remove")]
    [String[]]$Remove,
    [Parameter(Mandatory=$True, ParameterSetName="Extract")]
    [String[]]$Extract,
    [Parameter(Mandatory=$False, ParameterSetName="Extract")]
    [String]$Destination=$PWD,
    [Parameter(Mandatory=$False, ParameterSetName="Add")]
    [Parameter(Mandatory=$False, ParameterSetName="Remove")]
    [Parameter(Mandatory=$False, ParameterSetName="Extract")]
    [Switch]$Folders,
    [Parameter(Mandatory=$True, ParameterSetName="List")]
    [Switch]$List
  )
  DynamicParam {
    if ($ZipFile -match ".*Zip\\.*")  {
      $NewAttrib = New-Object -TypeName  System.Management.Automation.ParameterAttribute
      $NewAttrib.ParameterSetName = "List"
      $NewAttrib.Mandatory = $True
      $AttribCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
      $AttribCollection.Add($NewAttrib)
      $DynamicParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("Path", [String], $AttribCollection)
      $paramDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
      $paramDictionary.Add("Path", $DynamicParam)
      return $ParamDictionary
    }
  }
  Begin {
    $Shell = New-Object -ComObject Shell.Application
    if (![System.IO.File]::Exists($ZipFile) -and ($PSCmdlet.ParameterSetName -eq "Add")) {
      Try {
        [System.IO.File]::WriteAllText($ZipFile, $("PK" + [Char]5 + [Char]6 + $("$([Char]0)" * 18)))
      }
      Catch {
      }
    }
    $ZipArchive = $Shell.NameSpace($ZipFile)
    if ($PSCmdlet.ParameterSetName -eq "Add") {
      $TempFolder = "$([System.IO.Path]::GetTempPath())$([System.IO.Path]::GetRandomFileName())"
      if (![System.IO.Directory]::Exists($TempFolder)) {
        [Void][System.IO.Directory]::CreateDirectory($TempFolder)
      }
    }
  }
  Process {
    Switch ($PSCmdlet.ParameterSetName) {
      "Add" {
        Try {
          if ($Folders) {
            ForEach ($File in $Add) {
              $SearchPath = [System.IO.Path]::GetDirectoryName($File)
              $SearchName = [System.IO.Path]::GetFileName($File)
              $DirList = [System.IO.Directory]::GetDirectories($SearchPath, $SearchName)
              $Total = $ZipArchive.Items().Count
              ForEach ($Dir in $DirList) {
                $ParseName = $ZipArchive.ParseName([System.IO.Path]::GetFileName($Dir))
                if ([String]::IsNullOrEmpty($ParseName)) {
                  if (!$Recurse) {
                    # Write-Host "Adding Folder: $Dir " original line from zip function
                    Write-Host "Processing Computer: $Computername Adding Folder: $Dir to $filename" # customized message 
                  }
                  $ZipArchive.CopyHere($Dir, 0x14)
                  Do {
                    [System.Threading.Thread]::Sleep(100)
                  } While ($ZipArchive.Items().Count -eq $Total)
                } else {
                  if (!$Recurse) {
                    Write-Host "Folder Exists in Archive: $Dir"
                  }
                }
              }
            }
          } else {
            ForEach ($File in $Add) {
              $SearchPath = [System.IO.Path]::GetDirectoryName($File)
              $SearchName = [System.IO.Path]::GetFileName($File)
              $FileList = [System.IO.Directory]::GetFiles($SearchPath, $SearchName)
              $Total = $ZipArchive.Items().Count
              ForEach ($File in $FileList) {
                $ParseName = $ZipArchive.ParseName([System.IO.Path]::GetFileName($File))
                if ([String]::IsNullOrEmpty($ParseName)) {
                  Write-Host "Adding File: $File"
                  $ZipArchive.CopyHere($File, 0x14)
                  Do {
                    [System.Threading.Thread]::Sleep(100)
                  } While ($ZipArchive.Items().Count -eq $Total)
                } else {
                  Write-Host "File Exists in Archive: $File"
                }
              }
              if ($Recurse) {
                $DirList = [System.IO.Directory]::GetDirectories($SearchPath)
                ForEach ($Dir in $DirList) {
                  $NewFolder = [System.IO.Path]::GetFileName($Dir)
                  if (!$ZipArchive.ParseName($NewFolder)) {
                    [Void][System.IO.Directory]::CreateDirectory("$TempFolder\$NewFolder")
                    [System.IO.File]::WriteAllText("$TempFolder\$NewFolder\.Dir", "")
                    Zip-File -ZipFile $ZipFile -Add "$TempFolder\$NewFolder" -Folders -Recurse
                  }
                  $NewAdd = @()
                  ForEach ($Item in $Add) {
                    $NewAdd += "$([System.IO.Path]::GetDirectoryName($Item))\$NewFolder\$([System.IO.Path]::GetFileName($Item))"
                  }
                  Zip-File -ZipFile "$ZipFile\$NewFolder" -Add $NewAdd -Recurse:$Recurse
                }
              }
            }
          }
        }
        Catch {
          Throw "Error Adding Files to Zip Archive"
        }
        Break
      }
      "Remove" {
        Try {
          ForEach ($File in $Remove) {
            if ($Folders) {
              $($ZipArchive.Items() | Where-Object -FilterScript { $_.IsFolder -and (($_.Name -eq $File) -or ($_.Name -match $File.Replace('.', '\.').Replace('*', '.*'))) }) | ForEach-Object -Process { Write-Host "Removing Folder: $($_.Name)"; $_.InvokeVerbEx("Delete", 0x14) }
            } else {
              $($ZipArchive.Items() | Where-Object -FilterScript { !$_.IsFolder -and (($_.Name -eq $File) -or ($_.Name -match $File.Replace('.', '\.').Replace('*', '.*'))) }) | ForEach-Object -Process { Write-Host "Removing File: $($_.Name)"; $_.InvokeVerbEx("Delete", 0x14) }
            }
          }
          ForEach ($Folder in $($ZipArchive.Items() | Where-Object -FilterScript { $_.IsFolder })) {
            Zip-File -ZipFile "$ZipFile\$($Folder.Name)" -Remove $Remove -Folders:$Folders
          }
        }
        Catch {
          Throw "Error Removing Files from Zip Archive"
        }
        Break
      }
      "Extract" {
        Try {
          if (![System.IO.Directory]::Exists($Destination)) {
            [Void][System.IO.Directory]::CreateDirectory($Destination)
          }
          $DestFolder = $Shell.NameSpace($Destination)
          ForEach ($File in $Extract) {
            if ($Folders) {
              $($ZipArchive.Items() | Where-Object -FilterScript { $_.IsFolder -and (($_.Name -eq $File) -or ($_.Name -match $File.Replace('.', '\.').Replace('*', '.*'))) }) | ForEach-Object -Process { Write-Host "Extracting Folder: $($_.Name) to $Destination"; $DestFolder.CopyHere($_, 0x14) }
            } else {
              $($ZipArchive.Items() | Where-Object -FilterScript { !$_.IsFolder -and (($_.Name -eq $File -and $_.Name -ne ".Dir") -or ($_.Name -match $File.Replace('.', '\.').Replace('*', '.*'))) }) | ForEach-Object -Process { Write-Host "Extracting File: $($_.Name) to $Destination"; $DestFolder.CopyHere($_, 0x14) }
            }
          }
          ForEach ($Folder in $($ZipArchive.Items() | Where-Object -FilterScript { $_.IsFolder })) {
            Zip-File -ZipFile "$ZipFile\$($Folder.Name)" -Extract $Extract -Destination "$Destination\$($Folder.Name)" -Folders:$Folders
          }
        }
        Catch {
        $Error[0]
          Throw "Error Extracting Files from Zip Archive"
        }
        Break
      }
      "List" {
        Try {
          $ZipArchive.Items() | Where-Object -FilterScript { !$_.IsFolder -and $_.Name -ne ".Dir" } | Select-Object -Property "Name", "Size", "ModifyDate", "Type", @{"Name"="Path";"Expression"={$(if ($($PSCmdlet.MyInvocation.BoundParameters["Path"])) {$($PSCmdlet.MyInvocation.BoundParameters["Path"])} else {"\"})}}
          ForEach ($Folder in $($ZipArchive.Items() | Where-Object -FilterScript { $_.IsFolder })) {
            Zip-File -ZipFile "$ZipFile\$($Folder.Name)" -List -Path "$(if ($($PSCmdlet.MyInvocation.BoundParameters["Path"])) {$($PSCmdlet.MyInvocation.BoundParameters["Path"])})\$($Folder.Name)"
          }
        }
        Catch {
          Throw "Error Listing Files in Zip Archive"
        }
        Break
      }
    }
  }
  End {
    $Shell = $Null
    $ZipArchive = $Null
    if ($PSCmdlet.ParameterSetName -eq "Add") {
      if ([System.IO.Directory]::Exists($TempFolder)) {
        [Void][System.IO.Directory]::Delete($TempFolder, $True)
      }
    }
  }
}
# end of ZIP-File Function
 
 
 
Function Send-File {
 
##############################################################################
##
## Send-File
##
## From Windows PowerShell Cookbook (O'Reilly)
## by Lee Holmes (http://www.leeholmes.com/guide)
##
## http://www.powershellcookbook.com/recipe/ISfp/program-transfer-a-file-to-a-remote-computer
##############################################################################
 
<#
 
.SYNOPSIS
 
Sends a file to a remote session.
 
.EXAMPLE
 
PS &gt;$session = New-PsSession leeholmes1c23
PS &gt;Send-File c:\temp\test.exe c:\temp\test.exe $session
 
#>
 
param(
    ## The path on the local computer
    [Parameter(Mandatory = $true)]
    $Source,
 
    ## The target path on the remote computer
    [Parameter(Mandatory = $true)]
    $Destination,
 
    ## The session that represents the remote computer
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.Runspaces.PSSession] $Session
)
 
 
 
Set-StrictMode -Version Latest
 
## Get the source file, and then get its content
$sourcePath = (Resolve-Path $source).Path
$sourceBytes = [IO.File]::ReadAllBytes($sourcePath)
$streamChunks = @()
 
## Now break it into chunks to stream
Write-Progress -Activity "Sending $Source" -Status "Preparing file"
$streamSize = 1MB
for($position = 0; $position -lt $sourceBytes.Length;
    $position += $streamSize)
{
    $remaining = $sourceBytes.Length - $position
    $remaining = [Math]::Min($remaining, $streamSize)
 
    $nextChunk = New-Object byte[] $remaining
    [Array]::Copy($sourcebytes, $position, $nextChunk, 0, $remaining)
    $streamChunks += ,$nextChunk
}
 
$remoteScript = {
    param($destination, $length)
 
    ## Convert the destination path to a full filesytem path (to support
    ## relative paths)
    $Destination = $executionContext.SessionState.`
        Path.GetUnresolvedProviderPathFromPSPath($Destination)
 
    ## Create a new array to hold the file content
    $destBytes = New-Object byte[] $length
    $position = 0
 
    ## Go through the input, and fill in the new array of file content
    foreach($chunk in $input)
    {
        Write-Progress -Activity "Writing $Destination" `
            -Status "Sending file" `
            -PercentComplete ($position / $length * 100)
 
        [GC]::Collect()
        [Array]::Copy($chunk, 0, $destBytes, $position, $chunk.Length)
        $position += $chunk.Length
    }
 
    ## Write the content to the new file
    [IO.File]::WriteAllBytes($destination, $destBytes)
 
    ## Show the result
    Get-Item $destination
    [GC]::Collect()
}
 
## Stream the chunks into the remote script
$streamChunks | Invoke-Command -Session $session $remoteScript `
    -ArgumentList $destination,$sourceBytes.Length
 
 
}
### End of Send-File function
 
# -----------------------------------------------------------------------------------------------------------------------#
# Below are the commands we execute remotely
# -----------------------------------------------------------------------------------------------------------------------#
 
# Get the Windows Temp folder on the remote system
$tmpfolder = "$env:SystemRoot\TEMP\"
# create timestamp variable 
$timestamp = $((get-date).tostring("MMddyyyyHHmmss"))
$hostname = [System.Net.Dns]::GetHostByName((hostname)).HostName;
# construct the filename including the path
$filename =  "RDSLogs_" + $hostname + "_" + $timestamp + ".zip"
$RDStmpfolder = "$env:SystemRoot\TEMP\RDSLogs_"+ $hostname + "_" + $timestamp
New-Item -Path "$RDStmpfolder\EventLogs" -ItemType  Directory
$logsPath = "$RDStmpfolder\EventLogs\"   

Get-WinEvent -ListLog System,Application,Microsoft-Windows-RemoteDesktopServices-*,Microsoft-Windows-TerminalServices-* | Get-WinEvent | Where { $_.TimeCreated -gt '7/1/2016 9:00:00' } | Sort-Object -Property RecordId | select RecordId,TimeCreated,LogName,Id,Message | Out-File $logsPath\EventInfo.txt


# Generate ZIP file with content from temp log folder.
If (Test-path $RDStmpfolder) {zip-file -ZipFile "$tmpfolder$filename" -Add $RDStmpfolder -Folders} Else {Write-Warning "Could not find folder" $RDStmpfolder}
 
 
}
# End of ZIP-EClogs function
 
    # -----------------------------------------------------------------------------------------------------------------------#
    # Commands from Get-RDSEventLogs Main function
    # -----------------------------------------------------------------------------------------------------------------------#
    # Process all computers provided
    ForEach ($iComputername in $Computername)
    {
        Function Get-Remotelogs {
            # Settings this option prevents the creation of the user profile on the remote system 
            $SesOpt = New-PSSessionOption -NoMachineProfile 
            # Start a new Remote Session
            $ses = New-PSSession -ComputerName $iComputername   -Credential $cred
            # Execute the ZIP-EClogs function on the remote machine. 
            $ab = Invoke-Command -Session $ses -ScriptBlock ${function:ZIP-EClogs} -ArgumentList $iComputername, $ThisComputer, $cred, $localtmpfolder
            # Get the path of archived log from remote mathine.
            $temp = "C:\Windows\TEMP";
            $archivePath = Invoke-Command -ScriptBlock { param($path) $latest = (Get-ChildItem -Path $path | Where-Object { $_.Name -match "[ECLogs_]\d" } | Sort-Object LastAccessTime -Descending | Select-Object -First 1); Join-Path $path -Child $latest.name } -ArgumentList $temp -Session $ses
            $localfile = $localtmpfolder + "\" + (Split-Path $archivePath -Leaf);
            [io.file]::WriteAllBytes("$localfile",(Invoke-Command -ComputerName $iComputername -Credential $cred -ScriptBlock {get-content $Args[0] -encoding byte -Read 0} -ArgumentList "$archivePath"))

            # Clsoe the session
            Remove-PSSession $ses
        }
 
        Get-Remotelogs $iComputername
    }
 
}
# End of Get-RDSEventLogs function

function Get-LastLogArchiveFilePath {
    $dir = "$env:USERPROFILE\Documents\RDSLogs"
    $latest = Get-ChildItem -Path $dir | Sort-Object LastAccessTime -Descending | Select-Object -First 1
    return Join-Path $dir -Child $latest.name
}


#use this if you want a loop without a windows task
#Start-Monitoring
#CreateGridLogs -logsPath c:\
TestSystem