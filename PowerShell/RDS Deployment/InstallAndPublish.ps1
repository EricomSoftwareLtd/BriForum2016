<#
.Synopsis
Install and Publish RemoteApps on RD Session Host 

.NOTES   
Name: InstallAndPublish
Author: Erez Pasternak
Version: 1.0
DateCreated: 2016-06-23
DateUpdated: 2016-07-05
#>

$CollectionName =   "My Apps"
$ConnectionBroker = "connect1.corp.jlxload.com"

function Publish-App
{
    param (
		[Parameter(Mandatory = $true)]
		[string]$Alias,
		[Parameter(Mandatory = $true)]
		[string]$DisplayName,
        [Parameter(Mandatory = $true)]
		[string]$FilePath
  
	)
   
   New-RDRemoteapp -Alias $Alias -DisplayName $DisplayName -FilePath $FilePath  -ShowInWebAccess 1 -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker
}

function Install-Apps
{
	# list of possilbe apps (4000) can be found here - https://chocolatey.org/packages
	New-Item -Path "C:\Install-Apps" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Apps installation has been started."
	
    # installing Chocolatey
	iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))

    # installing FireFox
    Write-Output "Installing fireofx"
	choco install -y firefox
    Publish-App -Alias FireFox -DisplayName MyBroswer -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe"
   
	
    #installing PowerPoint Viewer
	Write-Output "Installing powerpoint.viewer"
	choco install -y powerpoint.viewer
	
    Publish-App -Alias PowerPoint -DisplayName "PPT Viewer" -FilePath "C:\Program Files (x86)\Microsoft Office\Office14\PPTVIEW.exe"

        
    Write-Output "Apps installation has been ended."
}
Install-Apps