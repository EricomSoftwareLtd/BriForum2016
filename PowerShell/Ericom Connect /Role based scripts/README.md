![Ericom::Access Done Right](http://www.ericom.com/imgs/home/EricomLogo2.jpg "Ericom Logo") 

### This folder contains deployment powershell scripts:

##### DeployEricomConnect.ps1

This script will create a complete single machine working environment , it will download the needed MSI from Ericom web site (can use local path as well),
Then it will install the Ericom Connect, and publish application to users 


##### ESGServer.ps1 

This script is used to deploy an ESG machine that is part of an existing Ericom Connect environment

##### RDSHApps.ps1

This script is used to deploy an Terminal Server that will be used to run applicaitons - it uses Chocolatey packge manager to install the needed applicaitons 

##### RDSHDesktops.ps1

TThis script is used to deploy an Terminal Server that will be used to run desktops - it uses Chocolatey packge manager to install the needed applicaitons, 
it also install Ericom AccessPad with SSO for seamless experience for end users
