# Get Product information from a specified MSI file

# How to use
# Just run this script using Powershell and provide the Path to the MSI file when asked.
# The second parameter is the information type you need. You have 3 choices: ProductCode, ProductVersion and ProductName


param(
    [parameter(Mandatory=$true)]
    [IO.FileInfo]$Path,
    [parameter(Mandatory=$true)]
    [ValidateSet("ProductCode","ProductVersion","ProductName")]
    [string]$Property
)

function Get-MSIFileInformation {
    param(
    [parameter(Mandatory=$true)]
    [IO.FileInfo]$Path,
    [parameter(Mandatory=$true)]
    [ValidateSet("ProductCode","ProductVersion","ProductName")]
    [string]$Property
    )
    try {
        $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
        $MSIDatabase = $WindowsInstaller.GetType().InvokeMember("OpenDatabase","InvokeMethod",$Null,$WindowsInstaller,@($Path.FullName,0))
        $Query = "SELECT Value FROM Property WHERE Property = '$($Property)'"
        $View = $MSIDatabase.GetType().InvokeMember("OpenView","InvokeMethod",$null,$MSIDatabase,($Query))
        $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null)
        $Record = $View.GetType().InvokeMember("Fetch","InvokeMethod",$null,$View,$null)
        $Value = $Record.GetType().InvokeMember("StringData","GetProperty",$null,$Record,1)
        return $Value
    } 
    catch {
        Write-Output $_.Exception.Message
    }
}

Get-MSIFileInformation -Path $Path -Property $Property