# Get Product information from all MSIs in a specified folder

# How to use
# Just run this script using Powershell and provide the Path folder containing all the MSIs
# The script will create a file called ProductIDs.json containing all the product ids of the MSIs


param(
    [parameter(Mandatory=$true)]
    [IO.FileInfo]$Path
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

$dir = Get-ChildItem $path;
$list = $dir | where { $_.extension -eq ".msi" }
$data = @{};
foreach ($file in $list) {
    $msi = $file.FullName;
    $product = Get-MSIFileInformation -Path $msi -Property ProductCode
    $guid = "";
    foreach($item in $product) {
        $guid = $guid + $item;
    }
    $data.Add($file.Name, $guid.Trim());
}
Write-Output $data
$outputPath = Join-Path $path -ChildPath "ProductIDs.json"
$data | ConvertTo-Json | Out-File $outputPath