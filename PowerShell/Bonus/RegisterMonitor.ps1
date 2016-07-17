# Task Scheduler Registration
param(
)
try {
    Unregister-ScheduledJob MonitorEirocmConnect -Force -Confirm:$false
} catch { }

$PathProcess = "c:\demos\MonitorEC.ps1"

# Register MonitorEirocmConnect
$repeat = (New-TimeSpan -Minute 5)
$option = New-ScheduledJobOption -RunElevated -MultipleInstancePolicy StopExisting
$trigger = New-JobTrigger -Once -At (Get-Date).Date -RepeatIndefinitely -RepetitionInterval $repeat
$filePath = "C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe"
$argForPS = "-executionPolicy bypass -noexit -file `"$PathProcess`" "
Register-ScheduledJob -ScheduledJobOption $option  -Trigger $trigger -Name "MonitorEirocmConnect" -ErrorAction SilentlyContinue -ScriptBlock  {
    Write-Verbose "$args[0] $args[1]"
    $exitCode = (Start-Process -Filepath $args[0] -ArgumentList $args[1] -Wait -Passthru).ExitCode
} -ArgumentList $filePath, $argForPS