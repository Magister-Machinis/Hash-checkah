#
# ControlWrapper.ps1
#
param(
[string]$initialinput =  ".\alertid.txt",
[string]$stage1o = ".\refined.csv",
[string]$stage2second = ".\ips.txt",
[string]$stage2target=".\results.csv",
[string]$stage2prioritytarget=".\priorityresults.csv",
[string]$stage2suspectoutput=".\suspectresults.csv",
[string]$stage3outputtarget =".\report.csv",
[string]$stage3priorityoutput = ".\priorityreport.csv",
[string]$stage3suspectoutput=".\suspectreport.csv"
)

$MyParam = $MyInvocation.MyCommand.Parameters
foreach($item in $MyParam.Keys)
{
	New-Item (Get-Variable $item).Value -ItemType File -ErrorAction SilentlyContinue
	(Get-Variable $item).Value = Resolve-Path (Get-Variable $item).Value 
	Write-Host "Creating $((Get-Variable $item).Value)"
}

$start = get-date
Write-Host "Pulling Alerts"
& ".\CBpull.ps1" -source $initialinput -outputtarget $stage1o
Write-Host "Checking Hashes"
& ".\hashcheck.ps1" -source $stage1o -secondsource $stage2second -outputtarget $stage2target -prioritytarget $stage2prioritytarget -suspectoutput $stage2suspectoutput
Write-Host "Generating Reports"
& ".\combiner.ps1" -inputtarget $initialinput -prioritytarget $stage2prioritytarget -outputtarget $stage3outputtarget -priorityoutput $stage3priorityoutput -suspectinput $stage2suspectoutput -suspectoutput $stage3suspectoutput
$end = get-date
$times= $end - $start
write-host "Time taken:"
$times
Read-Host -Prompt "Press Enter to exit"