#
# combiner.ps1
#
param(
[string]$configfile=".\config.csv",
[string]$inputtarget=".\refined.csv",
[string]$inputt = ".\results.csv",
[string]$prioritytarget=".\priorityresults.csv",
[string]$outputtarget=".\report.csv",
[string]$priorityoutput=".\output\priorityreport.csv",
[string]$suspectinput=".\output\suspectresults.csv",
[string]$suspectoutput=".\output\suspectreport.csv"
)
$MyParam = $MyInvocation.MyCommand.Parameters
foreach($item in $MyParam.Keys)
{
	New-Item (Get-Variable $item).Value -ItemType File -ErrorAction SilentlyContinue
	(Get-Variable $item).Value = Resolve-Path (Get-Variable $item).Value 
	Write-Host "Creating $((Get-Variable $item).Value) for $item"
}
Write-Host "Beginning Recombination"

$('DeviceName,Filepath,Hash')| Out-File -FilePath $outputtarget
$('DeviceName,Filepath,Hash')| Out-File -FilePath $priorityoutput
$('DeviceName,Filepath,Hash')| Out-File -FilePath $suspectoutput




function Normalprocess
{
	param(
	[string]$inp,
	[string]$output,
	[string]$list
	)
	Write-Host "Recombining $inp and $list into $output"

	
	$clientlist = Import-Csv $inp
	$OSINT = Import-Csv $list
	
	Write-Host "Gathering list of devices"
	
	$resultlist = @{} #table of devices keyed by devicename
	$i = 0
	$StartTime = Get-Date
	foreach($item in $clientlist)
	{
	$i++
	$SecondsElapsed = ((Get-Date) - $StartTime).TotalSeconds
    $SecondsRemaining = ($SecondsElapsed / ($i / $clientlist.Count)) - $SecondsElapsed
    Write-Progress -Activity "Processing Record $i of $($clientlist.Count)" -PercentComplete (($i/$($clientlist.Count)) * 100) -CurrentOperation "$("{0:N2}" -f ((($i/$($clientlist.Count)) * 100),2))% Complete" -SecondsRemaining $SecondsRemaining
		if($item.DataType -eq "DeviceName")
		{
			if($resultlist.ContainsKey($item.Value) -eq $false)
			{
				$resultlist.Add($item.Value, @{"DeviceName"=$item.Value; "Paths"=@()})			
			}
		}
	}

	

	Write-Host "Gathering list of paths and hashes"
	$hashandpath = @{} #hash/paths keyed by path
	$pathandhash = @{} #hash/paths keyed by hash
	$i = 0
	$StartTime = Get-Date
	for($count = 0; $count -lt $clientlist.Count; $count++)
	{
		
		$i++
		$SecondsElapsed = ((Get-Date) - $StartTime).TotalSeconds
		$SecondsRemaining = ($SecondsElapsed / ($count / $clientlist.Count)) - $SecondsElapsed
		Write-Progress -Activity "Processing Record $count of $($clientlist.Count)" -PercentComplete (($count/$($clientlist.Count)) * 100) -CurrentOperation "$("{0:N2}" -f ((($count/$($clientlist.Count)) * 100),2))% Complete" -SecondsRemaining $SecondsRemaining
		
		if($clientlist[$count].DataType -eq "Path")
		{
			if($hashandpath.ContainsKey($clientlist[$count].Value))
			{
				$hashandpath.Add($clientlist[$count].Value, @{"Path"=$clientlist[$count].Value; "Hash" = $clientlist[$count+1].Value})
				$pathandhash.Add($clientlist[$count+1].Value, @{"Path"=$clientlist[$count+1].Value; "Hash" = $clientlist[$count+1].Value})
			}
		}
	}
	

	Write-Host "Processing OSINT list"
	$hashrep = @{} #hash scores keyed by hash
	$i = 0
	$StartTime = Get-Date
	foreach($item in $OSINT)
	{
		$i++
		$SecondsElapsed = ((Get-Date) - $StartTime).TotalSeconds
		$SecondsRemaining = ($SecondsElapsed / ($count / $OSINT.Count)) - $SecondsElapsed
		Write-Progress -Activity "Processing Record $count of $($OSINT.Count)" -PercentComplete (($count/$($OSINT.Count)) * 100) -CurrentOperation "$("{0:N2}" -f ((($count/$($OSINT.Count)) * 100),2))% Complete" -SecondsRemaining $SecondsRemaining
		$hashrep.Add($item.Hash,$item.score)
	}
	

	Write-Host "Correlating Report"

	

}


Normalprocess -inp $prioritytarget -output $priorityoutput -list $inputtarget
Normalprocess -inp $inputt -output $outputtarget -list $inputtarget
Normalprocess -inp $suspectinput -output $suspectoutput -list $inputtarget