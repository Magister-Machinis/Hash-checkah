#
# combiner.ps1
#
param(
[string]$inputtarget=".\refined.csv",
[string]$inputt = ".\results.csv",
[string]$prioritytarget=".\priorityresults.csv",
[string]$outputtarget=".\report.csv",
[string]$priorityoutput=".\priorityreport.csv",
[string]$suspectinput=".\suspectresults.csv",
[string]$suspectoutput=".\suspectreport.csv"
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
	$vtdata = Import-Csv $inp 
	$badhashes = $vtdata | select Hash
	$rawlist = Import-Csv $list
	$refinedlist = @()
	$listcounter=-1
	for($count=0; $count -lt $rawlist.Length; $count++)
	{
		switch($rawlist[$count].DataType)
		{
			"DeviceName" {$listcounter++; $refinedlist+= @{"DeviceName" = $rawlist[$count].Value};break;}
			"Path" {$refinedlist[$listcounter].Add("Path", $rawlist[$count].Value);break;}
			"][" {$refinedlist[$listcounter].Add("Hash",$rawlist[$count].Value);$count++;break;}
		}
	}
	foreach($item in $refinedlist)
	{
		$place = [array]::IndexOf($badhashes,$item.Hash)
		$item.Add("VTPresent", $vtdata[$place].VTStatusCODE)
		$item.Add("VTScore", $vtdata[$place].'VT Hits')
		$item.Add("OTXHits", $vtdata[$place].'OTX hits')
		$item.Add("VTLink", $vtdata[$place].'VT Link')		
	}

	$refinedlist | Export-Csv -Path $output
	
}


Normalprocess -inp $prioritytarget -output $priorityoutput -list $inputtarget
Normalprocess -inp $inputt -output $outputtarget -list $inputtarget
Normalprocess -inp $suspectinput -output $suspectoutput -list $inputtarget