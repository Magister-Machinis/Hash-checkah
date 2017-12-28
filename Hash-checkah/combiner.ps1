#
# combiner.ps1
#
param(
[string]$inputtarget=".\refined.csv",
[string]$prioritytarget=".\priorityresults.csv",
[string]$outputtarget=".\report.csv",
[string]$priorityoutput=".\priorityreport.csv",
[string]$suspectinput=".\suspectresults.csv",
[string]$suspectoutput=".\suspectreport.csv"
)

Write-Host "Beginning Recombination"
$inputtarget = resolve-path $inputtarget
$prioritytarget = resolve-path $prioritytarget
$outputtarget = resolve-path $outputtarget
$priorityoutput = resolve-path $priorityoutput
$suspectinput = resolve-path $suspectinput
$suspectoutput = resolve-path $suspectoutput
$('DeviceName,Filepath,Hash')| Out-File -FilePath $outputtarget
$('DeviceName,Filepath,Hash')| Out-File -FilePath $priorityoutput
$('DeviceName,Filepath,Hash')| Out-File -FilePath $suspectoutput

function Normalprocess($input, $output, $list)
{
Write-Host "Recombining $input and $list into $output"
$badhashes = Get-Content $input | select -Skip 1 | ForEach-Object {$_ -split(",")}
$rawlist = Get-Content $list | select -Skip 1 | ForEach-Object {$_ -split(",")}
$rawhashes = @()
foreach($item in $badhashes)
{
	$rawhashes += $item[1]
}

$refinedlist = @()


$counter =-1
for($count = 0; $count -lt $rawlist.Length; $count++)
{
	$holder = $rawlist[$count][0]
	switch ($holder)
	{
		"DeviceName" {$counter++; $refinedlist[$counter] = @{'DeviceName' =$rawlist[$count][1]}; break}
		"Event Items" {$refinedlist[$counter].Add("Events",@{}); break}
		"Path" {$Eventitem =@{"Filepath" =$rawlist[$count][1]}; $count++; $Eventitem.Add("Hash", $rawlist[$count][1]); $count++; $refinedlist[$counter].Events.Add($Eventitem); break}
	}
}

foreach($item in $refinedlist)
{
	$item.DeviceName | Out-File -FilePath $output -Append
	foreach($subitem in $item.Events)
	{
		if($badhashes -contains $subitem.Hash)
		{
			$(","+$subitem.Filepath+","+$subitem.Hash) | Out-File -FilePath $output -Append
		}
	}
}
}
Normalprocess $prioritytarget $priorityoutput $inputtarget
Normalprocess $inputtarget $outputtarget $inputtarget
Normalprocess $suspectinput $suspectoutput $inputtarget