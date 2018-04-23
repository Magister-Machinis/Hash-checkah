#
# CBpull.ps1
#
param (
[string]$configfile=".\config.csv",
[string]$source=".\alertid.txt",
[string]$outputtarget=".\refined.csv"

)
$MyParam = $MyInvocation.MyCommand.Parameters
foreach($item in $MyParam.Keys)
{
	New-Item (Get-Variable $item).Value -ItemType File -ErrorAction SilentlyContinue
	(Get-Variable $item).Value = Resolve-Path (Get-Variable $item).Value 
	Write-Host "Creating $((Get-Variable $item).Value)"
}

function sleepbar($seconds)
{
    
    for($count = 0; $count -lt $seconds; $count++)
    {
        $percent = ($count / $seconds) * 100
        write-progress -id 1 -activity "Sleeping: " -status "=][=  $count" -percentcomplete $percent -secondsremaining ($seconds - $count)
        start-sleep -s 1
    }
    Write-Progress -id 1 -Completed -activity "Sleeping: "
}

$("DataType, Value") | Out-File -FilePath $outputtarget

$targetlist = Get-Content $source
$targetlist = $targetlist | sort -unique -Descending
$url = 'https://api-prod05.conferdeploy.net/integrationServices/v3/alert/'
$param = @{}
$count = 0
$count = 0
$counter =0
$size = $targetlist.Length

$i = 0
$StartTime = Get-Date
foreach($target in $targetlist)
{
	
	$i++
	$counter++
	$SecondsElapsed = ((Get-Date) - $StartTime).TotalSeconds
    $SecondsRemaining = ($SecondsElapsed / ($i / $targetlist.Length)) - $SecondsElapsed
    Write-Progress -Activity "Processing Record $i of $($targetlist.Length)" -PercentComplete (($i/$($targetlist.Length)) * 100) -CurrentOperation "$("{0:N2}" -f ((($i/$($targetlist.Length)) * 100),2))% Complete" -SecondsRemaining $SecondsRemaining
	$count++
	if($count -ge (25*$param.Count))
	{
		Write-Host "limit reached, sleeping"
		sleepbar 305
		$count = 0		
	}
	$tempurl= $url + $target
	$tempurl
	
	$response = Invoke-RestMethod -uri $tempurl -Header $param[($counter % $param.Count)] -Method GET
	$response
	$("DeviceName,"+$response.deviceInfo.deviceName) | Out-File -FilePath $outputtarget -Append
	$("AlertID,"+$target) | Out-File -FilePath $outputtarget -Append
	$("Summary,"+$response.threatInfo.summary) | Out-File -FilePath $outputtarget -Append
	$("Event Items") | Out-File -FilePath $outputtarget -Append
	foreach($item in $response.events)
	{
		$("Path,"+$item.applicationPath) | Out-File -FilePath $outputtarget -Append
		$("][,"+$item.processHash) | Out-File -FilePath $outputtarget -Append
		$("][,"+$item.parentHash) | Out-File -FilePath $outputtarget -Append
	}
	

}
