#
# CBpull.ps1
#
param (
[string]$source=".\alertid.txt",
[string]$outputtarget=".\refined.csv"

)


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

$source = resolve-path $source

$outputtarget = resolve-path $outputtarget
$("Raw Information") | Out-File -FilePath $outputtarget

$targetlist = Get-Content $source
$targetlist = $targetlist | sort -unique -Descending
$url = 'https://api-prod05.conferdeploy.net/integrationServices/v3/alert/'
$param = @{'X-AUTH-TOKEN' = 'LZKLUNP6PCRTZZDIH8KJKRZL/IVRQM5WPS8'}, @{'X-AUTH-TOKEN' = '3WUW16TDKTZ3BY5NYFLAKJ6A/8PUFWW84EC'}, @{'X-AUTH-TOKEN' = 'A22EFYHWIZ5RBQJMH2BZ5Q5I/258QSVCFZ1'}, @{'X-AUTH-TOKEN' = 'LVQMHNW15ENZT2LJ57LW76YF/THEVK9R3LB'}, @{'X-AUTH-TOKEN' = 'RP4YLRVJKK49TUTGSV718ILK/EF6RB79QCL'}, @{'X-AUTH-TOKEN' ='RMTVHUDUMRQM9CZTCCT6SW8K/43L9AUU6IW'}, @{'X-AUTH-TOKEN' ='1NTFDFCYP4W33CJEMVT5TNIZ/CTVABLZWDG'}, @{'X-AUTH-TOKEN' ='GWWNPWL1NZ7Y6KIGGN7RZ8UC/FBIYPINDAA'}, @{'X-AUTH-TOKEN' ='V2N3AEYQ6EGNTNY692W4RYMV/D4KZTT1L7H'}, @{'X-AUTH-TOKEN' ='7ZDRNMDU8Z9FEVCSIDN8IHYG/ZZYQM8K2Z4'}
$count = 0
$counter =0
$size = $targetlist.Length
foreach($target in $targetlist)
{
	
	$counter++
	$percent = ($counter / $size) * 100
	Write-Progress -Id 2 -Activity "Progress" -Status "$counter of $size done" -PercentComplete $percent
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
