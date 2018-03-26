#
# Sideitem.ps1
#

param (
[string]$source=".\alertid.txt",
[string]$outputtarget=".\QueryResults.csv"

)

$SearchItem = "PUP","MALWARE"
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

$("DataType `t Value") | Out-File -FilePath $outputtarget

$targetlist = Get-Content $source
$targetlist = $targetlist | sort -unique -Descending
$url = 'https://api-prod05.conferdeploy.net/integrationServices/v3/alert/'
$param = @{'X-AUTH-TOKEN' = 'YFUH2YVRZPZ12AJZZC7GYMAC/SK8AKCG43K'}, @{'X-AUTH-TOKEN' = 'NM967QJCPA3FDY47M6AS91K7/NY2HI8H4IG'}, @{'X-AUTH-TOKEN' = 'DR1R8MKQS1MHC9HZNCN4SGYJ/S5HFZC1NEN'}, @{'X-AUTH-TOKEN' = 'CHIZRBBZZTB3I8943RAQW2JM/RJKFQV8A6C'}, @{'X-AUTH-TOKEN' = '5TNBFBC1CGAWAV9G2FD3EW1Z/ZJSLRAQEHU'}, @{'X-AUTH-TOKEN' = 'FV33ZIP96TKI4AQ34V61YQE4/NYR3GVIG2R'}, @{'X-AUTH-TOKEN' = 'R8QZP6LNVUBNPN1IMBAAP2E2/NIHABAA7VW'}, @{'X-AUTH-TOKEN' = 'WJF5EGAV7HR9RQZFHZZDT2ZW/4MHL77PARJ'},@{'X-AUTH-TOKEN' = 'WS8SS476ILEWT33Q37ZM2FPI/3Z1EFP82MT'},@{'X-AUTH-TOKEN' = 'MLRU3FG5WRPRNEUNVUA2N1T3/3GZ51DJ5WZ'}
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
	#$response
	$test = $false
	foreach($item in $response.threatInfo.indicators)
	{
		foreach($subitem in $item)
		{
			$subitem
			foreach($match in $SearchItem)
			{
				if($subitem -imatch $match)
				{				
					$test = $true
				}
			}
		}
	}
	if($test -eq $true)
	{
		$test = $false
		$("DeviceName`t"+$response.deviceInfo.deviceName) | Out-File -FilePath $outputtarget -Append		
		$("Summary`t"+$response.threatInfo.summary) | Out-File -FilePath $outputtarget -Append
		$("Descriptions`t") | Out-File -FilePath $outputtarget -Append
		foreach($item in $response.events)
		{
			foreach($subitem in $item.threatIndicators)
			{
				
				foreach($match in $SearchItem)
				{
					if($subitem -imatch $match)
					{				
						$test = $true
					}
				}
			}
			if($test -eq $true)
			{
				$(("`t"+$item.longDescription) -replace('"<share><[a-zA-Z0-9"= ]+>',"")) -replace('<\/link>.+>"',"") | Out-File -FilePath $outputtarget -Append
			}
		
		}
	}
	}