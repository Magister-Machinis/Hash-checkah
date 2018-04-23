#
# Sideitem.ps1
#

param (
[string]$configfile=".\config.csv",
[string]$source=".\alertid.txt",
[string]$outputtarget=".\QueryResults.csv",
[string]$hashoutput =".\ExtractedHashes.csv"

)
$MyParam = $MyInvocation.MyCommand.Parameters
foreach($item in $MyParam.Keys)
{
	New-Item (Get-Variable $item).Value -ItemType File -ErrorAction SilentlyContinue
	(Get-Variable $item).Value = Resolve-Path (Get-Variable $item).Value 
	Write-Host "Creating $((Get-Variable $item).Value)"
}


function ingestconfig($conf)
{
	$conffile = Import-Csv -Path $conf
	
	$searchparam = @()
	$keys = @()
	foreach($item in $conffile)
	{
		switch ($item.Type )
		{
			CBKey {$keys.Add($item.Data)}
			CBSearch {$searchparam.Add('X-AUTH-TOKEN',$item.Data)}
		}
	}
	
	return $searchparam,$keys
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



$SearchItem,$param = ingestconfig $configfile



$("DataType `t Value") | Out-File -FilePath $outputtarget
$("Hashs") | Out-File -FilePath $hashoutput

$targetlist = Get-Content $source
$targetlist = $targetlist | sort -unique -Descending
$url = 'https://api-prod05.conferdeploy.net/integrationServices/v3/alert/'

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
				$($item.longDescription) -match '=".+">'
								
				 $($matches[0] -replace '="',"") -replace '">',""| Out-File -FilePath $hashoutput -Append
			}
		
		}
	}
}

$sifter = Import-Csv -Delimiter "`t"  $hashoutput | sort Hashs -Unique
$sifter| Export-Csv -Delimiter "`t" $hashoutput