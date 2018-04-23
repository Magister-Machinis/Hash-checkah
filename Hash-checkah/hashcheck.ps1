#
# Script.ps1
#

param (
[string]$configfile=".\config.csv",
[string]$source=".\refined.csv",
[string]$secondsource = ".\hashes.txt",
[string]$outputtarget=".\results.csv",
[string]$prioritytarget=".\priorityresults.csv",
[string]$suspectoutput=".\suspectresults.csv"
)
$MyParam = $MyInvocation.MyCommand.Parameters
foreach($item in $MyParam.Keys)
{
	New-Item (Get-Variable $item).Value -ItemType File -ErrorAction SilentlyContinue
	(Get-Variable $item).Value = Resolve-Path (Get-Variable $item).Value 
	Write-Host "Creating $((Get-Variable $item).Value)"
}

function vtcheck($hash)
{
	$param = @{'apikey' = 'a397bb0bbc39b53f67e57514432281c57beb53c96182292108510aa08b5fe934'; 'resource' = $hash}
	$response = Invoke-RestMethod -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $param -Method Get
	$info = @{'hits' = $response.positives; 'link' = $response.permalink; 'status'= $response.response_code; 'scans' = $response.scans}
	return $info
	
	
}

function otxcheck($hash)
{
	$param = @{'X-OTX-API-KEY' = '0690e2eb9a3296b0933e1073047be755a13955d6a7ec64149119ecf6960698c6'}
	$url = 'https://otx.alienvault.com/api/v1/indicators/file/' + $hash + '/general'
	$response = Invoke-RestMethod -Uri $url -Body $param -Method GET
	return $response.pulse_info
}
function sleepbar($seconds)
{
    
    for($count = 0; $count -lt $seconds; $count++)
    {
        $percent = ($count / $seconds) * 100
        write-progress -id 1 -activity "Sleeping: " -status "=][=  $count" -percentcomplete $percent -secondsremaining ($seconds - $count)
        start-sleep -s 1
    }
    Write-Progress -id 1 -Completed -activity "Resuming: "
}

function gatherer($target, $outputtarget, $prioritytarget, $suspectoutput)
{
		$test = $false
		$suspecttest = $false
		Write-Host "Checking $target"
		$vt = vtcheck $target
		#Write-Host "VT results are $vt"
		$otx = otxcheck $target
		#Write-Host "OTX results are $otx"
		[string]$output =[string]([string]([int]$vt.hits+[int]$otx.count)+","+[string]$vt.status +","+ [string]$target + "," + [string]$vt.hits + "," + [string]$vt.link +"," + [string]$otx.count+"," + [string]$otx.references)

		if($vt.hits+$otx.count -gt 0)
		{
			$suspecttest = $true
		}
		
		$checklist = @("Bkav","MicroWorld-eScan","nProtect","CMC","CAT-QuickHeal","McAfee","Malwarebytes","Zillya","AegisLab","CrowdStrike","K7GW","K7AntiVirus","TheHacker","Invincea","Baidu","F-Prot","Symantec","TotalDefense","Zoner","TrendMicro-HouseCall","Avast","ClamAV","GData","Kaspersky","BitDefender","NANO-Antivirus","ViRobot","Rising","Ad-Aware","Sophos","Comodo","F-Secure","DrWeb","VIPRE","TrendMicro","McAfee-GW-Edition","Emsisoft","SentinelOne","Cyren","Jiangmin","Webroot","Avira","Antiy-AVL","Kingsoft","Endgame","SUPERAntiSpyware","ZoneAlarm","Microsoft","AhnLab-V3","ALYac","AVware","MAX","VBA32","Cylance","WhiteArmor","Panda","Arcabit","ESET-NOD32","Tencent","Yandex","Ikarus","Fortinet","AVG","Paloalto","Qihoo-360","Ad-Aware","AegisLab","AhnLab-V3","ALYac","Arcabit","Avast","AVG","Avira (no cloud)","AVware","Baidu","BitDefender","CAT-QuickHeal","ClamAV","CrowdStrike Falcon (ML)","Cybereason","Cylance","Cyren","eGambit","Emsisoft","Endgame","ESET-NOD32","F-Secure","Fortinet","GData","Ikarus","Sophos ML","K7AntiVirus","K7GW","Kaspersky","Malwarebytes","MAX","McAfee","McAfee-GW-Edition","Microsoft","eScan","NANO-Antivirus","Palo Alto Networks (Known Signatures)","Panda","Qihoo-360","Rising","SentinelOne (Static ML)","Sophos AV","Symantec","Tencent","TrendMicro","TrendMicro-HouseCall","VBA32","VIPRE","ViRobot","Webroot","Zillya","ZoneAlarm by Check Point","Alibaba","Avast-Mobile","Bkav","CMC","Comodo","DrWeb","F-Prot","Jiangmin","Kingsoft","nProtect","SUPERAntiSpyware","Symantec Mobile Insight","TheHacker","TotalDefense","Trustlook","WhiteArmor","Yandex","Zoner")
		$checklist = $checklist | sort -Unique
		Write-Host $(($vt.scans).Length)
		for([int]$count =0; $count -lt [int]$checklist.Length; [int]$count+=1)
		{
			Write-Host "Checking "
			$($checklist[$count])
			$ptarget = $vt.scans.$($checklist[$count])
			$ptarget
			[string]$output += (("|"+$ptarget.result) -replace("\|\|","")) 
			if($ptarget.detected -eq $true)
			{
				Write-Host "Suspect item found"
				$suspecttest = $true
			}
			if($ptarget.result -imatch "emotet" -or $ptarget.result -imatch "qakbot" -or $ptarget.result -imatch "qbot")
			{
				Write-Host "Potential hit found"
				$test = $true
			}
		}
		Write-Host "Recording to file:"
		$output
		if($test -eq $true)
		{
			$output | Out-File -FilePath $prioritytarget -Append
		}
		if($suspecttest -eq $true)
		{
			$output | Out-File -FilePath $suspectoutput -Append
		}
		
			$output | Out-File -FilePath $outputtarget -Append
		

}

$source = resolve-path $source
$secondsource = resolve-path $secondsource
$outputtarget = resolve-path $outputtarget
$prioritytarget = resolve-path $prioritytarget
$suspectoutput = resolve-path $suspectoutput
Write-Host "Resolved Paths are"
$source
$secondsource
$outputtarget
$prioritytarget
$suspectoutput
$initial = "Score,VTStatusCODE,Hash,VT Hits,VT Referrence,OTX hits,OTX Referrence,VT Matches"
$initial | Out-File -filepath $outputtarget 
$initial | Out-File -filepath $prioritytarget 
$initial | Out-File -filepath $suspectoutput
 
$targetlist = Get-Content $source | select -Skip 1 | sort -Descending -Unique | Where-Object {$_ -match '\]\['}
$secondlist = Get-Content $secondsource
Write-Host "List loaded is: "
$refinedlist = @()
foreach($item in $targetlist)
{
	$refinedlist += (($item -split(','))[1]) -replace("[^a-zA-Z0-9]","")
}
$targetlist=($refinedlist + $secondlist) | sort -Descending -Unique
$targetlist
$mcount = 0
$dcount = 0

$size = $targetlist.Length
$numcount = 0

$i = 0
$StartTime = Get-Date
foreach($target in $targetlist)
{
	

	$i++
	$numcount++
	$SecondsElapsed = ((Get-Date) - $StartTime).TotalSeconds
    $SecondsRemaining = ($SecondsElapsed / ($i / $targetlist.Count)) - $SecondsElapsed
    Write-Progress -Activity "Processing Record $i of $($targetlist.Count)" -PercentComplete (($i/$($targetlist.Count)) * 100) -CurrentOperation "$("{0:N2}" -f ((($i/$($targetlist.Count)) * 100),2))% Complete" -SecondsRemaining $SecondsRemaining
	
	
		
		$mcount++
		$dcount++
		if($mcount -gt 3)
		{
			Write-Host "Per-minute limit reached"
			$mcount = 0
			sleepbar 61
		}
		if($dcount -gt 5750 )
		{
			Write-Host "Per-day limit reached"
			$dcount = 0
			sleepbar 86400
		}
		
		gatherer $target $outputtarget $prioritytarget $suspectoutput
}


