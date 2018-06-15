#
# Script.ps1
#

param (
[string]$configfile=".\config.csv",
[string]$source=".\refined.csv",
[string]$secondsource = ".\hashes.txt",
[string]$outputtarget=".\results.csv",
[string]$prioritytarget=".\priorityresults.csv",
[string]$suspectoutput=".\suspectresults.csv",
[string]$knowngoodsalpha=".\seemsharmless.txt"
)
$MyParam = $MyInvocation.MyCommand.Parameters
foreach($item in $MyParam.Keys)
{
	New-Item (Get-Variable $item).Value -ItemType File -ErrorAction SilentlyContinue
	(Get-Variable $item).Value = Resolve-Path (Get-Variable $item).Value 
	Write-Host "Creating $((Get-Variable $item).Value)"
}
$auth= import-csv -Path $configfile


$knowngoods = get-content -Path $knowngoodsalpha

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
[scriptblock]$funbits ={
param (
$target,
$auth
)
	function vtcheck($hash, $auth)
	{
		$param = @{'apikey' = $auth.vt; 'resource' = $hash}
		$response = Invoke-RestMethod -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $param -Method Get
		$info = @{'hits' = $response.positives; 'link' = $response.permalink; 'status'= $response.response_code; 'scans' = $response.scans}
		return $info
	
	
	}

	function otxcheck($hash, $auth)
	{
		$param = @{'X-OTX-API-KEY' = $auth.otx}
		$url = 'https://otx.alienvault.com/api/v1/indicators/file/' + $hash + '/general'
		$response = Invoke-RestMethod -Uri $url -Body $param -Method GET
		return $response.pulse_info
	}


	function gatherer($target, $auth)
	{
			$test = $false
			$suspecttest = $false
			Write-Host "Checking $target"
			$vt = vtcheck $target $auth
			#Write-Host "VT results are $vt"
			$otx = otxcheck $target $auth
			#Write-Host "OTX results are $otx"
			[string]$output =[string]([string]([int]$vt.hits+[int]$otx.count)+","+[string]$vt.status +","+ [string]$target + "," + [string]$vt.hits + "," + [string]$vt.link +"," + [string]$otx.count+"," + [string]$otx.references +",")

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
			
				if(!([string]::IsNullOrEmpty($ptarget.result) -or [string]::IsNullOrWhiteSpace($ptarget.result)))
				{
					[string]$output += ("|"+$ptarget.result)
				}
				if($ptarget.detected -eq $true)
				{
					Write-Host "Suspect item found"
					$suspecttest = $true
				}
				if($ptarget.result -imatch "emotet" -or $ptarget.result -imatch "qakbot" -or $ptarget.result -imatch "qbot" -or $ptarget.result -imatch "emo")
				{
					Write-Host "Potential hit found"
					$test = $true
				}
			}
			return @{'output'=$output;'priority'=$test;'suspect'=$suspectest;'hash'=$target}
		
			
		

	}
	return gatherer $target $auth
}


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

$runspacepool = [RunspaceFactory ]::CreateRunspacePool(1,12)

$runspacepool.Open()
$jobs = @()
$size = $targetlist.Length
$numcount = 0

$i = 0
$StartTime = Get-Date
foreach($target in $targetlist)
{
	if(!($knowngoods.Contains($target)))
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
			#$dcount = 0
			#sleepbar ((New-TimeSpan -End "11:59pm").TotalSeconds+120)
			break
		}

		$job=[powershell]::Create().AddScript($funbits).AddArgument($target).AddArgument($auth)
	$job.RunspacePool = $runspacepool
	$jobs += New-Object PSObject -Property @{
		Pipe = $job
		Result = $job.BeginInvoke()}	
		}
}

Write-Host "Waiting for translation to conclude"

Do {
	write-progress -id 1 -activity $("Number remaining: " + $($jobs.Result.IsCompleted -contains $false | Group-Object -AsHashTable -AsString)['false'].Count) -percentcomplete $(100-(($($jobs.Result.IsCompleted -contains $false | Group-Object -AsHashTable -AsString)['false'].Count)/$jobs.Count)*100)
	Start-Sleep -Seconds 1
} While ( $jobs.Result.IsCompleted -contains $false )

$count =0

foreach($job in $jobs)
{
	$percent = ($count / $jobs.Count) * 100
	write-progress -id 1 -activity "Retrieving Events: " -status "=][=  $count of $($jobs.Count)" -percentcomplete $percent 
	$count++

	
	$temp= $job.Pipe.EndInvoke($job.Result)
	if(($temp.priority -eq $true)-or($temp.suspect -eq $true) )
	{
		if($temp.priority -eq $true)
		{
			$temp.output | Out-File -FilePath $prioritytarget -Append
		}
		if($temp.suspect -eq $true)
		{
			$temp.output | Out-File -FilePath $suspectoutput -Append
		}
	}
	else
	{
		$temp.output | out-file -FilePath $outputtarget -Append
		$knowngoods += $temp.output.hash
	}
	$knowngoods | sort -Unique | Out-File -FilePath $knowngoodsalpha
}