#
# Eventingester.ps1
#
param (
[string]$configfile=".\config.csv",
[string]$secondsource = ".\hashes.txt",
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
$auth= import-csv -Path $configfile
[scriptblock]$eventingress ={
	param(
	[int]$rowcount,
	$auth
)
	$url = 'https://api-prod05.conferdeploy.net/integrationServices/v3/event?searchWindow=1d&start='+$rowcount+'&rows=50000'
	$key = @{'X-AUTH-TOKEN'=$auth.cb}
	
	$results = invoke-restmethod -uri $url -Header $key -method GET
	
	
	$counter = 0
	$usable = @()
	foreach($item in $results.results)
	{
		Write-Progress -id 1 -activity "Checking item $counter of $($results2.count)" -PercentComplete $(($counter/$($results2.count)) * 100)
		$counter+=1
		$usable += $item.selectedApp.sha256Hash 
		$usable += $item.parentApp.sha256Hash 
		$usable += $item.targetApp.sha256Hash
	

		foreach($thing in $(([regex]::match($item.longDescription,'hash=".+">')).Value))
		{
		
			$thang = $thing -replace 'hash=',""
			$thang = $thang -replace '"',''
		
			$thang = $($thang -split '>')[0]
		
			$usable += $thang 
		}	
	}
	$usable = $usable | sort -Unique

	return $usable 
}
$("") | Out-File -FilePath $secondsource 
$results2 = @()
$rowcount = 1
$counter = 0

$runspacepool = [RunspaceFactory ]::CreateRunspacePool(1,48)
$count =0
$runspacepool.Open()
$jobs = @()

do{
	if($counter -eq 24)
	{
		Write-Host "throttling call rate"
		Start-Sleep -Seconds 300
		$counter =0
	}

	$job=[powershell]::Create().AddScript($eventingress).AddArgument($rowcount).AddArgument($auth)
	$job.RunspacePool = $runspacepool
	$jobs += New-Object PSObject -Property @{
		Pipe = $job
		Result = $job.BeginInvoke()
		}  

	$counter+=1
	$rowcount+=5000
	$rowcount
	
}while($rowcount -le 100000)

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
		
	$results2 += $job.Pipe.EndInvoke($job.Result)

}
Write-Host "Retrieval complete"


$results2.count
$counter = 0
$results2 | Out-File -FilePath $secondsource

& ".\hashcheck.ps1" -secondsource $secondsource
$worklocation=resolve-path ".\"

if(!(Test-Path -Path $worklocation))
{
	new-item -ItemType Directory $worklocation
}
$worklocation = Join-Path -Path $worklocation -ChildPath "\reports"

if(!(Test-Path -Path $worklocation))
{
	new-item -ItemType Directory $worklocation
}
$todayr= Import-Csv $prioritytarget
$filename = [string]((("priority"+(get-date).tostring() + ".csv") -replace"/","") -replace " ","") -replace ":",""
$todayr | Export-Csv -Delimiter "`t" -Path $(Join-Path -Path $worklocation -ChildPath $filename) -NoTypeInformation

$todayr= Import-Csv $suspectoutput
$filename = [string]((("suspect"+(get-date).tostring() + ".csv") -replace"/","") -replace " ","") -replace ":",""
$todayr | Export-Csv -Delimiter "`t" -Path $(Join-Path -Path $worklocation -ChildPath $filename) -NoTypeInformation