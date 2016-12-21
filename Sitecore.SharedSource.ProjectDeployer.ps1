# Copyright (c) [2016] [David Walker] - MIT License - see License.txt
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False, Position=1)]
   [string]$targetPath,
	
   [Parameter(Mandatory=$False, Position=2)]
   [string]$projectPath,
	
   [Parameter(Mandatory=$False, Position=3)]
   [string]$auditPath,

   [Parameter(Mandatory=$False, Position=4)]
   [string]$updateSiteListCache
)
$audit = 1
$verbose = 0
#$packagesSourceSitePackagesFolder = "" #this disables
$packagesSourceSitePackagesFolder = "d:\webs\sc81mvc\Data\packages".ToLower()
#$pseUrl = "/sitecore%20modules/PowerShell/Services/RemoteAutomation.asmx?WSDL"
$pseTestPath = "\sitecore modules\PowerShell\Services\RemoteAutomation.asmx"
$validateSite = 0

# VISUAL STUDIO Tokens:
# $TargetPath$ - full path and file name to assembly.dll
# $TargetDir$ - full path to folder

$stats = @{"Sites Deployed" = 0; "Packages Imported" = 0}

if ($audit -eq 1) { $verbose = 1}

function message($message) {
	if ($verbose -eq 1) {"$message"}
}

message "Import-Module WebAdministration-started"
Import-Module WebAdministration
message "Import-Module WebAdministration-completed"

if (-NOT(Test-Path($packagesSourceSitePackagesFolder))) {
	message "packagesSourceSitePackagesFolder does not exist - not installing packages"
	$packagesSourceSitePackagesFolder = ""
}

message "projectPath:$projectPath"

if ($projectPath.EndsWith('"')) {
	message "removing extra double quote at end of projectPath"
	$projectPath = $projectPath.Remove($projectPath.Length - 1, 1)
}
message "projectPath:$projectPath"

message "args:$args"
$cmdLine = (Get-History 1 -count 1).CommandLine
message "cmd:$cmdLine"

$projectName = $projectPath
if ($projectName.LastIndexOf("\") -gt -1) {
	$projectName = $projectName.Remove(0, $projectName.LastIndexOf("\"))
}
message "projectName:$projectName"

#$scriptlocation = (Get-Item -Path ".\" -Verbose).FullName
#$scriptlocation = $MyInvocation.MyCommand.Path
$scriptlocation = $PSScriptRoot + "\"
message "scriptlocation:$scriptlocation"


$siteListCache = $scriptlocation + "siteListCache.txt"
message "siteListCache:$siteListCache"

#"targetPath: $targetPath"

$targetFile = Get-ChildItem $targetPath | % { ($_.name)}
message "targetFile:$targetFile"

message "auditPath:$auditPath"

if ($audit -eq 1 -and $auditPath.Length -eq 0 -and $projectPath.Length -ne 0) {
	$auditPath = ($projectPath.Substring(0, $projectPath.LastIndexOf("\"))) + "\builds"
	message "auditPath:$auditPath"

	$cmd = "$scriptlocation" + $MyInvocation.MyCommand.Name
	message "cmd:$cmd"

	if(Test-Path $auditPath) {
		message "auditing"

		$dateFormatAuditName = Get-Date -format M.d.yyyy.HH.mm
		message "dateFormatAuditName:$dateFormatAuditName"

		$auditPath = $auditPath + "\$projectName-$dateFormatAuditName.log"
		message "auditPath:$auditPath"

		. $cmd  $targetPath $projectPath $auditPath | tee $auditPath
	} else {
		message "running"
		. $cmd $targetPath $projectPath $auditPath
	}
	return;
} else {
	message "running"
}

message "packagesSourceSitePackagesFolder: $packagesSourceSitePackagesFolder"
#message "pseUrl: $pseUrl"
message "pseTestPath:$pseTestPath"

$destinations = @()
#$destinations = "sc70rev130424", "sc72", "sc75", "sc81", "sc81mvc", "sc81rev160519"
$destinations = $destinations + "*"

$excludedSites = @()
$excludedSites = $excludedSites + "Default Web Site", "autohaus", "jetstream", "habitat.localhost"

$refChecks = "Sitecore.SharedSource.Common.dll","" #, "Sitecore.SharedSource.Sniper.dll"
message "refChecks:$refChecks"

$assetFolders = "App_Config", "Controllers", "sitecore", "SharedSource", "Views"
message "assetFolders:$assetFolders"

$excludedFiles = @()
$excludedFiles = $excludedFiles + "sitecore.kernel.dll", "sitecore.mvc.dll", "Newtonsoft.Json.dll", "license.txt", "packages.config", $targetFile.Replace(".dll", ".xml")
message "excludedFiles:$excludedFiles"

$destinationRoot = "D:\webs"
#IF "%COMPUTERNAME%"=="RADDAVE-WIN-VM" SET DESTINATIONROOT=\\mac\data\webs
message "destinationRoot:$destinationRoot"

#$getWebSiteRoot = "$scriptlocation" + "GetWebSiteRoot.exe"
#message "getWebSiteRoot: $getWebSiteRoot"

if($projectPath -ne "")
{
  $loc = $targetPath.IndexOf("\bin")
  If ($loc -ne -1)
  {
	  $projectPath = $targetPath.Substring(0, $loc)
  }
}
message "projectPath:$projectPath"

#todo: needs error handling when $path is invalid
function GetFileVersion($path) {
	$results = ""
	try
	{
		$results = (Get-Command $path).Version
	}
	catch
	{
		write-host "Caught an exception:" -ForegroundColor Red
		write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
	}
	return $results 
}

#if ($targetPath.EndsWith($refCheck))
if ($refChecks -contains $targetFile)
{
  # Get targetfileVersion ONCE IF NEEDED, SINCE IT NEVER CHANGES
	$refCheckFile = $targetPath.Replace($refChecks[0], "Sitecore.Kernel.dll")
	#$targetFileVersion = (Get-Command $refCheckFile).Version
	$targetFileVersion = GetFileVersion $refCheckFile
	#"targetFileVersion: $targetFileVersion"
}


#TODO: Skip if apppool not running because of potential to need packages
function DeploySite($site) {
	message "*********************"
	"DeploySite:$site"
	#try
	#{
		#$siteConfig = Get-Website -Name $site.localhost
		#$siteConfig = Get-Website | Where-Object {$_.name -eq "$site"}
		#if ($siteConfig -eq $null) {$siteCOnfig = Get-Website | Where-Object {$_.name -eq "$site.localhost"}}
		#$siteConfig = Get-Website | Where-Object {$_.name -eq "$site" -or $_.name -eq "$site.localhost"}}
		$siteConfig = Get-Website | Where-Object {$_.name -eq "$site"}
	#}
	#catch
	#{
	#    $ErrorMessage = $_.Exception.Message
	#	$FailedItem = $_.Exception.ItemName
	#	#Send-MailMessage -From ExpensesBot@MyCompany.Com -To WinAdmin@MyCompany.Com -Subject "HR File Read Failed!" -SmtpServer EXCH01.AD.MyCompany.Com
	#	message "Error in DeploySite:" + $ErrorMessage + "-" + $FailedItem
	#	Break
	#}
	if ($siteConfig -eq $null) {
		$isAdmin = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Administrators")
		message "running as administrator: $isAdmin"
		message "$env:PROCESSOR_ARCHITEW6432"
		message "Test-Path $Profile"
		message "Error: Get-Website could not find site - $site"
		#continue
	}
	#message "siteConfig:$siteConfig"
	#if ($verbose -eq 1) { return;}
	#&$getWebSiteRoot "$site.localhost" | Tee-Object -Variable sitecorePath | Out-Null
	#both below return this error:
	#Retrieving the COM class factory for component with CLSID 
	#EXEC : {688EEEE5-6A7E-422F-B2E1-6AF00DC944A6} failed due to the following error : 
	#80040154 Class not registered (Exception from HRESULT: 0x80040154 
	#(REGDB_E_CLASSNOTREG))
	#$sitePath = (get-item IIS:\Sites\$site.localhost).physicalPath
	#$sitePath = (Get-Website -Name $site.localhost).physicalPath
	$sitePath = $siteConfig.physicalPath

	if (!$sitePath) {
		message "Determing SITECOREPATH from DESTINATIONROOT:$destinationRoot"
		# since GetWebSiteRoot.exe $site.localhost returned blank"		
		$sitePath = $destinationRoot + "\" + $site + "\website"
		message "sitePath:$sitePath"
		if (Test-Path $sitePath)
		{
			#found it
		} else {
			$sitePath = $destinationRoot + "\" + $site + ".localhost\website"
			if (Test-Path $sitePath)
			{
				#found it
			} else {
				$sitePath = ""
			}
		}
		#return;
	}
	
	if (-not $sitePath.ToLower().Contains("\website")) {
		message "$site skipped - not a Sitecore site"
		return
	}

	message "sitecorePath:$sitePath"
	
	$siteBindingInfo = $siteConfig.bindings.Collection | Where-Object { $_.protocol -eq 'http'} | Select -ExpandProperty bindingInformation -first 1
	
	message "siteBindingInfo:$siteBindingInfo"
	
	if ($siteBindingInfo.StartsWith("*:80:")) {
		message "getting hostname"
		$siteBindingInfo = $siteBindingInfo.Remove(0, 5)
		$siteBindingInfoSplitLoc = $siteBindingInfo.LastIndexOf(" ")
		message "siteBindingInfoSplitLoc:$siteBindingInfoSplitLoc"
		if ($siteBindingInfoSplitLoc -gt -1 -or ($siteBindingInfo.StartsWith("*"))) {
			message "site has multiple hostnames getting primary"
			$siteBindingInfo = $siteBindingInfo.Remove(0, 2)
			#$siteBindingInfo = $siteBindingInfo.Substring(0, $siteBindingInfoSplitLoc)
		}
	}
	#if ($siteBindingInfo.Contains(":")) {
#		$siteBindingInfo = $siteBindingInfo.Remove(0, $siteBindingInfo.LastIndexOf(":") + 1)
#	}
	$siteUrl = "http://$siteBindingInfo"
	message "siteUrl:$siteUrl"

	#If ($targetPath.EndsWith($refCheck
	if ($refChecks -contains $targetFile)
	{
		 # IF Common then do this extra reference check to copy one with references only - if not right version then GOTO EXIT

		$refCheckFileVersion = GetFileVersion "$sitePath\bin\Sitecore.Kernel.dll"
		message "refCheckFileVersion:$refCheckFileVersion"

		if ($targetFileVersion -ne $refCheckFileVersion) {
			message "Skipping deploy for this site due to incompatible Sitecore Versions"
			return
		}
	}

	$stats["Sites Deployed"] = $stats["Sites Deployed"] + 1

	DeployFiles $targetPath $sitePath

	#********************************
	#ImportPackages - Check
	#********************************
	$sitePseTestPath = "$sitePath$pseTestPath"
	message "sitePseTestPath:$sitePseTestPath"

	if (-NOT(Test-Path($sitePseTestPath))) {
		$sitePseTestPath = ""
		message "sitePseTestPath could not be found"
		message "Sitecore PSE not installed - not installing packages"
	}
	
	#********************************
	#ImportPackages
	#********************************
	if ($packagesSourceSitePackagesFolder -ne "" -and ($sitePseTestPath -ne "")) {
		$sitePackagePath = $sitePath.ToLower().Replace("\website", "\data\packages")
		message "sitePackagePath:$sitePackagePath"
		if ($packagesSourceSitePackagesFolder -eq $sitePackagePath){
			message "skipping current site since it is packages source site"
		} else {
			$deployed = 0
			#use package designer xml files as base
			Get-ChildItem $packagesSourceSitePackagesFolder -Filter *.xml | 
			Foreach-Object {

				$packageDesignerPath = $_.FullName
				message "packageDesignerPath:$packageDesignerPath"

				$packageFilter = $_.Name.Replace(".xml", "-*.zip")
				message "packageFilter:$packageFilter"

				#get latest build of package
				#| sort LastWriteTime | select -last 1
				#http://stackoverflow.com/questions/9675658/powershell-get-childitem-most-recent-file-in-directory
				$package = Get-ChildItem $packagesSourceSitePackagesFolder -Filter $packageFilter | select -last 1
                
				if($package -ne $null) {
					$packagePath = $package.FullName
					message "packagePath:$packagePath"

					$packageName = $package.Name
					message "packageName:$packageName"

					$targetPackage = $sitePackagePath + "\" + $packageName
					message "targetPackage:$targetPackage"

					#needs to be deployed?
					$deploy = 0
					if (-NOT(Test-Path ($targetPackage))) {
						$deploy = 1
					} else {
						$packageSrc = Get-Item $packagePath
						$packageDest = Get-Item $targetPackage

						# check if files are same version; if the same do nothing, if not then copy
						if ($packageDest.LastWriteTime -lt $packageSrc.LastWriteTime){
							$deploy = 1
						}
						else
						{
							message "skipped-Current or newer package already exists"
						}
					}

					if ($deploy -eq 1) {
						message "copy $packagePath to $targetPackage"
						if ($verbose -eq 1) {
							&COPY $packagePath $targetPackage
						} else {
							&COPY $packagePath $targetPackage|Out-Null
						}
                    
						if (Test-Path ("$sitePackagePath\$packageName")) {
							message "calling PSE to ImportPackage"
							$proxyURI = "$siteUrl/sitecore%20modules/PowerShell/Services/RemoteAutomation.asmx?WSDL"
							message "proxyURI:$proxyURI"
							$proxy = New-WebServiceProxy -uri $proxyURI #-namespace "com.example" -class "MyProxyClass"
							$request = $proxy.ExecuteScript("admin", "b", "Install-Package -Path $packageName -InstallMode Merge -MergeMode Merge", "results");
							#$proxy.output;
							"respponse:"
							$request.replyContent | Get-Member

							$deployed = $deployed + 1
						}
					}
				}
			}

			message "packages installed:$deployed"

			$stats["Packages Deployed"] = $stats["Packages Deployed"] + 1

			#if ($deployed -ne 0) {
			#	message "calling PSE to Start-Publish"
			#	$proxy = New-WebServiceProxy -uri "$siteUrl/sitecore%20modules/PowerShell/Services/RemoteAutomation.asmx?WSDL" #-namespace "com.example" -class "MyProxyClass"

			#	#reference: https://sitecorepowershell.gitbooks.io/sitecore-powershell-extensions/content/appendix/commands/Publish-Item.html

			#	$publishCmd = "Publish-Item -Item] [-Recurse] [-Target ] [-PublishMode ]

			#	$request = $proxy.ExecuteScript("admin", "b", "Start-Publish", "results");
							
			#	#$proxy.output;
			#	"respponse:"
			#	$request.replyContent | Get-Member
			#}
		}
	}
	else {	
		message "*********************"
		message "importPackages skipped"
	    message "packagesSourceSitePackagesFolder: $packagesSourceSitePackagesFolder"
		message "sitePseTestPath:$sitePath$pseTestPath"
	}

	if ($validateSite -eq 1) {
		message "Requesting $siteUrl ..."
		[string]$testContent = (Invoke-WebRequest -URI "http://$siteUrl").Content

		message "Validating $siteUrl ..."

		if ($testContent.IndexOf("Welcome to Sitecore") -ne -1) {
		   "$siteUrl pass"
		} else {
			"$siteUrl fail"		
			message "testContent: $testContent"
		}
	}
}

function DeployFiles($target, $destination) {
	message "DeployFiles $target $destination"

	#Main Assembly
	#&XCOPY $targetPath "$sitePath\bin" /y /d

	#References - only missings
	$targetPathFolder = ([System.IO.FileInfo]"$targetPath").Directory.FullName
	message "targetPathFolder:$targetPathFolder"
	$kernelPath = $targetPathFolder + "\sitecore.kernel.dll"
	message "kernelPath:$kernelPath"
	#Remove-Item $targetPathFolder\sitecore.kernel.dll|Out-Null
	
	
	#if (Test-Path ($kernelPath))
	#{
	#	if ($verbose -eq 1) {"remove-item $kernelPath"}
	#	remove-item $kernelPath
	#}

	
	foreach ($excludedFile in $excludedFiles) {
		if (Test-Path ($excludedFile))
		{
			message "remove-item $excludedFile"
			remove-item $excludedFile
		}
	}
	if ($verbose -eq 1) {
		&XCOPY $targetPathFolder "$sitePath\bin" /s /e /y /d
	} else {
		&XCOPY $targetPathFolder "$sitePath\bin" /s /e /y /d|Out-Null
	}
	# | echo "No"
	#Copy-Item "$targetPathFolder\*" "$sitePath\bin"

	#$source = "$targetPathFolder"
	#$dest = "$sitePath\bin"
	#$exclude = "Sitecore.Kernel.dll" , "Sitecore.Analytics.dll" , "*.pdb"
	#Get-ChildItem $source -Recurse -Exclude $exclude | Copy-Item -Destination {Join-Path $dest $_.FullName.Substring($source.length)} 
	#Get-ChildItem $source -Recurse -Exclude $exclude | ? {$_.FullName }

	message "projectPath:$projectPath"

	foreach ($assetFolder in $assetFolders) {
		$sourceFolder = $projectPath + "\" + $assetFolder
		
		if(Test-Path $sourceFolder) {
			message "sourceFolder:$sourceFolder"

			if ($verbose -eq 1) {
				&XCOPY $sourceFolder\*.* "$sitePath\$assetFolder\*.*" /s /e /y /d
			} else {
				&XCOPY $sourceFolder\*.* "$sitePath\$assetFolder\*.*" /s /e /y /d|out-null
			}
			#Copy-Item doesnt have a "newer" only?
			#robocopy is MS provided??? http://ss64.com/nt/robocopy.html
			#Copy-Item "$targetPathFolder\*" "$siteorePath\bin"
		}
	}
}
$sites = $destinations

if ($destinations -eq "*")
{
	if ($updateSiteListCache -ne "1" -and $siteListCache -ne "") {
		message "read siteListCache"
		if (Test-Path($siteListCache)) {
			$content = [System.IO.File]::ReadAllText($siteListCache)
			message "content:$content"
			if($content -ne "") {
				#trim?
				$destinations = $content -split ","
				message "destinations:$destinations"
				$sites = $destinations
			}
		}
	}
	#TODO: Fitler out if apppool not running
	if ($destinations -eq "*") {
		message "excludeSites:$excludedSites"
		$sites = @()
		message "*********************"
		message "Getting list of sites from IIS"
		message "Get-Website"
		$sitesAll = Get-Website #| foreach-object { "$($_.Name)" } #| select name # | select $_.Name #| Where-Object {$_.PhysicalPath -like '\website'}
		foreach ($siteConfig in $sitesAll) {
			message "*********************"

			$siteName = $siteConfig.Name        
			message "siteName:$siteName"

			$sitePath = $siteConfig.physicalPath
			message "sitePath:$sitePath"

			if (-not $sitePath.ToLower().Contains("\website")) {
				message "$siteName skipped - not a Sitecore site"
				continue
			}

			$found = 0
			foreach ($exclude in $excludedSites) {
				message "exclude:$exclude - site:$siteName"
			
				if ($siteName.ToLower().Contains($exclude.ToLower())) {
					message "*********************"
					message "exclude found!"
					$found = 1
					break
				}
			}
			If ($found -eq 0) {
					message "process site:$siteName"
					$sites = $sites + $siteName
			}
			Else
			{
				message "*********************"
				message "skip site:$siteName"
			}
		}
		
		if ($siteListCache -ne "") {
			message "save siteListCache:$siteListCache"
			$sites -join ',' | Out-File -FilePath $siteListCache;
		}
	}
}
message "sites:$sites"

message ""
message "*********************"
if ($updateSiteListCache -eq "1" -or $targetPath -eq "") { exit }

"deployment started: " + (Get-Date -format "M.d.yyyy HH:mm")

foreach ($site in $sites) { DeploySite $site}

$stats

"deployment completed: " + (Get-Date -format "M.d.yyyy HH:mm")
message "*********************"