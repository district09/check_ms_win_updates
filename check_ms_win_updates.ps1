# Script name:		check_ms_win_updates.ps1
# Version:			v1.05.151206
# Created on:		12/05/2015
# Author:			D'Haese Willem
# Purpose:			Checks a Microsoft Windows Server for pending updates and alert in Nagios style output if a number of days is exceeded.
# On Github:		https://github.com/willemdh/check_ms_win_updates
# On OutsideIT:		http://outsideit.net/check-ms-win-updates
# Recent History:
#	06/08/15 => Edite message and severity if lastsuccestime was not found in the registry
#	03/09/15 => Cleanup and proper Nagios plugin parameter verification
#	07/09/15 => Convert lastsuccessful update date to local timezone and only removes cachefile when reboot required if cache older then 1 hour.
#	12/11/15 => Check if registry string lastsuccesstime exists
#	06/12/15 => Prepare for Windows 10 support with PSWindowsUpdate
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

$WsusStruct = New-object PSObject -Property @{
    CheckStart = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss.fff');
    CheckEnd = '';
    CheckDuration = '';
    Exitcode = 3;
	UpdateCacheFile = 'C:\Program Files\NSClient++\scripts\powershell\cache\check_ms_win_updates_cache.xml';
	UpdateCacheExpireHours = 24;
	LastSuccesTime = '';
	DaysBeforeWarning = 120;
	DaysBeforeCritical = 150;
    NumberOfUpdatesPending = '';
	ReturnString = 'UNKNOWN: Please debug the script...'
}

[void][System.Reflection.Assembly]::LoadWithPartialName('System.Core')
$VerbosePreference = 'SilentlyContinue'

#region Functions

Function Initialize-Args {
    Param ( 
        [Parameter(Mandatory=$True)]$Args
    )
	
    try {
        For ( $i = 0; $i -lt $Args.count; $i++ ) { 
		    $CurrentArg = $Args[$i].ToString()
            if ($i -lt $Args.Count-1) {
				$Value = $Args[$i+1];
				If ($Value.Count -ge 2) {
					foreach ($Item in $Value) {
						Test-Strings $Item | Out-Null
					}
				}
				else {
	                $Value = $Args[$i+1];
					Test-Strings $Value | Out-Null
				}	                             
            } else {
                $Value = ''
            };

            switch -regex -casesensitive ($CurrentArg) {
                "^(-wd|--Warning-Days)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 1000)) {
                        $WsusStruct.DaysBeforeWarning = $value
                    } else {
                        throw "Warning treshold should be numeric and less than 1000. Value given is $value."
                    }
                    $i++
                }
                "^(-cd|--Critical-Days)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 1000)) {
                        $WsusStruct.DaysBeforeCritical = $value
                    } else {
                        throw "Critical treshold should be numeric and less than 1000. Value given is $value."
                    }
                    $i++
                 }
                "^(-h|--Help)$" {
                    Write-Help
                }
                default {
                    throw "Illegal arguments detected: $_"
                 }
            }
        }
    } catch {
		Write-Host "Error: $_"
        Exit 2
	}	
}

Function Test-Strings {
    Param ( [Parameter(Mandatory=$True)][string]$String )
    $BadChars=@("``", '|', ';', "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host "Error: String `"$String`" contains illegal characters."
            Exit $WsusStruct.ExitCode
        }
    }
    Return $true
} 
function Test-FileLock {
      param ([parameter(Mandatory=$true)][string]$Path)
  $oFile = New-Object System.IO.FileInfo $Path
  try
  {
      $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
      if ($oStream)
      {
        $oStream.Close()
      }
      return $false
  }
  catch
  {
    return $true
  }
}
function Write-Log {
    param (
	[parameter(Mandatory=$true)][string]$Log,
	[parameter(Mandatory=$true)][string]$Severity,
	[parameter(Mandatory=$true)][string]$Message
	)
	$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
    if ($Log -eq 'Verbose') {
    	Write-Verbose "${Now}: ${Severity}: $Message"
    }
	elseif ($Log -eq 'Debug') {
    	Write-Debug "${Now}: ${Severity}: $Message"
    }
    else {
		if (!(Test-Path -Path $Log)){
			Write-Host "Write-Log can't find the path `"$Log`". Please debug.."
		}
		else {
	        $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
		    while (Test-FileLock $Log) {Start-Sleep (Get-Random -minimum 1 -maximum 10)}
		    "${Now}: ${Severity}: $Message" | Out-File -filepath $Log -Append
    	}
	}
}

Function Write-Help {
	Write-Host @"
check_ms_win_updates.ps1:
This script is designed to check a Microsoft Windows Server for pending updates and alert in Nagios style output if a number of days is exceeded.
Arguments:
    -wd | --Warning-Days 	=> Number of days since last succesful WSUS update to return a warning state
    -cd | --Critical-Days 	=> Number of days since last succesful WSUS update to return a critical state
    -h  | --Help         => Print this help output.
"@
    Exit $WsusStruct.ExitCode;
} 

Function Get-LocalTime($UTCTime) {
    $strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    Return $LocalTime
}

Function Search-Updates { 

    if (!(Test-path -Path 'C:\Program Files\NSClient++\scripts\powershell\cache')){
	    New-Item -Path 'C:\Program Files\NSClient++\scripts\powershell\cache' -Type directory -Force | Out-Null
    }

    if (([System.Environment]::OSVersion.Version).Major -ge 10){
    
        Write-Log Verbose Info 'Windows 10 has no LastSuccessTime in the registry.'
       
    }
    else {
        Write-Host "Other OS detected: $(([System.Environment]::OSVersion.Version).Major)"
        $LastSuccessTimeFolder = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
        if (Test-Path $LastSuccessTimeFolder) {
	        $LastSuccessTimeValue = Get-ItemProperty -Path $LastSuccessTimeFolder -Name LastSuccessTime | Select-Object -ExpandProperty LastSuccessTime
		    if ($LastSuccessTimeValue) { 
		        try {
	    	        $WsusStruct.LastSuccesTime = Get-LocalTime (Get-date "$LastSuccessTimeValue")
		        }
		        catch {
			        Write-Log Verbose Warning 'Unable to use [System.TimeZoneInfo].'
			        $WsusStruct.LastSuccesTime = Get-date "$LastSuccessTimeValue"
		        }
		    }
		    else {
	    	    Write-Host 'String LastSuccessTime not found in the registry. This server was probably never updated or your custom WSUS Update solution does not create this string.'
	    	    $WsusStruct.LastSuccesTime = Get-date '2015-01-01 00:00:01'            
		    }
        }
        else {
	        Write-Host 'Install key not found in the registry. This server was probably never updated or your custom WSUS Update solution does not create this key.'
	        $WsusStruct.LastSuccesTime = Get-date '2015-01-01 00:00:01'
        }
    }



    $RebootRequiredKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path $RebootRequiredKey){ 
	    $RebootRequired = $true
	    if ((Test-Path $WsusStruct.UpdateCacheFile) -and (Get-Date) -gt ((Get-Item $WsusStruct.UpdateCacheFile).LastWriteTime.AddHours(1))) {
		    Remove-Item $WsusStruct.UpdateCacheFile | Out-Null
	    }
    }

    if (!(Test-Path $WsusStruct.UpdateCacheFile) -or (Get-Date) -gt ((Get-Item $WsusStruct.UpdateCacheFile).LastWriteTime.AddHours($WsusStruct.UpdateCacheExpireHours))) {
        Write-Log verbose Info 'Cachefile not found or out of date. Creation initiated.'
	    $UpdateSession = new-object -ComObject 'Microsoft.Update.Session'
	    $Updates = $UpdateSession.CreateupdateSearcher().Search(('IsAssigned=1 and IsInstalled=0 and IsHidden=0'))
	    Export-Clixml -InputObject $Updates -Encoding UTF8 -Path $WsusStruct.UpdateCacheFile
    }
    else {
        Write-Log verbose Info 'Valid cachefile found.'
	    $Updates = Import-Clixml $WsusStruct.UpdateCacheFile
    }

    $Total = ($updates.updates).count
    $Critical = ($Updates.updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }).count
    $Important = ($Updates.updates | Where-Object { $_.MsrcSeverity -eq 'Important' }).count
    $Other = $Total - $Critical - $Important
    if (! $Total ) {
	    $Total = 0
    }
    if (! $Critical ) {
	    $Critical = 0
    }
    if (! $Important ) {
	    $Important = 0
    }
    if (! $Other ) {
	    $Other = 0
    }
    if ($Total -eq 1 -and $Other -eq 1){
        $Total = $Other = 0
    }
    $WsusStruct.ReturnString =''
    if (([System.Environment]::OSVersion.Version).Major -lt 10){
        $WarningLimit = ($WsusStruct.LastSuccesTime).AddDays($WsusStruct.DaysBeforeWarning)
        $CriticalLimit = ($WsusStruct.LastSuccesTime).AddDays($WsusStruct.DaysBeforeCritical)
        $LastSuccesTimeStr = ($WsusStruct.LastSuccesTime).ToString('yyyy/MM/dd HH:mm:ss')
        if($CriticalLimit -lt (Get-Date)) {
	        $WsusStruct.ReturnString += "CRITICAL: Last successful update at $LastSuccesTimeStr exceeded critical threshold of $($WsusStruct.DaysBeforeCritical) days. " 
	        $WsusStruct.Exitcode = 2
        }
        elseif($WarningLimit -lt (Get-Date)) {
	        $WsusStruct.ReturnString += "WARNING: Last successful update at $LastSuccesTimeStr exceeded warning threshold of $($WsusStruct.DaysBeforeWarning) days. " 
	        $WsusStruct.Exitcode = 1
        }
        elseif ($RebootRequired) {
	        $WsusStruct.ReturnString += "WARNING: Reboot required. Last successful update: $LastSuccesTimeStr. "
	        $WsusStruct.Exitcode = 1
        }
        else {
	        $WsusStruct.ReturnString += "OK: Last successful update: $LastSuccesTimeStr. "
	        $WsusStruct.Exitcode = 0
        }
    }
    else { 
        $WsusStruct.ReturnString += 'Unable to detect last successful update. '
        $WsusStruct.Exitcode = 0
    }
    $WsusStruct.ReturnString += "Pending updates {Total: $Total {Critical: $Critical}{Important: $Important}{Other: $Other}}"
}

#endregion Functions

# Main block

if ($Args) {
    if(!($Args[0].ToString()).StartsWith("$")){
	    if($Args.count -ge 1){Initialize-Args $Args}
    }
}

Search-Updates

Write-Host $WsusStruct.ReturnString
$WsusDuration = New-TimeSpan –Start $WsusStruct.CheckStart –End (Get-Date)
$WsusStruct.CheckDuration = '{0:HH:mm:ss.fff}' -f ([datetime]$WsusDuration.Ticks)   
Write-Log verbose Info "Check took $($WsusStruct.CheckDuration) seconds."
exit $WsusStruct.Exitcode