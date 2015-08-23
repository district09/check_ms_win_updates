# Script name:		check_ms_win_updates.ps1
# Version:			v1.01.150823
# Created on:		12/05/2015
# Author:			D'Haese Willem
# Purpose:			Opens xaml gui from Powershell with information and link to Nagios monitoring system
# On Github:		https://github.com/willemdh/check_ms_win_updates
# On OutsideIT:		http://outsideit.net/check-ms-win-updates
# Recent History:
#	12/05/2015 => Creation date, thanks to Christian Kaufmann for the idea of caching the WSUS updates
#	05/08/2015 => Removed @() from import-clixml and counts, subtraction for other
#	06/08/2015 => Edit message and severity if lastsuccestime was not found in the registry
#	23/08/2015 => Cleanup for release
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

$VerbosePreference = 'SilentlyContinue'

#region Functions

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

#endregion Functions

if (!(Test-path -Path 'C:\Program Files\NSClient++\scripts\powershell\cache')){
	New-Item -Path 'C:\Program Files\NSClient++\scripts\powershell\cache' -Type Directory -Force | Out-Null
}

$LastSuccessTimeFolder = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
if (Test-Path $LastSuccessTimeFolder) {
	$LastSuccessTimeValue = Get-ItemProperty -Path $LastSuccessTimeFolder -Name LastSuccessTime | Select-Object -ExpandProperty LastSuccessTime
	$WsusStruct.LastSuccesTime = Get-date "$LastSuccessTimeValue"
}
else {
	Write-Host 'LastSuccesTime value not found in the registry. This server was probably never updated...'
	$WsusStruct.LastSuccesTime = Get-date '2015-01-01 00:00:01'
}
$RebootRequiredKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
if (Test-Path $RebootRequiredKey){ 
	$RebootRequired = $true
	if (Test-Path $WsusStruct.UpdateCacheFile) {
		Remove-Item $WsusStruct.UpdateCacheFile | Out-Null
	}
}

if (!(Test-Path $WsusStruct.UpdateCacheFile) -or (Get-Date) -gt ((Get-Item $WsusStruct.UpdateCacheFile).LastWriteTime.AddHours($WsusStruct.UpdateCacheExpireHours))) {
    Write-Log Verbose Info 'Cachefile not found or out of date. Creation initiated.'
	$UpdateSession = new-object -ComObject 'Microsoft.Update.Session'
	$Updates = $UpdateSession.CreateupdateSearcher().Search(('IsAssigned=1 and IsInstalled=0 and IsHidden=0'))
	Export-Clixml -InputObject $Updates -Encoding UTF8 -Path $WsusStruct.UpdateCacheFile
}
else {
    Write-Log Verbose Info 'Valid cachefile found.'
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
$WarningLimit = ($WsusStruct.LastSuccesTime).AddDays($WsusStruct.DaysBeforeWarning)
$CriticalLimit = ($WsusStruct.LastSuccesTime).AddDays($WsusStruct.DaysBeforeCritical)
$LastSuccesTimeStr = ($WsusStruct.LastSuccesTime).ToString('yyyy/MM/dd HH:mm:ss')
if($CriticalLimit -lt (Get-Date)) {
	$WsusStruct.ReturnString += "CRITICAL: Last succesful update at $LastSuccesTimeStr exceeded critical threshold of $($WsusStruct.DaysBeforeCritical) days. " 
	$WsusStruct.Exitcode = 2
}
elseif($WarningLimit -lt (Get-Date)) {
	$WsusStruct.ReturnString += "WARNING: Last succesful update at $LastSuccesTimeStr exceeded warning threshold of $($WsusStruct.DaysBeforeWarning) days. " 
	$WsusStruct.Exitcode = 1
}
elseif ($RebootRequired) {
	$WsusStruct.ReturnString += "WARNING: Reboot required. Last succesful update: $LastSuccesTimeStr. "
	$WsusStruct.Exitcode = 1
}
else {
	$WsusStruct.ReturnString += "OK: Last succesful update: $LastSuccesTimeStr. "
	$WsusStruct.Exitcode = 0
}

$WsusStruct.ReturnString += "Pending updates {Total: $Total {Critical: $Critical}{Important: $Important}{Other: $Other}}"

Write-Host $WsusStruct.ReturnString
$WsusDuration = New-TimeSpan –Start $WsusStruct.CheckStart –End (Get-Date)
$WsusStruct.CheckDuration = '{0:HH:mm:ss.fff}' -f ([datetime]$WsusDuration.Ticks)   
Write-Log Verbose Info "Check took $($WsusStruct.CheckDuration) seconds."
exit $WsusStruct.Exitcode
