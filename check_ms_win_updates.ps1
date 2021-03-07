# Script name:      check_ms_win_updates.ps1
# Version:          v3.03.190408
# Created on:       12/05/2015
# Author:           Willem D'Haese
# Purpose:          Checks a Microsoft Windows Server for pending updates and alert in Nagios style output if a number of days is exceeded.
# On Github:        https://github.com/OutsideIT/check_ms_win_updates
# Copyright:
#   This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#   by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed
#   in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
#   PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public
#   License along with this program.  If not, see <http://www.gnu.org/licenses

$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$Struct = New-object PSObject -Property @{
    StopWatch = [Diagnostics.Stopwatch]::StartNew()
    Duration = ''
    Exitcode = 3
    Method = 'UpdateSearcher'
    UpdateCacheFile = 'C:\Program Files\NSClient++\scripts\cache\check_ms_win_updates_cache.xml'
    UpdateCacheExpireHours = 24
    LastSuccesTime = ''
    DaysBeforeWarning = 120
    DaysBeforeCritical = 250
    NumberOfUpdates = ''
    ReturnString = 'UNKNOWN: Please debug the script...'
}

[void][Reflection.Assembly]::LoadWithPartialName('System.Core')

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
                        $Struct.DaysBeforeWarning = $value
                    } else {
                        throw "Warning treshold should be numeric and less than 1000. Value given is $value."
                    }
                    $i++
                }
                "^(-cd|--Critical-Days)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 1000)) {
                        $Struct.DaysBeforeCritical = $value
                    } else {
                        throw "Critical treshold should be numeric and less than 1000. Value given is $value."
                    }
                    $i++
                }
                "^(-M|--Method)$" {
                    if ($value -match "(^PSWindowsUpdate$)|(^UpdateSearcher$)|(^WMI$)") {
                        $Struct.Method = $value
                    } else {
                        throw "Method `"$value`" does not meet regex requirements."
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
    }
    catch {
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
            Exit $Struct.ExitCode
        }
    }
    Return $true
}
function Write-Log {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)][string]$Log,
        [parameter(Mandatory=$true)][ValidateSet('Debug', 'Info', 'Warning', 'Error')][string]$Severity,
        [parameter(Mandatory=$true)][string]$Message
    )
    $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
    if ($Log -eq 'Verbose') {
        Write-Verbose "${Now}: ${Severity}: $Message"
    }
    elseif ($Log -eq 'Debug') {
        Write-Debug "${Now}: ${Severity}: $Message"
    }
    elseif ($Log -eq 'Output') {
        Write-Host "${Now}: ${Severity}: $Message"
    }
    elseif ($Log -match '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(?::(?<port>\d+))$' -or $Log -match "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$") {
        $IpOrHost = $log.Split(':')[0]
        $Port = $log.Split(':')[1]
        if  ($IpOrHost -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$') {
            $Ip = $IpOrHost
        }
        else {
            $Ip = ([Net.Dns]::GetHostAddresses($IpOrHost)).IPAddressToString
        }
        Try {
            $JsonObject = (New-Object PSObject | Add-Member -PassThru NoteProperty logdestination $Log | Add-Member -PassThru NoteProperty logtime $Now| Add-Member -PassThru NoteProperty severity $Severity | Add-Member -PassThru NoteProperty message $Message ) | ConvertTo-Json
            $JsonString = $JsonObject -replace "`n",' ' -replace "`r",' ' -replace ' ',''
            $Socket = New-Object System.Net.Sockets.TCPClient($Ap,$Port)
            $Stream = $Socket.GetStream()
            $Writer = New-Object System.IO.StreamWriter($Stream)
            $Writer.WriteLine($JsonString)
            $Writer.Flush()
            $Stream.Close()
            $Socket.Close()
        }
        catch {
            Write-Host "${Now}: Error: Something went wrong while trying to send message to Logstash server `"$Log`"."
        }
        Write-Host "${Now}: ${Severity}: Ip: $Ip Port: $Port JsonString: $JsonString"
    }
    elseif ($Log -match '^((([a-zA-Z]:)|(\\{2}\w+)|(\\{2}(?:(?:25[0-5]|2[0-4]\d|[01]\d\d|\d?\d)(?(?=\.?\d)\.)){4}))(\\(\w[\w ]*))*)') {
        if (Test-Path -Path $Log -pathType container){
            Write-Host "${Now}: Error: Passed Path is a directory. Please provide a file."
            exit 1
        }
        elseif (!(Test-Path -Path $Log)) {
            try {
                New-Item -Path $Log -Type file -Force | Out-null
            }
            catch {
                $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
                Write-Host "${Now}: Error: Write-Log was unable to find or create the path `"$Log`". Please debug.."
                exit 1
            }
        }
        try {
            "${Now}: ${Severity}: $Message" | Out-File -filepath $Log -Append
        }
        catch {
            Write-Host "${Now}: Error: Something went wrong while writing to file `"$Log`". It might be locked."
        }
    }
}
Function Write-Help {
    Write-Host @"
check_ms_win_updates.ps1:
This script is designed to check a Microsoft Windows host for pending updates and alert in Nagios style output if a number of days is exceeded.
Arguments:
    -wd | --Warning-Days    => Number of days since last successful WSUS update to return a warning state
    -cd | --Critical-Days   => Number of days since last successful WSUS update to return a critical state
    -M  | --Method          => Method to count the WSUS update. 'PsWindowsUpdate', 'WMI or 'UpdateSearcher' (default).
    -h  | --Help            => Print this help output.
"@
    Exit $Struct.ExitCode
}
Function Get-LocalTime {
    param (
        [parameter(Mandatory=$true)]$UTCTime
    )
    $strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
    $TZ = [TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $LocalTime = [TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    Return $LocalTime
}
Function Search-WithUpdateSearcher {
    if (!(Test-path -Path 'C:\Program Files\NSClient++\scripts\cache')){
        New-Item -Path 'C:\Program Files\NSClient++\scripts\cache' -Type directory -Force | Out-Null
    }

    $LastSuccessTimeFolder = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
    if (Test-Path $LastSuccessTimeFolder) {
        $LastSuccessTimeValue = Get-ItemProperty -Path $LastSuccessTimeFolder -Name LastSuccessTime | Select-Object -ExpandProperty LastSuccessTime
        if ($LastSuccessTimeValue) {
            try {
                $Struct.LastSuccesTime = Get-LocalTime (Get-date "$LastSuccessTimeValue")
            }
            catch {
                Write-Log Verbose Warning 'Unable to use [System.TimeZoneInfo].'
                $Struct.LastSuccesTime = Get-date "$LastSuccessTimeValue"
            }
        }
        else {
            Write-Host 'String LastSuccessTime not found in the registry. This server was probably never updated or your custom WSUS Update solution does not create this string.'
            $Struct.LastSuccesTime = Get-date '2015-01-01 00:00:01'
        }
    }
    else {
        Write-Host 'Install key not found in the registry. This server was probably never updated or your custom WSUS Update solution does not create this key.'
        $Struct.LastSuccesTime = Get-date '2015-01-01 00:00:01'
    }

    $RebootRequiredKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path $RebootRequiredKey){
        $RebootRequired = $true
        if ((Test-Path $Struct.UpdateCacheFile) -and (Get-Date) -gt ((Get-Item $Struct.UpdateCacheFile).LastWriteTime.AddHours(1))) {
            Remove-Item $Struct.UpdateCacheFile | Out-Null
        }
    }
    if (!(Test-Path $Struct.UpdateCacheFile) -or (Get-Date) -gt ((Get-Item $Struct.UpdateCacheFile).LastWriteTime.AddHours($Struct.UpdateCacheExpireHours))) {
        Write-Log verbose Info 'Cachefile not found or out of date. Creation initiated.'
        $UpdateSession = new-object -ComObject 'Microsoft.Update.Session'
        $Updates = $UpdateSession.CreateupdateSearcher().Search(('IsAssigned=1 and IsInstalled=0 and IsHidden=0'))
        Export-Clixml -InputObject $Updates -Encoding UTF8 -Path $Struct.UpdateCacheFile
    }
    else {
        Write-Log verbose Info 'Valid cachefile found.'
        $Updates = Import-Clixml $Struct.UpdateCacheFile
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
<#  On Windows 2003 this code results in 0 updates while there was in fact 1 update. Noticed other cases. To be investigated.
    if ($Total -eq 1 -and $Other -eq 1){
        $Total = $Other = 0
    }
    Windows 2012 R2, it seems Total count is always 1 more. Wi'll need to triplecheck this and mplement os check
#>
    $Struct.ReturnString =''
    $WarningLimit = ($Struct.LastSuccesTime).AddDays($Struct.DaysBeforeWarning)
    $CriticalLimit = ($Struct.LastSuccesTime).AddDays($Struct.DaysBeforeCritical)
    $LastSuccesTimeStr = ($Struct.LastSuccesTime).ToString('yyyy/MM/dd HH:mm:ss')
    if($Total -ge 1 -and $CriticalLimit -lt (Get-Date)) {
        $Struct.ReturnString += "CRITICAL: Last successful update at $LastSuccesTimeStr exceeded critical threshold of $($Struct.DaysBeforeCritical) days. "
        $Struct.Exitcode = 2
    }
    elseif($Total -ge 1 -and $WarningLimit -lt (Get-Date)) {
        $Struct.ReturnString += "WARNING: Last successful update at $LastSuccesTimeStr exceeded warning threshold of $($Struct.DaysBeforeWarning) days. "
        $Struct.Exitcode = 1
    }
    elseif ($RebootRequired) {
        $Struct.ReturnString += "WARNING: Reboot required. Last successful update: $LastSuccesTimeStr. "
        $Struct.Exitcode = 1
    }
    else {
        $Struct.ReturnString += "OK: Last successful update: $LastSuccesTimeStr. "
        $Struct.Exitcode = 0
    }
    $Struct.ReturnString += "Pending updates {Total: $Total {Critical: $Critical}{Important: $Important}{Other: $Other}}"
}

Function Search-WithPSWindowsUpdate {
    Write-Log Verbose Info "Querying WSUS updates with $($Struct.Method) method."
    Try {
        Import-Module PSWindowsUpdate
    }
    catch {
        Write-Log Verbose Info 'Something went wrong while importing Powershell module PSWindowsUpdate.'
        $Struct.ReturnString = 'UNKNOWN: Unable to import module PSWindowsUpdate.'
        $Struct.Exitcode = 3
        return
    }
    try {
        $Struct.NumberOfUpdates = ((Get-WUList -Notcategory 'Driver' -WarningAction SilentlyContinue) | Measure-Object).count
        $Struct.LastSuccesTime = [datetime](Get-WUHistory | Measure-Object Date -Maximum).Maximum
        Write-Log Verbose Info "LastSuccesTime: $($Struct.LastSuccesTime)"
        $Struct.ReturnString =''
        $WarningLimit = ($Struct.LastSuccesTime).AddDays($Struct.DaysBeforeWarning)
        $CriticalLimit = ($Struct.LastSuccesTime).AddDays($Struct.DaysBeforeCritical)
        $LastSuccesTimeStr = ($Struct.LastSuccesTime).ToString('yyyy/MM/dd HH:mm:ss')
        Write-Log Verbose Info "LastSuccesTimeStr yyyy/MM/dd HH:mm:ss: $LastSuccesTimeStr"
        $RebootRequired = Get-WURebootStatus -Silent
        if($Struct.NumberOfUpdates -ge 1 -and $CriticalLimit -lt (Get-Date)) {
            $Struct.ReturnString += "CRITICAL: Last successful update at $LastSuccesTimeStr exceeded critical threshold of $($Struct.DaysBeforeCritical) days. "
            $Struct.Exitcode = 2
        }
        elseif($Struct.NumberOfUpdates -ge 1 -and $WarningLimit -lt (Get-Date)) {
            $Struct.ReturnString += "WARNING: Last successful update at $LastSuccesTimeStr exceeded warning threshold of $($Struct.DaysBeforeWarning) days. "
            $Struct.Exitcode = 1
        }
        elseif ($RebootRequired) {
            $Struct.ReturnString += "WARNING: Reboot required. Last successful update: $LastSuccesTimeStr. "
            $Struct.Exitcode = 1
        }
        else {
            $Struct.ReturnString += "OK: Last successful update: $LastSuccesTimeStr. "
            $Struct.Exitcode = 0
        }
    }
    Catch {
        Write-Log Verbose Info "Something went wrong with the date conversion. Culture is $((Get-Culture).Name)"
    }
    $Struct.ReturnString += "Pending updates {Total: $($Struct.NumberOfUpdates)}"
}

Function Search-withWMI{
  Write-Log Verbose Info "Querying WSUS updates with $($Struct.Method) method."
  $Struct.ReturnString =''
    Try { $LastUpdate = Get-WmiObject -Class "win32_quickfixengineering" |  Select-Object -Property "Description", "HotfixID", @{label="InstalledOn";e={[DateTime]::Parse($_.psbase.properties["installedon"].value,$([System.Globalization.CultureInfo]::GetCultureInfo("en-US")))}} | Sort-Object -Property InstalledOn | Select-Object InstalledOn -Last 1
		    }
    Catch { Write-Log Verbose Info "Something went wrong while querying WMI"
          }
    Try { $Struct.LastSuccesTime = $LastUpdate.InstalledOn
          $WarningLimit = ($Struct.LastSuccesTime).AddDays($Struct.DaysBeforeWarning)
          $CriticalLimit = ($Struct.LastSuccesTime).AddDays($Struct.DaysBeforeCritical)
        }
    Catch { Write-Log Verbose Info "Something went wrong with date conversion"}
Try {
    if($CriticalLimit -lt (Get-Date))
      {
          $Struct.ReturnString += "CRITICAL: Last successful update at $($Lastupdate.InstalledOn) exceeded critical tresshold of $($Struct.DaysBeforeCritical) days"
		  $Struct.Exitcode = 2
      }
    elseif ($WarningLimit -lt (Get-Date)){
			$Struct.ReturnString += "WARNING: Last successful update at $($Lastupdate.InstalledOn) exceeded warning tresshold of $($Struct.DaysBeforeWarning) days"
			$Struct.Exitcode = 1
			}
    else {
		   $Struct.ReturnString += "OK: Last successful update: $($LastUpdate.InstalledOn)"
		   $Struct.Exitcode = 0}
    }
    Catch { Write-Log Verbose Info "Something went wrong while comparing WMI results with treshold"}
}

#endregion Functions

#region Main

If ( $Args ) {
    If ( ! ( $Args[0].ToString()).StartsWith('$') ) {
        If ( $Args.count -ge 1 ) {
            Initialize-Args $Args
        }
    }
}
If ( $Struct.Method -eq 'WMI') {
    Search-withWMI
    }
ElseIf ( $Struct.Method -eq 'PsWindowsUpdate' ) {
    Search-WithPSWindowsUpdate
    }
Else {
If ( ([Environment]::OSVersion.Version).Major -ge 10 ) {
    Write-Log Verbose Info 'Windows 10 or later has no LastSuccessTime in the registry. Using PSWindowsUpdate as method.'
    $Struct.Method = 'PsWindowsUpdate'
   }
Else {
  If (([System.Environment]::OSversion.Version).Major -le 6){
    Write-Log Verbose Info "Windows 2008 or earlier has issues with UpdateSearcher. Using WMI as method."
	$Struct.Method = "WMI"
       }
     }
If ( $Struct.Method -eq 'PsWindowsUpdate' ) {
    Search-WithPSWindowsUpdate
    }
Else { If ($Struct.Method -eq 'WMI'){
        Search-WithWMI }
  Else {
    Search-WithUpdateSearcher
  }
 }
}
$Struct.Duration = $Struct.StopWatch.Elapsed.TotalSeconds
$Struct.ReturnString += " ($($Struct.Duration)s)"
Write-Host $Struct.ReturnString
Exit $Struct.Exitcode

#endregion Main
