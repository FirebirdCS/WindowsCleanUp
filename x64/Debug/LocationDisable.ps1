# https://privacy.sexy — v0.11.4 — Mon, 03 Apr 2023 17:08:55 GMT
# Ensure admin privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "& '" + $MyInvocation.MyCommand.Path + "'"
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

# ----------------------------------------------------------
# ------------Turn off Windows Location Provider------------
# ----------------------------------------------------------
Write-Host "--- Turn off Windows Location Provider"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWORD -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ---------------Turn off location scripting----------------
# ----------------------------------------------------------
Write-Host "--- Turn off location scripting"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWORD -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------------------Turn off location---------------------
# ----------------------------------------------------------
Write-Host "--- Turn off location"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWORD -Force
# For older Windows (before 1903)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Force > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWORD -Force
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Force > $null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Value "Deny" -Type String -Force
# ----------------------------------------------------------

# ----------------------------------------------------------
# --------------------Uninstall Nvidia Telemetry---------------------
# ----------------------------------------------------------
Write-Output "--- Uninstall NVIDIA telemetry tasks"
if (Test-Path "$env:ProgramFiles\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL") {
rundll32 "$env:ProgramFiles\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
rundll32 "$env:ProgramFiles\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
}

# ----------------------------------------------------------
# --------------------Remove Nvidia Telemetry Fiiles---------------------
# ----------------------------------------------------------
Write-Output "--- Delete NVIDIA residual telemetry files"
Remove-Item -Path "$env:SystemRoot\System32\DriverStore\FileRepository\NvTelemetry*.dll" -Recurse -Force
Remove-Item -Path "$env:ProgramFiles(x86)\NVIDIA Corporation\NvTelemetry" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramFiles\NVIDIA Corporation\NvTelemetry" -Recurse -Force -ErrorAction SilentlyContinue

# ----------------------------------------------------------
# --------Disable Nvidia Telemetry Container service--------
# ----------------------------------------------------------
Write-Output "--- Disable Nvidia Telemetry Container service"
$serviceName = "NvTelemetryContainer"
if ($service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  Write-Output "Disabling service: `"$serviceName`"."
  # 1. Skip if service does not exist
  # 2. Stop if running
  if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
    Write-Output "`"$serviceName`" is running, stopping it."
    try {
      Stop-Service -Name $serviceName -Force -ErrorAction Stop
      Write-Output "Stopped `"$serviceName`" successfully."
    }
    catch {
      Write-Warning "Could not stop `"$serviceName`", it will be stopped after reboot: $_"
    }
  }
  else {
    Write-Output "`"$serviceName`" is not running, no need to stop."
  }
  # 3. Skip if already disabled
  # 4. Disable service
  if ($service.StartType -ne "Disabled") {
    try {
      Set-Service -Name $serviceName -StartupType Disabled -Confirm:$false -ErrorAction Stop
      Write-Output "Disabled `"$serviceName`" successfully."
    }
    catch {
      Write-Error "Could not disable `"$serviceName`": $_"
    }
  }
  else {
    Write-Output "$serviceName is already disabled, no further action is needed"
  }
}
else {
  Write-Output "Service `"$serviceName`" could not be not found, no need to disable it."
}

# ----------------------------------------------------------
# ------------Disable NVIDIA telemetry services-------------
# ----------------------------------------------------------
Write-Output "--- Disable NVIDIA telemetry services"
$tasks = @("NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", `
           "NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", `
           "NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}")
foreach ($task in $tasks) {
  & schtasks /change /TN $task /DISABLE | Out-Null
}
# ----------------------------------------------------------
# Disable Google update service
Write-Host "--- Disable Google update service"

$serviceName = 'gupdate'
Write-Host "Disabling service: $serviceName."

# Skip if service does not exist
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (!$service) {
    Write-Host "Service '$serviceName' could not be not found, no need to disable it."
    Exit 0
}

# Stop if running
if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
    Write-Host "`"$serviceName`" is running, stopping it."
    try {
        Stop-Service -Name $serviceName -Force -ErrorAction Stop
        Write-Host "Stopped `"$serviceName`" successfully."
    } catch {
        Write-Warning "Could not stop `"$serviceName`", it will be stopped after reboot: $_"
    }
} else {
    Write-Host "`"$serviceName`" is not running, no need to stop."
}

# Skip if already disabled
$startupType = $service.StartType
if (!$startupType) {
    $startupType = (Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='$serviceName'" -ErrorAction Ignore).StartMode
    if (!$startupType) {
        $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='$serviceName'" -ErrorAction Ignore).StartMode
    }
}
if ($startupType -eq 'Disabled') {
    Write-Host "$serviceName is already disabled, no further action is needed"
}

# Disable service
try {
    Set-Service -Name $serviceName -StartupType Disabled -Confirm:$false -ErrorAction Stop
    Write-Host "Disabled `"$serviceName`" successfully."
} catch {
    Write-Error "Could not disable `"$serviceName`": $_"
}

# Disable text and handwriting collection
Write-Host "--- Disable text and handwriting collection"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWORD -Force

# ---------Hide most used apps (tracks app launch)----------
Write-Output "--- Hide most used apps (tracks app launch)"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -PropertyType DWORD -Force

# ---------------Disable Inventory Collector----------------
Write-Output "--- Disable Inventory Collector"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -PropertyType DWORD -Force

# --------------Disable Auto Downloading Maps---------------
Write-Output "--- Disable Auto Downloading Maps"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Value 0 -PropertyType DWORD -Force

# Disable Activity Feed
echo "--- Disable Activity Feed"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWORD -Force

# Disable feedback on write (sending typing info)
echo "--- Disable feedback on write (sending typing info)"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWORD -Force

# Disable game screen recording
echo "--- Disable game screen recording"
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWORD -Force


Read-Host "Press Enter to exit"
