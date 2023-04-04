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

# Do not allow use of biometrics
Write-Host "--- Do not allow the use of biometrics"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWORD -Force

# Do not allow users to log on using biometrics
Write-Host "--- Do not allow users to log on using biometrics"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" -Name "Enabled" -Value 0 -Type DWORD -Force

# Disable ad customization with Advertising ID
echo "--- Disable ad customization with Advertising ID"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1

# Turn Off Suggested Content in Settings app
echo "--- Turn Off Suggested Content in Settings app"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 -Type DWORD
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWORD
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWORD

# Disable Windows Tips
echo "--- Disable Windows Tips"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value "1"

# Disable Windows Spotlight (random wallpaper on lock screen)
echo "--- Disable Windows Spotlight (random wallpaper on lock screen)"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value "1"

# Disable Microsoft consumer experiences
echo "--- Disable Microsoft consumer experiences"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "1"

# Disable Activity Feed
Write-Host "--- Disable Activity Feed"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord -Force

# ----------------------------------------------------------
# ------------------Kill OneDrive process-------------------
# ----------------------------------------------------------
Write-Host "--- Kill OneDrive process"
Stop-Process -Name OneDrive -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# --------------------Uninstall OneDrive--------------------
# ----------------------------------------------------------
Write-Host "--- Uninstall OneDrive"
if ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    & "$env:SystemRoot\System32\OneDriveSetup.exe" /uninstall 2>$null
} else {
    & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall 2>$null
}
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------Remove OneDrive leftovers-----------------
# ----------------------------------------------------------
Write-Host "--- Remove OneDrive leftovers"
Remove-Item "$env:UserProfile\OneDrive" -Recurse -Force
Remove-Item "$env:LocalAppData\Microsoft\OneDrive" -Recurse -Force
Remove-Item "$env:ProgramData\Microsoft OneDrive" -Recurse -Force
Remove-Item "$env:SystemDrive\OneDriveTemp" -Recurse -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------Delete OneDrive shortcuts-----------------
# ----------------------------------------------------------
Write-Host "--- Delete OneDrive shortcuts"
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force
Remove-Item "$env:USERPROFILE\Links\OneDrive.lnk" -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------Disable usage of OneDrive-----------------
# ----------------------------------------------------------
Write-Host "--- Disable usage of OneDrive"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1 -Type DWord -Force
# ----------------------------------------------------------


# ----------------------------------------------------------
# ---Prevent automatic OneDrive install for current user----
# ----------------------------------------------------------
Write-Host "--- Prevent automatic OneDrive install for current user"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force
# ----------------------------------------------------------

# Remove OneDrive from explorer menu
Write-Host "--- Remove OneDrive from explorer menu"
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force
New-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCR:\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -PropertyType DWORD -Force

# Delete all OneDrive related Services
Write-Host "--- Delete all OneDrive related Services"
$scheduledTasks = schtasks /query /fo csv | Select-String -Pattern "OneDrive" | ConvertFrom-Csv
$scheduledTasks | ForEach-Object { schtasks /Delete /TN $_.TaskName /F }

# Delete OneDrive path from registry
Write-Host "--- Delete OneDrive path from registry"
Remove-ItemProperty -Path "HKCU:\Environment" -Name "OneDrive" -Force

# Uninstall Cortana app
Write-Host "--- Uninstall Cortana app"
Get-AppxPackage 'Microsoft.549981C3F5F10' | Remove-AppxPackage

# Microsoft Tips app
Write-Host "--- Microsoft Tips app"
Get-AppxPackage 'Microsoft.Getstarted' | Remove-AppxPackage

# Microsoft Messaging app
Write-Host "--- Microsoft Messaging app"
Get-AppxPackage 'Microsoft.Messaging' | Remove-AppxPackage

# Mixed Reality Portal app
Write-Host "--- Mixed Reality Portal app"
Get-AppxPackage 'Microsoft.MixedReality.Portal' | Remove-AppxPackage

# Feedback Hub app
Write-Host "--- Feedback Hub app"
Get-AppxPackage 'Microsoft.WindowsFeedbackHub' | Remove-AppxPackage

# Windows Alarms and Clock app
Write-Host "--- Windows Alarms and Clock app"
Get-AppxPackage 'Microsoft.WindowsAlarms' | Remove-AppxPackage

# Paint 3D app
Write-Host "--- Paint 3D app"
Get-AppxPackage 'Microsoft.MSPaint' | Remove-AppxPackage

# Windows Maps app
Write-Host "--- Windows Maps app"
Get-AppxPackage 'Microsoft.WindowsMaps' | Remove-AppxPackage

# ------------------------------------------
# ---- Minecraft for Windows 10 app ----
# ------------------------------------------
Write-Host "--- Minecraft for Windows 10 app"
Get-AppxPackage 'Microsoft.MinecraftUWP' | Remove-AppxPackage
# ------------------------------------------


# ------------------------------------------
# -------- Microsoft People app -----------
# ------------------------------------------
Write-Host "--- Microsoft People app"
Get-AppxPackage 'Microsoft.People' | Remove-AppxPackage
# ------------------------------------------


# ------------------------------------------
# ---------- Microsoft Pay app ------------
# ------------------------------------------
Write-Host "--- Microsoft Pay app"
Get-AppxPackage 'Microsoft.Wallet' | Remove-AppxPackage
# ------------------------------------------
 

# ------------------------------------------
# ---------- Snip & Sketch app -----------
# ------------------------------------------
Write-Host "--- Snip & Sketch app"
Get-AppxPackage 'Microsoft.ScreenSketch' | Remove-AppxPackage
# ------------------------------------------


# ------------------------------------------
# ------------ Print 3D app ---------------
# ------------------------------------------
Write-Host "--- Print 3D app"
Get-AppxPackage 'Microsoft.Print3D' | Remove-AppxPackage
# ------------------------------------------

# ----------------------------------------------------------
# ---------------------Mobile Plans app---------------------
# ----------------------------------------------------------
Write-Host "--- Mobile Plans app"
Get-AppxPackage 'Microsoft.OneConnect' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------------Microsoft Solitaire Collection app------------
# ----------------------------------------------------------
Write-Host "--- Microsoft Solitaire Collection app"
Get-AppxPackage 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------Microsoft Sticky Notes app----------------
# ----------------------------------------------------------
Write-Host "--- Microsoft Sticky Notes app"
Get-AppxPackage 'Microsoft.MicrosoftStickyNotes' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# ------------------Mail and Calendar app-------------------
# ----------------------------------------------------------
Write-Host "--- Mail and Calendar app"
Get-AppxPackage 'microsoft.windowscommunicationsapps' | Remove-AppxPackage
# ----------------------------------------------------------

# ----------------------------------------------------------
# ------------------------Skype app-------------------------
# ----------------------------------------------------------
Write-Host "--- Skype app"
Get-AppxPackage 'Microsoft.SkypeApp' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# -----------------------GroupMe app------------------------
# ----------------------------------------------------------
Write-Host "--- GroupMe app"
Get-AppxPackage 'Microsoft.GroupMe10' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------Windows Voice Recorder app----------------
# ----------------------------------------------------------
Write-Host "--- Windows Voice Recorder app"
Get-AppxPackage 'Microsoft.WindowsSoundRecorder' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# -----------------Microsoft 3D Builder app-----------------
# ----------------------------------------------------------
Write-Host "--- Microsoft 3D Builder app"
Get-AppxPackage 'Microsoft.3DBuilder' | Remove-AppxPackage
# ----------------------------------------------------------


# ----------------------------------------------------------
# ----------------------3D Viewer app-----------------------
# ----------------------------------------------------------
Write-Host "--- 3D Viewer app"
Get-AppxPackage 'Microsoft.Microsoft3DViewer' | Remove-AppxPackage
# ----------------------------------------------------------

# Uninstall Edge (chromium-based)
Write-Host "--- Uninstall Edge (chromium-based)"
$installer = Get-ChildItem "$env:ProgramFiles*\Microsoft\Edge\Application\*\Installer\setup.exe"
if (!$installer) {
    Write-Host "Could not find the installer"
} else {
    & $installer.FullName -Uninstall -System-Level -Verbose-Logging -Force-Uninstall
}



Read-Host "Press Enter to exit"
