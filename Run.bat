@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    >nul 2>&1 powershell -Command "Start-Process '%~dpnx0' -Verb RunAs" && exit
)

:menu
cls

echo.
echo  +-------------------------------+
echo  ^|     SYSTEM CONTROL PANEL      ^|
echo  ^|-------------------------------^|
echo  ^| [1] - Setup                   ^|
echo  ^| [2] - Cleaner                 ^|
echo  ^| [3] - Priority                ^|
echo  ^| [4] - Microsoft Debloater     ^|
echo  ^| [5] - Restore Services        ^|
echo  ^| [6] - Restore System          ^|
echo  ^| [7] - Exit                    ^|
echo  +-------------------------------+
echo.
set /p choice="Enter Command (1-7): "

if "%choice%"=="1" goto Setup
if "%choice%"=="2" goto Cleaner
if "%choice%"=="3" goto Priority
if "%choice%"=="4" goto Debloater
if "%choice%"=="5" goto Restore
if "%choice%"=="6" goto SystemRestore
if "%choice%"=="7" goto exit

echo Status: Invalid choice! Try again.
goto menu

:: Setup -- Organization
:Setup
setlocal enabledelayedexpansion
cls
echo === Setup Section ===

:: Create System Restore Point

set /p createRestore="Do you want to create a restore point? [Y/N]: "
if /i "%createRestore%"=="Y" (
    echo Status: Attempting to create a restore point...
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f >nul 2>&1
    powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Zero Tweaks Setup' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue"
    if %errorlevel% equ 0 (
        echo Status: System restore point created successfully.
    ) else (
        echo Status: Could not create restore point. A restore point may have been created recently.
    )
) else (
    echo Status: Skipping restore point creation.
)
cls

if not exist "C:\ZeroTweaks" mkdir "C:\ZeroTweaks"
set "MPath=C:\ZeroTweaks"

:: Add 'End Task' to Context Menu
set /p addEndTask="Do you want to add 'End Task' to the context menu? [Y/N]: "
if /i "%addEndTask%"=="Y" (
    echo Status: Adding 'End Task' to context menu
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings /v TaskbarEndTask /t REG_DWORD /d 1 /f
) else (
    echo Status: Skipping adding 'End Task' to context menu.
)
cls

:: Enable Windows 10 Right-Click Menu
set /p enableClickMenu="Do you want to enable the Windows 10 right-click menu? [Y/N]: "
if /i "%enableClickMenu%"=="Y" (
    echo Status: Enabling Windows 10 right-click menu
    reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve >nul 2>&1
    powershell -Command "Remove-Item -Path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
) else (
    echo Status: Skipping enabling Windows 10 right-click menu.
)
cls

:: Change Services
set /p changeServices="Do you want to change services? [Y/N]: "
if /i "%changeServices%"=="Y" (
    echo Status: Changing services
    :: Set services to demand start and stop them
    for %%s in (
        VSS HvHost BITS RemoteRegistry SEMgrSvc MixedRealityOpenXRSvc SCardSvr 
        icssvc RetailDemo WbioSrv fhsvc WpcMonSvc CertPropSvc WdiServiceHost 
        WdiSystemHost TrkWks WerSvc EntAppSvc PcaSvc MapsBroker BDESVC lmhosts 
        PNRPAutoReg AXInstSV DmEnrollmentSvc BcastDVRUserService WMPNetworkSvc 
        TieringEngineService Themes Schedule PimIndexMaintenanceSvc TabletInputService 
        DiagTrack dmwappushservice CDPUserSvc_* CryptographicServices 
        DisplayEnhancementService DoSvc FontCache GraphicsPerfSvc HomeGroupListener 
        HomeGroupProvider PrintSpooler PrintNotify QWAVE RpcLocator ScDeviceEnum 
        SharedAccess StillImageService StorSvc SysMain TapiSrv TokenBroker 
        UevAgentService UserDataSvc WaaSMedicSvc WalletService WebClient wscsvc 
        XboxGipSvc XboxNetApiSvc AdobeARMservice AdobeUpdateService AJRouter 
        AppXSvc Browser DusmSvc EdgeUpdate edgeupdate edgeupdatem gupdate gupdatem 
        MessagingService_* OneSyncSvc_* PerfHost PhoneSvc SecureAssessmentService 
        SharedRealitySvc Spooler TeamViewer TermService 
        TroubleshootingSvc tzautoupdate uhssvc VSStandardCollectorService 
        wuauserv wudfsvc XblAuthManager XblGameSave XboxNetApiSvc FrameServer 
        CloudBackupSvc DiagTrack DevicesFlowUserSvc_* DevicePickerUserSvc_* 
        CredentialEnrollmentManagerUserSvc PrintWorkflowUserSvc_* BcastDVRUserService_* 
        AppReadiness AppIDSvc AarSvc_* DeviceAssociationBrokerSvc_* DialogBlockingService 
        SensorService SensorDataService CoreMessaging LicenseManager 
        InstallService sppsvc GameInput wisvc DPS OfflineFiles seclogon
    ) do (
        sc config %%s start=demand >nul 2>&1
        sc stop %%s >nul 2>&1
    )
    cls

    :: Disable additional services
    for %%s in (
        DiagTrack MapsBroker WerSvc DoSvc MessagingService_* PimIndexMaintenanceSvc 
        OneSyncSvc_* UnistoreSvc_* UserDataSvc_* WaaSMedicSvc WalletService 
        TabletInputService SysMain RetailDemo SharedAccess diagnosticshub.standardcollector.service 
        lfsvc WpcMonSvc PhoneSvc TermService TroubleshootingSvc RemoteRegistry 
        WbioSrv VSStandardCollectorService uhssvc WGPCSVC WebClient Wecsvc wbengine 
        TrkWks XblGameSave FrameServer CDPUserSvc_* DevicesFlowUserSvc_* 
        DevicePickerUserSvc_* cbdhsvc_* DisplayEnhancementService DPS SecureAssessmentService wisvc 
        GameDVR XblAuthManager XboxGipSvc 
        XboxNetApiSvc EdgeUpdate edgeupdate edgeupdatem MicrosoftEdgeElevationService 
        PrintWorkflowUserSvc_* InstallService sppsvc ClipSVC AppXSvc LicenseManager 
        OfflineFiles CscService FontCache WMPNetworkSvc WerSvc seclogon RemoteAccess WinRM
        RmSvc Fax
    ) do (
        sc config %%s start=disabled >nul 2>&1
        sc stop %%s >nul 2>&1
    )
    cls  
)

cls
:: User Account Control (UAC) Information
@echo off
echo Status: User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes to the operating system.
echo Status: It does this by prompting for permission or an administrator's password before allowing actions that could potentially affect the system's operation or that change settings that affect other users.
echo Status:.

:: Disable UAC
set /p disableUAC="Do you want to disable UAC? [Y/N]: "
if /i "%disableUAC%"=="Y" (
    echo Status: Disabling UAC
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
    cls
) else (
    echo Status: Skipping UAC changes.
    cls
)

:: Disable Notifications
set /p disableNotifications="Do you want to disable Notifications? [Y/N]: "
if /i "%disableNotifications%"=="Y" (
    echo Status: Disabling Notifications
    reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
) else (
    echo Status: Skipping notification changes.
)
cls

:: Install Personal Applications
set /p installApps="Do you want to install personal applications? [Y/N]: "
if /i "%installApps%"=="Y" (
    echo Status: Installing personal applications
    winget install --silent --accept-source-agreements --accept-package-agreements Discord.Discord >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements Brave.Brave >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements Valve.Steam >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements NVIDIA.GeForceExperience >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements NVIDIA.NvContainer >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements NVIDIA.ControlPanel >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements MSI.Afterburner >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements Microsoft.VisualStudioCode >nul 2>&1
    winget install --silent --accept-source-agreements --accept-package-agreements EpicGames.EpicGamesLauncher >nul 2>&1
    cls
) else (
    echo Status: Skipping personal application installations.
    cls
)
cls

set /p removeApps="Do you want to remove Microsoft Apps? [Y/N]: "
if /i "%removeApps%"=="Y" (
    echo Status: Removing non-essential Microsoft Apps
    powershell -Command "$essential = @('Microsoft.WindowsStore','Microsoft.WindowsCalculator','Microsoft.Windows.Photos','Microsoft.WindowsCamera','Microsoft.ScreenSketch','Microsoft.WindowsNotepad'); Get-AppxPackage *Microsoft* | Where-Object {$_.Name -notin $essential} | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
) else (
    echo Status: Skipping Microsoft Apps removal.
)
cls


:: Install PC Essentials
set /p restoreApps2="Do you want to install PC essentials? [Y/N]: "
if /i "%restoreApps2%"=="Y" (
    echo Status: Restoring Microsoft Store and Snipping Tool
    winget install 9WZDNCRFJBMP --accept-package-agreements --accept-source-agreements
    winget install 9MZ95KL8MR0L --accept-package-agreements --accept-source-agreements
    winget install 9nf8h0h7wmlt --accept-package-agreements --accept-source-agreements
    winget install 9MSMLRH6LZF3 --accept-package-agreements --accept-source-agreements
) else (
    echo Status: Skipping restore of Microsoft Store and Snipping Tool.
)
cls

:: NVIDIA Profile Inspector

set "downloadUrl=https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip"
set "destinationDir=%MPath%\NvidiaProfileInspector"
set "tempZip=%temp%\nvidiaProfileInspector.zip"
set "settingsUrl=https://cdn.discordapp.com/attachments/1279506221014974536/1313616508441591879/457-30-and-above.nip?ex=6750c835&is=674f76b5&hm=9976faec1b5aecb61d79d9489029fe4d22536f1fc364a330cae6b1050ad47a8b&"
set "settings=%destinationDir%\Import\"

if not exist "%destinationDir%" mkdir "%destinationDir%"

if not exist "%destinationDir%\Import" mkdir "%destinationDir%\Import"

if not exist "%destinationDir%\Import\Exports.nip" (
    echo Downloading settings file
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%settingsUrl%', '%destinationDir%\Import\Exports.nip')"
)

if not exist "%destinationDir%\*ProfileInspector*" (
    echo App isn't installed.

    echo Downloading NVIDIA Profile Inspector
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%downloadUrl%', '%tempZip%')" >nul 2>&1
    if %errorlevel% neq 0 (
        echo Failed to download the file.
        exit /b 1
    )

    echo Extracting NVIDIA Profile Inspector
    powershell -Command "Expand-Archive -Path '%tempZip%' -DestinationPath '%destinationDir%' -Force" >nul 2>&1
    if %errorlevel% neq 0 (
        echo Failed to extract the file.
        exit /b 1
    )

    set "appPath=%destinationDir%\nvidiaProfileInspector.exe"
    if exist "!appPath!" (
        echo Found app!
        echo Applying settings!
        "!appPath!" -import "%destinationDir%\Import\Exports.nip"
    ) else (
        echo Application executable not found.
        exit /b 1
    )
    del "%tempZip%" >nul 2>&1
    echo NVIDIA Profile Inspector has been downloaded.
    exit /b 0
) else (
    set "appPath=%destinationDir%\nvidiaProfileInspector.exe"
    if exist "!appPath!" (
        echo Found app!
        echo Applying settings!
        "!appPath!" -import "%destinationDir%\Import\Exports.nip"
    ) else (
        echo Application executable not found.
        exit /b 1
    )
)
cls


:: Power Plan Configuration
echo Choose a power plan:
echo 1. Zero Tweaks Performance
echo 2. Zero Tweaks Performance (Idle Off)
echo 3. Skip
set /p powerselection="Enter choice (1-3): "

if "%powerselection%"=="3" goto endPowerPlan

if "%powerselection%"=="1" (
    set "planUrl=https://drive.google.com/uc?export=download&id=1P9dhToAkxzibo8-mLZ8yKtHPOzT9jBlL"
    set "planName=Zero Tweaks Performance"
) else (
    set "planUrl=https://drive.google.com/uc?export=download&id=1x0KmbKLnyt_ca6XrqGBsp8VinGPvVIf_"
    set "planName=Zero Tweaks Performance (Idle Off)"
)

md "%MPath%\PowerPlans" 2>nul

powershell -Command "Invoke-WebRequest -Uri '%planUrl%' -OutFile '%MPath%\PowerPlans\%planName%.pow'"
powercfg /import "%MPath%\PowerPlans\%planName%.pow" >nul

for /f "tokens=4" %%i in ('powercfg /list ^| find /i "Zero"') do powercfg /s %%i >nul
for /f "tokens=4" %%a in ('powercfg /list ^| findstr /i "e"') do powercfg /delete %%a >nul 2>&1

:endPowerPlan
cls

:: Network Adapter Power Settings
echo Status: Applying network adapter power settings
powershell -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'SilentlyContinue'; $adapters = Get-NetAdapter; if ($adapters) { foreach ($adapter in $adapters) { Write-Host 'Updating adapter:' $adapter.Name; Set-NetAdapterPowerManagement -Name $adapter.Name -IncludeHidden -SelectiveSuspend Disabled -WakeOnMagicPacket Disabled -WakeOnPattern Disabled; $properties = '*EEE','*FlowControl','EnableGreenEthernet','GigaLite','PowerSavingMode','AdaptiveIFS','*InterruptModeration','*PriorityVLANTag','*SpeedDuplex','WakeOnLink','*TCPChecksumOffloadIPv4','*TCPChecksumOffloadIPv6','*UDPChecksumOffloadIPv4','*UDPChecksumOffloadIPv6'; foreach ($prop in $properties) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword $prop -RegistryValue 0 }; Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword '*JumboPacket' -RegistryValue 1514; Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword 'QoSTimerResolution' -RegistryValue 1; Write-Host 'Adapter' $adapter.Name 'updated successfully.' } } else { Write-Host 'No network adapters found.' }"
cls

:: Disable Nagle's Algorithm
echo Status: Disabling Nagle's Algorithm
for /f "tokens=2 delims={}" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"') do (
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%%i}" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%%i}" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul 2>&1
)
cls

:: Change Tcpip Settings
echo Status: Changing Tcpip settings
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpDelAckTicks /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 64 /f
cls

:: Disable GameDVR
echo Status: Disabling GameDVR
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
cls

:: Explorer Settings
echo Status: Configuring Explorer settings
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
cls

:: Disable Mitigations
echo Status: Disabling Mitigations
bcdedit /set hypervisorlaunchtype off >nul 2>&1
bcdedit /set isolatedcontext No >nul 2>&1
bcdedit /set allowedinmemorysettings 0x0 >nul 2>&1
bcdedit /set disableelamdrivers Yes >nul 2>&1
bcdedit /set vsmlaunchtype Off >nul 2>&1
bcdedit /set vm No >nul 2>&1

reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul 2>&1
powershell -Command "Set-ProcessMitigation -System -Disable CFG,StrictHandle,DEP,SEHOP,AuditSEHOP,SEHOPTelemetry,ForceRelocateImages" >nul 2>&1
cls

:: Remove Network Bandwidth Limits
echo Status: Removing Network Bandwidth Limits
echo Status: Configuring QOS Packet Scheduler reservable bandwidth
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "LimitReserve" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f >nul 2>&1
cls

:: Disable Printer Services
echo Status: Disabling Printer Services
sc config PrintNotify start=disabled
sc config Spooler start=disabled
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable 
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable 
cls

:: Disable Scheduled Tasks
echo Status: Disabling Scheduled Tasks
for %%t in (
    AMDInstallLauncher AMDLinkUpdate AMDRyzenMasterSDKTask DriverEasyScheduledScan ModifyLinkUpdate 
    SoftMakerUpdater StartCN StartDVR "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" 
    "Microsoft\Windows\Application Experience\PcaPatchDbTask" "Microsoft\Windows\Application Experience\ProgramDataUpdater" 
    "Microsoft\Windows\Application Experience\StartupAppTask" "Microsoft\Windows\Autochk\Proxy" 
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" 
    "Microsoft\Windows\Defrag\ScheduledDefrag" "Microsoft\Windows\Device Information\Device" 
    "Microsoft\Windows\Device Information\Device User" "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" 
    "Microsoft\Windows\Diagnosis\Scheduled" "Microsoft\Windows\DiskCleanup\SilentCleanup" 
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" "Microsoft\Windows\DiskFootprint\Diagnostics" 
    "Microsoft\Windows\DiskFootprint\StorageSense" "Microsoft\Windows\DUSM\dusmtask" 
    "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" "Microsoft\Windows\Feedback\Siuf\DmClient" 
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" "Microsoft\Windows\FileHistory\File History (maintenance mode)" 
    "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" 
    "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" "Microsoft\Windows\Flighting\OneSettings\RefreshCache" 
    "Microsoft\Windows\Input\LocalUserSyncDataAvailable" "Microsoft\Windows\Input\MouseSyncDataAvailable" 
    "Microsoft\Windows\Input\PenSyncDataAvailable" "Microsoft\Windows\Input\TouchpadSyncDataAvailable" 
    "Microsoft\Windows\International\Synchronize Language Settings" "Microsoft\Windows\LanguageComponentsInstaller\Installation" 
    "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" 
    "Microsoft\Windows\License Manager\TempSignedLicenseExchange" "Microsoft\Windows\Management\Provisioning\Cellular" 
    "Microsoft\Windows\Management\Provisioning\Logon" "Microsoft\Windows\Maintenance\WinSAT" 
    "Microsoft\Windows\Maps\MapsToastTask" "Microsoft\Windows\Maps\MapsUpdateTask" 
    "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" "Microsoft\Windows\MUI\LPRemove" 
    "Microsoft\Windows\NetTrace\GatherNetworkInfo" "Microsoft\Windows\PI\Sqm-Tasks" 
    "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" "Microsoft\Windows\PushToInstall\Registration" 
    "Microsoft\Windows\Ras\MobilityManager" "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" 
    "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" "Microsoft\Windows\RetailDemo\CleanupOfflineContent" 
    "Microsoft\Windows\Servicing\StartComponentCleanup" "Microsoft\Windows\SettingSync\NetworkStateChangeTask" 
    "Microsoft\Windows\Setup\SetupCleanupTask" "Microsoft\Windows\Setup\SnapshotCleanupTask" 
    "Microsoft\Windows\SpacePort\SpaceAgentTask" "Microsoft\Windows\SpacePort\SpaceManagerTask" 
    "Microsoft\Windows\Speech\SpeechModelDownloadTask" "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" 
    "Microsoft\Windows\Sysmain\ResPriStaticDbSync" "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" 
    "Microsoft\Windows\Task Manager\Interactive" "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" 
    "Microsoft\Windows\Time Synchronization\SynchronizeTime" "Microsoft\Windows\Time Zone\SynchronizeTimeZone" 
    "Microsoft\Windows\TPM\Tpm-HASCertRetr" "Microsoft\Windows\TPM\Tpm-Maintenance" 
    "Microsoft\Windows\UPnP\UPnPHostConfig" "Microsoft\Windows\User Profile Service\HiveUploadTask" 
    "Microsoft\Windows\WDI\ResolutionHost" "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" 
    "Microsoft\Windows\WOF\WIM-Hash-Management" "Microsoft\Windows\WOF\WIM-Hash-Validation" 
    "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" 
    "Microsoft\Windows\Workplace Join\Automatic-Device-Join" "Microsoft\Windows\WwanSvc\NotificationTask" 
    "Microsoft\Windows\WwanSvc\OobeDiscovery" "Microsoft\XblGameSave\XblGameSaveTask"
    "GoogleUpdateTaskMachineCore{9C99738B-B026-4A33-A16D-7CCD7650D527}" "GoogleUpdateTaskMachineUA{2E0C9FAD-7C87-42A8-8EFF-986A5662B894}"
    "Opera GX scheduled Autoupdate 1711926802" "BraveSoftwareUpdateTaskMachineCore{A8A54493-B843-4D11-BA1F-30C26E9F10BE}"
    "BraveSoftwareUpdateTaskMachineUA{FF1E0511-D7AF-4DB6-8A41-DC39EA60EC93}" "CCleaner Update" "CCleanerCrashReporting"
    "CCleanerUpdateTaskMachineCore" "CCleanerUpdateTaskMachineUA" "Microsoft\Windows\capabilityaccessmanager"
    "Microsoft\Windows\Setup\SetupCleanupTask" "Microsoft\Windows\Setup\SnapshotCleanupTask"
    "Microsoft\Windows\Shell\FamilySafetyMonitor" "Microsoft\Windows\Shell\FamilySafetyRefreshTask"
    "Microsoft\Windows\Shell\ThemesSyncedImageDownload" "Microsoft\Windows\Shell\UpdateUserPictureTask"
    "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
    "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"
    "Microsoft\Windows\Application Experience\SdbinstMergeDbTask" "Microsoft\Windows\Printing\PrintJobCleanupTask"
) do (
    schtasks /Change /TN "%%t" /Disable >nul 2>&1
)
schtasks /Delete /TN "GoogleUpdateTaskMachineCore{9C99738B-B026-4A33-A16D-7CCD7650D527}" /F >nul 2>&1
schtasks /Delete /TN "GoogleUpdateTaskMachineUA{2E0C9FAD-7C87-42A8-8EFF-986A5662B894}" /F >nul 2>&1
schtasks /Delete /TN "Opera GX scheduled Autoupdate 1711926802" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineCore{A8A54493-B843-4D11-BA1F-30C26E9F10BE}" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineUA{FF1E0511-D7AF-4DB6-8A41-DC39EA60EC93}" /F >nul 2>&1
schtasks /Delete /TN "CCleaner Update" /F >nul 2>&1
schtasks /Delete /TN "CCleanerCrashReporting" /F >nul 2>&1
schtasks /Delete /TN "CCleanerUpdateTaskMachineCore" /F >nul 2>&1
schtasks /Delete /TN "CCleanerUpdateTaskMachineUA" /F >nul 2>&1
cls

:: Cleanup Application Folders
echo Status: Cleaning up application folders
for /d %%i in ("%LOCALAPPDATA%\Packages\*") do (
    if exist "%%i" (
        echo Status: Attempting to delete %%i
        rmdir /s /q "%%i" 2>nul
        if errorlevel 1 (
            echo Status: Could not delete %%i - folder may be in use.
        )
    )
)
cls

:: Disable Browser Services
echo Status: Disabling Browser Services
for %%s in (
    edgeupdate edgeupdatem GoogleChromeElevationService gupdate
    gupdatem BraveElevationService brave bravem
) do (
    sc config %%s start=disabled >nul 2>&1
)
cls

:: Change WTK Threshold
echo Status: Changing WTK Threshold
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "2000" /f >nul 2>&1
cls

:: Disable Background Apps
echo Status: Turning off Background Apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f >nul 2>&1
cls

:: Disable Hibernation
echo Status: Disabling Hibernation
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
powercfg -h off
cls

:: Disable C States
echo Status: Disabling C States
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1
cls

:: Disable Core Parking
echo Status: Disabling Core Parking
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1
cls

:: Disable Throttling States
echo Status: Disabling Throttling States
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f >nul 2>&1
cls

:: Disable Mouse Acceleration
echo Status: Disabling Mouse Acceleration
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f
cls

:: Disable StickyKeys
echo Status: Disabling StickyKeys
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
cls

:: Remove Storage Sense
echo Status: Removing Storage Sense
powershell -Command "Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
cls

:: Disable HomeGroup
echo Status: Disabling HomeGroup
sc config HomeGroupListener start=demand >nul 2>&1
sc config HomeGroupProvider start=demand >nul 2>&1
cls

:: Install Visual C++
echo Status: Installing Visual C++ 2015-2022 Redistributable
reg query "HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" >nul 2>&1
if %errorlevel% == 0 (
    echo Status: Visual C++ 2015-2022 Redistributable is already installed.
    timeout /t 2 >nul
) else (
    echo Status: Visual C++ 2015-2022 Redistributable is not installed.
    echo Status: Downloading and installing
    set "download=https://github.com/abbodi1406/vcredist/releases/download/v0.85.0/VisualCppRedist_AIO_x86_x64.exe"

    powershell -Command "(New-Object Net.WebClient).DownloadFile('%download%', '%temp%\VisualCPP.exe')" >nul 2>&1

    %temp%\VisualCPP.exe /install /quiet /norestart
    del "%temp%\vc_redist.x64.exe" /f /q
    timeout /t 2 >nul
)

:: Set Priority Separation
echo Status: Setting Priority Separation
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000016 /f
echo Status: Disabling Suggested Apps in Start Menu
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f

:: Disable Windows Update
echo Status: Disabling Windows Update
sc config wuauserv start=disabled >nul 2>&1
sc stop wuauserv >nul 2>&1
cls

echo Status: Setting Svc Memory Threshold
for /f %%a in ('powershell -Command "(Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb"') do set "ram_kb=%%a"
powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SvcHostSplitThresholdInKB' -Type DWord -Value %ram_kb% -Force"
cls

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
cls

:: Enable Gamemode
echo Status: Enabling Gamemode
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 1 /f
cls

:: Set Priorities
echo Status: Setting Priorities
set key="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
reg add %key% /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add %key% /v "Priority" /t REG_DWORD /d 6 /f
reg add %key% /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add %key% /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add %key% /v "Background Only" /t REG_DWORD /d 0 /f
reg add %key% /v "Clock Rate" /t REG_DWORD /d 0 /f
reg add %key% /v "Affinity" /t REG_DWORD /d 0 /f
reg add %key% /v "SFIO Priority" /t REG_SZ /d "High" /f
cls

:: Copy System Configuration
echo Status: Copying System Configuration
powershell -Command "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f
cls

:: Disable Location
echo Status: Disabling Location
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f
cls

:: Disable Activity History
echo Status: Disabling Activity History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
cls

:: Disable Cortana
echo Status: Disabling Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverNonMeteredConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverWifiOnly" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverCellular" /t REG_DWORD /d 0 /f
cls

:: Disable Windows Defender
echo Status: Disabling Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableScanOnSchedule" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableScanOnStartup" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableScriptScanning" /t REG_DWORD /d 1 /f
powershell -Command "Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue"
cls

:: Disable Windows Update
echo Status: Disabling Windows Update
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AUOptions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
cls

:: Finalize Setup
echo Status: Changing PrioritySeparation to 28
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f

echo Status: Removing Autologging DiagTrack
set "autoLoggerDir=%PROGRAMDATA%\Microsoft\Diagnosis\ETLLogs\AutoLogger"
if exist "%autoLoggerDir%\AutoLogger-Diagtrack-Listener.etl" (
    del /q "%autoLoggerDir%\AutoLogger-Diagtrack-Listener.etl" >nul 2>&1
)
icacls "%autoLoggerDir%" /deny SYSTEM:(OI)(CI)F >nul 2>&1
cls

echo Status: Removing Smartscreen
for %%f in (
    "C:\Windows\System32\smartscreen.exe"
    "C:\Windows\SystemApps\Microsoft.Windows.AppRep.ChxApp_cw5n1h2txyewy\CHXSmartScreen.exe"
) do (
    if exist "%%f" (
        echo Status: Taking ownership of %%f
        takeown /F "%%f" >nul 2>&1
        echo Status: Adjusting permissions for %%f
        icacls "%%f" /grant administrators:F >nul 2>&1
        echo Status: Removing %%f
        del "%%f" /f /q
        echo Status: %%f deleted successfully.
    )
)
cls

echo Status: Removing LockApp
set "lockAppFileToDelete=C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe"
if exist "%lockAppFileToDelete%" (
    takeown /F "%lockAppFileToDelete%" >nul 2>&1
    icacls "%lockAppFileToDelete%" /grant administrators:F >nul 2>&1
    del "%lockAppFileToDelete%" /f /q
    echo Status: LockApp.exe removed.
) else (
    echo Status: LockApp.exe not found.
)
cls

echo Status: Disabling HPET
bcdedit /set useplatformclock false
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d 1 /f
cls

echo Status: Disabling HPET in Device Manager
powershell -Command "Get-PnpDevice | Where-Object { $_.FriendlyName -like '*High Precision Event Timer*' } | Select-Object -ExpandProperty InstanceId" > temp.txt
set /p instanceId=<temp.txt
del temp.txt

if not "%instanceId%"=="" (
    pnputil /disable-device "%instanceId%"
) else (
    echo Status: HPET not found on this system.
)
cls

echo Status: Refreshing Explorer
taskkill /f /im explorer.exe & start explorer.exe
cls

:: Restart PC Prompt
set /p restartPC="Would you like to restart your PC? [Y/N]: "
if /i "%restartPC%"=="Y" (
    echo Status: Restarting PC
    shutdown /r /t 0
) else (
    echo Status: Skipping restart.
)

pause
goto menu

:: Cleaner
:Cleaner
cls

:: Downloads Cleaning
echo === Downloads Cleanup ===
set /p cleanDownloads="Do you want to clean downloads? [Y/N]: "
if /i "%cleanDownloads%"=="Y" (
    echo Status: Cleaning Downloads folder
    del /f /s /q "%USERPROFILE%\Downloads\*"
    rd /s /q "%USERPROFILE%\Downloads"
    md "%USERPROFILE%\Downloads"
) else (
    echo Status: Skipping downloads cleanup.
)
cls

:: Network Cleaning 
@echo off
echo === Network Cleanup ===
set /p cleanNetwork="Do you want to clean the network? [Y/N]: "
if /i "%cleanNetwork%"=="Y" (
    echo Status: Cleaning Network
    netsh winsock reset

    set "found_ethernet="
    set "found_wifi="
    
    for /f "tokens=1,2,*" %%i in ('netsh interface show interface ^| findstr /i "Connected"') do (
        if not defined found_ethernet (
            if /i "%%k" == "Ethernet" (
                echo Status: Cleaning Ethernet adapter: %%k
                netsh interface ip set address "%%k" dhcp
                netsh interface ip set dns "%%k" dhcp
                ipconfig /release "%%k"
                ipconfig /renew "%%k"
                set "found_ethernet=1"
            )
        )
        if not defined found_wifi (
            if /i "%%k" == "Wi-Fi" (
                echo Status: Cleaning WiFi adapter: %%k
                netsh interface ip set address "%%k" dhcp
                netsh interface ip set dns "%%k" dhcp
                ipconfig /release "%%k"
                ipconfig /renew "%%k"
                set "found_wifi=1"
            )
        )
    )

    ipconfig /flushdns
    ipconfig /registerdns >nul 2>&1
    
    echo Status: Resetting TCP Stack
    netsh int ip reset resetlog.txt
) else (
    echo Status: Skipping network cleaning.
)
cls

:: Taskbar and Start Menu Cleanup
echo === Taskbar and Start Menu Cleanup ===
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsSearch" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableMeetNow /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableSecurityIcons /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
cls

:: Browser Cleanup
echo === Browser Cleanup ===
echo Status: Disabling Browser Hardware Acceleration
reg add "HKCU\Software\Google\Chrome" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Google\Chrome\WidevineCdm" /v "Hardware Accelerated Video Decode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Edge" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Edge\VideoConfig" /v "HardwareAccelerationEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Mozilla\Firefox\Preferences" /v "gfx.direct2d.disabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Mozilla\Firefox\Preferences" /v "layers.acceleration.disabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Opera Software\Opera Stable" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Opera Software\Opera Stable\VideoConfig" /v "HardwareAccelerationEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\BraveSoftware\Brave-Browser" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\BraveSoftware\Brave-Browser\WidevineCdm" /v "Hardware Accelerated Video Decode" /t REG_DWORD /d "0" /f >nul 2>&1

:: System Cleanup
echo === System Cleanup ===
echo Status: Cleaning Device Manager
powershell -Command "& {Get-PnpDevice -Status Unknown | ForEach-Object { & pnputil /remove-device $_.InstanceId }}"
powershell -Command "& {Get-PnpDevice -Status Error | ForEach-Object { & pnputil /remove-device $_.InstanceId }}"
cls

echo Status: Cleaning System Files
del /s /f /q "%SystemRoot%\*.log"
del /s /f /q "%SystemRoot%\Debug\*.log"
del /s /f /q "%SystemRoot%\security\logs\*.log"
del /s /f /q "%SystemRoot%\Logs\CBS\*.log"
del /s /f /q "%SystemRoot%\Logs\DISM\*.log"
del /s /f /q "%WinDir%\Logs"
del /s /f /q "%WinDir%\Installer\$PatchCache$"
del /s /f /q "%WinDir%\System32\LogFiles"
cls

echo Status: Cleaning Windows Components
rd /s /q "%SystemDrive%\$GetCurrent"
rd /s /q "%SystemDrive%\$SysReset"
rd /s /q "%SystemDrive%\$Windows.~BT"
rd /s /q "%SystemDrive%\$Windows.~WS"
rd /s /q "%SystemDrive%\$WinREAgent"
rd /s /q "%SystemDrive%\OneDriveTemp"
cls

echo Status: Running System Maintenance
sfc /scannow /StartComponentCleanup
dism /online /cleanup-image /restorehealth /StartComponentCleanup /resetbase
compact /compactos:always >nul 2>&1
cleanmgr /sageset:1 >nul 2>&1
cls

:: Cache and Temp Files
echo === Cache and Temp Cleanup ===

echo Status: Cleaning Windows Caches
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*"
del /s /f /q "%LocalAppData%\Microsoft\Windows\WER\*"
del /s /f /q "%temp%\*"
rd /s /q "%LocalAppData%\Temp"
rd /s /q "%WinDir%\Temp"
cls

:: UI Cleanup
echo === UI Cleanup ===
echo Status: Clearing Quick Access History
del /f /q "%APPDATA%\Microsoft\Windows\Recent\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"

echo Status: Cleaning Start Menu
del /f /s /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\*.lnk"
del /f /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\*.lnk"
del /f /q "%LocalAppData%\Microsoft\Windows\Shell\DefaultLayouts.xml"
del /f /q "%LocalAppData%\Microsoft\Windows\Shell\LayoutModification.xml"

echo Status: Refreshing Explorer
taskkill /f /im explorer.exe & start explorer.exe

echo Status: Cleanup Complete!
pause
goto menu

:: Priority

:Priority

setlocal enabledelayedexpansion

for %%s in (
    Phasmophobia FortniteClient-Win64-Shipping javaw steam csgo dota2
    hl2 GTA5 RainbowSix VALORANT VALORANT-Win64-Shipping Overwatch ApexLegends
    RobloxPlayerBeta
) do (
    echo Status: Changed %%s Priority
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%s.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 0x00000003 /f > nul
    
    echo Status: Searching and Changing Games to Performance Mode
    set "found="

    pushd "C:\Program Files" 2>nul && (
        for /f "delims=" %%a in ('where /r . %%s.exe 2^>nul') do (
            set "found=%%a"
            echo Status: Found: !found!
            for %%F in ("!found!") do set "gamedir=%%~dpF"
            echo Status: Directory: !gamedir!
            if "%%s"=="FortniteClient-Win64-Shipping" (
                reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "!found!" /t REG_SZ /d "~ DISABLEDXMAXIMIZEDWINDOWEDMODE" /f >nul
                echo Status: Disabled fullscreen optimizations for Fortnite
            )
            reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "!found!" /t REG_SZ /d "GpuPreference=2;" /f > nul
            echo Status: !gamedir!| clip
        )
        popd
    )

    pushd "C:\Program Files (x86)" 2>nul && (
        for /f "delims=" %%a in ('where /r . %%s.exe 2^>nul') do (
            set "found=%%a"
            echo Status: Found: !found!
            for %%F in ("!found!") do set "gamedir=%%~dpF"
            echo Status: Directory: !gamedir!
            reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "!found!" /t REG_SZ /d "GpuPreference=2;" /f > nul
            echo Status: !gamedir!| clip
        )
        popd
    )

    if not defined found (
        echo Status: File not found: %%s
    )
)

set /p "MissedPriority=Did I miss a game? [Y/N]: "
if /i "!MissedPriority!"=="Y" (
    set /p "SelectedGame=Enter the game process: "
    if /i "!SelectedGame:~-4!"==".exe" ( set "SelectedGame=!SelectedGame:~0,-4!" )
    echo Status: Changed !SelectedGame! Priority
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\!SelectedGame!.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 0x00000003 /f > nul
    
    echo Status: Searching and Changing Game to Performance Mode
    set "found="

    pushd "C:\Program Files" 2>nul && (
        for /f "delims=" %%a in ('where /r . !SelectedGame!.exe 2^>nul') do (
            set "found=%%a"
            echo Status: Found: !found!
            for %%F in ("!found!") do set "gamedir=%%~dpF"
            echo Status: Directory: !gamedir!
            reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "!found!" /t REG_SZ /d "GpuPreference=2;" /f > nul
            echo Status: !gamedir!| clip
        )
        popd
    )

    pushd "C:\Program Files (x86)" 2>nul && (
        for /f "delims=" %%a in ('where /r . !SelectedGame!.exe 2^>nul') do (
            set "found=%%a"
            echo Status: Found: !found!
            for %%F in ("!found!") do set "gamedir=%%~dpF"
            echo Status: Directory: !gamedir!
            reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "!found!" /t REG_SZ /d "GpuPreference=2;" /f > nul
            echo Status: !gamedir!| clip
        )
        popd
    )

    if not defined found (
        echo Status: File not found: !SelectedGame!
    )
    pause
)

cls
goto menu

:: Debloater
:Debloater
echo Status: Removing Built-in Apps
powershell -Command "Get-AppxPackage -AllUsers | Remove-AppxPackage"
powershell -Command "Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online"

echo Status: Disabling Unnecessary Services
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled

echo Status: Disabling Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f

echo Status: Disabling Xbox Services
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop XblGameSave
sc config XblGameSave start= disabled
sc stop XboxNetApiSvc
sc config XboxNetApiSvc start= disabled
sc stop XboxGipSvc
sc config XboxGipSvc start= disabled

echo Status: Disabling Background Apps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 2 /f

echo Status: Disabling Windows Tips and Feedback
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f

echo Status: Removing Microsoft Edge
taskkill /f /im msedge.exe >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\Edge" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeCore" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeWebView" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\Temp" >nul 2>&1
del "C:\Users\Public\Desktop\Microsoft Edge.lnk" >nul 2>&1
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" >nul 2>&1
del "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" >nul 2>&1

if exist "HKLM\SOFTWARE\Policies\Microsoft\Edge" (
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /f >nul 2>&1
)
cls

    echo Status: Removing Onedrive
    taskkill.exe /F /IM "OneDrive.exe"  >nul 2>&1
    taskkill.exe /F /IM "explorer.exe"  >nul 2>&1
    winget uninstall --silent --accept-source-agreements Microsoft.OneDrive >nul 2>&1
    echo Status: The operation completed successfully.
    reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
    reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
    reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
    reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >nul 2>&1
    reg unload "hku\Default"
    del /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" >nul 2>&1
    schtasks /delete /tn "OneDrive*" /f >nul 2>&1
cls


    echo Status: Removing Widgets
    taskkill /F /IM WidgetService.exe >nul 2>&1
    taskkill /F /IM Widgets.exe >nul 2>&1
    winget uninstall --silent --accept-source-agreements "Windows web experience Pack" >nul 2>&1
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
    for %%f in (WidgetService.exe Widgets.exe) do (
        if exist "%%f" (
            echo Status: Taking ownership of %%f
            takeown /F "%%f" >nul 2>&1
            echo Status: Adjusting permissions for %%f
            icacls "%%f" /grant administrators:F >nul 2>&1
            echo Status: Removing %%f
            del "%%f" /f /q
            echo Status: %%f deleted successfully.
        )
    )
start explorer.exe
cls


pause
cls
goto menu

:: Restore
:Restore
echo Status: Restoring services to default configuration

for %%s in (
    BFE BrokerInfrastructure CoreMessagingRegistrar CryptSvc DcomLaunch Dhcp Dnscache EventLog FontCache
    gpsvc LSM MMCSS MpsSvc NlaSvc nsi Power ProfSvc RpcEptMapper RpcSs SamSs ShellHWDetection StateRepository
    SystemEventsBroker Themes UserManager Winmgmt AudioEndpointBuilder Audiosrv LanmanServer LanmanWorkstation 
    WlanSvc vmwaretools Schedule PlugPlay TokenBroker WdiSystemHost DusmSvc OneSyncSvc XblAuthManager
    XboxNetApiSvc CDPUserSvc RemoteRegistry WbioSrvc PimIndexMaintenanceSvc UdkUserSvc WpnUserService 
    DevicesFlowUserSvc PrintWorkflowUserSvc
) do (
    sc config %%s start= auto
    cls
)

for %%s in (
    AJRouter ALG AppIDSvc AppMgmt AppReadiness AppXSvc AppVClient
    AssignedAccessManagerSvc autotimesvc AxInstSV BDESVC BITS BTAGService
    Browser CDPSvc CertPropSvc ClipSVC cloudidsvc COMSysApp
    CscService camsvc defragsvc DeviceInstall DevQueryBroker
    diagnosticshub.standardcollector.service DiagTrack DialogBlockingService
    DisplayEnhancementService DmEnrollmentSvc dmwappushservice DoSvc
    dot3svc DPS DsmSvc DsSvc Eaphost EFS EntAppSvc EventSystem
    Fax fdPHost FDResPub fhsvc hidserv HvHost icssvc
    InstallService InventorySvc IEEtwCollectorService IKEEXT iphlpsvc
    IpxlatCfgSvc KeyIso KtmRm lfsvc lltdsvc lmhosts MapsBroker
    McpManagementService MSDTC MsKeyboardFilter MSiSCSI msiserver
    NaturalAuthentication NcaSvc NcbService NcdAutoSetup Netlogon
    Netman netprofm NetSetupSvc NetTcpPortSharing NgcCtnrSvc
    NgcSvc p2pimsvc p2psvc PcaSvc PeerDistSvc PerfHost
    pla PlugPlay PNRPAutoReg PNRPsvc PolicyAgent PrintNotify
    QWAVE RasAuto RasMan RetailDemo RmSvc RpcLocator
    SCardSvr ScDeviceEnum Schedule SCPolicySvc SDRSVC seclogon
    SensorDataService SensorService SensrSvc SessionEnv SharedAccess
    smphost SmsRouter SNMPTRAP Spooler sppsvc SSDPSRV
    SstpSvc stisvc StorSvc svsvc swprv TapiSrv TermService
    TrkWks TrustedInstaller TroubleshootingSvc UmRdpService upnphost
    UsoSvc VaultSvc vds vmcompute WarpJITSvc wbengine WbioSrvc
    Wcmsvc wcncsvc WdiServiceHost WdiSystemHost WdNisSvc WebClient
    Wecsvc WEPHOSTSVC wercplsupport WerSvc WiaRpc WinDefend
    WinHttpAutoProxySvc WinRM wlidsvc wlpasvc wmiApSrv WMPNetworkSvc
    workfolderssvc WPDBusEnum WpcMonSvc WpnService wscsvc WSearch
    wuauserv WwanSvc FontCache3.0.0.0 FileSyncHelper HNS nvagent
    VSS vmicguestinterface vmicheartbeat vmicrdv vmicshutdown
    vmictimesync vmicvmsession vmicvss W32Time WalletService FrameServer
    Containers SysMain RemoteAccess RemoteRegistry TabletInputService
    XboxGipSvc XboxNetApiSvc PhoneSvc PrintSpooler EdgeUpdate edgeupdate 
    edgeupdatem MessagingService OneSyncSvc ShellHWDetection Spooler 
    StorSvc TeamViewer uhssvc UnistoreSvc UserDataSvc WSearch WSearchIndexer
    BluetoothUserService_* CDPUserSvc_* cbdhsvc_* DeviceAssociationBrokerSvc_*
    DeviceFlowUserSvc_* MessagingService_* PimIndexMaintenanceSvc_*
    UdkUserSvc_* UnistoreSvc_* UserDataSvc_* WpnUserService_*
) do (
    sc config %%s start= demand
    cls
)

for %%s in (
    CDPSvc MapsBroker PcaSvc sppsvc StorSvc UsoSvc wscsvc WSearch
    diagtrack MixedRealityOpenXRSvc RetailDemo SEMgrSvc WpcMonSvc
    WpnService DisplayEnhancementService CDPUserSvc_* DevicesFlowUserSvc_*
) do (
    sc config %%s start= delayed-auto
    cls
)

powershell -Command "Get-Service \"BluetoothUserService_*\" | Set-Service -StartupType Automatic -PassThru -ErrorAction SilentlyContinue" >nul 2>&1

echo Status: Services have been restored to default configuration.
pause
goto menu

:SystemRestore
cls
echo === System Restore Process ===

:: Create System Restore Point
echo Status: Creating restore point...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f >nul 2>&1
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Before System Restore' -RestorePointType 'MODIFY_SETTINGS'"

:: Restore Context Menu
echo Status: Restoring context menu settings...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /f >nul 2>&1
reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f >nul 2>&1

:: Restore Services
echo Status: Restoring Windows services...
for %%s in (VSS HvHost BITS RemoteRegistry SEMgrSvc MixedRealityOpenXRSvc 
    SCardSvr icssvc RetailDemo WbioSrv fhsvc WpcMonSvc CertPropSvc 
    WdiServiceHost WdiSystemHost TrkWks WerSvc EntAppSvc PcaSvc MapsBroker 
    BDESVC lmhosts DiagTrack dmwappushservice Schedule sppsvc wuauserv) do (
    sc config %%s start=auto >nul 2>&1
    sc start %%s >nul 2>&1
)

:: Restore UAC
echo Status: Restoring UAC...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul 2>&1

:: Restore Notifications
echo Status: Restoring notifications...
reg delete "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /f >nul 2>&1

:: Restore Network Settings
echo Status: Restoring network settings...
netsh winsock reset
netsh int ip reset
ipconfig /release
ipconfig /renew
ipconfig /flushdns

:: Restore Power Settings
echo Status: Restoring power settings...
powercfg -restoredefaultschemes

:: Restore System Settings
echo Status: Restoring system settings...
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue useplatformtick
bcdedit /deletevalue disabledynamictick

:: Enable HPET
echo Status: Enabling HPET...
bcdedit /set useplatformclock true

:: Restore Windows Defender
echo Status: Restoring Windows Defender...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /f >nul 2>&1
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false" >nul 2>&1

:: Restore Windows Update
echo Status: Restoring Windows Update...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v AUOptions /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v NoAutoUpdate /f >nul 2>&1
sc config wuauserv start=auto >nul 2>&1
sc start wuauserv >nul 2>&1

:: Restore Game DVR
echo Status: Restoring Game DVR...
reg delete "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /f >nul 2>&1
reg delete "HKCU\System\GameConfigStore" /v GameDVR_Enabled /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /f >nul 2>&1

:: Restore Explorer Settings
echo Status: Restoring Explorer settings...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 1 /f >nul 2>&1

:: Restore Mouse Settings
echo Status: Restoring mouse settings...
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 6 /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 10 /f >nul 2>&1

:: Restore everything from Setup section
echo Status: Restoring system modifications...

:: Visual Effects
echo Status: Restoring visual effects...
reg delete "HKCU\Control Panel\Desktop" /v UserPreferencesMask /f >nul 2>&1 
reg delete "HKCU\Control Panel\Desktop" /v MenuShowDelay /f >nul 2>&1
reg delete "HKCU\Control Panel\Keyboard" /v KeyboardDelay /f >nul 2>&1
reg delete "HKCU\Control Panel\Desktop" /v FontSmoothing /f >nul 2>&1
reg delete "HKCU\Control Panel\Desktop" /v DragFullWindows /f >nul 2>&1
reg delete "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /f >nul 2>&1

:: Restore Network Adapter Settings
echo Status: Restoring network adapter settings...
powershell -ExecutionPolicy Bypass -Command "$adapters = Get-NetAdapter; foreach ($adapter in $adapters) { Set-NetAdapterPowerManagement -Name $adapter.Name -SelectiveSuspend Enabled -WakeOnMagicPacket Enabled -WakeOnPattern Enabled }" >nul 2>&1

:: Enable Nagle's Algorithm
echo Status: Enabling Nagle's Algorithm...
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TcpAckFrequency /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TCPNoDelay /f >nul 2>&1

:: Restore TCP/IP Settings
echo Status: Restoring TCP/IP settings...
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpDelAckTicks /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /f >nul 2>&1

:: Enable Mitigations
echo Status: Enabling mitigations...
bcdedit /deletevalue hypervisorlaunchtype >nul 2>&1
bcdedit /deletevalue isolatedcontext >nul 2>&1
bcdedit /deletevalue allowedinmemorysettings >nul 2>&1
bcdedit /deletevalue disableelamdrivers >nul 2>&1
bcdedit /deletevalue vsmlaunchtype >nul 2>&1
bcdedit /deletevalue vm >nul 2>&1

:: Restore QoS Settings
echo Status: Restoring QoS settings...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v LimitReserve /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v NonBestEffortLimit /f >nul 2>&1

:: Enable Printer Services
echo Status: Enabling printer services...
sc config PrintNotify start=auto >nul 2>&1
sc config Spooler start=auto >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Enable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Enable >nul 2>&1

:: Enable Windows Features
echo Status: Enabling Windows features...
dism /online /enable-feature /featurename:PrintToPDFServices /norestart >nul 2>&1
dism /online /enable-feature /featurename:Printing-PrintToPDFServices-Features /norestart >nul 2>&1

:: Reset System Timer Resolution
echo Status: Resetting system timer resolution...
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /f >nul 2>&1

:: Enable Background Apps
echo Status: Enabling background apps...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /f >nul 2>&1

:: Enable Hibernation
echo Status: Enabling hibernation...
powercfg /h on >nul 2>&1
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /f >nul 2>&1

:: Enable C States & Core Parking
echo Status: Enabling C States and Core Parking...
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 10 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 10 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1

:: Reset Priority Separation
echo Status: Resetting priority separation...
reg delete "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v Win32PrioritySeparation /f >nul 2>&1

:: Enable Location Services
echo Status: Enabling location services...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /f >nul 2>&1
sc config lfsvc start=auto >nul 2>&1

:: Restart Explorer
echo Status: Restarting Explorer...
taskkill /f /im explorer.exe >nul 2>&1
start explorer.exe

echo Status: System restore complete! A restart is recommended.
set /p restart="Do you want to restart now? (Y/N): "
if /i "%restart%"=="Y" shutdown /r /t 0
goto menu

:exit
exit /B
