@echo off
setlocal enabledelayedexpansion

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges
    goto UACPrompt
) else (
    goto gotAdmin
)

:UACPrompt
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
exit /B

:gotAdmin
@echo off


:menu
cls
echo Choose an option:
echo 1. Setup
echo 2. Cleaner
echo 3. Wi-fi Fixer
echo 4. Restore Services
echo 5. Exit
set /p choice="Select an option (1-4): "

if "%choice%"=="1" goto Setup
if "%choice%"=="2" goto Cleaner
if "%choice%"=="3" goto Fixer
if "%choice%"=="4" goto Restore
if "%choice%"=="5" goto exit

echo Invalid choice! Try again.
goto menu

:: Setup -- Organization
:Setup
cls
:: Microsoft

set /p createRestorePoint="Do you want to create a System Restore Point? [Y/N]: "
if /i "%createRestorePoint%"=="Y" (
    echo Creating System Restore Point
    powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Before Setup Changes' -RestorePointType 'MODIFY_SETTINGS'" >nul 2>&1
    echo System Restore Point created.
) else (
    echo Skipping System Restore Point creation.
)
cls

:: Context Menu
set /p addEndTask="Do you want to add 'End Task' to the context menu? [Y/N]: "
if /i "%addEndTask%"=="Y" (
    echo Adding end task to context menu
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings /v TaskbarEndTask /t REG_DWORD /d 1 /f
) else (
    echo Skipping adding end task to context menu
)
cls

set /p enableClickMenu="Do you want to enable the Windows 10 right-click menu? [Y/N]: "
if /i "%enableClickMenu%"=="Y" (
    echo Enabling Windows 10 right-click menu
    powershell -Command "Remove-Item -Path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Recurse" >nul 2>&1
) else (
    echo Skipping enabling Windows 10 right-click menu
    cls
)

set /p changeServices="Do you want to change services to manual? [Y/N]: "
if /i "%changeServices%"=="Y" (
    echo Changing services to manual
    for %%s in (
        AJRouter ALG AppIDSvc AppMgmt AppReadiness AppVClient AppXSvc Appinfo AssignedAccessManagerSvc 
        AudioEndpointBuilder AudioSrv Audiosrv AxInstSV BDESVC BFE BITS BTAGService BcastDVRUserService_dc2a4 
        BrokerInfrastructure Browser CDPSvc CDPUserSvc_dc2a4 COMSysApp CaptureService_dc2a4 CertPropSvc 
        ConsentUxUserSvc_dc2a4 CoreMessagingRegistrar CredentialEnrollmentManagerUserSvc_dc2a4 CryptSvc CscService 
        DPS DcomLaunch DcpSvc DevQueryBroker DeviceAssociationBrokerSvc_dc2a4 DeviceAssociationService DeviceInstall 
        DevicePickerUserSvc_dc2a4 DevicesFlowUserSvc_dc2a4 DiagTrack DialogBlockingService DmEnrollmentSvc Dnscache 
        DoSvc DsSvc DsmSvc DusmSvc EFS EapHost EntAppSvc EventLog EventSystem FDResPub Fax FrameServer 
        FrameServerMonitor HomeGroupListener HomeGroupProvider HvHost IEEtwCollectorService IKEEXT InstallService 
        InventorySvc IpxlatCfgSvc KeyIso KtmRm LSM LanmanServer LanmanWorkstation LicenseManager LxpSvc MSDTC MSiSCSI 
        MapsBroker McpManagementService MessagingService_dc2a4 MicrosoftEdgeElevationService MixedRealityOpenXRSvc 
        MpsSvc MsKeyboardFilter NPSMSvc_dc2a4 NaturalAuthentication NcaSvc NcbService NcdAutoSetup NetSetupSvc 
        NetTcpPortSharing Netlogon Netman NgcCtnrSvc NgcSvc NlaSvc OneSyncSvc_dc2a4 P9RdrService_dc2a4 PNRPAutoReg 
        PNRPsvc PcaSvc PeerDistSvc PenService_dc2a4 PerfHost PhoneSvc PimIndexMaintenanceSvc_dc2a4 PlugPlay 
        PolicyAgent Power PrintNotify PrintWorkflowUserSvc_dc2a4 ProfSvc PushToInstall QWAVE RasAuto RasMan 
        RemoteAccess RemoteRegistry RetailDemo RmSvc RpcLocator SCPolicySvc SCardSvr SDRSVC SEMgrSvc SENS SNMPTRAP 
        SNMPTrap SSDPSRV SamSs ScDeviceEnum SecurityHealthService Sense SensorDataService SensorService SensrSvc 
        SessionEnv SgrmBroker SharedAccess SharedRealitySvc ShellHWDetection SmsRouter Spooler SstpSvc StateRepository 
        StiSvc SysMain SystemEventsBroker TabletInputService TapiSrv TermService TextInputManagementService Themes 
        TieringEngineService TimeBroker TimeBrokerSvc TokenBroker TrkWks TroubleshootingSvc TrustedInstaller UI0Detect 
        UdkUserSvc_dc2a4 UevAgentService UmRdpService UnistoreSvc_dc2a4 UserDataSvc_dc2a4 UserManager UsoSvc VGAuthService 
        VMTools VSS VacSvc VaultSvc W32Time WEPHOSTSVC WMPNetworkSvc WManSvc WPDBusEnum WSService WSearch WaaSMedicSvc 
        WalletService WarpJITSvc WbioSrvc Wcmsvc WcsPlugInService WdNisSvc WdiServiceHost WdiSystemHost WebClient Wecsvc 
        WerSvc WiaRpc WinDefend WinHttpAutoProxySvc WinRM Winmgmt WpcMonSvc WpnService WpnUserService_dc2a4 WwanSvc 
        XblAuthManager XblGameSave XboxGipSvc XboxNetApiSvc autotimesvc camsvc cbdhsvc_dc2a4 cloudidsvc dcsvc defragsvc 
        diagnosticshub.standardcollector.service diagsvc dmwappushservice dot3svc edgeupdate edgeupdatem embeddedmode 
        fdPHost fhsvc gpsvc hidserv icssvc iphlpsvc lfsvc lltdsvc lmhosts mpssvc msiserver netprofm nsi p2pimsvc 
        p2psvc perceptionsimulation pla seclogon shpamsvc smphost spectrum sppsvc ssh-agent svsvc swprv tiledatamodelsvc 
        tzautoupdate uhssvc upnphost vds vm3dservice vmicguestinterface vmicheartbeat vmickvpexchange vmicrdv vmicshutdown 
        vmictimesync vmicvmsession vmicvss vmvss wbengine wcncsvc webthreatdefsvc webthreatdefusersvc_dc2a4 wercplsupport 
        wisvc wlidsvc wlpasvc wmiApSrv workfolderssvc wscsvc wuauserv wudfsvc
    ) do (
        sc config %%s start=demand >nul 2>&1
    )
    cls
) else (
    echo Skipping changing services to manual.
    cls
)

set /p disableServices="Do you want to disable Services? [Y/N]: "
if /i "%disableServices%"=="Y" (
    for %%s in (
        ALG AJRouter XblAuthManager XblGameSave XboxNetApiSvc WSearch RemoteRegistry SEMgrSvc 
        SCardSvr Netlogon icssvc wisvc RetailDemo WbioSrvc iphlpsvc wcncsvc fhsvc 
        seclogon FrameServer StiSvc PcaSvc MapsBroker BDESVC WpcMonSvc CertPropSvc 
        WdiServiceHost lmhosts WdiSystemHost TrkWks WerSvc TabletInputService EntAppSvc 
        Spooler BcastDVRUserService WMPNetworkSvc diagnosticshub.standardcollector.service 
        DmEnrollmentSvc PNRPAutoReg AXInstSV lfsvc NcbService DeviceAssociationService 
        TieringEngineService DPS Themes AppReadiness HvHost vmickvpexchange vmicguestinterface 
        vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss vmcompute CmService 
        Schedule PimIndexMaintenanceSvc WinHttpAutoProxySvc xbgm wlidsvc DiagTrack DusmSvc 
        Fax SharedAccess SessionEnv MicrosoftEdgeElevationService edgeupdate edgeupdatem autotimesvc 
        CscService TermService SensorDataService SensorService SensrSvc shpamsvc PhoneSvc TapiSrv 
        UevAgentService WalletService TokenBroker WebClient MixedRealityOpenXRSvc Wecsvc XboxGipSvc 
        BackupperService cbdhsvc CDPSvc CDPUserSvc DevQueryBroker DevicesFlowUserSvc dmwappushservice 
        dLauncherLoopback EFS fdPHost FDResPub IKEEXT NPSMSvc WPDBusEnum RasMan SstpSvc 
        ShellHWDetection SSDPSRV SysMain OneSyncSvc UserDataSvc UnistoreSvc Wcmsvc W32Time 
        tzautoupdate DsSvc DevicesFlowUserSvc_5f1ad diagsvc DialogBlockingService 
        MessagingService_5f1ad AppVClient MsKeyboardFilter NetTcpPortSharing ssh-agent wercplsupport 
        WpnUserService_5f1ad
    ) do (
        sc config %%s start=disabled >nul 2>&1
    )
    cls
) else (
    echo Skipping service changes.
    cls
)

@echo off
echo User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes to the operating system.
echo It does this by prompting for permission or an administrator's password before allowing actions that could potentially affect the system's operation or that change settings that affect other users.
echo.

set /p disableUAC="Do you want to disable UAC? [Y/N]: "
if /i "%disableUAC%"=="Y" (
    echo Disabling UAC
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
    cls
) else (
    echo Skipping UAC changes.
    cls
)

:: WIFI

set /p disableWifi="Do you want disable WI-FI Mechanics? [Y/N]: "
if /i "%disableWifi%"=="Y" (
    echo Disabling Wi-Fi Mechanics
    reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f >nul 2>&1
    sc config NlaSvc start= disabled
    sc config LanmanWorkstation start= disabled
    sc config BFE start= demand >nul 2>&1
    sc config Dnscache start= demand >nul 2>&1
    sc config WinHttpAutoProxySvc start= demand >nul 2>&1
    sc config Dhcp start= auto 
    sc config DPS start= auto 
    sc config lmhosts start= disabled
    sc config nsi start= auto
    sc config Wcmsvc start= disabled
    sc config Winmgmt start= auto
    sc config WlanSvc start= demand
    reg add "HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "1" /f
    reg add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f
    schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
    schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
    schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
    schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable >nul 2>&1
    cls
) else (
    echo Skipping.
)
cls

:: Network
set /p disableNotifications="Do you want to disable Notifications? [Y/N]: "
if /i "%disableNotifications%"=="Y" (
    echo Disabling Notifications
    reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
) else (
    echo Skipping notification changes.
)
cls

set /p networkTweaks="Do you want to apply network tweaks? [Y/N]: "
if /i "%networkTweaks%"=="Y" (
    
echo Disabling Teredo / IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 255 /f
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6" >nul 2>&1

) else (
    echo Skipping network tweaks.
)
cls

set /p installApps="Do you want to install personal applications? [Y/N]: "
if /i "%installApps%"=="Y" (
    echo Installing Discord
    winget install --silent --accept-source-agreements --accept-package-agreements Discord.Discord >nul 2>&1

    echo Installing Brave
    winget install --silent --accept-source-agreements --accept-package-agreements Brave.Brave >nul 2>&1

    echo Installing Steam
    winget install --silent --accept-source-agreements --accept-package-agreements Valve.Steam >nul 2>&1

    echo Installing Bloxstrap
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/bloxstraplabs/bloxstrap/releases/latest/download/Bloxstrap.exe' -OutFile '%temp%\Bloxstrap.exe'"
    start /wait "" "%temp%\Bloxstrap.exe" /SILENT

    echo Installing Geforce Experience
    winget install --silent --accept-source-agreements --accept-package-agreements NVIDIA.GeForceExperience >nul 2>&1

    echo Installing NVIDIA App
    winget install --silent --accept-source-agreements --accept-package-agreements NVIDIA.NvContainer >nul 2>&1

    echo Installing MSI Afterburner
    winget install --silent --accept-source-agreements --accept-package-agreements MSI.Afterburner >nul 2>&1
    cls
) else (
    echo Skipping personal application installations.
    cls
)
cls

set /p removeApps="Do you want to remove Microsoft Apps? [Y/N]: "
if /i "%removeApps%"=="Y" (
    echo Removing Microsoft Apps
    powershell -Command "Get-AppxPackage | Where-Object {$_.Publisher -like '*Microsoft*'} | Remove-AppxPackage" >nul 2>&1
) else (
    echo Skipping Microsoft Apps removal.
)
cls

set /p restoreApps="Do you want to restore Microsoft Store and Snipping Tool? [Y/N]: "
if /i "%restoreApps%"=="Y" (
    echo Restoring Microsoft Store and Snipping Tool
    powershell -Command "Get-AppXPackage *WindowsStore* -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\AppXManifest.xml\"}"
    powershell -Command "Get-AppXPackage *ScreenSketch* -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\AppXManifest.xml\"}"
) else (
    echo Skipping restore of Microsoft Store and Snipping Tool.
)
cls

echo Deleting application folders from local packages
for /d %%i in ("%LOCALAPPDATA%\Packages\*") do (
    echo Deleting %%i
    rmdir /s /q "%%i"
)
cls

if exist "HKLM\SOFTWARE\Policies\Microsoft\Edge" (
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /f >nul 2>&1
)

echo Disabling Gamemode
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f
cls

echo Disabling GameDVR
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
cls

:: Explorer
echo Clearing Quick Access and Quick Menu
del /f /q "%APPDATA%\Microsoft\Windows\Recent\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"
cls

echo Show Hidden Files and Folders
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
echo Enabling extended names
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
cls

:: Services
echo Disabling Sysmain
sc config sysmain start=disabled >nul 2>&1
sc stop sysmain >nul 2>&1
cls

echo Disabling Remote Service
sc config RemoteRegistry start= disabled
sc config RemoteAccess start= disabled
sc config WinRM start= disabled
sc config RmSvc start= disabled
cls

echo Disabling Printer Services
sc config PrintNotify start= disabled
sc config Spooler start= disabled
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable 
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable 
cls

echo Disabling Tasks
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


echo Dsiabling Browser Services
for %%s in (
    edgeupdate edgeupdatem GoogleChromeElevationService gupdate
    gupdatem BraveElevationService brave bravem
) do (
    sc config %%s start=disabled >nul 2>&1
)
echo Changing WTK Threshold
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "2000" /f >nul 2>&1
cls

echo Turning off Background Apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f >nul 2>&1
cls

:: Powerplan

setlocal enabledelayedexpansion
set "fileName=Kyles Ultimate Performance.pow"

echo Checking for existing power plans
for /f "tokens=2 delims=:" %%i in ('powercfg -list ^| findstr "Power Scheme GUID"') do (
    set "existingGUID=%%i"
    set "existingGUID=!existingGUID:* =!"
    for /f "delims= " %%j in ("!existingGUID!") do (
        set "cleanGUID=%%j"
        powercfg -query !cleanGUID! | findstr /c:"Quaked" >nul
        if not errorlevel 1 (
            echo Power plan already exists: !cleanGUID!
            goto SetPlan
        )
    )
)

echo Downloading Powerplan
powershell -Command "Invoke-WebRequest -Uri 'https://drive.google.com/uc?export=download&id=1fmVNTSvqH9UtUTiVlUQcaAQz1GCHYUOk' -OutFile '%temp%\%fileName%'"

echo Importing Powerplan
powercfg -import "%temp%\%fileName%"
if errorlevel 1 (
    echo Failed to import power plan.
    pause
    exit /b 1
)

for /f "tokens=2 delims=:" %%i in ('powercfg -list ^| findstr "Power Scheme GUID"') do (
    set "newPowerPlanGUID=%%i"
    set "newPowerPlanGUID=!newPowerPlanGUID:* =!"
    for /f "delims= " %%j in ("!newPowerPlanGUID!") do (
        set "cleanGUID=%%j"
        powercfg -query !cleanGUID! | findstr /c:"Ultimate Performance" >nul
        if not errorlevel 1 (
            echo Found new power plan: !cleanGUID!
            goto SetPlan
        )
    )
)

:SetPlan
echo Setting Powerplan
powercfg -setactive !cleanGUID!
if errorlevel 1 (
    echo Failed to set power plan !cleanGUID!.
    pause
    exit /b 1
)
echo Power plan successfully set to !cleanGUID!.



echo Disabling Hibernation
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
powercfg -h off
cls

echo Disabling C States 
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0 >nul 2>&1
powercfg /setactive SCHEME_CURRENT >nul 2>&1
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0 >nul 2>&1
powercfg /setactive SCHEME_CURRENT >nul 2>&1
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0 >nul 2>&1
powercfg /setactive SCHEME_CURRENT >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >nul 2>&1
powercfg /setactive SCHEME_CURRENT >nul 2>&1
cls

echo Disabling Core Parking
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >nul 2>&1
powercfg /setactive SCHEME_CURRENT >nul 2>&1
cls

echo Disabling Throttling States
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f >nul 2>&1
cls

:: Mouse
echo Disabling Mouse Acceleration
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f
cls

:: Keyboard
echo Disabling StickyKeys
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
cls

:: Storage

echo Removing Storage Sense
powershell -Command "Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
cls

:: Policies
echo Disabling HomeGroup
sc config HomeGroupListener start=demand >nul 2>&1
sc config HomeGroupProvider start=demand >nul 2>&1
cls

:: Features

echo Installing Visual C++ 2015-2022 Redistributable
echo.
:: Check if Visual C++ 2015-2022 Redistributable (x64) is installed
reg query "HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" >nul 2>&1
if %errorlevel% == 0 (
    echo Visual C++ 2015-2022 Redistributable is installed
    timeout 2 >nul
) else (
    echo Visual C++ 2015-2022 Redistributable is not installed
    timeout 2 >nul
)

:: Registries
echo Setting Priority Separation
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000016 /f

echo Changing Timer Resolution
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d 256 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
cls

echo Disabling Suggested Apps in Start Menu
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f

:: Windows Features
echo Disabling Windows Search
sc config WSearch start=disabled >nul 2>&1
sc stop WSearch >nul 2>&1

echo Disabling Windows Update
sc config wuauserv start=disabled >nul 2>&1
sc stop wuauserv >nul 2>&1
cls

:: Taskbar
echo Disabling Transparency Effects
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize /v EnableTransparency /t REG_DWORD /d 0 /f
cls

echo Disabling Taskbar Widgets
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f
cls

:: GPU
echo Toggling Hardware Accelerated GPU Scheduling
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f
cls

:: System

echo Changing Priorities
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

echo Copying System Configuration
powershell -Command "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d 0 /f

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

echo Disabling Location
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f
cls

echo Disabling Activity History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
cls

echo Disabling Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverNonMeteredConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverWifiOnly" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverCellular" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverWifiOnly" /t REG_DWORD /d 0 /f
cls

echo Disabling Windows Defender
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

echo Disabling Windows Update
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AUOptions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
cls

echo Disabling Telemetry
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 400 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 30 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
cls

echo Changing Svc Memory Threshold
for /f %%a in ('powershell -Command "(Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb"') do set "ram_kb=%%a"
powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SvcHostSplitThresholdInKB' -Type DWord -Value %ram_kb% -Force"
cls

echo Remove Autologging DiagTrack
set "autoLoggerDir=%PROGRAMDATA%\Microsoft\Diagnosis\ETLLogs\AutoLogger"
if exist "%autoLoggerDir%\AutoLogger-Diagtrack-Listener.etl" (
    del /q "%autoLoggerDir%\AutoLogger-Diagtrack-Listener.etl" >nul 2>&1
)
icacls "%autoLoggerDir%" /deny SYSTEM:(OI)(CI)F >nul 2>&1
cls

echo Removing Microsoft Edge
taskkill /f /im msedge.exe >nul 2>&1
taskkill /f /im msedge.exe /fi "IMAGENAME eq msedge.exe" >nul 2>&1
taskkill /f /im msedge.exe /fi "IMAGENAME eq msedge.exe" >nul 2>&1
echo Deleting Edge Directories.
rd /s /q "C:\Program Files (x86)\Microsoft\Edge" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeCore" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\EdgeWebView" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Microsoft\Temp" >nul 2>&1
echo Deleting Microsoft Edge Shortcuts.
del "C:\Users\Public\Desktop\Microsoft Edge.lnk" >nul 2>&1
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" >nul 2>&1
del "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" >nul 2>&1
cls

echo Removing OneDrive
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"
echo Removing OneDrive.
winget uninstall --silent --accept-source-agreements Microsoft.OneDrive >nul 2>&1
echo The operation completed successfully.
echo Removing OneDrive Shortcuts.
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >nul 2>&1
reg unload "hku\Default"
del /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" >nul 2>&1
schtasks /delete /tn "OneDrive*" /f >nul 2>&1
cls

echo Removing Widget
taskkill /F /IM WidgetService.exe >nul 2>&1
taskkill /F /IM Widgets.exe >nul 2>&1
echo Uninstalling Windows web experience Pack
winget uninstall --silent --accept-source-agreements "Windows web experience Pack" >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
CD /D "C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_424.1301.450.0_x64__cw5n1h2txyewy\Dashboard" >nul 2>&1
for %%f in (WidgetService.exe Widgets.exe) do (
    if exist "%%f" (
        echo Taking ownership of %%f.
        takeown /F "%%f" >nul 2>&1
        echo Adjusting permissions for %%f.
        icacls "%%f" /grant administrators:F >nul 2>&1
        echo Removing %%f.
        del "%%f" /s /f /q
        echo %%f deleted successfully.
    ) else (
        echo File not found: %%f. >nul 2>&1
    )
)
cls

echo Removing Smartscreen
for %%f in (
    "C:\Windows\System32\smartscreen.exe"
    "C:\Windows\SystemApps\Microsoft.Windows.AppRep.ChxApp_cw5n1h2txyewy\CHXSmartScreen.exe"
) do (
    if exist "%%f" (
        echo Taking ownership of %%f.
        takeown /F "%%f" >nul 2>&1
        echo Adjusting permissions for %%f.
        icacls "%%f" /grant administrators:F >nul 2>&1
        echo Removing %%f.
        del "%%f" /f /q
        echo %%f deleted successfully.
    ) else (
        echo File not found: %%f.
    )
)
cls

echo Removing LockApp
set "lockAppFileToDelete=C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe"
if exist "%lockAppFileToDelete%" (
    takeown /F "%lockAppFileToDelete%" >nul 2>&1
    icacls "%lockAppFileToDelete%" /grant administrators:F >nul 2>&1
    del "%lockAppFileToDelete%" /f /q
    echo LockApp.exe removed.
) else (
    echo LockApp.exe not found.
)
cls

echo Refreshing Explorer
taskkill /f /im explorer.exe & start explorer.exe
cls

set /p restartPC="Would you like to restart your PC? [Y/N]: "
if /i "%restartPC%"=="Y" (
    echo Restarting PC
    shutdown /r /t 0
) else (
    echo Skipping restart.
)

pause
goto menu

:: Cleaner -- Organization
:Cleaner
cls

echo Cleaning up the system

set /p cleanDownloads="Do you want to clean downloads? [Y/N]: "
if /i "%cleanDownloads%"=="Y" (
    echo Cleaning Downloads folder
    del /f /s /q "%USERPROFILE%\Downloads\*"
    rd /s /q "%USERPROFILE%\Downloads"
    md "%USERPROFILE%\Downloads"
) else (
    echo Skipping downloads cleanup.
)
cls

set /p cleanNetwork="Do you want to clean the network? [Y/N]: "
if /i "%cleanNetwork%"=="Y" (
    echo Resetting Winsock
    netsh winsock reset
    cls

    echo Cleaning Network
    ipconfig /release
    ipconfig /renew
    arp -d *
    nbtstat -R
    nbtstat -RR
    ipconfig /flushdns
    ipconfig /registerdns >nul 2>&1

) else (
    echo Skipping network cleaning.
)
cls

echo Detecting and cleaning cache files...

for /d %%D in ("%LocalAppData%\*") do (
    if exist "%%D\Cache" (
        echo Found cache in: %%D\Cache
        del /s /q "%%D\Cache\*.*" 2>nul
    )
    if exist "%%D\Code Cache" (
        echo Found code cache in: %%D\Code Cache  
        del /s /q "%%D\Code Cache\*.*" 2>nul
    )
    if exist "%%D\GPUCache" (
        echo Found GPU cache in: %%D\GPUCache
        del /s /q "%%D\GPUCache\*.*" 2>nul
    )
)

for /d %%D in ("%AppData%\*") do (
    if exist "%%D\Cache" (
        echo Found cache in: %%D\Cache
        del /s /q "%%D\Cache\*.*" 2>nul
    )
    if exist "%%D\Code Cache" (
        echo Found code cache in: %%D\Code Cache
        del /s /q "%%D\Code Cache\*.*" 2>nul
    )
)

del "%LocalAppData%\Microsoft\Windows\INetCache\." /s /f /q
del "%AppData%\Local\Microsoft\Windows\INetCookies\." /s /f /q
del "%temp%" /s /f /q
del "%AppData%\Discord\Cache\." /s /f /q >nul 2>&1
del "%AppData%\Discord\Code Cache\." /s /f /q >nul 2>&1
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
del "C:\Windows\System32\SleepStudy" /s /f /q
del "%SystemRoot%\*.log" /s /f /q
del "%SystemRoot%\Debug\*.log" /s /f /q
del "%SystemRoot%\security\logs\*.log" /s /f /q
del "%SystemRoot%\Logs\CBS\*.log" /s /f /q
del "%SystemRoot%\Logs\DISM\*.log" /s /f /q
del "%SystemRoot%\minidump\*.dmp" /s /f /q
del "%LocalAppData%\Microsoft\Windows\Explorer\*.db" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache\*" /s /f /q
del "%LocalAppData%\Google\Chrome\User Data\Default\Cache\*" /s /f /q
del "%LocalAppData%\BraveSoftware\Brave-Browser\User Data\Default\Cache\*" /s /f /q
del "%LocalAppData%\Opera Software\Opera GX Stable\Cache\*" /s /f /q
del "%AppData%\Microsoft\Teams\Cache\*" /s /f /q
del "%LocalAppData%\Microsoft\Windows\Notifications\*" /s /f /q
del "%LocalAppData%\Microsoft\Windows\Explorer\ThumbCacheToDelete\*" /s /f /q
del "%LocalAppData%\Microsoft\Windows\Explorer\IconCacheToDelete\*" /s /f /q

rmdir /S /Q "%AppData%\Local\Microsoft\Windows\INetCache\"
rmdir /S /Q "%AppData%\Local\Microsoft\Windows\INetCookies"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\WebCache"
rmdir /S /Q "%AppData%\Local\Temp\"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\WER"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\History"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\INetCache\IE"
rmdir /S /Q "%LocalAppData%\Microsoft\Terminal Server Client\Cache"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\Explorer\IconCache"
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\Explorer\ThumbCache"
rd "%AppData%\Discord\Cache" /s /q >nul 2>&1
rd "%AppData%\Discord\Code Cache" /s /q >nul 2>&1
rd "%SystemDrive%\$GetCurrent" /s /q
rd "%SystemDrive%\$SysReset" /s /q
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q
rd "%SystemDrive%\$WinREAgent" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q

del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
del "%WINDIR%\System32\LogFiles" /s /f /q
del /f /s /q "%SystemDrive%\*.tmp"
del /f /s /q "%SystemDrive%\*._mp"
del /f /s /q "%SystemDrive%\*.log"
del /f /s /q "%SystemDrive%\*.gid"
del /f /s /q "%SystemDrive%\*.chk"
del /f /s /q "%SystemDrive%\*.old"

rd /s /q %LocalAppData%\Temp
rd /s /q %LocalAppData%\Temp\mozilla-temp-files
rd /s /q "%SystemRoot%\System32\SleepStudy"
rd /s /q "%SystemRoot%\System32\SleepStudy >nul 2>&1"

Del /S /F /Q %temp%
Del /S /F /Q %Windir%\Temp
Del /S /F /Q C:\WINDOWS\Prefetch

wsreset.exe -i >nul 2>&1

net stop FontCache >nul 2>&1
del /f /s /q "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*" >nul 2>&1
net start FontCache >nul 2>&1

del /f /s /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db" >nul 2>&1
cls

echo Running Disk Cleanup
cleanmgr /sageset:1 >nul 2>&1
cls

echo Resetting TCP Stack
netsh int ip reset resetlog.txt
cls

echo Compacting OS
compact /compactos:always >nul 2>&1

set /a difference=newsize-oldsize
echo The disk size has changed by %difference% bytes.
timeout /t 3 /nobreak >nul
cls

echo Repairing System Files
sfc /scannow

echo Clearing Quick Access and Quick Menu
echo Removing Quick Access items
del /f /q "%APPDATA%\Microsoft\Windows\Recent\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"

echo Removing Quick Menu items
del /f /q "%APPDATA%\Microsoft\Windows\Recent\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"
cls

echo Removing pinned items from Start Menu
$path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
Remove-Item "$path\*.lnk" -Force
cls

echo Finished
pause
goto menu

:: Fixer
:Fixer
for %%s in (BluetoothUserService_dc2a4 BthAvctpSvc BthHFSrv bthserv WlanSvc WFDSConMgrSvc) do (
    echo Setting %%s to automatic startup
    sc config "%%s" start=auto
    echo Starting %%s
    net start "%%s" >nul 2>&1
)

:: Restore
:Restore
echo Restoring services to default configuration

for %%s in (
    AxInstSV SensrSvc AarSvc AJrouter AppReadiness AeLookupSvc AppIDSvc 
    Appinfo ALG AppMgmt AppXSCV tzautoupdate BthAvctpSvc BDESVC wbengine
    BTAGService bthserv BluetoothUserService_562a9 PeerDistSvc camsvc
    CaptureService autotimesvc CertPropSvc ClipSVC cbdhsvc KeyIso Browser
    ConsentUxUserSvc PimIndexMaintenanceSvc VaultSvc CredentialEnrollmentManagerUserSvc
    DsSvc DeviceAssociationService DeviceInstall DmEnrollmentSvc dmwappushservice
    DsmSvc DeviceAssociationBrokerSvc DevicePickerUserSvc DevicesFlowUserSvc
    DevQueryBroker diagsvc WdiServiceHost WdiSystemHost DisplayEnhancementService
    defragsvc EasyAntiCheat embeddedmode EFS EntAppSvc EapHost Fax fhsvc fdPHost
    BcastDVRUserService lfsvc GoogleChromeElevationService gupdatem GraphicsPerfSvc
    hkmsvc HomeGroupListener HomeGroupProvider hidserv HvHost UI0Detect SharedAccess
    ipxlatCfgSvc PolicyAgent KtmRm LxpSvc lltdsvc wlpasvc MessagingService wlidsvc
    WdNisSvc diagnosticshub.standardcollector.service MicrosoftEdgeElevationService
    MSiSCSI NgcSvc NgcCtnrSvc swprv smphost InstallService SmsRouter
    NaturalAuthentication Netlogon napagent NcdAutoSetup NcbService Netman NcaSvc
    netprofm NetSetupSvc CscService wwansvc ndiskd NetworkListSvc COMSysApp CryptSvc edgeupdatem
) do (
    sc config %%s start= demand
    echo Configured %%s to Manual start
)

for %%s in (
    BITS BrokerInfrastructure BFE BcastDVRUserService EventSystem CDPSvc
    CDPUserSvc DiagTrack CoreMessagingRegistrar DcomLaunch DoSvc UxSms
    Dhcp DPS DispBrokerDesktopSvc TrkWks Dnscache MapsBroker FDResPub
    gupdate gpsvc IKEEXT RstMwService iphlpsvc LSM MDM WinDefend
    edgeupdate MMCSS NlaSvc nsi
) do (
    sc config %%s start= auto
    net start %%s >nul 2>&1
    echo Configured and started %%s
)

for %%s in (
    Mcx2Svc NetTcpPortSharing ssh-agent
) do (
    sc config %%s start= disabled
    echo Configured %%s to Disabled
)


echo Services have been restored to default configuration.
pause
goto menu

:exit
exit /B
