function Write-Log {
    param (
        [string]$message
    )
    Write-Output $message
}

Write-Log "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe" -ErrorAction SilentlyContinue
taskkill.exe /F /IM "explorer.exe" -ErrorAction SilentlyContinue

Write-Log "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Log "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"

if (Test-Path "$env:userprofile\OneDrive" -and (Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Log "Disable OneDrive via Group Policies"
if (-not (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive")) {
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1

Write-Log "Remove OneDrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR" -ErrorAction SilentlyContinue
if (-not (Test-Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}")) {
    New-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force
}
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
if (-not (Test-Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}")) {
    New-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force
}
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
Remove-PSDrive "HKCR" -ErrorAction SilentlyContinue

Write-Log "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT" -ErrorAction SilentlyContinue
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f -ErrorAction SilentlyContinue
reg unload "hku\Default" -ErrorAction SilentlyContinue

Write-Log "Removing start menu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Log "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Log "Removing OneDrive from startup for all users"
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Where-Object { $_.Name -like "*OneDrive*" } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Where-Object { $_.Name -like "*OneDrive*" } | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Log "Removing OneDrive context menu entries"
Remove-Item -Force -ErrorAction SilentlyContinue "HKCR\*\shellex\ContextMenuHandlers\OneDrive"
Remove-Item -Force -ErrorAction SilentlyContinue "HKCR\Directory\shellex\ContextMenuHandlers\OneDrive"
Remove-Item -Force -ErrorAction SilentlyContinue "HKCR\Drive\shellex\ContextMenuHandlers\OneDrive"
Remove-Item -Force -ErrorAction SilentlyContinue "HKCR\LibraryFolder\background\shellex\ContextMenuHandlers\OneDrive"

Write-Log "Restarting explorer"
Start-Process "explorer.exe"

Write-Log "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Log "OneDrive removal process completed"
