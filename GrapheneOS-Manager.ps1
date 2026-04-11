# ============================================================================
# COMPREHENSIVE ADB POWERSHELL SCRIPT FOR GRAPHENEOS & ANDROID HARDENING
# ============================================================================
# Save as: GrapheneOS-Manager.ps1
# Usage: .\GrapheneOS-Manager.ps1
# ============================================================================

param(
    [string]$Action = "menu",
    [string]$PackageName,
    [string]$APKPath,
    [string]$BackupPath = "$env:USERPROFILE\Desktop\adb-backup",
    [string]$OutputFile = "permission-audit.txt",
    [switch]$Full
)

# ============================================================================
# CORE ADB FUNCTIONS
# ============================================================================

function Test-ADBConnection {
    $devices = adb devices | Select-Object -Skip 1 | Where-Object { $_ -match "\s+device$" }
    if ($devices) {
        Write-Host "✓ ADB device(s) connected:" -ForegroundColor Green
        $devices | ForEach-Object { Write-Host "  - $_" }
        return $true
    } else {
        Write-Host "✗ No ADB devices connected" -ForegroundColor Red
        return $false
    }
}

function Invoke-ADB {
    param([string]$Command)
    $output = adb shell $Command 2>&1
    return $output
}

function Get-DeviceInfo {
    param([string]$Property)
    adb shell getprop $Property
}

function Wait-ForDevice {
    Write-Host "Waiting for device..."
    adb wait-for-device
    Write-Host "✓ Device connected" -ForegroundColor Green
}

function Install-App {
    param([string]$APKPath)
    if (-not (Test-Path $APKPath)) {
        Write-Host "✗ APK not found: $APKPath" -ForegroundColor Red
        return
    }
    Write-Host "Installing: $(Split-Path $APKPath -Leaf)"
    adb install -r $APKPath
}

function Uninstall-App {
    param([string]$PackageName)
    Write-Host "Uninstalling: $PackageName"
    adb uninstall $PackageName
}

function Get-InstalledApps {
    param([switch]$SystemApps, [switch]$UserApps)
    
    $filter = ""
    if ($SystemApps) { $filter = "-s" }
    if ($UserApps) { $filter = "-3" }
    
    adb shell pm list packages $filter | ForEach-Object { $_ -replace "^package:", "" }
}

function Push-File {
    param([string]$LocalPath, [string]$DevicePath)
    adb push $LocalPath $DevicePath
}

function Pull-File {
    param([string]$DevicePath, [string]$LocalPath)
    adb pull $DevicePath $LocalPath
}

function Reboot-Device {
    param([string]$Mode = "")
    if ($Mode) {
        adb reboot $Mode
    } else {
        adb reboot
    }
    Write-Host "Rebooting device..."
}

# ============================================================================
# PERMISSION AUDIT FUNCTION
# ============================================================================

function Audit-Permissions {
    param(
        [string]$OutputFile = "permission-audit.txt",
        [switch]$Restrictive
    )
    
    if (-not (Test-ADBConnection)) { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $report = @("Permission Audit Report - $timestamp", "=" * 50, "")
    
    $dangerousPermissions = @(
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALENDAR",
        "android.permission.READ_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.GET_ACCOUNTS"
    )
    
    $userApps = Get-InstalledApps -UserApps
    
    Write-Host "Scanning $($userApps.Count) user apps for dangerous permissions..." -ForegroundColor Cyan
    
    foreach ($app in $userApps) {
        $permissions = adb shell dumpsys package $app | Select-String "android.permission\." | ForEach-Object {
            [regex]::Matches($_, "android\.permission\.\w+") | ForEach-Object { $_.Value }
        } | Sort-Object -Unique
        
        $dangerous = $permissions | Where-Object { $_ -in $dangerousPermissions }
        
        if ($dangerous) {
            $report += "$app:"
            $dangerous | ForEach-Object {
                $report += "  ⚠ $_"
            }
            $report += ""
        }
    }
    
    $report | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "✓ Report saved to: $OutputFile" -ForegroundColor Green
}

# ============================================================================
# HARDENING FUNCTION
# ============================================================================

function Harden-Device {
    if (-not (Test-ADBConnection)) { return }
    
    Write-Host "`nGrapheneOS Device Hardening Script" -ForegroundColor Cyan
    Write-Host "=" * 50
    
    $appsToRemove = @(
        "com.google.android.apps.maps",
        "com.google.android.apps.photos",
        "com.android.chrome",
        "com.facebook.katana",
        "com.instagram.android"
    )
    
    $confirm = Read-Host "`nRemove bloatware apps? (y/n)"
    if ($confirm -eq 'y') {
        foreach ($app in $appsToRemove) {
            $installed = adb shell pm list packages | Select-String $app
            if ($installed) {
                Write-Host "Removing: $app"
                adb shell pm uninstall --user 0 $app 2>&1 | Out-Null
            }
        }
    }
    
    Write-Host "`nDisabling unnecessary services..." -ForegroundColor Yellow
    
    $servicesToDisable = @(
        "com.google.android.gms/.location.LocationManagerService"
    )
    
    foreach ($service in $servicesToDisable) {
        Write-Host "Disabling: $service"
        adb shell pm disable-user --user 0 $service 2>&1 | Out-Null
    }
    
    Write-Host "`nConfiguring security settings..." -ForegroundColor Yellow
    adb shell settings put secure adb_enabled 1
    adb shell settings put secure lock_screen_owner_info "Hardened Device"
    
    Write-Host "`n✓ Hardening complete!" -ForegroundColor Green
    Write-Host "⚠ Remember to enable 'Restricted USB' in Settings > Developer options" -ForegroundColor Yellow
}

# ============================================================================
# BACKUP FUNCTION
# ============================================================================

function Backup-Device {
    param(
        [string]$BackupPath = "$env:USERPROFILE\Desktop\adb-backup",
        [switch]$Full
    )
    
    if (-not (Test-ADBConnection)) { return }
    
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = Join-Path $BackupPath "backup-$timestamp"
    New-Item -ItemType Directory -Path $backupDir | Out-Null
    
    Write-Host "`nCreating backup in: $backupDir" -ForegroundColor Cyan
    
    Write-Host "Backing up device information..."
    adb shell getprop > "$backupDir\device-props.txt"
    adb shell settings list global > "$backupDir\settings-global.txt"
    adb shell settings list secure > "$backupDir\settings-secure.txt"
    adb shell pm list packages > "$backupDir\installed-apps.txt"
    
    if ($Full) {
        Write-Host "Creating full backup (this may take a while)..." -ForegroundColor Yellow
        adb backup -apk -shared -all -f "$backupDir\full-backup.adb"
        Write-Host "⚠ Set backup password on device when prompted" -ForegroundColor Yellow
    }
    
    Write-Host "Backing up photos/documents..."
    $localDirs = @(
        "/sdcard/DCIM",
        "/sdcard/Documents",
        "/sdcard/Downloads"
    )
    
    foreach ($dir in $localDirs) {
        $exists = adb shell test -d $dir 2>&1
        if ($exists -eq "") {
            $localName = $dir -replace "/sdcard/", ""
            Write-Host "  Pulling: $localName"
            adb pull $dir "$backupDir\$localName" 2>&1 | Out-Null
        }
    }
    
    Write-Host "`n✓ Backup complete: $backupDir" -ForegroundColor Green
}

# ============================================================================
# DIAGNOSTICS FUNCTION
# ============================================================================

function Diagnose-Security {
    if (-not (Test-ADBConnection)) { return }
    
    Write-Host "`nGrapheneOS Security Diagnostics" -ForegroundColor Cyan
    Write-Host "=" * 50
    
    Write-Host "`n[Encryption Status]"
    $encStatus = adb shell getprop ro.crypto.state
    Write-Host "Encryption: $encStatus"
    
    Write-Host "`n[SELinux Policy]"
    $selinux = adb shell getenforce
    Write-Host "SELinux Mode: $selinux"
    
    Write-Host "`n[Verified Boot]"
    $vb = adb shell getprop ro.boot.verifiedbootstate
    Write-Host "Verified Boot: $vb"
    
    Write-Host "`n[ADB Configuration]"
    $adbNetworkEnabled = adb shell settings get global adb_wifi_enabled
    Write-Host "ADB over network: $adbNetworkEnabled (should be 0)"
    
    Write-Host "`n[Security Apps Installed]"
    $securityApps = @(
        "org.signal",
        "org.wireguard.android",
        "com.bitwarden",
        "com.nextcloud.client"
    )
    
    foreach ($app in $securityApps) {
        $installed = adb shell pm list packages | Select-String "^package:$app"
        if ($installed) {
            Write-Host "✓ $app"
        } else {
            Write-Host "✗ $app (not installed)"
        }
    }
    
    Write-Host "`n[Network Test]"
    $ping = adb shell ping -c 1 8.8.8.8 2>&1 | Select-String "time="
    if ($ping) {
        Write-Host "✓ Network connectivity: OK"
    } else {
        Write-Host "✗ Network connectivity: Check connection"
    }
    
    Write-Host "`n[Device Info]"
    $model = adb shell getprop ro.product.model
    $android = adb shell getprop ro.build.version.release
    $graphene = adb shell getprop ro.build.fingerprint
    
    Write-Host "Model: $model"
    Write-Host "Android: $android"
    Write-Host "Build: $graphene"
    
    Write-Host "`n✓ Diagnostics complete" -ForegroundColor Green
}

# ============================================================================
# APP MANAGEMENT FUNCTION
# ============================================================================

function Manage-Apps {
    param(
        [string]$Action = "list",
        [string]$PackageName,
        [string]$APKPath
    )
    
    if (-not (Test-ADBConnection)) { return }
    
    switch ($Action.ToLower()) {
        "list" {
            Write-Host "`nUser-installed apps:" -ForegroundColor Cyan
            Get-InstalledApps -UserApps | ForEach-Object { Write-Host "  $_" }
        }
        
        "list-system" {
            Write-Host "`nSystem apps:" -ForegroundColor Cyan
            Get-InstalledApps -SystemApps | ForEach-Object { Write-Host "  $_" }
        }
        
        "info" {
            if (-not $PackageName) { 
                Write-Host "Specify -PackageName"; 
                return 
            }
            Write-Host "`nApp Info: $PackageName" -ForegroundColor Cyan
            adb shell dumpsys package $PackageName | Select-String "User|permission|install"
        }
        
        "disable" {
            if (-not $PackageName) { 
                Write-Host "Specify -PackageName"; 
                return 
            }
            Write-Host "Disabling: $PackageName"
            adb shell pm disable-user --user 0 $PackageName
            Write-Host "✓ Disabled" -ForegroundColor Green
        }
        
        "enable" {
            if (-not $PackageName) { 
                Write-Host "Specify -PackageName"; 
                return 
            }
            Write-Host "Enabling: $PackageName"
            adb shell pm enable $PackageName
            Write-Host "✓ Enabled" -ForegroundColor Green
        }
        
        "uninstall" {
            if (-not $PackageName) { 
                Write-Host "Specify -PackageName"; 
                return 
            }
            $confirm = Read-Host "Uninstall $PackageName ? (y/n)"
            if ($confirm -eq 'y') {
                Uninstall-App -PackageName $PackageName
                Write-Host "✓ Uninstalled" -ForegroundColor Green
            }
        }
        
        "install" {
            if (-not $APKPath) { 
                Write-Host "Specify -APKPath"; 
                return 
            }
            Install-App -APKPath $APKPath
        }
        
        default {
            Write-Host "Invalid action: $Action"
        }
    }
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

function Show-Menu {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     GrapheneOS ADB Management Tool v1.0                    ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-ADBConnection)) {
        Write-Host "⚠ WARNING: No ADB device connected" -ForegroundColor Yellow
        Write-Host ""
    }
    
    Write-Host "MAIN MENU:" -ForegroundColor Yellow
    Write-Host "  1. Device Connection Status"
    Write-Host "  2. Device Diagnostics"
    Write-Host "  3. List All Apps"
    Write-Host "  4. List User Apps"
    Write-Host "  5. List System Apps"
    Write-Host "  6. App Info"
    Write-Host "  7. Disable App"
    Write-Host "  8. Enable App"
    Write-Host "  9. Uninstall App"
    Write-Host "  10. Install APK"
    Write-Host ""
    Write-Host "SECURITY & HARDENING:" -ForegroundColor Yellow
    Write-Host "  11. Audit Permissions"
    Write-Host "  12. Harden Device"
    Write-Host "  13. Backup Device (Standard)"
    Write-Host "  14. Backup Device (Full)"
    Write-Host ""
    Write-Host "SYSTEM OPERATIONS:" -ForegroundColor Yellow
    Write-Host "  15. Reboot Device"
    Write-Host "  16. Reboot to Bootloader"
    Write-Host "  17. Pull File from Device"
    Write-Host "  18. Push File to Device"
    Write-Host ""
    Write-Host "  0. Exit"
    Write-Host ""
}

function Interactive-Menu {
    do {
        Show-Menu
        $choice = Read-Host "Select an option (0-18)"
        
        switch ($choice) {
            "1" {
                Clear-Host
                Test-ADBConnection
                Read-Host "`nPress Enter to continue"
            }
            
            "2" {
                Clear-Host
                Diagnose-Security
                Read-Host "`nPress Enter to continue"
            }
            
            "3" {
                Clear-Host
                Write-
                
