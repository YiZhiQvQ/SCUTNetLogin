# SCUTNetLogin - Disable NIC power-saving features (requires Administrator)
#
# WHY: Realtek/Intel NICs have Power Saving Mode / Green Ethernet / EEE /
# Gigabit Lite / Power Down PLL. When enabled, the NIC drops parts of its
# RX/TX path when the link is idle. Npcap is a kernel-level filter driver;
# the conflict can make pcap_activate block FOREVER in kernel mode. A thread
# stuck in the kernel cannot be terminated, so the process cannot be killed
# (Task Manager does nothing) and only a reboot clears it.
#
# USAGE (right-click PowerShell -> Run as administrator):
#   powershell -ExecutionPolicy Bypass -File close-nic-powersaving.ps1
#
# NOTE: keep this file PURE ASCII. Windows PowerShell 5.1 reads BOM-less files
# as ANSI (GBK on zh-CN), so non-ASCII bytes break the parser and can silently
# swallow quotes/braces after them.

$ErrorActionPreference = "Continue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Administrator rights required." -ForegroundColor Red
    Write-Host "        Right-click PowerShell -> Run as administrator, then retry." -ForegroundColor Red
    exit 1
}

# Display names vary by driver, so match several spellings.
$targets = @(
    "Power Saving Mode",
    "Green Ethernet",
    "Advanced EEE",
    "Energy-Efficient Ethernet",
    "Energy Efficient Ethernet",
    "Gigabit Lite",
    "Power Down PLL"
)

$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne "Not Present" }
if (-not $adapters) {
    Write-Host "[INFO] No physical NIC found."
    exit 0
}

$totalChanged = 0

foreach ($ad in $adapters) {
    Write-Host ""
    Write-Host ("=== " + $ad.Name + " (" + $ad.InterfaceDescription + ") ===") -ForegroundColor Cyan
    $props = Get-NetAdapterAdvancedProperty -Name $ad.Name -ErrorAction SilentlyContinue
    if (-not $props) {
        Write-Host "  [SKIP] No advanced properties readable." -ForegroundColor DarkGray
        continue
    }
    foreach ($t in $targets) {
        $p = $props | Where-Object { $_.DisplayName -eq $t }
        if (-not $p) { continue }
        $cur = [string]$p.DisplayValue
        if ($cur -eq "Disabled") {
            Write-Host ("  " + $t + " : already Disabled") -ForegroundColor DarkGray
            continue
        }
        $valid = $p.ValidDisplayValues
        if ($valid -and ($valid -notcontains "Disabled")) {
            Write-Host ("  " + $t + " : cannot disable (valid: " + ($valid -join ", ") + ")") -ForegroundColor DarkGray
            continue
        }
        try {
            Set-NetAdapterAdvancedProperty -Name $ad.Name -DisplayName $t -DisplayValue "Disabled" -NoRestart -ErrorAction Stop
            Write-Host ("  " + $t + " : " + $cur + " -> Disabled   [CHANGED]") -ForegroundColor Green
            $totalChanged = $totalChanged + 1
        } catch {
            Write-Host ("  " + $t + " : FAILED - " + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

Write-Host ""
if ($totalChanged -eq 0) {
    Write-Host "Nothing to change. All listed power-saving features are already disabled." -ForegroundColor Green
} else {
    Write-Host ("Done. " + $totalChanged + " setting(s) changed.") -ForegroundColor Green
    Write-Host "Some settings need a NIC restart or a system reboot to take effect."
    Write-Host "To apply now (replace NIC name as needed):"
    Write-Host "  Restart-NetAdapter -Name ""Ethernet"""
}

Write-Host ""
Write-Host "=== Verification ===" -ForegroundColor Cyan
foreach ($ad in $adapters) {
    $props = Get-NetAdapterAdvancedProperty -Name $ad.Name -ErrorAction SilentlyContinue
    $left = @($props | Where-Object {
        $targets -contains $_.DisplayName -and [string]$_.DisplayValue -ne "Disabled"
    })
    if ($left.Count -eq 0) {
        Write-Host ("  " + $ad.Name + " : OK (all disabled)") -ForegroundColor Green
    } else {
        foreach ($l in $left) {
            Write-Host ("  " + $ad.Name + " : " + $l.DisplayName + " = " + $l.DisplayValue + "  [STILL ON]") -ForegroundColor Yellow
        }
    }
}