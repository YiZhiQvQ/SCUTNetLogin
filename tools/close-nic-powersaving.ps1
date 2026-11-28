# SCUTNetLogin - 关闭网卡省电特性（需管理员）
#
# 为什么需要：Realtek 网卡的 Power Saving Mode / Green Ethernet / EEE 会在链路
# 空闲时进入低功耗、关断部分收发通路。Npcap 是内核级过滤驱动，两者冲突时
# pcap_activate 会永久阻塞在内核态，导致程序无法被终止（任务管理器也结束不掉），
# 只能重启系统。关闭这些特性可从根本上避免该类卡死。
#
# 用法：右键「以管理员身份运行 PowerShell」，然后执行：
#   powershell -ExecutionPolicy Bypass -File close-nic-powersaving.ps1

$ErrorActionPreference = "Continue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[错误] 需要管理员权限。请右键以管理员身份运行 PowerShell 后重试。" -ForegroundColor Red
    exit 1
}

$targets = @(
    "Power Saving Mode",
    "Green Ethernet",
    "Advanced EEE",
    "Energy Efficient Ethernet",
    "Power Down PLL"
)

$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne "Not Present" }
if (-not $adapters) { Write-Host "[提示] 未找到物理网卡"; exit 0 }

foreach ($ad in $adapters) {
    Write-Host ""
    Write-Host ("=== " + $ad.Name + " (" + $ad.InterfaceDescription + ") ===") -ForegroundColor Cyan
    $props = Get-NetAdapterAdvancedProperty -Name $ad.Name -ErrorAction SilentlyContinue
    $changed = $false
    foreach ($t in $targets) {
        $p = $props | Where-Object { $_.DisplayName -eq $t }
        if (-not $p) { continue }
        $cur = $p.DisplayValue
        if ($cur -eq "Disabled") { Write-Host ("  " + $t + " : 已是 Disabled"); continue }
        try {
            Set-NetAdapterAdvancedProperty -Name $ad.Name -DisplayName $t -DisplayValue "Disabled" -NoRestart -ErrorAction Stop
            Write-Host ("  " + $t + " : " + $cur + " -> Disabled  [已修改]") -ForegroundColor Green
            $changed = $true
        } catch {
            Write-Host ("  " + $t + " : 修改失败 - " + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
    if (-not $changed) { Write-Host "  （无需修改）" }
}

Write-Host ""
Write-Host "完成。部分设置需重启网卡或重启系统后生效。" -ForegroundColor Green
Write-Host "立即生效可执行： Disable-NetAdapter -Name 网卡名 -Confirm:0 ; Enable-NetAdapter -Name 网卡名 -Confirm:0"