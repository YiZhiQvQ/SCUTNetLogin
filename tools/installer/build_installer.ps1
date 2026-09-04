# ============================================================================
# SCUTNetLogin installer build script
# Usage:  powershell -File tools\installer\build_installer.ps1
# Output: release\SCUTNetLogin-Setup.exe
#   - self-contained installer (C# WinForms, compiled with csc)
#   - payload: app exe + Qt runtime (manual list) + MSVC runtime DLLs + qt.conf
#   - payload embedded into installer as zip resource
# NOTE: keep this file pure ASCII. Windows PowerShell 5.1 reads UTF-8 no-BOM as
#       ANSI and mangles non-ASCII characters (a Chinese comment inside a code
#       line can silently eat the following array entry).
# ============================================================================

$ErrorActionPreference = 'Stop'

# repo root: this script lives in <root>\tools\installer
$root        = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildDir    = Join-Path $PSScriptRoot 'build'
$stage       = Join-Path $buildDir 'stage'
$payloadZip  = Join-Path $buildDir 'installer_payload.zip'
$setupExe    = Join-Path $root 'release\SCUTNetLogin-Setup.exe'
$appExe      = Join-Path $root 'release\SCUTNetLogin.exe'
$csc         = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

if (-not (Test-Path $appExe)) { throw "not found: $appExe (build Release x64 first)." }

# ---- 1. staging dir ----
if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# ---- 2. app exe + Qt runtime (manual collection; windeployqt needs a child
#         process with piped stdio, which is blocked in sandboxed shells) ----
$qt = 'C:\Qt\6.11.0\msvc2022_64'
Copy-Item $appExe -Destination $stage

# verify: release\SCUTNetLogin.exe imports Qt6Core/Gui/Widgets/Network only;
# the svg image-format plugin (qsvg.dll) additionally needs Qt6Svg.dll,
# which is required to render check.svg from the stylesheet.
$copyList = @(
    @("$qt\bin\Qt6Core.dll",                 ''),
    @("$qt\bin\Qt6Gui.dll",                  ''),
    @("$qt\bin\Qt6Widgets.dll",              ''),
    @("$qt\bin\Qt6Network.dll",              ''),
    @("$qt\bin\Qt6Svg.dll",                  ''),
    @("$qt\plugins\platforms\qwindows.dll",  'plugins\platforms'),
    @("$qt\plugins\styles\qmodernwindowsstyle.dll", 'plugins\styles'),
    @("$qt\plugins\imageformats\qico.dll",   'plugins\imageformats'),
    @("$qt\plugins\imageformats\qjpeg.dll",  'plugins\imageformats'),
    @("$qt\plugins\imageformats\qsvg.dll",   'plugins\imageformats'),
    @("$qt\plugins\iconengines\qsvgicon.dll",'plugins\iconengines'),
    @("$qt\plugins\networkinformation\qnetworklistmanager.dll", 'plugins\networkinformation')
)
foreach ($item in $copyList) {
    $src = $item[0]; $rel = $item[1]
    if (-not (Test-Path $src)) { Write-Warning "missing: $src" ; continue }
    $dstDir = if ($rel -eq '') { $stage } else { Join-Path $stage $rel }
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    Copy-Item $src -Destination (Join-Path $dstDir (Split-Path $src -Leaf))
}

# qt.conf: explicit plugin location for deployed mode (Prefix=. relative to
# the executable directory; plugins are under <app>\plugins). Without it, Qt
# infers paths from the build machine location of Qt6Core.dll.
[System.IO.File]::WriteAllText(
    (Join-Path $stage 'qt.conf'),
    "[Paths]`r`nPrefix=.`r`nPlugins=plugins`r`n",
    (New-Object System.Text.UTF8Encoding($false)))

# ---- 3. MSVC runtime (app is /MD release; target may lack VC++ 2015-2022 redist) ----
$sys = "$env:SystemRoot\System32"
foreach ($dll in 'vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll') {
    $src = Join-Path $sys $dll
    if (Test-Path $src) { Copy-Item $src -Destination $stage }
    else { Write-Warning "not found: $dll (target machine will need VC++ runtime)" }
}

Write-Host "=== payload ==="
Get-ChildItem $stage -Recurse | ForEach-Object { $_.FullName.Substring($stage.Length + 1) }

# ---- 4. pack payload ----
Remove-Item $payloadZip -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $payloadZip -CompressionLevel Optimal -Force
Write-Host "payload size: $((Get-Item $payloadZip).Length) bytes"

# ---- 5. compile installer (payload zip + icon + admin manifest embedded) ----
& $csc /nologo /target:winexe /platform:x64 /optimize+ `
    /out:$setupExe `
    /win32icon:"$root\res\SCUTnetwork.ico" `
    /win32manifest:"$PSScriptRoot\Installer.manifest" `
    /resource:$payloadZip `
    /r:System.Windows.Forms.dll /r:System.Drawing.dll `
    /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll `
    "$PSScriptRoot\Installer.cs"
if ($LASTEXITCODE -ne 0) { throw "csc failed (exit $LASTEXITCODE)" }

# ---- 6. verify ----
if (-not (Test-Path $setupExe)) { throw "setup not generated: $setupExe" }
Write-Host ""
Write-Host "OK: $setupExe ($((Get-Item $setupExe).Length) bytes)"
