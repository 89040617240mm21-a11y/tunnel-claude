# Сборка «Мост» из профиля: powershell -ExecutionPolicy Bypass -File build.ps1 [-Ini profile.ini]
# Берёт profile.ini + enroll_key, подставляет {{...}} в копии ps1 (папка obj\) и собирает TunnelClaude.exe.
param([string]$Ini = 'profile.ini', [string]$Out = 'TunnelClaude.exe')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path $Ini)) { throw "Нет $Ini — скопируйте profile.example.ini в profile.ini и впишите свои данные" }

# --- читаем ini: секция -> список (ключ, значение)
$sec = [ordered]@{}; $cur = 'main'
foreach ($ln in [IO.File]::ReadAllLines((Resolve-Path $Ini), [Text.Encoding]::UTF8)) {
    $t = $ln.Trim()
    if ($t -eq '' -or $t.StartsWith(';') -or $t.StartsWith('#')) { continue }
    if ($t -match '^\[(.+)\]$') { $cur = $Matches[1]; if (-not $sec.Contains($cur)) { $sec[$cur] = @() }; continue }
    $i = $t.IndexOf('='); if ($i -lt 1) { continue }
    if (-not $sec.Contains($cur)) { $sec[$cur] = @() }
    $sec[$cur] += ,@($t.Substring(0, $i).Trim(), $t.Substring($i + 1).Trim())
}
function Get1($s, $k, $def = '') { foreach ($p in $sec[$s]) { if ($p[0] -eq $k) { return $p[1] } }; return $def }
function M($k, $def = '') { Get1 'main' $k $def }
function Q($v) { $v -replace "'", "''" }   # строка внутри '...' в PowerShell

$keyFile = M 'enroll_key_file' 'enroll_key'
if (-not (Test-Path $keyFile)) { throw "Нет файла ключа регистрации $keyFile (см. server\README.md)" }
$enrollKey = ([IO.File]::ReadAllText((Resolve-Path $keyFile))).Trim() -replace "`r", ''

$hostkeys = (@($sec['hostkeys'] | Where-Object { $_[0] -eq 'line' } | ForEach-Object { $_[1] + '`n' }) -join '')
$allow = @(); $from = @("'127.0.0.1' = '$(Q (M 'tunnel_from'))'", "'::1' = '$(Q (M 'tunnel_from'))'")
foreach ($name in $sec.Keys) {
    if ($name -notlike 'server.*') { continue }
    $ip = Get1 $name 'ip'; $rd = Get1 $name 'radmin'; $lb = Q (Get1 $name 'label')
    if ($ip) { $allow += "'$ip'"; $from += "'$ip' = '$lb'" }
    if ($rd) { $allow += "'$rd'"; $from += "'$rd' = 'Radmin: $lb'" }
}

$map = @{
    SERVER = M 'host'; PORT = M 'port' '22'; SRV_NAME = Q (M 'srv_name'); HOST_ALIAS = M 'host_alias' 'tunnelsrv'
    TUNNEL_USER = M 'tunnel_user' 'claude_tunnel'; ENROLL_USER = M 'enroll_user' 'claude_enroll'
    TASK_NAME = Q (M 'task_name' 'Claude туннель'); JOURNAL = M 'journal' 'Журнал доступа Claude.txt'
    FILES_URL = Q (M 'files_url'); SSH_FALLBACK_URL = Q (M 'ssh_fallback_url'); ENROLL_KEY = $enrollKey
    HOSTKEYS = $hostkeys; ALLOW_IPS = ($allow -join ', '); FROM_MAP = ($from -join '; ')
    RD_URL = Q (M 'rustdesk_url'); RD_SHA = M 'rustdesk_sha256'; RD_HOST = Q (M 'rustdesk_host'); RD_RELAY = Q (M 'rustdesk_relay')
    RD_KEY = Q (M 'rustdesk_key'); RD_CFG = Q (M 'rustdesk_config')   # RustDesk первым шагом (12503); пусто — шаг пропускается
}

New-Item -ItemType Directory -Force obj | Out-Null
$utf8bom = New-Object Text.UTF8Encoding $true
foreach ($f in 'setup_core.ps1', 'setup_suffix.ps1') {
    $src = Join-Path 'installer' $f; if (-not (Test-Path $src)) { $src = $f }
    $txt = [IO.File]::ReadAllText((Resolve-Path $src), [Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
    foreach ($k in $map.Keys) { $txt = $txt.Replace('{{' + $k + '}}', [string]$map[$k]) }
    if ($txt -match '\{\{[A-Z_]+\}\}') { throw "В $f осталась незаполненная метка $($Matches[0])" }
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot "obj\$f"), $txt, $utf8bom)
}

$cs = 'TunnelGui.cs'; if (Test-Path 'src\TunnelGui.cs') { $cs = 'src\TunnelGui.cs' }
$csc = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { $csc = "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
$ico = M 'icon' 'tunnel.ico'   # значок и фон окна — из профиля (у нас «Мост»: theme\most.ico, 12483)
$bg = @(); if (Test-Path 'theme\bg.jpg') { $bg = @('-resource:theme\bg.jpg,bg.jpg') }
& $csc -nologo -codepage:65001 -target:winexe "-out:$Out" -win32manifest:app.manifest "-win32icon:$ico" @bg `
    -resource:obj\setup_core.ps1,setup_core.ps1 -resource:obj\setup_suffix.ps1,setup_suffix.ps1 "-resource:$Ini,profile.ini" `
    -r:System.Management.dll -r:System.ServiceProcess.dll -r:Microsoft.CSharp.dll -r:System.Core.dll `
    -r:System.Windows.Forms.dll -r:System.Drawing.dll $cs
if ($LASTEXITCODE -ne 0) { throw "csc: ошибка сборки ($LASTEXITCODE)" }
Write-Host "Готово: $Out ($(M 'rel'))"
