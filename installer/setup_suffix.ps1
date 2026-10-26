
# === Добавка программы «Туннель Claude» версия 102 (26.10.2026, ответ 12436; 101 — ответ 12434) ===
$ErrorActionPreference = 'Continue'
# 1) прямой вход по SSH (Radmin VPN и интернет) — только с машин специалистов из профиля сборки
try {
    $r = Get-NetFirewallRule -Name 'SSH-Claude-In' -EA Stop
    $a = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r).RemoteAddress)
    $add = @({{ALLOW_IPS}})
    $n = @($a + $add | Where-Object { $_ -and $_ -ne 'Any' } | Select-Object -Unique)
    Set-NetFirewallRule -Name 'SSH-Claude-In' -RemoteAddress $n
    Write-Host "Прямой вход по SSH (Radmin и интернет) разрешён только с: $($n -join ', ')" -ForegroundColor Green
} catch { Write-Host "Правило брандмауэра SSH-Claude-In: $($_.Exception.Message)" -ForegroundColor Yellow }

# 2) журнал «кто заходил и что делал» — на общий рабочий стол, каждый вход по SSH пишется сам
$ep = Get-ExecutionPolicy -Scope LocalMachine
if ($ep -in 'Restricted', 'Undefined', 'AllSigned') {
    try { Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -EA Stop; Write-Host "Политика скриптов: $ep -> RemoteSigned (нужно для журнала входов)" } catch {
        # PowerShell кидает «Ошибка безопасности», даже когда политика ЗАПИСАНА, но перекрыта Bypass самого установщика — проверяем факт
        if ((Get-ExecutionPolicy -Scope LocalMachine) -eq 'RemoteSigned') { Write-Host "Политика скриптов: $ep -> RemoteSigned (нужно для журнала входов)" }
        else { Write-Host "Политика скриптов не изменена: $($_.Exception.Message)" }
    }
}
$eff = Get-ExecutionPolicy
if ($eff -in 'Restricted', 'AllSigned') { Write-Host "Журнал команд не включён: политика скриптов $eff (задана администратором). Входы всё равно видны в журнале." -ForegroundColor Yellow }
else {
    $prof = "$PSHOME\profile.ps1"
    $block = @'
# >>> Claude журнал SSH (программа «Туннель Claude») — каждый вход специалиста по SSH и его команды пишутся в журнал на рабочем столе
if ($env:SSH_CLIENT -and -not $global:ClaudeSshLog) {
    $global:ClaudeSshLog = 1
    try {
        $cdir = "$env:ProgramData\ClaudeTunnel\sessions"; New-Item -ItemType Directory -Force $cdir | Out-Null
        $cid = "$(Get-Date -f 'yyyy-MM-dd_HH-mm-ss')_$PID"
        $cip = $env:SSH_CLIENT.Split(' ')[0]
        $cfrom = @{ {{FROM_MAP}} }[$cip]
        if (-not $cfrom) { $cfrom = $cip }
        $ccmd = [Environment]::CommandLine; if ($ccmd.Length -gt 400) { $ccmd = $ccmd.Substring(0, 400) + ' …(полностью — в файле записи)' }
        Add-Content "$env:PUBLIC\Desktop\{{JOURNAL}}" "$(Get-Date -f 'dd.MM.yyyy HH:mm:ss') | КОМАНДА | вход Windows: $env:USERNAME | $cfrom | $ccmd | запись: $cdir\$cid.txt" -Encoding UTF8
        Start-Transcript -Path "$cdir\$cid.txt" -Append | Out-Null
    } catch {}
}
# <<< Claude журнал SSH
'@
    try {
        $old = if (Test-Path $prof) { [IO.File]::ReadAllText($prof) } else { '' }
        $old = [regex]::Replace($old, '(?s)\r?\n?# >>> Claude журнал SSH.*?# <<< Claude журнал SSH\r?\n?', '')
        [IO.File]::WriteAllText($prof, ($old.TrimEnd() + "`r`n" + $block + "`r`n").TrimStart(), (New-Object Text.UTF8Encoding $true))
        Write-Host "Журнал входов и команд включён: рабочий стол -> «Журнал доступа Claude.txt», полные записи — $env:ProgramData\ClaudeTunnel\sessions" -ForegroundColor Green
    } catch { Write-Host "Журнал команд не включён: $($_.Exception.Message)" -ForegroundColor Yellow }
}
