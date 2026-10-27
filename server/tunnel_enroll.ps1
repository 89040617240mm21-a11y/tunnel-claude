# Регистрация туннеля клиента — РЕЛИЗ 4 (27.10.2026, Мост 104.9). РЕЛИЗ 3 — 26.10.2026, ответ 12436. РЕЛИЗ 2 — 19.10.2026, ответ 9838. Запускается sshd (ForceCommand) от claude_enroll.
# РЕЛИЗ 2: можно БЕЗ сотового — вместо него «0»; уникальный номер клиента = выданный порт (не повторяется).
#   Вход: "<сотовый 7XXXXXXXXXX или 0> ssh-ed25519 <ключ> [pc=ИМЯ_ПК] [rd=ID_RustDesk]". Выход: "PORT=<порт>".
#   Строка ports.csv: кто;порт;ключ;дата;адрес;pc;rd. Сотовый потом — tunnel_bind.ps1 <порт> <сотовый>.
# РЕЛИЗ 1: только по сотовому. Ключ в tunnel_authorized_keys вписывает задача SYSTEM «Claude туннели — ключи» (раз в минуту).
# РЕЛИЗ 3: команда "log <сотовый или 0> <имя ПК>" — программа «Туннель Claude» (версия 102+) присылает лог запуска и ошибок
#   текстом через stdin. Кладём в tunnels\logs\<сотовый>_<ПК>\<дата>.txt + строка в tunnels\logs\index.csv. Лог только хранится,
#   никогда не выполняется. Ключ регистрации общий (он в каждом скрипте), поэтому лимиты: файл до 256 КБ, клиенту до 200 логов (было 60)
#   в сутки, всем до 3000 в сутки, вся папка до 500 МБ. Выход: "LOG=OK" или "ERR ...".
# РЕЛИЗ 4: "check <порт>" — сервер сам стучится в 127.0.0.1:<порт> (только 22610–22999) и ждёт ответ SSH клиента до 12 с:
#   CHECK=OK / CHECK=NOBANNER / CHECK=NOLISTEN; один и тот же порт — не чаще раза в 20 с (иначе CHECK=WAIT + прошлый ответ).
#   "live <сотовый или 0> <ПК>" — живой лог, пока туннель не зелёный (Мост шлёт каждые 15 с): перезаписывает live.txt (до 256 КБ),
#   дописывает live-history.log (больше 2 МБ — в .1, хранится 2 файла), в index.csv не пишется, чаще раза в 10 с — отказ.
#   Лимит обычных логов клиенту поднят 60 -> 200 в сутки.
$ErrorActionPreference = 'Stop'
$c = "$env:SSH_ORIGINAL_COMMAND".Trim()
if ($c -match '^check (\d{5})$') {
    $port = [int]$Matches[1]; if ($port -lt 22610 -or $port -gt 22999) { 'ERR порт'; exit 1 }
    $cd = 'C:\ProgramData\ssh\tunnels\checks'; New-Item -ItemType Directory -Force $cd | Out-Null; $cf = Join-Path $cd "$port.txt"
    if ((Test-Path $cf) -and ((Get-Date) - (Get-Item $cf).LastWriteTime).TotalSeconds -lt 20) { "CHECK=WAIT $([IO.File]::ReadAllText($cf))"; exit 0 }
    $res = 'CHECK=NOLISTEN'
    try {
        $t = New-Object Net.Sockets.TcpClient; $ar = $t.BeginConnect('127.0.0.1', $port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(3000) -and $t.Connected) {
            $t.EndConnect($ar); $st = $t.GetStream(); $st.ReadTimeout = 12000; $b = New-Object byte[] 64; $n = 0
            try { $n = $st.Read($b, 0, 64) } catch { $n = 0 }
            $bn = if ($n -gt 0) { [Text.Encoding]::ASCII.GetString($b, 0, $n).Trim() } else { '' }
            $res = if ($bn -like 'SSH-2.0*') { "CHECK=OK $bn" } else { 'CHECK=NOBANNER' }
        }
        $t.Close()
    } catch { }
    [IO.File]::WriteAllText($cf, $res); $res; exit 0
}
if ($c -match '^live (7\d{10}|0) ([A-Za-z0-9._-]{1,40})$') {
    $ph = $Matches[1]; $pc = $Matches[2]
    $root = 'C:\ProgramData\ssh\tunnels\logs'; $d = Join-Path $root "${ph}_$pc"; New-Item -ItemType Directory -Force $d | Out-Null
    $lf = Join-Path $d 'live.txt'; $hf = Join-Path $d 'live-history.log'
    if ((Test-Path $lf) -and ((Get-Date) - (Get-Item $lf).LastWriteTime).TotalSeconds -lt 10) { 'ERR часто'; exit 1 }
    if (((Get-ChildItem $root -Recurse -File | Measure-Object Length -Sum).Sum) -gt 500MB) { 'ERR папка логов переполнена'; exit 1 }
    $in = [Console]::OpenStandardInput(); $buf = New-Object byte[] 262144; $n = 0
    while ($n -lt $buf.Length) { $r = $in.Read($buf, $n, $buf.Length - $n); if ($r -le 0) { break }; $n += $r }
    $body = [Text.Encoding]::UTF8.GetString($buf, 0, $n)
    $ip = ($env:SSH_CLIENT -split ' ')[0]
    $head = "# Живой лог, принят сервером 16: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') МСК, с адреса $ip, $n байт`r`n"
    [IO.File]::WriteAllText($lf, $head + $body, (New-Object Text.UTF8Encoding $true))
    if ((Test-Path $hf) -and (Get-Item $hf).Length -gt 2MB) { Move-Item $hf "$hf.1" -Force }
    [IO.File]::AppendAllText($hf, "`r`n===== " + $head + $body, (New-Object Text.UTF8Encoding $false))
    'LIVE=OK'; exit 0
}
if ($c -match '^log (7\d{10}|0) ([A-Za-z0-9._-]{1,40})$') {
    $ph = $Matches[1]; $pc = $Matches[2]
    $root = 'C:\ProgramData\ssh\tunnels\logs'; $d = Join-Path $root "${ph}_$pc"; $idx = Join-Path $root 'index.csv'
    New-Item -ItemType Directory -Force $d | Out-Null
    $today = Get-Date -Format 'yyyy-MM-dd'
    if (@(Get-ChildItem $d -Filter "$today*" -File).Count -ge 200) { 'ERR лимит логов в сутки'; exit 1 }
    if ((Test-Path $idx) -and @(Get-Content $idx | ? { $_ -like "$today*" }).Count -ge 3000) { 'ERR общий лимит в сутки'; exit 1 }
    if (((Get-ChildItem $root -Recurse -File | Measure-Object Length -Sum).Sum) -gt 500MB) { 'ERR папка логов переполнена'; exit 1 }
    $in = [Console]::OpenStandardInput(); $buf = New-Object byte[] 262144; $n = 0
    while ($n -lt $buf.Length) { $r = $in.Read($buf, $n, $buf.Length - $n); if ($r -le 0) { break }; $n += $r }
    $body = [Text.Encoding]::UTF8.GetString($buf, 0, $n)
    $first = (($body -split "`n")[0] -replace '[;\r\t]', ' ').Trim(); if ($first.Length -gt 160) { $first = $first.Substring(0, 160) }
    $ip = ($env:SSH_CLIENT -split ' ')[0]
    $f = Join-Path $d "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_$PID.txt"
    $head = "# Принято сервером 16: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') МСК, с адреса $ip, $n байт`r`n"
    [IO.File]::WriteAllText($f, $head + $body, (New-Object Text.UTF8Encoding $true))
    $m = New-Object Threading.Mutex($false, 'claude_enroll_log'); [void]$m.WaitOne(10000)
    try { [IO.File]::AppendAllText($idx, "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');$ph;$pc;$ip;${ph}_$pc\$(Split-Path $f -Leaf);$first`r`n", (New-Object Text.UTF8Encoding $false)) } finally { $m.ReleaseMutex() }
    'LOG=OK'; exit 0
}
if ($c -notmatch '^(7\d{10}|0) (ssh-ed25519 [A-Za-z0-9+/]{68})((?: (?:pc=[A-Za-z0-9._-]{1,40}|rd=\d{6,12}))*)$') { 'ERR формат'; exit 1 }
$ph = $Matches[1]; $pk = $Matches[2]; $tail = $Matches[3]
$pc = if ($tail -match 'pc=([A-Za-z0-9._-]+)') { $Matches[1] } else { '' }
$rd = if ($tail -match 'rd=(\d+)') { $Matches[1] } else { '' }
$reg = 'C:\ProgramData\ssh\tunnels\ports.csv'
$m = New-Object Threading.Mutex($false, 'claude_enroll')
[void]$m.WaitOne(15000)
try {
    $all = @(if (Test-Path $reg) { Get-Content $reg })
    $rows = @($all | ? { $_ -match '^(7\d{10}|0);\d+;ssh-ed25519 ' })
    $same = $rows | ? { ($_ -split ';')[2] -eq $pk } | Select-Object -First 1
    if ($same) {   # тот же ПК запустил снова: порт прежний; сотовый вписываем, если раньше был «-»
        $f = $same -split ';'
        if ($ph -ne '0' -and $f[0] -eq '0') {
            $f[0] = $ph; $new = $f -join ';'
            [IO.File]::WriteAllLines("$reg.tmp", [string[]]($all | % { if ($_ -eq $same) { $new } else { $_ } }))
            Move-Item "$reg.tmp" $reg -Force
        }
        "PORT=$($f[1])"; exit 0
    }
    $today = Get-Date -Format 'yyyy-MM-dd'
    if (@($rows | ? { ($_ -split ';')[3] -like "$today*" }).Count -ge 50) { 'ERR лимит в сутки'; exit 1 }
    $max = 22609; foreach ($r in $rows) { $p = [int]($r -split ';')[1]; if ($p -gt $max) { $max = $p } }
    $port = $max + 1
    Add-Content $reg "$ph;$port;$pk;$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');$env:SSH_CLIENT;$pc;$rd" -Encoding ascii
    "PORT=$port"
} finally { $m.ReleaseMutex() }
