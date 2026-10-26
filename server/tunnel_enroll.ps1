# Регистрация туннеля клиента — РЕЛИЗ 3 (26.10.2026). Запускается sshd (ForceCommand) от пользователя claude_enroll.
# РЕЛИЗ 2: можно БЕЗ сотового — вместо него «0»; уникальный номер клиента = выданный порт (не повторяется).
#   Вход: "<сотовый 7XXXXXXXXXX или 0> ssh-ed25519 <ключ> [pc=ИМЯ_ПК] [rd=ID_RustDesk]". Выход: "PORT=<порт>".
#   Строка ports.csv: кто;порт;ключ;дата;адрес;pc;rd. Сотовый потом — tunnel_bind.ps1 <порт> <сотовый>.
# РЕЛИЗ 1: только по сотовому. Ключ в tunnel_authorized_keys вписывает задача SYSTEM «Туннели — ключи» (tunnel_build_keys.ps1, раз в минуту).
# РЕЛИЗ 3: команда "log <сотовый или 0> <имя ПК>" — программа «Туннель Claude» (версия 102+) присылает лог запуска и ошибок
#   текстом через stdin. Кладём в tunnels\logs\<сотовый>_<ПК>\<дата>.txt + строка в tunnels\logs\index.csv. Лог только хранится,
#   никогда не выполняется. Ключ регистрации общий (он в каждом скрипте), поэтому лимиты: файл до 256 КБ, клиенту до 60 логов
#   в сутки, всем до 3000 в сутки, вся папка до 500 МБ. Выход: "LOG=OK" или "ERR ...".
$ErrorActionPreference = 'Stop'
$c = "$env:SSH_ORIGINAL_COMMAND".Trim()
if ($c -match '^log (7\d{10}|0) ([A-Za-z0-9._-]{1,40})$') {
    $ph = $Matches[1]; $pc = $Matches[2]
    $root = 'C:\ProgramData\ssh\tunnels\logs'; $d = Join-Path $root "${ph}_$pc"; $idx = Join-Path $root 'index.csv'
    New-Item -ItemType Directory -Force $d | Out-Null
    $today = Get-Date -Format 'yyyy-MM-dd'
    if (@(Get-ChildItem $d -Filter "$today*" -File).Count -ge 60) { 'ERR лимит логов в сутки'; exit 1 }
    if ((Test-Path $idx) -and @(Get-Content $idx | ? { $_ -like "$today*" }).Count -ge 3000) { 'ERR общий лимит в сутки'; exit 1 }
    if (((Get-ChildItem $root -Recurse -File | Measure-Object Length -Sum).Sum) -gt 500MB) { 'ERR папка логов переполнена'; exit 1 }
    $in = [Console]::OpenStandardInput(); $buf = New-Object byte[] 262144; $n = 0
    while ($n -lt $buf.Length) { $r = $in.Read($buf, $n, $buf.Length - $n); if ($r -le 0) { break }; $n += $r }
    $body = [Text.Encoding]::UTF8.GetString($buf, 0, $n)
    $first = (($body -split "`n")[0] -replace '[;\r\t]', ' ').Trim(); if ($first.Length -gt 160) { $first = $first.Substring(0, 160) }
    $ip = ($env:SSH_CLIENT -split ' ')[0]
    $f = Join-Path $d "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')_$PID.txt"
    $head = "# Принято сервером: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') (время сервера), с адреса $ip, $n байт`r`n"
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
