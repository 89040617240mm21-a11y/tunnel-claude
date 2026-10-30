& {
# Туннель для Claude (общий) — РЕЛИЗ 9 (19.10.2026, ответ 9888): шаг 1 проверяет не только службу, а настоящий ответ SSH-2.0
#   на 127.0.0.1:22 (один ПК: служба Running, вход рвётся); нет ответа — перезапуск службы, журнал, подсказка про 360.
# РЕЛИЗ 8 (19.10.2026, ответ 9867): SSH нет — ставит OpenSSH Microsoft из нашей копии на сервер
#   (без Windows Update и GitHub; помогает и ПК без DNS), только если не вышло — старый путь ssh-claude.txt.
#   port.txt: icacls /T с (OI)(CI) давал файлам пустой список доступа (один ПК, ответ 9866, правка чата №148).
# РЕЛИЗ 8 (30.10.2026, 14153): полной проверки Защитником больше нет — только быстрая (соединения наружу, удалённый доступ, автозапуск)
# РЕЛИЗ 7 (19.10.2026, ответ 9861): сразу после туннеля сам запускал проверку на вирусы
#   (Защитник без удаления, фоном от SYSTEM, после перезагрузки продолжает) — правило 9784.
# РЕЛИЗ 6 (19.10.2026, ответ 9860): ключ туннеля «too open» (личное право пользователя от ssh-keygen) —
#   права ключа задаются целиком заново (только SYSTEM и Администраторы), в лог — итоговые права.
# РЕЛИЗ 5 (19.10.2026, ответ 9857): 360 Total Security держал запуск ЛЮБОГО sshd (и встроенного, и MSI
#   Microsoft: ошибка 1920) — скрипт видит 360 и говорит, что нажать, вместо замены OpenSSH.
# РЕЛИЗ 4 (19.10.2026, ответ 9852): встроенный sshd Windows не стартует даже после починки —
#   убираем его службу и ставим официальный OpenSSH Microsoft 9.5 (MSI с сервера, подпись Microsoft), затем ключ и брандмауэр.
# РЕЛИЗ 3 (19.10.2026, ответ 9850): служба sshd не стартует — сама ищет причину (sshd -t, порт 22, журналы,
#   папка ssh) и чинит (права, ключи сервера, LocalSystem), всё в лог.
# РЕЛИЗ 2 (19.10.2026, ответ 9838): сотовый НЕ нужен — сервер выдаёт уникальный НОМЕР клиента
#   (= личный порт, не повторяется даже при одинаковых именах ПК, например «ПК_2»); имя ПК и ID RustDesk уходят на сервер для справки,
#   сотовый привязываем потом на сервер (tunnel_bind.ps1). Сотовый можно задать заранее: set CLAUDE_PHONE=7XXXXXXXXXX.
# РЕЛИЗ 1 (19.10.2026): один скрипт для любого клиента, регистрация по сотовому.
# Что делает: 1) включает SSH на этом ПК (вход только по ключу Claude); 2) создаёт ЛИЧНЫЙ ключ этого ПК;
# 3) регистрирует его на нашем сервере по сотовому клиента и получает личный порт;
# 4) ставит задачу «Claude туннель»: ПК сам держит исходящее SSH-соединение на сервер (при любом, динамическом IP).
# На роутере и в брандмауэре ничего не открывается. Отключить: Планировщик заданий -> «Claude туннель» -> Отключить.
# Опыт одного ПК (Win10 1909, ssh 7.7): пути с прямыми слешами, имя сервера {{HOST_ALIAS}}, владелец ключа — Администраторы.
$ErrorActionPreference = 'Stop'
$Srv = '{{SERVER}}'; $SrvPort = {{PORT}}
# 104.10: запасной адрес того же сервера (Radmin VPN) — прямой путь из-за границы до 16 рвётся или виснет (126, 12875);
#   берём его, только если он отвечает за 3 с; туннель потом идёт туда, где прошла регистрация
$SrvAlt = '{{SERVER_ALT}}'; $Srvs = @($Srv); if ($SrvAlt -and $SrvAlt -ne $Srv) { $Srvs += $SrvAlt }
function Test-Tcp($h, $p, $ms) {
    $c = New-Object Net.Sockets.TcpClient
    try { $a = $c.BeginConnect($h, $p, $null, $null); ($a.AsyncWaitHandle.WaitOne($ms) -and $c.Connected) } catch { $false } finally { $c.Close() }
}
# 104.13 (Михаил, 13047): Windows 7 = PowerShell 2.0 на .NET 2 — нет -in/-notin, Get-CimInstance, Get-NetTCPConnection, Get-FileHash,
#   Get-Content -Raw, командлетов брандмауэра и Планировщика, асинхронного чтения. Ниже — замены, работающие и на PS 2, и на 5.1.
function Get-Sha256($f) { $h = [Security.Cryptography.SHA256]::Create(); $fs = [IO.File]::OpenRead($f); try { -join ($h.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $fs.Close() } }
function Read-All($f) { [IO.File]::ReadAllText($f) }
function Get-PortPids($local, $remote, $rport) {   # вместо Get-NetTCPConnection: разбор netstat -ano
    foreach ($l in (netstat -ano -p tcp)) {
        $c = @($l.Trim() -split '\s+'); if ($c.Count -lt 5 -or $c[0] -ne 'TCP') { continue }
        if ($local -and $c[1] -match ":$local$" -and $c[3] -eq 'LISTENING') { [int]$c[4] }
        if ($remote -and $c[2] -eq "${remote}:$rport" -and $c[3] -eq 'ESTABLISHED') { [int]$c[4] }
    }
}
$NewPS = [bool](Get-Command Register-ScheduledTask -EA 0)   # Windows 8+ — командлеты Планировщика есть; Windows 7 — schtasks.exe
function Invoke-SshFile($exe, $argline, $sec, $mark) {   # 104.13: PS 2 — вывод ssh в файлы, ждём метку или предел времени
    $o = "$env:TEMP\claude_ssh_o.txt"; $e = "$env:TEMP\claude_ssh_e.txt"; $i = "$env:TEMP\claude_ssh_i.txt"
    foreach ($f in $o, $e) { Remove-Item $f -EA 0 }; [IO.File]::WriteAllText($i, '')
    try { $pr = Start-Process $exe -ArgumentList $argline -RedirectStandardOutput $o -RedirectStandardError $e -RedirectStandardInput $i -PassThru -WindowStyle Hidden } catch { return @("не запустился ssh: $($_.Exception.Message)") }
    $end = (Get-Date).AddSeconds($sec); $got = $false
    while ((Get-Date) -lt $end -and -not $pr.HasExited) {
        Start-Sleep -Milliseconds 300
        if ($mark -and (Test-Path $o) -and ((Read-Shared $o 50) -join "`n") -match $mark) { $got = $true; break }
    }
    $done = $pr.HasExited -or $got
    if (-not $pr.HasExited) { try { $pr.Kill() } catch {} }
    Start-Sleep -Milliseconds 300
    $lines = @(); foreach ($f in $o, $e) { if (Test-Path $f) { $lines += @(Read-Shared $f 200 | Where-Object { $_ -notmatch '^\(не прочитан' }) } }
    if ($got) { $lines += 'PORT-OK' }
    if (-not $done) { $lines += "timed out: нет ответа за $sec с" }
    $lines
}
function Invoke-SshT($exe, $argline, $sec, $mark = '') {
    if ($PSVersionTable.PSVersion.Major -lt 3) { return (Invoke-SshFile $exe $argline $sec $mark) }   # ssh с пределом времени: зависший обмен ключами не держит установку вечно
    $pi = New-Object Diagnostics.ProcessStartInfo $exe, $argline
    $pi.UseShellExecute = $false; $pi.RedirectStandardOutput = $true; $pi.RedirectStandardError = $true; $pi.CreateNoWindow = $true
    $pi.RedirectStandardInput = $true   # 104.10 (126): без своего ввода ssh наследовал ввод окна установки и ждал его вечно — даём пустой и сразу закрываем
    try { $pr = [Diagnostics.Process]::Start($pi) } catch { return @("не запустился ssh: $($_.Exception.Message)") }
    try { $pr.StandardInput.Close() } catch {}
    # 104.10 (126): ssh 8.1 с выводом в трубу получает ответ, но сам не закрывается — читаем по кускам и выходим, как только пришла метка ответа
    $e = $pr.StandardError.ReadToEndAsync(); $sb = New-Object Text.StringBuilder; $buf = New-Object char[] 4096
    $t = $pr.StandardOutput.ReadAsync($buf, 0, $buf.Length); $end = (Get-Date).AddSeconds($sec); $eof = $false
    while ((Get-Date) -lt $end) {
        if (-not $t.Wait(300)) { continue }
        if ($t.Result -le 0) { $eof = $true; break }
        [void]$sb.Append($buf, 0, $t.Result)
        if ($mark -and $sb.ToString() -match $mark) { break }
        $t = $pr.StandardOutput.ReadAsync($buf, 0, $buf.Length)
    }
    $got = $mark -and $sb.ToString() -match $mark
    if (-not $pr.WaitForExit($(if ($eof -or $got) { 2000 } else { 0 }))) { try { $pr.Kill() } catch {} }
    $err = if ($e.Wait(2000)) { $e.Result } else { '' }
    $lines = @(($sb.ToString() + "`n" + $err) -split "`r?`n" | Where-Object { $_ -ne '' })
    if (-not ($eof -or $got)) { $lines += "timed out: нет ответа за $sec с" }
    $lines
}
# 104.9: туннель ищем двумя путями — по командной строке (WMI) и по соединению ssh.exe с сервером (на части ПК WMI не отдаёт
#   командную строку процесса SYSTEM, и старый туннель не находился и не убивался — ПК PC, 22622). Убиваем через Планировщик + taskkill /F.
function Get-TunnelPids {
    $r = @()
    try { $r += @(Get-WmiObject Win32_Process -Filter "Name='ssh.exe'" -EA Stop | Where-Object { $_.CommandLine -like '*ClaudeTunnel*' } | ForEach-Object { [int]$_.ProcessId }) } catch {}
    foreach ($a in $Srvs) { try { $r += @(Get-PortPids '' $a $SrvPort | Where-Object { (Get-Process -Id $_ -EA 0).Name -eq 'ssh' }) } catch {} }
    @($r | Select-Object -Unique)
}
function Stop-Tunnel {
    cmd /c "schtasks /End /TN `"{{TASK_NAME}}`" >nul 2>&1"
    foreach ($i in Get-TunnelPids) { cmd /c "taskkill /F /PID $i >nul 2>&1" }
}
function Read-Shared($f, $n) {   # ssh.log держит открытым живой ssh — читаем с общим доступом
    try { $fs = [IO.File]::Open($f, 'Open', 'Read', 'ReadWrite, Delete'); $sr = New-Object IO.StreamReader($fs); $t = $sr.ReadToEnd(); $sr.Close(); @($t -split "`r?`n" | Where-Object { $_ } | Select-Object -Last $n) }
    catch { @("(не прочитан: $($_.Exception.Message))") }
}
$Url = '{{FILES_URL}}'
$Dir = "$env:ProgramData\ClaudeTunnel"; $D = $Dir.Replace([char]92, [char]47)
$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Запустите от имени администратора.' -ForegroundColor Red; return }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]3072 } catch {}   # TLS 1.2 (на .NET 2 у перечисления нет имени Tls12)
$wc = New-Object Net.WebClient
# 104.13 (Михаил, 13049): на Windows 7 RustDesk не скачался — старый PowerShell не умеет TLS 1.2. Запасные пути: тот же адрес через
#   Internet Explorer (IE 11 на Win7 умеет TLS 1.2), потом наша копия по http. Файлам по http верим только по контрольной сумме/подписи.
$Mirror = '{{HTTP_MIRROR}}'; $MsiSha = '{{MSI_SHA}}'
function Get-Urls($list) { $r = @("$list" -split '\|' | Where-Object { $_ }); if ($Mirror) { $r += @($r | ForEach-Object { "$Mirror/" + ($_ -split '/')[-1] }) }; $r | Select-Object -Unique }
function Save-Url($u, $f) {
    try { (New-Object Net.WebClient).DownloadFile($u, $f); return $true } catch { $e = $_.Exception.Message }
    try { $x = New-Object -ComObject Msxml2.XMLHTTP.6.0; $x.open('GET', $u, $false); $x.send()
        if ($x.status -eq 200) { [IO.File]::WriteAllBytes($f, [byte[]]$x.responseBody); return $true }; $e += " / через IE: код $($x.status)" } catch { $e += " / через IE: $($_.Exception.Message)" }
    Write-Host "   не скачалось: $e" -ForegroundColor DarkYellow; $false
}
function Test-Trust($f, $sha, $who) {   # '' — файлу верим; иначе — почему нет
    if (-not (Test-Path $f)) { return 'файла нет' }
    $h = Get-Sha256 $f
    if ($sha -and $h -ne $sha.ToLower()) { return "контрольная сумма не совпала ($h)" }
    $sg = Get-AuthenticodeSignature $f
    if ($sg.Status -eq 'Valid' -and $sg.SignerCertificate.Subject -like "*$who*") { return '' }
    if ($sha) { Write-Host "   подпись Windows не проверила ($($sg.Status)) — на Windows 7 без обновления SHA-2 так бывает; контрольная сумма совпала" -ForegroundColor DarkYellow; return '' }
    "подпись не $who ($($sg.Status))"
}
function Get-Msi($f) { foreach ($u in (Get-Urls "$Url/OpenSSH-Win64-v9.5.0.0.msi")) { Write-Host "   скачиваю: $u"; if (Save-Url $u $f) { $bad = Test-Trust $f $MsiSha 'Microsoft Corporation'; if (-not $bad) { return $true }; Write-Host "   $bad — не ставлю" -ForegroundColor Red; Remove-Item $f -EA 0 } }; $false }

$ph = "$env:CLAUDE_PHONE" -replace '\D', ''
if ($ph -match '^8\d{10}$') { $ph = '7' + $ph.Substring(1) }
if ($ph -notmatch '^7\d{10}$') { $ph = '0' }   # без сотового: привяжем потом по номеру клиента
# имя ПК латиницей (только для справки; кириллицу переводим: ПК_2 -> PK_2)
$tr = @{ 'а'='a';'б'='b';'в'='v';'г'='g';'д'='d';'е'='e';'ё'='e';'ж'='zh';'з'='z';'и'='i';'й'='y';'к'='k';'л'='l';'м'='m';'н'='n';'о'='o';'п'='p';'р'='r';'с'='s';'т'='t';'у'='u';'ф'='f';'х'='h';'ц'='c';'ч'='ch';'ш'='sh';'щ'='sch';'ъ'='';'ы'='y';'ь'='';'э'='e';'ю'='yu';'я'='ya' }
$pcName = -join ($env:COMPUTERNAME.ToCharArray() | ForEach-Object { $s = "$_"; $l = $s.ToLower(); if ($tr.ContainsKey($l)) { if ($s -cne $l) { $tr[$l].ToUpper() } else { $tr[$l] } } else { $s } })
$pcName = ($pcName -replace '[^A-Za-z0-9._-]', '_'); if ($pcName.Length -gt 40) { $pcName = $pcName.Substring(0, 40) }
if (-not $pcName) { $pcName = 'PC' }
# 1/7 RustDesk (Михаил, 12503): официальный подписанный RustDesk, тихая установка, наш сервер связи; ID уходит на сервер при регистрации (шаг 5)
#   Без удаления и без пароля: подключение только по ID, «Принять» нажимает человек. В профиле нет rustdesk_url — шаг пропускается.
$rdUrl = '{{RD_URL}}'; $rdSha = '{{RD_SHA}}'; $rdHost = '{{RD_HOST}}'; $rdRelay = '{{RD_RELAY}}'; $rdKey = '{{RD_KEY}}'; $rdCfg = '{{RD_CFG}}'
Write-Host '1/7 Удалённый помощник RustDesk...' -ForegroundColor Cyan
$rdExe0 = "$env:ProgramFiles\RustDesk\rustdesk.exe"
if (-not $rdUrl) { Write-Host '   в этой сборке RustDesk не задан — пропускаю' }
else {
  try {
    if (-not (Test-Path $rdExe0)) {
        $rdTmp = "$env:SystemRoot\Temp\claude_rd"; New-Item -ItemType Directory -Force $rdTmp | Out-Null
        $rdF = "$rdTmp\rustdesk-setup.exe"; $got = $false
        foreach ($u in (Get-Urls $rdUrl)) {
            if ($got) { continue }
            Write-Host "   скачиваю: $u"
            if (-not (Save-Url $u $rdF)) { continue }
            $bad = Test-Trust $rdF $rdSha 'PURSLANE'
            if ($bad) { Write-Host "   $bad — файл не запускаю" -ForegroundColor Red; Remove-Item $rdF -EA 0; continue }
            $got = $true
        }
        if ($got) {
            Write-Host '   файл RustDesk проверен — ставлю тихо (до 2 минут)'
            Start-Process $rdF -ArgumentList '--silent-install' -WindowStyle Hidden
            for ($i = 0; $i -lt 40 -and -not ((Test-Path $rdExe0) -and (Get-Service RustDesk -EA 0)); $i++) { Start-Sleep 3 }
            Start-Sleep 5
        }
    } else { Write-Host '   RustDesk уже установлен' }
    if ((Test-Path $rdExe0) -and $rdHost) {
        $rdToml = 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml'
        $rdOk = { (Test-Path $rdToml) -and ((Read-All $rdToml) -match [regex]::Escape("custom-rendezvous-server = '$rdHost'")) }
        if (-not (& $rdOk)) {
            if ($rdCfg) { cmd.exe /c "`"$rdExe0`" --config $rdCfg" | Out-Null; Start-Sleep 4 }
            if (-not (& $rdOk)) {
                # служба на свежем ПК не берёт сервер из --config («Empty source config, skipped») — дописываем в её конфиг сами, копия рядом
                sc.exe stop RustDesk | Out-Null; Start-Sleep 5
                Get-Process rustdesk -EA 0 | Where-Object { $_.SessionId -eq 0 } | Stop-Process -Force -EA 0
                $ls = @(); if (Test-Path $rdToml) { Copy-Item $rdToml ($rdToml + '.bak_' + (Get-Date -Format 'yyyyMMdd-HHmmss')); $ls = [IO.File]::ReadAllLines($rdToml) }
                $new = @("custom-rendezvous-server = '$rdHost'", "relay-server = '$rdRelay'", "key = '$rdKey'")
                $out = New-Object Collections.Generic.List[string]; $inOpt = $false; $done = $false
                foreach ($l in $ls) {
                    if ($l -match '^\s*\[') { $inOpt = ($l.Trim() -eq '[options]') }
                    if ($inOpt -and $l -match '^\s*(custom-rendezvous-server|relay-server|key)\s*=') { continue }
                    $out.Add($l)
                    if ($l.Trim() -eq '[options]' -and -not $done) { $new | ForEach-Object { $out.Add($_) }; $done = $true }
                }
                if (-not $done) { $out.Add(''); $out.Add('[options]'); $new | ForEach-Object { $out.Add($_) } }
                New-Item -ItemType Directory -Force (Split-Path $rdToml) | Out-Null
                [IO.File]::WriteAllLines($rdToml, $out, (New-Object Text.UTF8Encoding($false)))
                sc.exe start RustDesk | Out-Null; Start-Sleep 6
            }
        }
        Write-Host "   сервер связи RustDesk: $(if (& $rdOk) { $rdHost } else { 'не прописан — специалист поправит' })"
    }
    if (-not (Test-Path $rdExe0)) { Write-Host '   RustDesk не установился — продолжаю без него' -ForegroundColor DarkYellow }
  } catch { Write-Host "   RustDesk: $($_.Exception.Message) — продолжаю без него" -ForegroundColor DarkYellow }
}
# Radmin VPN (Михаил, 12540): официальный подписанный Famatech, тихая установка; в сеть ПК вводит человек — программно Radmin этого не умеет.
#   Уже стоит — не трогаем. В профиле нет radmin_url — пропускаем. Не вышло — Мост работает дальше без него.
$rvUrl = '{{RV_URL}}'; $rvSha = '{{RV_SHA}}'
if ($rvUrl) {
  try {
    if (Get-Service RvControlSvc -EA 0) { Write-Host '   Radmin VPN уже установлен' }
    else {
        $rvF = "$env:SystemRoot\Temp\claude_rd\radmin-vpn-setup.exe"; New-Item -ItemType Directory -Force (Split-Path $rvF) | Out-Null; $got = $false
        foreach ($u in (Get-Urls $rvUrl)) {
            if ($got) { continue }
            Write-Host "   Radmin VPN, скачиваю: $u"
            if (-not (Save-Url $u $rvF)) { continue }
            $bad = Test-Trust $rvF $rvSha 'Famatech'
            if ($bad) { Write-Host "   $bad — файл не запускаю" -ForegroundColor Red; Remove-Item $rvF -EA 0; continue }
            $got = $true
        }
        if ($got) {
            Write-Host '   файл Radmin VPN проверен — ставлю тихо (до 3 минут)'
            $p = Start-Process $rvF -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-' -PassThru -WindowStyle Hidden
            if (-not $p.WaitForExit(180000)) { $p.Kill() }
            Remove-Item $rvF -EA 0
        }
        Write-Host "   Radmin VPN: $(if (Get-Service RvControlSvc -EA 0) { 'установлен — войти в сеть: окно Radmin VPN -> Сеть -> Присоединиться' } else { 'не установился — продолжаю без него' })"
    }
  } catch { Write-Host "   Radmin VPN: $($_.Exception.Message) — продолжаю без него" -ForegroundColor DarkYellow }
}
# ID RustDesk, если стоит (для справки; ждём не больше 15 с)
$rdId = ''
$rdExe = @("$env:ProgramFiles\RustDesk\rustdesk.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($rdExe) { try { $j = Start-Job { param($e) & $e --get-id 2>$null } -ArgumentList $rdExe; if (Wait-Job $j -Timeout 15) { $rdId = ((Receive-Job $j) -join '' -replace '\D', '') }; Remove-Job $j -Force -EA 0 } catch {} }
$extra = "pc=$pcName"; if ($rdId -match '^\d{6,12}$') { $extra += " rd=$rdId" }
# ID RustDesk — в файл: окно Моста покажет его сразу при первом запуске, не дожидаясь RustDesk (Михаил, 12552)
if ($rdId -match '^\d{6,12}$') { try { New-Item -ItemType Directory -Force $Dir | Out-Null; [IO.File]::WriteAllText("$Dir\rustdesk_id.txt", $rdId) } catch {} }
Write-Host "ПК: $pcName   RustDesk: $(if ($rdId) { $rdId } else { 'нет' })   сотовый: $(if ($ph -ne '0') { $ph } else { 'привяжем потом' })"

Write-Host '2/7 SSH на этом ПК (вход только по ключу Claude)...' -ForegroundColor Cyan
$ak = "$env:ProgramData\ssh\administrators_authorized_keys"
$w7Url = '{{W7_URL}}'; $w7Sha = '{{W7_SHA}}'
if (-not (Get-Service sshd -EA 0) -and $PSVersionTable.PSVersion.Major -lt 3 -and $w7Url) {
    # 104.13 (13049): Windows 7 — OpenSSH 9.5 и встроенного компонента там нет; ставим проверенным рецептом для Win7 (OpenSSH 7.7, ответы 1897–1979)
    Write-Host '   Windows 7 — ставлю OpenSSH 7.7 (версия для Windows 7)...'
    $w7f = "$env:SystemRoot\Temp\claude_win7_ssh.ps1"
    if ((Save-Url $w7Url $w7f) -and (Get-Sha256 $w7f) -eq $w7Sha) {
        $ErrorActionPreference = 'Continue'
        try { & ([scriptblock]::Create([IO.File]::ReadAllText($w7f).TrimStart([char]0xFEFF))) } catch { Write-Host "   рецепт Win7: $($_.Exception.Message)" -ForegroundColor Yellow }
        $ErrorActionPreference = 'Stop'
    } else { Write-Host '   рецепт Win7 не скачался или контрольная сумма не совпала — не запускаю' -ForegroundColor Red }
    Remove-Item $w7f -EA 0
}
if (-not (Get-Service sshd -EA 0)) {
    # РЕЛИЗ 8: SSH нет — ставим сразу из НАШЕЙ копии установщика Microsoft на сервер: не зависит от обновлений Windows и GitHub
    #   (Windows в Parallels на Mac: DNS 10.211.55.1 не отвечает, Add-WindowsCapability 0x8024402c, api.github.com не найден)
    Write-Host '   SSH нет — ставлю OpenSSH Microsoft 9.5 с сервера {{SRV_NAME}}...'
    try {
        $msi = "$env:TEMP\OpenSSH-Win64-v9.5.0.0.msi"
        if (-not (Get-Msi $msi)) { Write-Host '   установщик не получил — не ставлю.' -ForegroundColor Red }
        else {
            $mp = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart ADDLOCAL=Client,Server /l*v `"$env:TEMP\openssh_msi.log`"" -Wait -PassThru
            Write-Host "   установщик: код $($mp.ExitCode) (0 — хорошо)"
            if (@(0, 3010) -notcontains $mp.ExitCode) { Get-Content "$env:TEMP\openssh_msi.log" -EA 0 | Select-String 'error|failed|Return value 3' | Select-Object -Last 6 | ForEach-Object { Write-Host "     $_" } }
            $cfg = "$env:ProgramData\ssh\sshd_config"
            if ((Get-Service sshd -EA 0) -and -not (Test-Path $cfg)) { Copy-Item "$env:ProgramFiles\OpenSSH\sshd_config_default" $cfg -EA 0 }
        }
        Remove-Item $msi -EA 0
    } catch { Write-Host "   с сервера {{SRV_NAME}} не поставился: $($_.Exception.Message) — пробую встроенный компонент Windows" -ForegroundColor Yellow }
}
if ($PSVersionTable.PSVersion.Major -ge 3 -and (-not (Get-Service sshd -EA 0) -or -not ((Test-Path $ak) -and ((Read-All $ak) -match 'hetzner-1c')))) {   # 104.13: этот рецепт — для Windows 8+
    & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($wc.DownloadData('{{SSH_FALLBACK_URL}}')).TrimStart([char]0xFEFF)))
    $ErrorActionPreference = 'Stop'
}
if (-not (Get-Service sshd -EA 0)) { Write-Host '   SSH не установился — пришлите текст этого окна.' -ForegroundColor Red; return }
Set-Service sshd -StartupType Automatic
try { Start-Service sshd } catch {
    # РЕЛИЗ 3: служба есть, но не стартует (один ПК, 19.10) — сами ищем причину и чиним, всё пишем в лог
    $ErrorActionPreference = 'Continue'
    Write-Host "   служба sshd не запускается: $($_.Exception.Message)" -ForegroundColor Yellow
    $svc = Get-WmiObject Win32_Service -Filter "Name='sshd'"
    $exe = ($svc.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1'
    Write-Host "   служба: $($svc.PathName)  от: $($svc.StartName)  файл есть: $(Test-Path $exe)"
    Write-Host '   --- проверка настроек (sshd -t):'; cmd /c "`"$exe`" -t 2>&1" | ForEach-Object { Write-Host "     $_" }
    Write-Host '   --- порт 22 занят?'; Get-PortPids 22 '' 0 | Select-Object -Unique | ForEach-Object { $pp = Get-Process -Id $_ -EA 0; Write-Host "     :22 — $($pp.ProcessName) $($pp.Path)" }
    Write-Host '   --- папка ssh:'; Get-ChildItem "$env:ProgramData\ssh" -EA 0 | ForEach-Object { Write-Host "     $($_.Name)  $($_.Length)" }
    Write-Host '   --- журнал OpenSSH:'; Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 8 -EA 0 | ForEach-Object { Write-Host "     $($_.TimeCreated) $($_.Message)" }
    Write-Host '   --- журнал служб:'; Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-30) } -MaxEvents 30 -EA 0 | Where-Object { $_.Message -match 'ssh' } | Select-Object -First 6 | ForEach-Object { Write-Host "     $($_.TimeCreated) [$($_.Id)] $($_.Message)" }
    Write-Host '   чиню: права папки ssh, ключи сервера, повторный запуск...' -ForegroundColor Cyan
    icacls "$env:ProgramData\ssh" /reset /T /Q 2>&1 | Out-Null
    $keys = "$env:ProgramData\ssh\administrators_authorized_keys"
    if (Test-Path $keys) { icacls $keys /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null }
    $kgen = Join-Path (Split-Path $exe) 'ssh-keygen.exe'
    if (Test-Path $kgen) { Push-Location "$env:ProgramData\ssh"; cmd /c "`"$kgen`" -A 2>&1" | ForEach-Object { Write-Host "     $_" }; Pop-Location }
    Get-ChildItem "$env:ProgramData\ssh\ssh_host_*_key" -EA 0 | ForEach-Object { icacls $_.FullName /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null }
    sc.exe config sshd obj= LocalSystem | Out-Null
    try { Start-Service sshd -EA Stop; Write-Host '   починил — служба запустилась' -ForegroundColor Green }
    catch {
        Write-Host "   всё ещё не запускается: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host '   --- запуск вручную на 5 с (sshd -d):'
        $o = "$env:TEMP\sshd_d.txt"; $pd = Start-Process $exe -ArgumentList '-d' -RedirectStandardError $o -PassThru -WindowStyle Hidden
        Start-Sleep 5; Stop-Process -Id $pd.Id -Force -EA 0; Get-Content $o -EA 0 | Select-Object -Last 15 | ForEach-Object { Write-Host "     $_" }
        $av = try { (Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -EA Stop | ForEach-Object { $_.displayName }) -join ', ' } catch { '?' }
        Write-Host "   антивирус: $av"
        # РЕЛИЗ 5: 360 Total Security держит запуск любой sshd (встроенный и MSI Microsoft, один ПК) — сначала его успокоить
        $q = Get-Process -EA 0 | Where-Object { $_.ProcessName -match '^(360|QH|ZhuDongFangYu)' } | Select-Object -ExpandProperty ProcessName -Unique
        if ($q -or $av -match '360') {
            Write-Host "`n   360 Total Security не даёт запустить SSH ($($q -join ', '))." -ForegroundColor Red
            Write-Host '   Нажмите на значок 360 у часов правой кнопкой -> «Выключить защиту» (или добавьте папки' -ForegroundColor Yellow
            Write-Host '   C:\Windows\System32\OpenSSH и C:\Program Files\OpenSSH в доверенные) и запустите этот файл ещё раз.' -ForegroundColor Yellow
            Write-Host '   Если всплыло окно 360 «Разрешить?» про sshd — нажмите «Разрешить» и запустите ещё раз.' -ForegroundColor Yellow
            Write-Host '   Если защита 360 уже выключена, а SSH всё равно не запускается, — пришлите этот лог Claude.' -ForegroundColor Yellow
            return
        }
        # РЕЛИЗ 4: встроенный sshd Windows завис (один ПК: тайм-аут 7009/7000, sshd -t и -d молчат) —
        #   убираем его службу и ставим официальный OpenSSH Microsoft 9.5 из установщика (копия на сервере, подпись Microsoft проверяем)
        Write-Host '   ставлю вместо встроенного официальный OpenSSH Microsoft 9.5...' -ForegroundColor Cyan
        sc.exe config sshd start= disabled | Out-Null
        Stop-Service sshd -Force -EA 0; Get-Process sshd -EA 0 | Stop-Process -Force -EA 0
        sc.exe delete sshd | Out-Null
        for ($i = 0; $i -lt 15 -and (Get-Service sshd -EA 0); $i++) { Start-Sleep 2 }
        if (Get-Service sshd -EA 0) { Write-Host '   старая служба ещё не удалилась (закройте окно «Службы», если открыто)' -ForegroundColor Yellow }
        $msi = "$env:TEMP\OpenSSH-Win64-v9.5.0.0.msi"
        if (-not (Get-Msi $msi)) { Write-Host '   установщик не получил — стоп. Пришлите этот лог Claude.' -ForegroundColor Red; return }
        $ml = "$env:TEMP\openssh_msi.log"
        $mp = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart ADDLOCAL=Server /l*v `"$ml`"" -Wait -PassThru
        Write-Host "   установщик: код $($mp.ExitCode) (0 — хорошо)"
        if (@(0, 3010) -notcontains $mp.ExitCode) { Get-Content $ml -EA 0 | Select-String 'error|failed|Return value 3' | Select-Object -Last 10 | ForEach-Object { Write-Host "     $_" }; Write-Host 'Пришлите этот лог Claude.' -ForegroundColor Red; return }
        Remove-Item $msi -EA 0
        $cfg = "$env:ProgramData\ssh\sshd_config"
        if (-not (Test-Path $cfg)) { Copy-Item "$env:ProgramFiles\OpenSSH\sshd_config_default" $cfg -EA 0 }
        Set-Service sshd -StartupType Automatic -EA 0
        try { Start-Service sshd -EA Stop } catch {
            Write-Host "   и новый не запускается: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "   служба: $((Get-WmiObject Win32_Service -Filter "Name='sshd'").PathName)"; Write-Host 'Пришлите этот лог Claude.' -ForegroundColor Red; return
        }
        Write-Host '   новый OpenSSH запустился — ключ Claude, вход только по ключу, брандмауэр...' -ForegroundColor Green
        & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($wc.DownloadData('{{SSH_FALLBACK_URL}}')).TrimStart([char]0xFEFF)))
        $ErrorActionPreference = 'Continue'
        # установщик мог открыть порт 22 всем — оставляем только наше правило (туннелю порт снаружи вообще не нужен)
        if ($NewPS) { Get-NetFirewallPortFilter -Protocol TCP -EA 0 | Where-Object { $_.LocalPort -contains '22' } | Get-NetFirewallRule -EA 0 | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Name -ne 'SSH-Claude-In' } | Disable-NetFirewallRule -EA 0 }
        if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd -EA 0 }
        if ((Get-Service sshd).Status -ne 'Running') { Write-Host '   SSH не работает — пришлите этот лог Claude.' -ForegroundColor Red; return }
    }
    $ErrorActionPreference = 'Stop'
}
# РЕЛИЗ 9: служба «работает» ещё не значит, что SSH отвечает (один ПК: служба Running, а вход через туннель
#   рвётся сразу — «kex_exchange_identification: Connection closed»). Проверяем по-настоящему: приветствие SSH-2.0 на 127.0.0.1:22.
function Test-SshBanner {
    try {
        $c = New-Object Net.Sockets.TcpClient
        $a = $c.BeginConnect('127.0.0.1', 22, $null, $null); if (-not ($a.AsyncWaitHandle.WaitOne(3000) -and $c.Connected)) { return '(порт 22 не отвечает)' }
        $st = $c.GetStream(); $st.ReadTimeout = 6000; $b = New-Object byte[] 80; $n = $st.Read($b, 0, 80); $c.Close()
        if ($n -le 0) { return '(соединение закрыто сразу)' }
        return [Text.Encoding]::ASCII.GetString($b, 0, $n).Trim()
    } catch { return "($($_.Exception.Message))" }
}
$bn = Test-SshBanner
if ($bn -notmatch '^SSH-2\.0') {
    Write-Host "   служба SSH запущена, но вход не принимает: $bn — перезапускаю службу..." -ForegroundColor Yellow
    Restart-Service sshd -Force -EA 0; Start-Sleep 3; $bn = Test-SshBanner
}
if ($bn -notmatch '^SSH-2\.0') {
    Write-Host "   SSH всё ещё не принимает вход: $bn" -ForegroundColor Red
    Write-Host '   --- журнал OpenSSH:'; Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 8 -EA 0 | ForEach-Object { Write-Host "     $($_.TimeCreated) $($_.Message)" }
    $q = Get-Process -EA 0 | Where-Object { $_.ProcessName -match '^(360|QH|ZhuDongFangYu)' } | Select-Object -ExpandProperty ProcessName -Unique
    if ($q) { Write-Host "   Работает 360 Total Security ($($q -join ', ')) — он рвёт вход SSH. Выключите защиту 360 (значок у часов -> «Выключить защиту») и запустите этот файл ещё раз." -ForegroundColor Yellow }
    Write-Host '   Продолжаю: номер клиента всё равно получим, вход починим потом.' -ForegroundColor DarkYellow
} else { Write-Host "   SSH работает ($bn)" }

Write-Host '3/7 Программа ssh...' -ForegroundColor Cyan
$ssh = @("$env:ProgramFiles\OpenSSH\ssh.exe", "$env:SystemRoot\System32\OpenSSH\ssh.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
# 12539: встроенный ssh 7.7 (Windows Server 2019) теряет ответ обмена ключами — висит на «expecting KEX_ECDH_REPLY» с любым сервером (180).
#   104.10: встроенный 8.1 (Windows 10, Server 2019/2022) на 126 рвётся так же — «Connection reset» на обмене ключами, а ssh 10.5 с того же
#   сервера в ту же минуту получает ответ за 3 с. Поэтому младше 9 — берём ssh 9.5 из нашего MSI распаковкой в папку Моста (msiexec /a: без установки, службы не трогаем)
$own = "$Dir\ssh95\Program Files\OpenSSH\ssh.exe"
if ((Test-Path $own) -and -not ($ssh -like "$env:ProgramFiles\*") -and ((cmd /c "`"$own`" -V 2>&1") -match 'OpenSSH')) { $ssh = $own }
elseif ($ssh -and ([version](Get-Item $ssh).VersionInfo.FileVersion).Major -lt 9) {
    Write-Host "   ssh $((Get-Item $ssh).VersionInfo.FileVersion) старый, с ним вход рвётся — беру ssh 9.5 с сервера {{SRV_NAME}}..." -ForegroundColor DarkYellow
    try {
        New-Item -ItemType Directory -Force $Dir | Out-Null
        $msi = "$Dir\OpenSSH-Win64-v9.5.0.0.msi"
        if (-not (Get-Msi $msi)) { throw 'установщик не получил' }
        Start-Process msiexec -ArgumentList "/a `"$msi`" /qn TARGETDIR=`"$Dir\ssh95`"" -Wait
        Remove-Item $msi -EA 0
        if (-not (Test-Path $own)) { throw 'ssh.exe не распаковался' }
        # 104.13: на Windows 7 ssh 9.5 может не запуститься — тогда остаёмся на своём
        if ((cmd /c "`"$own`" -V 2>&1") -match 'OpenSSH') { $ssh = $own } else { Remove-Item "$Dir\ssh95" -Recurse -Force -EA 0; throw 'ssh 9.5 на этой Windows не запускается' }
    } catch { Write-Host "   ssh 9.5 не получил: $($_.Exception.Message) — пробую старым" -ForegroundColor DarkYellow }
}
if (-not $ssh) { Write-Host '   ssh.exe не найден.' -ForegroundColor Red; return }
$kg = Join-Path (Split-Path $ssh) 'ssh-keygen.exe'
Write-Host "   $ssh"

Write-Host '4/7 Личный ключ этого ПК...' -ForegroundColor Cyan
New-Item -ItemType Directory -Force $Dir | Out-Null
Stop-Tunnel; Start-Sleep 2
$key = "$Dir\tunnel_key"; $ek = "$Dir\enroll_key"
# ключ прошлого запуска общего скрипта оставляем (тот же порт); ключ от старого личного скрипта (без port.txt) — заменяем
$old = (Test-Path $key) -and (Test-Path "$Dir\port.txt") -and (Test-Path "$key.pub")
$del = @($ek, "$Dir\known_hosts"); if (-not $old) { $del += @($key, "$key.pub", "$Dir\port.txt") }
foreach ($f in $del) { if (Test-Path $f) { cmd /c "takeown /f `"$f`" /a >nul 2>&1 & icacls `"$f`" /grant *S-1-5-32-544:F >nul 2>&1"; Remove-Item $f -Force } }
if (-not $old) { cmd /c "`"$kg`" -q -t ed25519 -N `"`" -C tunnel-$pcName -f `"$key`" >nul 2>&1" }
if (-not (Test-Path "$key.pub")) { Write-Host '   ключ не создался — пришлите текст этого окна.' -ForegroundColor Red; return }
$ekText = @'
{{ENROLL_KEY}}
'@
[IO.File]::WriteAllText($ek, $ekText.Replace("`r`n", "`n").Trim() + "`n")
$hk = "{{HOSTKEYS}}"
[IO.File]::WriteAllText("$Dir\known_hosts", $hk)
# port.txt: icacls /T с (OI)(CI) давал файлам пустой список доступа (один ПК, ответ 9866, чат №148) — файлам права сбрасываем на наследование
icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' /grant:r '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Get-ChildItem $Dir -Force -EA 0 | ForEach-Object { cmd /c "takeown /f `"$($_.FullName)`" /a >nul 2>&1"; icacls $_.FullName /reset | Out-Null; $_.Attributes = 'Normal' }
icacls $Dir /grant '*S-1-5-32-545:RX' | Out-Null; icacls "$Dir\known_hosts" /grant '*S-1-5-32-545:R' | Out-Null   # отпечаток сервера не секрет: ssh должен его прочитать (иначе «No host key is known»)
# РЕЛИЗ 6: ssh-keygen даёт ключу ЛИЧНОЕ право пользователя (один ПК\user) — ssh от SYSTEM считает его «too open».
#   Поэтому права ключа задаём целиком заново: владелец Администраторы, доступ только SYSTEM и Администраторы.
foreach ($f in $key, $ek) {
    cmd /c "takeown /f `"$f`" /a >nul 2>&1"
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'Allow'))) }
    try { Set-Acl -LiteralPath $f -AclObject $acl } catch { icacls $f /inheritance:r /grant:r '*S-1-5-18:F' /grant:r '*S-1-5-32-544:F' /remove:g "$env:USERNAME" | Out-Null }
}
Write-Host "   права ключа: $(((icacls $key) -join ' ') -replace '\s+', ' ')"
$g = "$env:ProgramData\ssh\ssh_known_hosts"     # общий файл доверенных серверов (ssh 7.7 читает его всегда)
if (-not ((Test-Path $g) -and ((Read-All $g) -match '{{HOST_ALIAS}} ssh-ed25519'))) { [IO.File]::AppendAllText($g, $hk) }
$pub = (((Read-All "$key.pub").Trim()) -split ' ')[0..1] -join ' '

Write-Host '5/7 Регистрация на сервере {{SRV_NAME}} и личный порт...' -ForegroundColor Cyan
$base = "-p $SrvPort -o StrictHostKeyChecking=yes -o HostKeyAlias={{HOST_ALIAS}} -o HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256 -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 -o ConnectionAttempts=3 -o CheckHostIP=no"  # CheckHostIP=no: ssh 7.7 сам пишет [IP]:порт ecdsa и потом падает «Host key verification failed» (180, 12521)
# три способа указать файлы — ssh 7.7 и новые читают по-разному; рабочий запоминаем для задачи
$ways = @(
    @{ kh = "-o UserKnownHostsFile=$D/known_hosts"; e = "$D/enroll_key"; t = "$D/tunnel_key" },
    @{ kh = ''; e = "$D/enroll_key"; t = "$D/tunnel_key" },
    @{ kh = "-o UserKnownHostsFile=`"$Dir\known_hosts`""; e = "`"$ek`""; t = "`"$key`"" })
$ok = $null; $Port = $null; $okSrv = $Srv; $ErrorActionPreference = 'Continue'
# сервер иногда рвёт соединение посреди обмена ключами («Connection reset», 180, 12521) — 6 кругов с паузой
# 12539: сброс — это очередь sshd на 16, а не неверный способ: тот же способ повторяем до 3 раз через 3/6 с, потом следующий
for ($try = 1; $try -le 6 -and -not $Port; $try++) {
    if ($try -gt 1) { Write-Host "   круг $try из 6 через 10 секунд..." -ForegroundColor DarkYellow; Start-Sleep 10 }
    # запасной адрес — только если отвечает; с 2-го круга он первым, если основной не дал номер
    $order = @($Srvs | Where-Object { $_ -eq $Srv -or (Test-Tcp $_ $SrvPort 3000) })
    if ($try -gt 1 -and $order.Count -gt 1) { [array]::Reverse($order) }
    foreach ($s in $order) {
        if ($Port) { break }
        if ($s -ne $Srv) { Write-Host "   пробую запасной путь $s (Radmin VPN)..." -ForegroundColor DarkYellow }
        foreach ($w in $ways) {
            for ($r = 1; $r -le 3; $r++) {
                $out = Invoke-SshT $ssh "-T $base $($w.kh) -i $($w.e) {{ENROLL_USER}}@$s `"$ph $pub $extra`"" 60 'PORT=\d+\r?\n'
                if (-not (($out -join ' ') -match 'reset|Connection closed|timed out|kex_exchange') -or $r -eq 3) { break }
                Write-Host "   сервер сбросил соединение — повтор $($r + 1) из 3 через $(3 * $r) с" -ForegroundColor DarkYellow; Start-Sleep (3 * $r)
            }
            $m = $out | Select-String 'PORT=(\d+)' | Select-Object -First 1
            if ($m) { $ok = $w; $okSrv = $s; $Port = $m.Matches[0].Groups[1].Value; break }
            Write-Host "   $s, способ «$($w.kh)» — нет: $(($out | Select-Object -Last 2) -join ' | ')" -ForegroundColor DarkYellow
            if (($out -join ' ') -match 'timed out') { break }   # адрес висит — остальные способы на нём не помогут, к следующему адресу
        }
    }
}
$ErrorActionPreference = 'Stop'
if (-not $Port) { Write-Host '   Регистрация не прошла — пришлите текст этого окна.' -ForegroundColor Red; exit 1 }   # код 1 — окно не пишет «Готово» (12521)
$pt = "$Dir\port.txt"
try { if (Test-Path $pt) { cmd /c "takeown /f `"$pt`" /a >nul 2>&1 & icacls `"$pt`" /reset >nul 2>&1 & attrib -r -h -s `"$pt`" >nul 2>&1"; Remove-Item $pt -Force }; [IO.File]::WriteAllText($pt, "$ph $Port $pcName`r`n") } catch { Write-Host "   port.txt не записан ($($_.Exception.Message)) — продолжаю" -ForegroundColor DarkYellow }
Write-Host "   НОМЕР КЛИЕНТА: $Port$(if ($okSrv -ne $Srv) { "  (через запасной путь $okSrv)" })" -ForegroundColor Green

# 104.13: Windows 7 — задача из XML через schtasks.exe (те же настройки: SYSTEM, при включении + каждую минуту, без предела времени)
function Register-TaskXml($name, $exe, $arg, $desc, $repeat, $limit) {
    $st = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    $rep = if ($repeat) { "<TimeTrigger><StartBoundary>$st</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>" } else { '' }
    $lim = if ($limit) { $limit } else { 'PT0S' }
    $x = '<?xml version="1.0" encoding="UTF-16"?>' + "`r`n" + '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        "<RegistrationInfo><Description>$([Security.SecurityElement]::Escape($desc))</Description></RegistrationInfo>" +
        "<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger>$rep</Triggers>" +
        '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>' +
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>$lim</ExecutionTimeLimit><Enabled>true</Enabled></Settings>" +
        "<Actions Context=`"Author`"><Exec><Command>$([Security.SecurityElement]::Escape($exe))</Command><Arguments>$([Security.SecurityElement]::Escape($arg))</Arguments></Exec></Actions></Task>"
    $xf = "$env:TEMP\claude_task.xml"; [IO.File]::WriteAllText($xf, $x, [Text.Encoding]::Unicode)
    $o = cmd /c "schtasks /Create /F /TN `"$name`" /XML `"$xf`" 2>&1"; $rc = $LASTEXITCODE; Remove-Item $xf -EA 0
    if ($rc -ne 0) { Write-Host "   задача «$name» не создалась: $o" -ForegroundColor Red }
}
Write-Host '6/7 Задача «Claude туннель» (от SYSTEM, при включении ПК и каждую минуту, если оборвался)...' -ForegroundColor Cyan
$targ = "-N -T $base $($ok.kh) -i $($ok.t) -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -E $D/ssh.log -R 127.0.0.1:${Port}:127.0.0.1:22 {{TUNNEL_USER}}@$okSrv"
$tdesc = "Туннель на сервер {{SRV_NAME}} для специалиста: номер клиента $Port, ПК $pcName, сотовый $ph (общий РЕЛИЗ 9). Отключить — правой кнопкой -> Отключить."
Stop-Tunnel
if ($NewPS) {
    $act = New-ScheduledTaskAction -Execute $ssh -Argument $targ
    $trg = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)))
    $set = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Unregister-ScheduledTask -TaskName '{{TASK_NAME}}' -Confirm:$false -EA 0
    Register-ScheduledTask -TaskName '{{TASK_NAME}}' -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Description $tdesc | Out-Null
} else { Register-TaskXml '{{TASK_NAME}}' $ssh $targ $tdesc $true '' }
Remove-Item "$Dir\ssh.log" -EA 0
cmd /c "schtasks /Run /TN `"{{TASK_NAME}}`" >nul 2>&1"

Write-Host '7/7 Проверка (сервер вписывает новый ключ до 1 минуты)...' -ForegroundColor Cyan
$desk = [Environment]::GetFolderPath('Desktop')
Get-ChildItem $desk -Filter 'Туннель Claude*.ps1' -EA 0 | Remove-Item -EA 0
$up = $false
for ($i = 1; $i -le 24 -and -not $up; $i++) {
    Start-Sleep 5
    $p = Get-TunnelPids | Select-Object -First 1
    if ($p) { Start-Sleep 8; $up = [bool](Get-Process -Id $p -EA 0) }
    if (-not $up -and $i % 4 -eq 0) { cmd /c "schtasks /Run /TN `"{{TASK_NAME}}`" >nul 2>&1"; Write-Host "   жду... ($($i * 5) с)" }
}
# РЕЛИЗ 8 (Михаил, 30.10, 14153): полную проверку Защитником убрали — грузила слабые ПК до 100 % и жар (A6, 2 ядра);
#   вместо неё быстрая проверка за секунды: какие программы держат соединения наружу и какие программы удалённого доступа
#   запущены или стоят в автозапуске — чтобы понять, сидит ли что-то лишнее. Ничего не удаляет и не сканирует диск.
try {
    $vo = "$env:SystemRoot\Temp\claude_chk"; New-Item -ItemType Directory -Force $vo | Out-Null
    $vn = 'Claude проверка вирусов'   # старая полная проверка с прошлых версий — снимаем
    cmd /c "schtasks /Query /TN `"$vn`" >nul 2>&1"
    if ($LASTEXITCODE -eq 0) { cmd /c "schtasks /End /TN `"$vn`" >nul 2>&1"; cmd /c "schtasks /Delete /TN `"$vn`" /F >nul 2>&1" }
    $mpx = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    if ((Get-Process MpCmdRun -EA 0) -and (Test-Path $mpx)) { & $mpx -Scan -Cancel 2>&1 | Out-Null }
    $ra = 'anydesk|teamviewer|tv_w32|tv_x64|ammyy|aa_v3|rudesktop|winvnc|tvnserver|vncserver|uvnc|litemanager|romserver|romviewer|aeroadmin|supremo|screenconnect|connectwise|rutserv|rfusclient|dwagent|meshagent|splashtop|srservice|ngrok|frpc|chisel|cloudflared|ncat|^nc$|plink|getscreen|assistant|zerotier|hamachi|remcos|njrat|quasar|asyncrat'
    $ours = '^(rustdesk|radmin|rserver3|ssh|sshd|TunnelClaude)$'
    $pr = @{}; Get-WmiObject Win32_Process -EA 0 | ForEach-Object { $pr[[int]$_.ProcessId] = $_ }
    $L = New-Object Collections.ArrayList
    [void]$L.Add("БЫСТРАЯ ПРОВЕРКА $(Get-Date -f 'dd.MM.yyyy HH:mm:ss') ПК $env:COMPUTERNAME")
    [void]$L.Add('--- Соединения наружу (программа, сколько адресов, путь, первые адреса):')
    $cn = @{}
    foreach ($ln in (netstat -ano 2>$null)) {
        $f = @(($ln -split '\s+') | Where-Object { $_ })
        if ($f.Count -lt 5 -or $f[0] -ne 'TCP' -or $f[3] -notmatch 'ESTABLISHED|УСТАНОВЛЕНО') { continue }
        $rem = $f[2] -replace ':\d+$',''; if ($rem -match '^(127\.|\[::1\]|0\.0\.0\.0)') { continue }
        $id = [int]$f[4]; $w = $pr[$id]; $nm = if ($w) { $w.Name -replace '\.exe$','' } else { "pid$id" }
        $path = if ($w -and $w.ExecutablePath) { $w.ExecutablePath } else { '' }
        $k = "$nm|$path"; if (-not $cn[$k]) { $cn[$k] = New-Object Collections.ArrayList }
        if (-not $cn[$k].Contains($rem)) { [void]$cn[$k].Add($rem) }
    }
    foreach ($k in ($cn.Keys | Sort-Object)) {
        $nm, $path = $k -split '\|', 2; $a = $cn[$k]
        $mark = if ($nm -match $ours) { '' } elseif ($nm -match $ra) { '  <== УДАЛЁННЫЙ ДОСТУП' } elseif ($path -match '\\(Temp|Users\\Public)\\' -or ($nm -match '^pid')) { '  <== проверить' } else { '' }
        [void]$L.Add("$nm ($($a.Count))  $path  $(($a | Select-Object -First 3) -join ', ')$mark")
    }
    [void]$L.Add('--- Программы удалённого доступа (запущены):')
    $hit = $pr.Values | Where-Object { ($_.Name -replace '\.exe$','') -match $ra -and ($_.Name -replace '\.exe$','') -notmatch $ours } | ForEach-Object { "$($_.Name)  $($_.ExecutablePath)" } | Sort-Object -Unique
    if ($hit) { $hit | ForEach-Object { [void]$L.Add($_) } } else { [void]$L.Add('нет (кроме наших RustDesk/Radmin/SSH)') }
    [void]$L.Add('--- Автозапуск (Run):')
    foreach ($rk in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
        $it = Get-ItemProperty $rk -EA 0; if (-not $it) { continue }
        $it.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $v = "$($_.Value)"; $mark = if ($v -match $ra) { '  <== УДАЛЁННЫЙ ДОСТУП' } elseif ($v -match '\\(Temp|Users\\Public)\\') { '  <== проверить' } else { '' }
            [void]$L.Add("$($_.Name) = $v$mark")
        }
    }
    $av = try { (Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -EA Stop | ForEach-Object { $_.displayName }) -join ', ' } catch { '?' }
    [void]$L.Add("--- Антивирус: $av")
    [IO.File]::WriteAllLines("$vo\quick.log", [string[]]$L, (New-Object Text.UTF8Encoding $true))
    $bad = @($L | Where-Object { $_ -match '<==' }).Count
    Write-Host "Быстрая проверка (соединения и удалённый доступ): подозрительных строк $bad, журнал $vo\quick.log" -ForegroundColor $(if ($bad) { 'Yellow' } else { 'Green' })
} catch { Write-Host "Быстрая проверка не прошла: $($_.Exception.Message)" -ForegroundColor Yellow }
try { [IO.File]::WriteAllText((Join-Path $desk "Номер для специалиста $Port.txt"), "Номер для специалиста: $Port`r`nПК: $pcName`r`nRustDesk: $rdId`r`n", (New-Object Text.UTF8Encoding $true)) } catch {}
if ($up) { Write-Host "`nГотово: туннель работает. НОМЕР КЛИЕНТА: $Port (ПК $pcName). Можно отключаться." -ForegroundColor Green }
else {
    Write-Host "`nТуннель пока не поднялся. Номер клиента $Port, ПК $pcName." -ForegroundColor Red
    if (Test-Path "$Dir\ssh.log") { Read-Shared "$Dir\ssh.log" 6 | ForEach-Object { Write-Host "   $_" } }
    Write-Host 'Пришлите текст этого окна.' -ForegroundColor Red
}
}
