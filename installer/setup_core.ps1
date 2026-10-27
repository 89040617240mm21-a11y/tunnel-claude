& {
# Туннель для Claude (общий) — РЕЛИЗ 9 (19.10.2026, ответ 9888): шаг 1 проверяет не только службу, а настоящий ответ SSH-2.0
#   на 127.0.0.1:22 (один ПК: служба Running, вход рвётся); нет ответа — перезапуск службы, журнал, подсказка про 360.
# РЕЛИЗ 8 (19.10.2026, ответ 9867): SSH нет — ставит OpenSSH Microsoft из нашей копии на сервер
#   (без Windows Update и GitHub; помогает и ПК без DNS), только если не вышло — старый путь ssh-claude.txt.
#   port.txt: icacls /T с (OI)(CI) давал файлам пустой список доступа (один ПК, ответ 9866, правка чата №148).
# РЕЛИЗ 7 (19.10.2026, ответ 9861): сразу после туннеля сам запускает проверку на вирусы
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
# 104.9: туннель ищем двумя путями — по командной строке (WMI) и по соединению ssh.exe с сервером (на части ПК WMI не отдаёт
#   командную строку процесса SYSTEM, и старый туннель не находился и не убивался — ПК PC, 22622). Убиваем через Планировщик + taskkill /F.
function Get-TunnelPids {
    $r = @()
    try { $r += @(Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" -EA Stop | Where-Object { $_.CommandLine -like '*ClaudeTunnel*' } | ForEach-Object { [int]$_.ProcessId }) } catch {}
    try { $r += @(Get-NetTCPConnection -RemoteAddress $Srv -RemotePort $SrvPort -EA Stop | Where-Object { (Get-Process -Id $_.OwningProcess -EA 0).Name -eq 'ssh' } | ForEach-Object { [int]$_.OwningProcess }) } catch {}
    @($r | Select-Object -Unique)
}
function Stop-Tunnel {
    Stop-ScheduledTask -TaskName '{{TASK_NAME}}' -EA 0
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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object Net.WebClient

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
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        foreach ($u in ($rdUrl -split '\|')) {
            if ($got -or -not $u) { continue }
            Write-Host "   скачиваю: $u"
            try { (New-Object Net.WebClient).DownloadFile($u, $rdF) } catch { Write-Host "   не скачалось: $($_.Exception.Message)" -ForegroundColor DarkYellow; continue }
            $h = (Get-FileHash $rdF -Algorithm SHA256).Hash.ToLower(); $sg = Get-AuthenticodeSignature $rdF
            if ($rdSha -and $h -ne $rdSha.ToLower()) { Write-Host "   контрольная сумма не совпала ($h) — файл не запускаю" -ForegroundColor Red; Remove-Item $rdF -EA 0; continue }
            if ($sg.Status -ne 'Valid' -or $sg.SignerCertificate.Subject -notlike '*PURSLANE*') { Write-Host "   подпись не RustDesk ($($sg.Status)) — файл не запускаю" -ForegroundColor Red; Remove-Item $rdF -EA 0; continue }
            $got = $true
        }
        if ($got) {
            Write-Host '   подпись RustDesk и контрольная сумма верны — ставлю тихо (до 2 минут)'
            Start-Process $rdF -ArgumentList '--silent-install' -WindowStyle Hidden
            for ($i = 0; $i -lt 40 -and -not ((Test-Path $rdExe0) -and (Get-Service RustDesk -EA 0)); $i++) { Start-Sleep 3 }
            Start-Sleep 5
        }
    } else { Write-Host '   RustDesk уже установлен' }
    if ((Test-Path $rdExe0) -and $rdHost) {
        $rdToml = 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml'
        $rdOk = { (Test-Path $rdToml) -and ((Get-Content $rdToml -Raw -Encoding UTF8) -match [regex]::Escape("custom-rendezvous-server = '$rdHost'")) }
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
        foreach ($u in ($rvUrl -split '\|')) {
            if ($got -or -not $u) { continue }
            Write-Host "   Radmin VPN, скачиваю: $u"
            try { (New-Object Net.WebClient).DownloadFile($u, $rvF) } catch { Write-Host "   не скачалось: $($_.Exception.Message)" -ForegroundColor DarkYellow; continue }
            $h = (Get-FileHash $rvF -Algorithm SHA256).Hash.ToLower(); $sg = Get-AuthenticodeSignature $rvF
            if ($rvSha -and $h -ne $rvSha.ToLower()) { Write-Host "   контрольная сумма не совпала ($h) — файл не запускаю" -ForegroundColor Red; Remove-Item $rvF -EA 0; continue }
            if ($sg.Status -ne 'Valid' -or $sg.SignerCertificate.Subject -notlike '*Famatech*') { Write-Host "   подпись не Famatech ($($sg.Status)) — файл не запускаю" -ForegroundColor Red; Remove-Item $rvF -EA 0; continue }
            $got = $true
        }
        if ($got) {
            Write-Host '   подпись Famatech и контрольная сумма верны — ставлю Radmin VPN тихо (до 3 минут)'
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
if (-not (Get-Service sshd -EA 0)) {
    # РЕЛИЗ 8: SSH нет — ставим сразу из НАШЕЙ копии установщика Microsoft на сервер: не зависит от обновлений Windows и GitHub
    #   (Windows в Parallels на Mac: DNS 10.211.55.1 не отвечает, Add-WindowsCapability 0x8024402c, api.github.com не найден)
    Write-Host '   SSH нет — ставлю OpenSSH Microsoft 9.5 с сервера {{SRV_NAME}}...'
    try {
        $msi = "$env:TEMP\OpenSSH-Win64-v9.5.0.0.msi"; $wc.DownloadFile("$Url/OpenSSH-Win64-v9.5.0.0.msi", $msi)
        $sig = Get-AuthenticodeSignature $msi
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation') { Write-Host "   подпись установщика не Microsoft ($($sig.Status)) — не ставлю." -ForegroundColor Red }
        else {
            $mp = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart ADDLOCAL=Client,Server /l*v `"$env:TEMP\openssh_msi.log`"" -Wait -PassThru
            Write-Host "   установщик: код $($mp.ExitCode) (0 — хорошо)"
            if ($mp.ExitCode -notin 0, 3010) { Get-Content "$env:TEMP\openssh_msi.log" -EA 0 | Select-String 'error|failed|Return value 3' | Select-Object -Last 6 | ForEach-Object { Write-Host "     $_" } }
            $cfg = "$env:ProgramData\ssh\sshd_config"
            if ((Get-Service sshd -EA 0) -and -not (Test-Path $cfg)) { Copy-Item "$env:ProgramFiles\OpenSSH\sshd_config_default" $cfg -EA 0 }
        }
        Remove-Item $msi -EA 0
    } catch { Write-Host "   с сервера {{SRV_NAME}} не поставился: $($_.Exception.Message) — пробую встроенный компонент Windows" -ForegroundColor Yellow }
}
if (-not (Get-Service sshd -EA 0) -or -not ((Test-Path $ak) -and ((Get-Content $ak -Raw) -match 'hetzner-1c'))) {
    & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($wc.DownloadData('{{SSH_FALLBACK_URL}}')).TrimStart([char]0xFEFF)))
    $ErrorActionPreference = 'Stop'
}
if (-not (Get-Service sshd -EA 0)) { Write-Host '   SSH не установился — пришлите текст этого окна.' -ForegroundColor Red; return }
Set-Service sshd -StartupType Automatic
try { Start-Service sshd } catch {
    # РЕЛИЗ 3: служба есть, но не стартует (один ПК, 19.10) — сами ищем причину и чиним, всё пишем в лог
    $ErrorActionPreference = 'Continue'
    Write-Host "   служба sshd не запускается: $($_.Exception.Message)" -ForegroundColor Yellow
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    $exe = ($svc.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1'
    Write-Host "   служба: $($svc.PathName)  от: $($svc.StartName)  файл есть: $(Test-Path $exe)"
    Write-Host '   --- проверка настроек (sshd -t):'; cmd /c "`"$exe`" -t 2>&1" | ForEach-Object { Write-Host "     $_" }
    Write-Host '   --- порт 22 занят?'; Get-NetTCPConnection -LocalPort 22 -State Listen -EA 0 | ForEach-Object { $pp = Get-Process -Id $_.OwningProcess -EA 0; Write-Host "     $($_.LocalAddress):22 — $($pp.ProcessName) $($pp.Path)" }
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
        $av = try { (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA Stop).displayName -join ', ' } catch { '?' }
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
        try { $wc.DownloadFile("$Url/OpenSSH-Win64-v9.5.0.0.msi", $msi) } catch { Write-Host "   установщик не скачался: $($_.Exception.Message)" -ForegroundColor Red; Write-Host 'Пришлите этот лог Claude.' -ForegroundColor Red; return }
        $sig = Get-AuthenticodeSignature $msi
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation') { Write-Host "   подпись установщика не Microsoft ($($sig.Status)) — стоп." -ForegroundColor Red; Write-Host 'Пришлите этот лог Claude.' -ForegroundColor Red; return }
        $ml = "$env:TEMP\openssh_msi.log"
        $mp = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart ADDLOCAL=Server /l*v `"$ml`"" -Wait -PassThru
        Write-Host "   установщик: код $($mp.ExitCode) (0 — хорошо)"
        if ($mp.ExitCode -notin 0, 3010) { Get-Content $ml -EA 0 | Select-String 'error|failed|Return value 3' | Select-Object -Last 10 | ForEach-Object { Write-Host "     $_" }; Write-Host 'Пришлите этот лог Claude.' -ForegroundColor Red; return }
        Remove-Item $msi -EA 0
        $cfg = "$env:ProgramData\ssh\sshd_config"
        if (-not (Test-Path $cfg)) { Copy-Item "$env:ProgramFiles\OpenSSH\sshd_config_default" $cfg -EA 0 }
        Set-Service sshd -StartupType Automatic -EA 0
        try { Start-Service sshd -EA Stop } catch {
            Write-Host "   и новый не запускается: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "   служба: $((Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName)"; Write-Host 'Пришлите этот лог Claude.' -ForegroundColor Red; return
        }
        Write-Host '   новый OpenSSH запустился — ключ Claude, вход только по ключу, брандмауэр...' -ForegroundColor Green
        & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($wc.DownloadData('{{SSH_FALLBACK_URL}}')).TrimStart([char]0xFEFF)))
        $ErrorActionPreference = 'Continue'
        # установщик мог открыть порт 22 всем — оставляем только наше правило (туннелю порт снаружи вообще не нужен)
        Get-NetFirewallPortFilter -Protocol TCP -EA 0 | Where-Object { $_.LocalPort -contains '22' } | Get-NetFirewallRule -EA 0 | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Name -ne 'SSH-Claude-In' } | Disable-NetFirewallRule -EA 0
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
        if (-not $c.ConnectAsync('127.0.0.1', 22).Wait(3000)) { return '(порт 22 не отвечает)' }
        $st = $c.GetStream(); $st.ReadTimeout = 6000; $b = New-Object byte[] 80; $n = $st.Read($b, 0, 80); $c.Close()
        if ($n -le 0) { return '(соединение закрыто сразу)' }
        return [Text.Encoding]::ASCII.GetString($b, 0, $n).Trim()
    } catch { return "($($_.Exception.InnerException.Message))" }
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
#   Старше 8 — берём ssh 9.5 из нашего MSI распаковкой в папку Моста (msiexec /a: без установки, службы не трогаем)
$own = "$Dir\ssh95\Program Files\OpenSSH\ssh.exe"
if ((Test-Path $own) -and -not ($ssh -like "$env:ProgramFiles\*")) { $ssh = $own }
elseif ($ssh -and ([version](Get-Item $ssh).VersionInfo.FileVersion).Major -lt 8) {
    Write-Host "   ssh $((Get-Item $ssh).VersionInfo.FileVersion) старый, с ним вход рвётся — беру ssh 9.5 с сервера {{SRV_NAME}}..." -ForegroundColor DarkYellow
    try {
        New-Item -ItemType Directory -Force $Dir | Out-Null
        $msi = "$Dir\OpenSSH-Win64-v9.5.0.0.msi"; (New-Object Net.WebClient).DownloadFile("$Url/OpenSSH-Win64-v9.5.0.0.msi", $msi)
        $sig = Get-AuthenticodeSignature $msi
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw "подпись не Microsoft ($($sig.Status))" }
        Start-Process msiexec -ArgumentList "/a `"$msi`" /qn TARGETDIR=`"$Dir\ssh95`"" -Wait
        Remove-Item $msi -EA 0
        if (Test-Path $own) { $ssh = $own } else { throw 'ssh.exe не распаковался' }
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
if (-not ((Test-Path $g) -and ((Get-Content $g -Raw) -match '{{HOST_ALIAS}} ssh-ed25519'))) { [IO.File]::AppendAllText($g, $hk) }
$pub = (((Get-Content "$key.pub" -Raw).Trim()) -split ' ')[0..1] -join ' '

Write-Host '5/7 Регистрация на сервере {{SRV_NAME}} и личный порт...' -ForegroundColor Cyan
$base = "-p $SrvPort -o StrictHostKeyChecking=yes -o HostKeyAlias={{HOST_ALIAS}} -o HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256 -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 -o ConnectionAttempts=3 -o CheckHostIP=no"  # CheckHostIP=no: ssh 7.7 сам пишет [IP]:порт ecdsa и потом падает «Host key verification failed» (180, 12521)
# три способа указать файлы — ssh 7.7 и новые читают по-разному; рабочий запоминаем для задачи
$ways = @(
    @{ kh = "-o UserKnownHostsFile=$D/known_hosts"; e = "$D/enroll_key"; t = "$D/tunnel_key" },
    @{ kh = ''; e = "$D/enroll_key"; t = "$D/tunnel_key" },
    @{ kh = "-o UserKnownHostsFile=`"$Dir\known_hosts`""; e = "`"$ek`""; t = "`"$key`"" })
$ok = $null; $Port = $null; $ErrorActionPreference = 'Continue'
# сервер иногда рвёт соединение посреди обмена ключами («Connection reset», 180, 12521) — 6 кругов с паузой
# 12539: сброс — это очередь sshd на 16, а не неверный способ: тот же способ повторяем до 3 раз через 3/6 с, потом следующий
for ($try = 1; $try -le 6 -and -not $Port; $try++) {
    if ($try -gt 1) { Write-Host "   круг $try из 6 через 10 секунд..." -ForegroundColor DarkYellow; Start-Sleep 10 }
    foreach ($w in $ways) {
        for ($r = 1; $r -le 3; $r++) {
            $out = cmd /c "`"$ssh`" -T $base $($w.kh) -i $($w.e) {{ENROLL_USER}}@$Srv `"$ph $pub $extra`" 2>&1"
            if (-not (($out -join ' ') -match 'reset|Connection closed|timed out|kex_exchange') -or $r -eq 3) { break }
            Write-Host "   сервер сбросил соединение — повтор $($r + 1) из 3 через $(3 * $r) с" -ForegroundColor DarkYellow; Start-Sleep (3 * $r)
        }
        $m = $out | Select-String 'PORT=(\d+)' | Select-Object -First 1
        if ($m) { $ok = $w; $Port = $m.Matches[0].Groups[1].Value; break }
        Write-Host "   способ «$($w.kh)» — нет: $(($out | Select-Object -Last 2) -join ' | ')" -ForegroundColor DarkYellow
    }
}
$ErrorActionPreference = 'Stop'
if (-not $Port) { Write-Host '   Регистрация не прошла — пришлите текст этого окна.' -ForegroundColor Red; exit 1 }   # код 1 — окно не пишет «Готово» (12521)
$pt = "$Dir\port.txt"
try { if (Test-Path $pt) { cmd /c "takeown /f `"$pt`" /a >nul 2>&1 & icacls `"$pt`" /reset >nul 2>&1 & attrib -r -h -s `"$pt`" >nul 2>&1"; Remove-Item $pt -Force }; [IO.File]::WriteAllText($pt, "$ph $Port $pcName`r`n") } catch { Write-Host "   port.txt не записан ($($_.Exception.Message)) — продолжаю" -ForegroundColor DarkYellow }
Write-Host "   НОМЕР КЛИЕНТА: $Port" -ForegroundColor Green

Write-Host '6/7 Задача «Claude туннель» (от SYSTEM, при включении ПК и каждую минуту, если оборвался)...' -ForegroundColor Cyan
$targ = "-N -T $base $($ok.kh) -i $($ok.t) -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -E $D/ssh.log -R 127.0.0.1:${Port}:127.0.0.1:22 {{TUNNEL_USER}}@$Srv"
$act = New-ScheduledTaskAction -Execute $ssh -Argument $targ
$trg = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)))
$set = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Stop-Tunnel
Unregister-ScheduledTask -TaskName '{{TASK_NAME}}' -Confirm:$false -EA 0
Register-ScheduledTask -TaskName '{{TASK_NAME}}' -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Description "Туннель на сервер {{SRV_NAME}} для специалиста: номер клиента $Port, ПК $pcName, сотовый $ph (общий РЕЛИЗ 9). Отключить — правой кнопкой -> Отключить." | Out-Null
Remove-Item "$Dir\ssh.log" -EA 0
Start-ScheduledTask -TaskName '{{TASK_NAME}}'

Write-Host '7/7 Проверка (сервер вписывает новый ключ до 1 минуты)...' -ForegroundColor Cyan
$desk = [Environment]::GetFolderPath('Desktop')
Get-ChildItem $desk -Filter 'Туннель Claude*.ps1' -EA 0 | Remove-Item -EA 0
$up = $false
for ($i = 1; $i -le 24 -and -not $up; $i++) {
    Start-Sleep 5
    $p = Get-TunnelPids | Select-Object -First 1
    if ($p) { Start-Sleep 8; $up = [bool](Get-Process -Id $p -EA 0) }
    if (-not $up -and $i % 4 -eq 0) { Start-ScheduledTask -TaskName '{{TASK_NAME}}' -EA 0; Write-Host "   жду... ($($i * 5) с)" }
}
# РЕЛИЗ 7 (правило 9784): на каждом новом ПК сразу проверка на вирусы Защитником БЕЗ удаления (активаторы не трогаем, 6549);
#   идёт в фоне от SYSTEM, после перезагрузки продолжает сама, пока в журнале нет DONE (урок одного ПК: перезагрузка оборвала проверку)
try {
    $vo = "$env:SystemRoot\Temp\claude_chk"; New-Item -ItemType Directory -Force $vo | Out-Null
    $vs = @'
# Проверка на вирусы Защитником БЕЗ удаления и карантина (-DisableRemediation): только список находок. РЕЛИЗ 2
$o = "$env:SystemRoot\Temp\claude_chk"; $log = "$o\scan.log"; $mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
if ((Test-Path $log) -and (Select-String -Path $log -Pattern '^DONE' -Quiet)) { return }
if (-not (Test-Path $mp)) { "NO DEFENDER $(Get-Date -f 'dd.MM HH:mm:ss')" | Out-File $log -Append -Encoding utf8; return }
"START $(Get-Date -f 'dd.MM HH:mm:ss')" | Out-File $log -Append -Encoding utf8
& $mp -SignatureUpdate 2>&1 | Out-File $log -Append -Encoding utf8
foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\' })) {
    "=== $d $(Get-Date -f 'HH:mm:ss')" | Out-File $log -Append -Encoding utf8
    & $mp -Scan -ScanType 3 -File $d -DisableRemediation 2>&1 | Out-File $log -Append -Encoding utf8
    "=== $d конец $(Get-Date -f 'HH:mm:ss') код $LASTEXITCODE" | Out-File $log -Append -Encoding utf8
}
"DONE $(Get-Date -f 'dd.MM HH:mm:ss')" | Out-File $log -Append -Encoding utf8
'@
    [IO.File]::WriteAllText("$vo\scan.ps1", $vs, (New-Object Text.UTF8Encoding $true))
    $vn = 'Claude проверка вирусов'
    if (-not (Get-ScheduledTask -TaskName $vn -EA 0)) {
        $va = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$vo\scan.ps1`""
        $vset = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 24) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $vn -Action $va -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $vset -User 'SYSTEM' -RunLevel Highest -Description 'Проверка на вирусы для специалиста Claude: Защитник БЕЗ удаления, только список находок. После DONE в журнале ничего не делает.' | Out-Null
    }
    if ((Get-ScheduledTask -TaskName $vn).State -ne 'Running') { Start-ScheduledTask -TaskName $vn }
    Write-Host "Проверка на вирусы запущена в фоне (без удаления), журнал: $vo\scan.log" -ForegroundColor Green
} catch { Write-Host "Проверка на вирусы не запустилась: $($_.Exception.Message)" -ForegroundColor Yellow }
try { [IO.File]::WriteAllText((Join-Path $desk "Номер для специалиста $Port.txt"), "Номер для специалиста: $Port`r`nПК: $pcName`r`nRustDesk: $rdId`r`n", (New-Object Text.UTF8Encoding $true)) } catch {}
if ($up) { Write-Host "`nГотово: туннель работает. НОМЕР КЛИЕНТА: $Port (ПК $pcName). Можно отключаться." -ForegroundColor Green }
else {
    Write-Host "`nТуннель пока не поднялся. Номер клиента $Port, ПК $pcName." -ForegroundColor Red
    if (Test-Path "$Dir\ssh.log") { Read-Shared "$Dir\ssh.log" 6 | ForEach-Object { Write-Host "   $_" } }
    Write-Host 'Пришлите текст этого окна.' -ForegroundColor Red
}
}
