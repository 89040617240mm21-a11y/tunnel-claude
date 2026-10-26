# Свой сервер туннелей за 15 минут (Windows Server)

Сервер нужен один: к нему ПК клиентов сами держат **исходящее** SSH-соединение, а специалист заходит к клиенту через этот сервер.
На роутере и в брандмауэре клиента ничего открывать не надо.

```
ПК клиента ──(исходящий SSH, порт 22022)──► ваш сервер ◄──(SSH по ключу)── специалист
           обратный туннель: 127.0.0.1:<личный порт клиента> на сервере → порт 22 ПК клиента
```

Как устроено:

- **отдельная служба `sshd_tunnel`** со своим конфигом и портом (22022). Обычный SSH сервера не трогается;
- **`claude_enroll`** — пользователь для регистрации. Все копии программы входят под ним **общим ключом регистрации**.
  Вход сразу запускает `tunnel_enroll.ps1` (`ForceCommand`), и больше ничего сделать нельзя. Скрипт выдаёт ПК личный порт и записывает его личный ключ. Ещё он принимает текстовый лог ошибок, с лимитами;
- **`claude_tunnel`** — пользователь для самих туннелей. Ключ каждого ПК может только одно: открыть свой порт на `127.0.0.1` сервера (`permitlisten`). Нет ни консоли, ни выхода в сеть;
- задача SYSTEM раз в минуту собирает `tunnel_authorized_keys` из реестра регистраций `tunnels\ports.csv` (`tunnel_build_keys.ps1`).

> Ключ регистрации общий: он вшит в каждую копию программы и потому не секретный. Его права намеренно урезаны до «выдать порт».
> Вход на ПК клиента — только по ключам специалистов из `profile.ini`, пароли выключены.

## 1. OpenSSH Server

Команды ниже — в PowerShell от администратора.

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Stop-Service sshd   # первый запуск создаёт ключи сервера в C:\ProgramData\ssh
```

## 2. Два пользователя без прав администратора

Пароль случайный и длинный: входа по паролю всё равно нет.

```powershell
foreach ($u in 'claude_tunnel', 'claude_enroll') {
    $p = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
    New-LocalUser $u -Password $p -PasswordNeverExpires -UserMayNotChangePassword
}
New-Item -ItemType Directory -Force C:\ProgramData\ssh\tunnels\logs | Out-Null
icacls C:\ProgramData\ssh\tunnels /grant 'claude_enroll:(OI)(CI)M' | Out-Null
```

## 3. Ключ регистрации

Ключ создаётся у вас, в папке проекта, рядом с `profile.ini`:

```powershell
ssh-keygen -t ed25519 -f enroll_key -N '""' -C enroll
```

Строку из `enroll_key.pub` впишите на сервере в `C:\ProgramData\ssh\enroll_authorized_keys`, с приставкой `restrict`:

```
restrict ssh-ed25519 AAAA...ваш_ключ... enroll
```

Затем оставьте доступ к файлу только SYSTEM и Администраторам:

```powershell
icacls C:\ProgramData\ssh\enroll_authorized_keys /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F'
```

## 4. Скрипты, конфиг, служба, задача

Скопируйте в `C:\ProgramData\ssh\` три файла из этой папки: `tunnel_enroll.ps1`, `tunnel_build_keys.ps1` и `sshd_tunnel_config`. Порт в конфиге можно поменять.

```powershell
sc.exe create sshd_tunnel binPath= '"C:\Windows\System32\OpenSSH\sshd.exe" -f C:\ProgramData\ssh\sshd_tunnel_config' start= auto DisplayName= 'OpenSSH туннели клиентов'
New-NetFirewallRule -DisplayName 'SSH туннели 22022' -Direction Inbound -Protocol TCP -LocalPort 22022 -Action Allow
$a = New-ScheduledTaskAction powershell.exe '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\ssh\tunnel_build_keys.ps1'
$t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask 'Туннели — ключи' -Action $a -Trigger $t -User SYSTEM -RunLevel Highest
Start-ScheduledTask 'Туннели — ключи'; Start-Service sshd_tunnel
```

Проверьте с любого ПК. Ответ `ERR формат` значит, что сервер готов:

```powershell
ssh -i enroll_key -p 22022 claude_enroll@ВАШ_IP test
```

## 5. Профиль и сборка

1. Скопируйте `profile.example.ini` в `profile.ini`.
2. Впишите в него:
   - `host` и `port`;
   - строки `[hostkeys]` из `ssh-keyscan -p 22022 ВАШ_IP`, заменив адрес в начале строки на значение `host_alias`;
   - ключи специалистов `[key.N]`;
   - свои серверы `[server.N]`.
3. Положите установщик `OpenSSH-Win64-v9.5.0.0.msi` с [PowerShell/Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/releases) по адресу `files_url`. Он нужен ПК, где SSH не ставится из Windows.
4. Соберите: `powershell -ExecutionPolicy Bypass -File build.ps1` — получится `TunnelClaude.exe`.

## 6. Как специалист заходит к клиенту

Клиент диктует «Номер для специалиста» — это его личный порт. Специалист входит через обычный SSH сервера (`-J`):

```powershell
ssh -J админ@ВАШ_IP -p <номер> <администратор_ПК_клиента>@127.0.0.1
```

Кто, когда, откуда и что делал, видно в журнале на рабочем столе клиента. Клиент сам выключает туннель кнопкой «ВЫКЛЮЧИТЬ».

Привязать сотовый к уже выданному номеру: строка в `tunnels\ports.csv` выглядит так — `сотовый;порт;ключ;дата;адрес;ПК;RustDesk`.
Вместо сотового там может стоять «0».

> Инструкция составлена по рабочему серверу авторов. Если на чистом сервере какой-то шаг не прошёл, напишите в Issues.
