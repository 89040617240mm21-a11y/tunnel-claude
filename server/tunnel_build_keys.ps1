# Сборка ключей туннелей — РЕЛИЗ 3 (строки без сотового «0» тоже). РЕЛИЗ 2 (права файла — только SYSTEM и Администраторы, иначе sshd: «Authentication refused»). РЕЛИЗ 1 (19.10.2026). Задача SYSTEM «Туннели — ключи», раз в минуту.
# tunnel_authorized_keys = постоянные строки (tunnel_static_keys) + по строке на каждую регистрацию из tunnels\ports.csv.
$ErrorActionPreference = 'Stop'
$s = 'C:\ProgramData\ssh'
$out = @(Get-Content "$s\tunnel_static_keys" -EA 0 | ? { $_.Trim() })
foreach ($r in (Get-Content "$s\tunnels\ports.csv" -EA 0)) {
    if ($r -match '^(7\d{10}|0);(\d{5});(ssh-ed25519 [A-Za-z0-9+/]{68});') {
        $out += "restrict,port-forwarding,permitlisten=`"127.0.0.1:$($Matches[2])`" $($Matches[3]) tunnel-$($Matches[1])-$($Matches[2])"
    }
}
$new = ($out -join "`n") + "`n"
$f = "$s\tunnel_authorized_keys"
if ((Test-Path $f) -and ([IO.File]::ReadAllText($f) -eq $new)) { return }
[IO.File]::WriteAllText("$f.tmp", $new)
icacls "$f.tmp" /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null
Move-Item "$f.tmp" $f -Force
