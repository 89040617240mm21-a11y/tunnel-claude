Add-Type -AssemblyName System.Drawing
$b = New-Object Drawing.Bitmap 64,64; $g = [Drawing.Graphics]::FromImage($b); $g.SmoothingMode = 'AntiAlias'
$g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(25,140,55))), 2, 2, 60, 60)
$p = New-Object Drawing.Pen ([Drawing.Color]::White), 7
$g.DrawArc($p, 14, 18, 36, 40, 180, 180); $g.DrawLine($p, 14, 38, 14, 54); $g.DrawLine($p, 50, 38, 50, 54)
$g.FillEllipse([Drawing.Brushes]::White, 27, 34, 10, 10)
$ms = New-Object IO.MemoryStream; $b.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $png = $ms.ToArray()
$o = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $o
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]1)
$w.Write([byte]64); $w.Write([byte]64); $w.Write([byte]0); $w.Write([byte]0); $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$png.Length); $w.Write([uint32]22); $w.Write($png)
[IO.File]::WriteAllBytes("$PSScriptRoot\tunnel.ico", $o.ToArray())
