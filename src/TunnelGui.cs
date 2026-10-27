// Мост (Туннель Claude) — окно для клиента: проверка ПК встроенным Защитником Windows (без удаления, с отчётом) и обратный SSH-туннель
// для удалённого обслуживания 1С. Кнопки ВКЛЮЧИТЬ / ВЫКЛЮЧИТЬ / ПОЧИНИТЬ, крупный статус «туннель поднят или нет и почему»,
// пинг до серверов специалистов (с флагами), Radmin VPN как запасной путь, снимок окна, журнал «кто заходил и что делал»
// на рабочем столе (понятен любому ИИ), лог запуска и ошибок специалистам (галочка). Установку делает встроенный скрипт туннеля.
// Всё «своё» (сервер, порт, ключи специалистов, отпечаток сервера, серверы с флагами) — в profile.ini, он вшивается при сборке (build.ps1).
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

static class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        bool first; var show = new EventWaitHandle(false, EventResetMode.AutoReset, "Local\\ClaudeTunnelGuiShow", out first);
        if (!first && !Environment.GetCommandLineArgs().Any(a => a.StartsWith("--demo"))) { show.Set(); return; }   // уже запущена — показать её окно
        var f = new MainForm();
        new Thread(() => { while (true) { show.WaitOne(); try { f.BeginInvoke(new Action(f.FromTray)); } catch { } } }) { IsBackground = true }.Start();
        Application.Run(f);
    }
}

class Srv
{
    public string Name, Ip, Radmin; public int TcpPort; public Bitmap Flag;
    public Srv(string name, string ip, string radmin, int tcpPort, Bitmap flag) { Name = name; Ip = ip; Radmin = radmin; TcpPort = tcpPort; Flag = flag; }
}

class Row
{
    public string Name, Value; public int St;   // St: 0 красный, 1 зелёный, 2 жёлтый, 3 серый
    public Row(string n, string v, int s) { Name = n; Value = v; St = s; }
}

class Result
{
    public List<Row> Rows = new List<Row>();
    public List<string[]> Pings = new List<string[]>();
    public int Overall; public string Head = "", Port = "", Radmin = "", Pc = "";
    public int TaskSt;
}

class MainForm : Form
{
    // профиль сборки (profile.ini, вшит ресурсом): сервер, порт, имена, ключи специалистов, серверы с флагами
    static readonly Profile Pf = Profile.Load();
    static readonly string Rel = Pf.Get("rel", "версия 102");
    static readonly string AppName = Pf.Get("app_name", "Мост");   // имя в окне и журнале (Михаил, 12483, 12501)
    static readonly string AppSub = Pf.Get("app_sub", "");   // мелкая подпись после имени: «Мост · для ИИ Агента» (Михаил, 12528)
    static readonly string SrvIp = Pf.Get("host", ""); static readonly int SrvPort = int.Parse(Pf.Get("port", "22")); static readonly string TaskName = Pf.Get("task_name", "Claude туннель");
    static readonly string SN = Pf.Get("srv_name", "поддержки"), HostAlias = Pf.Get("host_alias", "claude16");
    static readonly string TunnelUser = Pf.Get("tunnel_user", "claude_tunnel"), EnrollUser = Pf.Get("enroll_user", "claude_enroll");
    static readonly string Org = Pf.Get("org", "специалисты поддержки"), JournalName = Pf.Get("journal", "Журнал доступа Claude.txt");
    static readonly string SourceUrl = Pf.Get("source_url", "https://github.com/oblako-tech/tunnel-claude");   // открытый код: клиент сам видит, что делает программа
    static readonly string Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ClaudeTunnel");
    static readonly string JournalPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), JournalName);
    static readonly object jlock = new object();

    // известные ключи специалистов: отпечаток -> кто
    static readonly Dictionary<string, string> Keys = new Dictionary<string, string>();
    static void AddKey(string blob, string who)
    {
        try { using (var sha = SHA256.Create()) Keys["SHA256:" + Convert.ToBase64String(sha.ComputeHash(Convert.FromBase64String(blob))).TrimEnd('=')] = who; }
        catch (FormatException) { }   // в профиле не ключ (например, заготовка из profile.example.ini) — пропускаем
    }

    Label lblStatus, lblInfo, lblPhone; TextBox txtPhone, txtLog; ListView lvSrv, lvChk; CheckBox chkSend;
    Button bOn, bOff, bFix, bShot, bCopy, bJournal;
    System.Windows.Forms.Timer tm; volatile bool checking, busy;
    // ход установки для компактного окна (Михаил, 12489): шаг N из 7, полоса до 100 % (первый шаг — RustDesk, 12503), последняя строка скрипта
    static readonly string[] StepNames = { "запускаю установку", "RustDesk", "SSH на этом ПК", "программа ssh", "личный ключ ПК", "регистрация на сервере", "задача автозапуска", "проверка связи" };
    int stepN; string stepLine = ""; double prog, progShown; DateTime doneAt = DateTime.MinValue; bool doneOk; System.Windows.Forms.Timer anim;
    static readonly bool IsAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    static bool Demo { get { return Environment.GetCommandLineArgs().Any(a => a.StartsWith("--demo")); } }
    bool autoTried;
    NotifyIcon tray; bool quitting, trayTold, autoOn; CheckBox chkAuto; Rectangle rAuto;
    static readonly string AutoTask = Pf.Get("auto_task", AppName + " окно");   // имя задачи не меняем вместе с именем программы — иначе старая задача запустит вторую копию   // задача «запуск при входе в Windows» (по галочке)
    bool ShowProg { get { return busy || (DateTime.Now - doneAt).TotalSeconds < 5; } }
    Srv[] servers; Result last;
    // компактный вид (Михаил, 12479): тумблер, номер для специалиста, 3 шага; «Подробно» — прежнее окно с таблицами
    Panel pCompact; LinkLabel lnkSrc; Control[] full; bool copiedFlag; DateTime copiedAt;
    bool copied { get { return copiedFlag; } set { copiedFlag = value; if (value) copiedAt = DateTime.Now; } }

    public MainForm()
    {
        foreach (var k in Pf.Sections("key")) AddKey(k.Get("blob", ""), k.Get("label", ""));
        servers = Pf.Sections("server").Select(s => new Srv(s.Get("name", ""), s.Get("ip", ""), s.Get("radmin", ""), int.Parse(s.Get("tcp", "0")), FlagBy(s.Get("flag", "")))).ToArray();

        Text = AppName + " — " + Rel + " — ПК " + Environment.MachineName + (IsAdmin ? " — права администратора ✓" : " — БЕЗ прав администратора");
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        Font = new Font("Segoe UI", 11f);
        ClientSize = new Size(940, 860); MinimumSize = new Size(760, 640);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;

        lblStatus = new Label { Dock = DockStyle.Top, Height = 96, Font = new Font("Segoe UI", 19f, FontStyle.Bold), ForeColor = Color.White, BackColor = Color.Gray, TextAlign = ContentAlignment.MiddleCenter, Text = "Проверяю..." };
        lblInfo = new Label { Dock = DockStyle.Top, Height = 62, Font = new Font("Segoe UI", 13f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(10, 0, 0, 0) };

        var pPhone = new Panel { Dock = DockStyle.Top, Height = 42, Padding = new Padding(10, 6, 10, 4) };
        lblPhone = new Label { Text = "Ваш сотовый (необязательно):", AutoSize = true, Location = new Point(10, 10) };
        txtPhone = new TextBox { Location = new Point(250, 7), Width = 200 };
        chkSend = new CheckBox { Text = "Отправлять лог специалистам", AutoSize = true, Location = new Point(475, 9), Checked = !File.Exists(NoLogFlag) };
        new ToolTip { AutoPopDelay = 20000 }.SetToolTip(chkSend, "Программа отправляет на наш сервер " + SN + " состояние туннеля и текст ошибок (без паролей и ваших файлов).\nБез этого мы не увидим, почему туннель не поднялся, — придётся присылать снимок.");
        chkSend.CheckedChanged += delegate
        {
            try { Directory.CreateDirectory(GuiDir); if (chkSend.Checked) File.Delete(NoLogFlag); else File.WriteAllText(NoLogFlag, "лог специалистам выключен " + DateTime.Now); } catch { }
            Journal(null, chkSend.Checked ? "ЛОГ СПЕЦИАЛИСТАМ ВКЛЮЧЁН" : "ЛОГ СПЕЦИАЛИСТАМ ВЫКЛЮЧЕН", "клиент (галочка)", "этот ПК", "");
            sendInfo = chkSend.Checked ? "включено" : "выключено галочкой — специалисты не увидят причину ошибки"; sendSt = 3;
        };
        autoOn = AutoGet();
        chkAuto = new CheckBox { Text = "Запуск с Windows", AutoSize = true, Location = new Point(745, 9), Checked = autoOn };
        chkAuto.CheckedChanged += delegate { if (chkAuto.Checked != autoOn) AutoSet(chkAuto.Checked); };
        pPhone.Controls.Add(lblPhone); pPhone.Controls.Add(txtPhone); pPhone.Controls.Add(chkSend); pPhone.Controls.Add(chkAuto);

        var pBtn = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 64, Padding = new Padding(6, 6, 6, 4), WrapContents = false, AutoScroll = true };
        bOn = Btn("ВКЛЮЧИТЬ", Color.FromArgb(30, 140, 60), 150);
        bOff = Btn("ВЫКЛЮЧИТЬ", Color.FromArgb(190, 40, 40), 150);
        bFix = Btn("ПОЧИНИТЬ", Color.FromArgb(40, 90, 170), 140);
        bShot = Btn("СНИМОК ДЛЯ НАС", Color.FromArgb(90, 90, 90), 180);
        bCopy = Btn("Копировать текст", Color.FromArgb(120, 120, 120), 160);
        bJournal = Btn("Журнал", Color.FromArgb(120, 120, 120), 100);
        pBtn.Controls.AddRange(new Control[] { bOn, bOff, bFix, bShot, bCopy, bJournal });
        bOn.Click += delegate { DoOn(); };
        bOff.Click += delegate { DoOff(); };
        bFix.Click += delegate { RunSetup("ПОЧИНИТЬ"); };
        bShot.Click += delegate { DoShot(); };
        bCopy.Click += delegate { try { Clipboard.SetText(Report()); MessageBox.Show(this, "Текст скопирован. Вставьте его в WhatsApp (Ctrl+V) и отправьте нам.", Text); } catch { } };
        bJournal.Click += delegate { EnsureJournal(); try { Process.Start("notepad.exe", "\"" + JournalPath + "\""); } catch { } };

        var flags = new ImageList { ImageSize = new Size(36, 24), ColorDepth = ColorDepth.Depth32Bit };
        foreach (var s in servers) flags.Images.Add(s.Flag);
        lvSrv = new ListView { Dock = DockStyle.Top, Height = 128, View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, SmallImageList = flags, Font = new Font("Segoe UI", 12f) };
        lvSrv.Columns.Add("Наши серверы", 330); lvSrv.Columns.Add("Пинг через интернет", 250); lvSrv.Columns.Add("Пинг через Radmin VPN", 300);
        for (int i = 0; i < servers.Length; i++) { var it = new ListViewItem(servers[i].Name, i); it.SubItems.Add("..."); it.SubItems.Add("..."); lvSrv.Items.Add(it); }

        var dots = new ImageList { ImageSize = new Size(20, 20), ColorDepth = ColorDepth.Depth32Bit };
        foreach (var c in new[] { Color.FromArgb(210, 40, 40), Color.FromArgb(30, 160, 60), Color.FromArgb(230, 160, 0), Color.Gray }) dots.Images.Add(Dot(c));
        lvChk = new ListView { Dock = DockStyle.Top, Height = 290, View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, SmallImageList = dots, Font = new Font("Segoe UI", 12f) };
        lvChk.Columns.Add("Проверка", 300); lvChk.Columns.Add("Результат", 600);

        // ссылка на открытый код — главная защита доверия: любой может проверить, что программа делает и чего не делает
        lnkSrc = new LinkLabel { Dock = DockStyle.Bottom, Height = 34, Font = new Font("Segoe UI", 11f), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(10, 0, 0, 0),
            Text = "Открытый код программы (проверить, что она делает): " + SourceUrl };
        lnkSrc.LinkArea = new LinkArea(lnkSrc.Text.Length - SourceUrl.Length, SourceUrl.Length);
        lnkSrc.LinkClicked += delegate { try { Process.Start(SourceUrl); } catch { } };
        Controls.Add(lnkSrc);

        txtLog = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 10f), BackColor = Color.FromArgb(245, 245, 245) };

        // полоска над логом — тянуть мышью вверх, чтобы лог хода установки был больше (Михаил, 12490)
        var split = new Splitter { Dock = DockStyle.Top, Height = 8, MinSize = 60, MinExtra = 80, BackColor = Color.FromArgb(214, 160, 90) };
        Controls.Add(txtLog); Controls.Add(split); Controls.Add(lvChk); Controls.Add(lvSrv); Controls.Add(pBtn); Controls.Add(pPhone); Controls.Add(lblInfo); Controls.Add(lblStatus);
        full = new Control[] { txtLog, split, lvChk, lvSrv, pBtn, pPhone, lblInfo, lblStatus };
        BuildCompact();

        txtPhone.Text = GuessPhone();
        Log("Программа «" + AppName + "» " + Rel + ". Журнал входов: " + JournalPath);
        EnsureJournal();
        tm = new System.Windows.Forms.Timer { Interval = 5000 };
        tm.Tick += delegate { StartCheck(); Combine(); };
        ThreadPool.QueueUserWorkItem(_ => ReadRdId());
        BuildTray();
        Shown += delegate
        {
            StartCheck(); tm.Start();
            if (!autoOn && !File.Exists(AutoOffFlag) && !Demo) AutoSet(true);
            bool startTray = Environment.GetCommandLineArgs().Contains("--autostart");
            if (File.Exists(SetupFlag) && (DateTime.Now - File.GetLastWriteTime(SetupFlag)).TotalHours < 24)
            {   // установку оборвала перезагрузка — доводим сами и показываем ход
                Log("Установка не была закончена (перезагрузка?) — продолжаю.");
                RunSetup("продолжение после перезагрузки");
            }
            else if (startTray) BeginInvoke(new Action(Hide));   // запуск с Windows — тихо в трей
        };
        Resize += delegate { FitColumns(); };
        FitColumns();
        SetMode(Environment.GetCommandLineArgs().Contains("--full"));   // человеку — только простое окно (Михаил, 12496–12498); подробный вид — ключом --full для специалиста
    }

    void BuildCompact()
    {
        // вид «Закат» (Михаил, 12483–12488): своё тёмное окно со скруглёнными углами, во всё окно картинка с мостом —
        // включено ярко, выключено тускло; поверх объёмная стеклянная карточка и золотая кнопка
        try { using (var st = Assembly.GetExecutingAssembly().GetManifestResourceStream("bg.jpg")) if (st != null) { bgOn = new Bitmap(st); bgOff = Dim(bgOn); } } catch { }
        pCompact = new Canvas { Dock = DockStyle.Fill, BackColor = Color.FromArgb(40, 30, 28), Visible = false };
        pCompact.Paint += (s, e) => PaintCompact(e.Graphics);
        pCompact.MouseLeave += delegate { hover = Point.Empty; pCompact.Invalidate(); };
        pCompact.MouseMove += (s, e) =>
        {
            hover = e.Location; pCompact.Invalidate(new Rectangle(0, 0, pCompact.Width, TitleH));
            pCompact.Cursor = rBtn.Contains(e.Location) || rCode.Contains(e.Location) && CodeShown || rLink.Contains(e.Location) || rAuto.Contains(e.Location) || rRd.Contains(e.Location) || rUpd.Contains(e.Location) || rPwNew.Contains(e.Location) ? Cursors.Hand : Cursors.Default;
        };
        pCompact.MouseDown += (s, e) =>   // тянем окно за верхнюю строку
        {
            if (e.Button == MouseButtons.Left && e.Y < TitleH && !rMin.Contains(e.Location) && !rMax.Contains(e.Location) && !rClose.Contains(e.Location))
            { ReleaseCapture(); SendMessage(Handle, 0xA1, (IntPtr)2, IntPtr.Zero); }
        };
        pCompact.MouseClick += (s, e) =>
        {
            if (rClose.Contains(e.Location)) Close();
            else if (rMin.Contains(e.Location)) WindowState = FormWindowState.Minimized;
                        else if (rBtn.Contains(e.Location)) { if (busy || last == null) return; if (last.TaskSt > 0 && last.Overall != 0) DoOff(); else DoOn(); }
            else if (rCode.Contains(e.Location) && CodeShown)
            {
                try { Clipboard.SetText(ClipCard()); copied = true; pCompact.Invalidate(); } catch { }
            }
            else if (rLink.Contains(e.Location)) { try { Process.Start(SourceUrl); } catch { } }
            else if (rAuto.Contains(e.Location)) { AutoSet(!autoOn); pCompact.Invalidate(); }
            else if (rPwNew.Contains(e.Location)) NewRdPassword();
            else if (rRd.Contains(e.Location)) OpenRustDesk();
            else if (rUpd.Contains(e.Location)) CheckUpdate(true);
        };
        Controls.Add(pCompact); pCompact.BringToFront();
        Resize += delegate { if (pCompact.Visible) Corners(); };

        var bBack = Btn("Компактно ▴", Color.FromArgb(120, 120, 120), 140);   // из подробного вида — обратно
        bBack.Click += delegate { SetMode(false); };
        bJournal.Parent.Controls.Add(bBack);
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool ReleaseCapture();
    [System.Runtime.InteropServices.DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
    [System.Runtime.InteropServices.DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int val, int size);
    protected override CreateParams CreateParams { get { var cp = base.CreateParams; cp.ClassStyle |= 0x20000; return cp; } }   // тень вокруг окна

    void Corners()   // скруглённые углы: Windows 11 рисует сама и гладко, на 7/10 — вырезаем окно по скруглённой рамке
    {
        int round = 2, r = -1;
        try { r = DwmSetWindowAttribute(Handle, 33, ref round, 4); } catch { }
        if (r == 0) { Region = null; return; }
        using (var path = Round(new RectangleF(0, 0, Width, Height), 12)) Region = new Region(path);
    }

    class Canvas : Panel { public Canvas() { DoubleBuffered = true; ResizeRedraw = true; } }
    const int TitleH = 40;
    Bitmap bgOn, bgOff; Rectangle rBtn, rCode, rMore, rLink, rMin, rMax, rClose, rRd, rUpd, rPwNew; Point hover;
    // 103.9 (12521): повтор установки раз в 5 минут, пока туннель не встанет; обновление программы на лету; RustDesk и его ID в окне
    static readonly string UpdateUrl = Pf.Get("update_url", "");   // без расширения: рядом лежат .exe и .txt («103.9 SHA256»)
    DateTime retryAt = DateTime.MinValue, updAt = DateTime.Now.AddSeconds(40); int retryN; volatile bool gotPort, updBusy; string updText = "", rdId = "", rdPw = ""; volatile bool rdBusy;
    bool CodeShown { get { return last != null && last.TaskSt > 0 && last.Port != ""; } }

    static Bitmap Dim(Bitmap src)   // «мост погас»: почти без цвета и темнее
    {
        var b = new Bitmap(src.Width, src.Height);
        float k = 0.45f, g = 0.25f;   // яркость и остаток цвета
        var m = new System.Drawing.Imaging.ColorMatrix(new[] {
            new[] { k * (0.3f + 0.7f * g), k * 0.3f * (1 - g), k * 0.3f * (1 - g), 0, 0 },
            new[] { k * 0.59f * (1 - g), k * (0.59f + 0.41f * g), k * 0.59f * (1 - g), 0, 0 },
            new[] { k * 0.11f * (1 - g), k * 0.11f * (1 - g), k * (0.11f + 0.89f * g), 0, 0 },
            new[] { 0f, 0, 0, 1, 0 }, new[] { 0f, 0, 0, 0, 1 } });
        using (var gr = Graphics.FromImage(b)) using (var ia = new System.Drawing.Imaging.ImageAttributes())
        { ia.SetColorMatrix(m); gr.DrawImage(src, new Rectangle(0, 0, b.Width, b.Height), 0, 0, src.Width, src.Height, GraphicsUnit.Pixel, ia); }
        return b;
    }

    static System.Drawing.Drawing2D.GraphicsPath Round(RectangleF r, float rad)
    {
        var p = new System.Drawing.Drawing2D.GraphicsPath(); float d = rad * 2;
        p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); p.CloseFigure(); return p;
    }

    static void Shadow(Graphics g, RectangleF r, float rad, int depth, int alpha)   // мягкая тень под предметом — «объём»
    {
        for (int i = depth; i >= 1; i--)
            using (var p = Round(new RectangleF(r.X - i * 0.6f, r.Y + i * 0.9f, r.Width + i * 1.2f, r.Height + i * 0.6f), rad + i * 0.6f))
            using (var br = new SolidBrush(Color.FromArgb(alpha / depth + 2, 0, 0, 0))) g.FillPath(br, p);
    }

    static void Text3D(Graphics g, string t, Font f, Brush br, RectangleF r, StringFormat sf)   // буквы с тенью
    {
        using (var sh = new SolidBrush(Color.FromArgb(130, 0, 0, 0))) g.DrawString(t, f, sh, new RectangleF(r.X + 1, r.Y + 2, r.Width, r.Height), sf);
        g.DrawString(t, f, br, r, sf);
    }

    void PaintProgress(Graphics g, RectangleF card, StringFormat center)
    {   // «Шаг 4 из 7 · личный ключ ПК», под ней золотая полоса с процентами и последняя строка скрипта
        bool done = !busy;
        int pc = done && doneOk ? 100 : (int)Math.Round(Math.Min(progShown, 0.99) * 100);
        string st = done ? (doneOk ? "Готово · шаг 7 из 7" : retryAt != DateTime.MinValue ? "Не вышло · повтор в " + retryAt.ToString("HH:mm") : "Установка не закончена") : "Шаг " + Math.Max(stepN, 0) + " из 7 · " + StepNames[Math.Min(stepN, 7)];
        using (var f = new Font("Segoe UI", 13.5f, FontStyle.Bold)) Text3D(g, st, f, Brushes.White, new RectangleF(card.X, card.Y + 64, card.Width, 28), center);
        var tr = new RectangleF(card.X + 26, card.Y + 100, card.Width - 52 - 58, 16);
        using (var p = Round(tr, 8))
        {
            using (var br = new SolidBrush(Color.FromArgb(120, 0, 0, 0))) g.FillPath(br, p);
            using (var pen = new Pen(Color.FromArgb(70, 255, 236, 205))) g.DrawPath(pen, p);
        }
        float fw = tr.Width * pc / 100f;
        if (fw >= 8)
        {
            var fr = new RectangleF(tr.X, tr.Y, fw, tr.Height);
            Color c1 = done && !doneOk ? Color.FromArgb(250, 120, 100) : Color.FromArgb(255, 214, 110), c2 = done && !doneOk ? Color.FromArgb(190, 50, 40) : Color.FromArgb(222, 126, 18);
            using (var p = Round(fr, 8)) using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(fr, c1, c2, 90f)) g.FillPath(lg, p);
            var gl = new RectangleF(fr.X + 2, fr.Y + 1, Math.Max(fr.Width - 4, 1), fr.Height * 0.45f);
            using (var p = Round(gl, 5)) using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(gl, Color.FromArgb(120, 255, 255, 255), Color.FromArgb(10, 255, 255, 255), 90f)) g.FillPath(lg, p);
        }
        using (var f = new Font("Segoe UI", 12.5f, FontStyle.Bold))
            Text3D(g, pc + " %", f, Brushes.White, new RectangleF(tr.Right + 4, tr.Y - 6, 58, 28), new StringFormat { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
        using (var f = new Font("Segoe UI", 9.5f)) using (var br = new SolidBrush(Color.FromArgb(255, 222, 180)))
            g.DrawString(stepLine, f, br, new RectangleF(card.X + 16, card.Y + 122, card.Width - 32, 22), new StringFormat(center) { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap });
    }

    void PaintCompact(Graphics g)
    {
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias; g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
        int w = pCompact.ClientSize.Width, h = pCompact.ClientSize.Height, ih = h - TitleH;
        bool on = last != null && last.TaskSt > 0, lit = on && last.Overall == 1;
        var bg = lit ? bgOn : bgOff;
        if (bg != null)
        {   // картинка по ширине окна под тёмной строкой заголовка
            float sc = Math.Max((float)w / bg.Width, (float)ih / bg.Height);
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            g.DrawImage(bg, (w - bg.Width * sc) / 2, TitleH, bg.Width * sc, bg.Height * sc);
        }
        else using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(new Rectangle(0, TitleH, w, ih), Color.FromArgb(lit ? 250 : 120, lit ? 150 : 110, lit ? 60 : 100), Color.FromArgb(40, 30, 28), 90f)) g.FillRectangle(lg, 0, TitleH, w, ih);
        var center = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };

        // верхняя строка — тёмная, как на наброске: значок, имя, свёрнуть / подробно / закрыть
        using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(new Rectangle(0, 0, w, TitleH), Color.FromArgb(58, 54, 54), Color.FromArgb(38, 35, 35), 90f)) g.FillRectangle(lg, 0, 0, w, TitleH);
        using (var pen = new Pen(Color.FromArgb(90, 0, 0, 0))) g.DrawLine(pen, 0, TitleH - 1, w, TitleH - 1);
        try { using (var ic = new Icon(Icon, 24, 24)) g.DrawIcon(ic, new Rectangle(12, (TitleH - 24) / 2, 24, 24)); } catch { }
        float nameW;
        using (var f = new Font("Segoe UI", 11.5f, FontStyle.Bold)) { g.DrawString(AppName, f, Brushes.White, 44, (TitleH - f.Height) / 2f); nameW = g.MeasureString(AppName, f).Width; }
        if (AppSub != "") using (var f = new Font("Segoe UI", 9.5f)) using (var br = new SolidBrush(Color.FromArgb(200, 200, 200)))
        { g.DrawString(AppSub, f, br, 44 + nameW - 2, (TitleH - f.Height) / 2f + 1); nameW += g.MeasureString(AppSub, f).Width; }
        using (var f = new Font("Segoe UI", 9.5f, FontStyle.Bold))
        {   // плашка прав: зелёная «админ ✓» или красная «нет прав админа»
            string at = IsAdmin ? "админ ✓" : "нет прав админа";
            float ax = 44 + nameW + 8;
            var sz = g.MeasureString(at, f); var ar = new RectangleF(ax, (TitleH - 22) / 2f, sz.Width + 12, 22);
            using (var pth = Round(ar, 11)) using (var br = new SolidBrush(IsAdmin ? Color.FromArgb(46, 140, 60) : Color.FromArgb(196, 43, 28))) g.FillPath(br, pth);
            g.DrawString(at, f, Brushes.White, ar.X + 6, ar.Y + (22 - sz.Height) / 2);
        }
        rClose = new Rectangle(w - 46, 0, 46, TitleH); rMax = Rectangle.Empty; rMin = new Rectangle(w - 92, 0, 46, TitleH);   // «развернуть» убрана: подробного вида у человека нет
        foreach (var rb in new[] { rMin, rClose })
            if (rb.Contains(hover)) using (var br = new SolidBrush(rb == rClose ? Color.FromArgb(220, 196, 43, 28) : Color.FromArgb(40, 255, 255, 255))) g.FillRectangle(br, rb);
        using (var pen = new Pen(Color.FromArgb(225, 225, 225), 1.2f))
        {
            float cy = TitleH / 2f;
            g.DrawLine(pen, rMin.X + 18, cy, rMin.X + 28, cy);
            g.DrawLine(pen, rClose.X + 18, cy - 5, rClose.X + 28, cy + 5); g.DrawLine(pen, rClose.X + 28, cy - 5, rClose.X + 18, cy + 5);
        }

        // стеклянная карточка с тенью и светлой кромкой сверху
        var card = new RectangleF(w * 0.085f, TitleH + ih * 0.47f, w * 0.83f, ih * 0.43f);
        Shadow(g, card, 18, 10, 110);
        using (var p = Round(card, 18))
        {
            using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(card, Color.FromArgb(120, 70, 55, 48), Color.FromArgb(165, 22, 17, 14), 90f)) g.FillPath(lg, p);
            using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(card, Color.FromArgb(150, 255, 236, 205), Color.FromArgb(25, 255, 236, 205), 90f))
            using (var pen = new Pen(lg, 1.6f)) g.DrawPath(pen, p);
        }

        Color[] dot = { Color.FromArgb(240, 70, 60), Color.FromArgb(90, 230, 90), Color.FromArgb(255, 190, 40), Color.FromArgb(170, 170, 170) };
        string head = busy ? Pf.Get("state_busy", AppName + " открывается") : lit ? Pf.Get("state_on", AppName + " открыт") : Pf.Get("state_off", AppName + " закрыт");   // два слова (Михаил, 12487); у имени другого рода — свои слова в профиле (12504), подробности — строкой ниже
        using (var f = new Font("Segoe UI", 24f, FontStyle.Bold))
        {
            var sz = g.MeasureString(head, f); float x = (w - sz.Width - 30) / 2, y = card.Y + 18, cy = y + sz.Height / 2;
            var dc = last == null ? dot[3] : busy ? dot[2] : !on ? dot[3] : dot[last.Overall];
            using (var br = new SolidBrush(Color.FromArgb(70, dc))) g.FillEllipse(br, x - 5, cy - 14, 28, 28);   // свечение
            using (var path = new System.Drawing.Drawing2D.GraphicsPath())
            {   // шарик: светлый блик слева сверху
                path.AddEllipse(x, cy - 9, 18, 18);
                using (var pg = new System.Drawing.Drawing2D.PathGradientBrush(path) { CenterPoint = new PointF(x + 6, cy - 4), CenterColor = ControlPaint.Light(dc, 0.8f), SurroundColors = new[] { dc } }) g.FillPath(pg, path);
            }
            Text3D(g, head, f, Brushes.White, new RectangleF(x + 28, y, sz.Width + 4, sz.Height), new StringFormat());
        }
        string code = last == null ? "проверяю..." : busy ? "подождите..." : lit && CodeShown ? "Номер: " + last.Port : !on ? "нажмите «Включить»" : last.Overall == 2 ? "подключаюсь..." : "нет связи — нажмите «Включить»";
        rCode = new Rectangle((int)card.X, (int)card.Y + 72, (int)card.Width, 56);
        if (ShowProg) PaintProgress(g, card, center);
        else using (var f = new Font("Segoe UI", lit && CodeShown ? 25f : 14f, FontStyle.Bold)) Text3D(g, code, f, Brushes.White, rCode, center);
        if (!ShowProg && CodeShown && copied)
            using (var f = new Font("Segoe UI", 10.5f)) using (var br = new SolidBrush(Color.FromArgb(255, 215, 160)))
                g.DrawString("Скопировано — вставьте в чат (Ctrl+V)", f, br, new RectangleF(card.X, card.Y + 124, card.Width, 22), center);
        // под номером — призыв: снимок окна в чат, агент по ID и номеру сразу сопоставит клиента и его ПК (Михаил, 12554–12555)
        else if (!ShowProg && lit && CodeShown)
            using (var f = new Font("Segoe UI", 10.5f, FontStyle.Bold)) using (var br = new SolidBrush(Color.FromArgb(255, 236, 140)))
                Text3D(g, "Сфотографируйте это окно и отправьте специалисту в чат", f, br, new RectangleF(card.X + 12, card.Y + 124, card.Width - 24, 44), center);

        // золотая кнопка: тень, градиент, стеклянный блик сверху, тёмная кромка
        rBtn = new Rectangle((int)card.X + 24, (int)(card.Bottom - 78), (int)card.Width - 48, 58);
        bool off = on && last.Overall != 0, hot = rBtn.Contains(hover) && !busy;
        Shadow(g, rBtn, 14, 6, 120);
        using (var p = Round(rBtn, 14))
        {
            Color c1 = busy ? Color.FromArgb(150, 140, 130) : hot ? Color.FromArgb(255, 212, 110) : Color.FromArgb(255, 200, 88);
            Color c2 = busy ? Color.FromArgb(110, 100, 95) : hot ? Color.FromArgb(232, 140, 30) : Color.FromArgb(214, 118, 14);
            using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(rBtn, c1, c2, 90f)) g.FillPath(lg, p);
            var gl = new RectangleF(rBtn.X + 3, rBtn.Y + 2, rBtn.Width - 6, rBtn.Height * 0.48f);
            using (var gp = Round(gl, 11)) using (var lg = new System.Drawing.Drawing2D.LinearGradientBrush(gl, Color.FromArgb(110, 255, 255, 255), Color.FromArgb(10, 255, 255, 255), 90f)) g.FillPath(lg, gp);
            using (var pen = new Pen(Color.FromArgb(160, 150, 75, 5), 1.4f)) g.DrawPath(pen, p);
        }
        string bt = busy ? "Подождите..." : off ? "Отключить" : "Включить";
        using (var f = new Font("Segoe UI", 16f, FontStyle.Bold))
        {
            var sz = g.MeasureString(bt, f); float x = rBtn.X + (rBtn.Width - sz.Width - 36) / 2, cy = rBtn.Y + rBtn.Height / 2f;
            for (int k = 1; k >= 0; k--)   // значок питания с тенью
                using (var pen = new Pen(k == 1 ? Color.FromArgb(110, 90, 40, 0) : Color.White, 3.2f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round })
                { g.DrawArc(pen, x + k, cy - 11 + 2 * k, 22, 22, -60, 300); g.DrawLine(pen, x + 11 + k, cy - 15 + 2 * k, x + 11 + k, cy - 3 + 2 * k); }
            using (var sh = new SolidBrush(Color.FromArgb(110, 90, 40, 0))) g.DrawString(bt, f, sh, x + 37, cy - sz.Height / 2 + 2);
            g.DrawString(bt, f, Brushes.White, x + 36, cy - sz.Height / 2);
        }

        using (var f = new Font("Segoe UI", 11f)) using (var br = new SolidBrush(Color.FromArgb(255, 215, 160)))
        {   // галочка «Запуск с Windows»: после перезагрузки (драйверы и т. п.) Мост поднимется сам
            float x = card.X + 8, y = card.Bottom + 8;
            var bx = new RectangleF(x, y + 2, 16, 16);
            using (var bb = new SolidBrush(Color.FromArgb(autoOn ? 230 : 110, autoOn ? 214 : 0, autoOn ? 126 : 0, autoOn ? 18 : 0))) using (var pth = Round(bx, 4)) g.FillPath(bb, pth);
            using (var pen = new Pen(Color.FromArgb(255, 222, 175), 1.4f)) using (var pth = Round(bx, 4)) g.DrawPath(pen, pth);
            if (autoOn) using (var pen = new Pen(Color.White, 2.2f)) g.DrawLines(pen, new[] { new PointF(x + 3.5f, y + 10), new PointF(x + 7, y + 13.5f), new PointF(x + 13, y + 6) });
            var sz = g.MeasureString("Запуск с Windows", f);
            Text3D(g, "Запуск с Windows", f, br, new RectangleF(x + 22, y, sz.Width + 6, sz.Height + 4), new StringFormat());
            rAuto = new Rectangle((int)x, (int)y, (int)sz.Width + 26, (int)sz.Height + 4);
        }
        // вверху на картинке: RustDesk с ID (крупно — клиент фотографирует окно) и «Обновить»
        rRd = new Rectangle((int)card.X, TitleH + 12, (int)card.Width, rdPw != "" ? 70 : 46);
        rUpd = new Rectangle((int)card.Right - 210, rRd.Bottom + 8, 210, 32);
        // кнопка «Сменить пароль» (Михаил, 12557–12558: скрины для ребят — надёжнее сменить пароль, чем прятать)
        rPwNew = rdPw != "" ? new Rectangle((int)card.X, rUpd.Y, 170, 32) : Rectangle.Empty;
        foreach (var rr in rdPw != "" ? new[] { rRd, rUpd, rPwNew } : new[] { rRd, rUpd })
            using (var pth = Round(rr, 12))
            {
                using (var br = new SolidBrush(Color.FromArgb(rr.Contains(hover) ? 200 : 160, 30, 24, 20))) g.FillPath(br, pth);
                using (var pen = new Pen(Color.FromArgb(150, 255, 222, 175), 1.3f)) g.DrawPath(pen, pth);
            }
        using (var f = new Font("Segoe UI", 15f, FontStyle.Bold))
        {   // ID и пароль — одним снимком окна (Михаил, 12525–12527: пароль RustDesk можно и нужно в чат)
            var r1 = rdPw != "" ? new Rectangle(rRd.X, rRd.Y + 4, rRd.Width, 32) : rRd;
            Text3D(g, rdId != "" ? "RustDesk  ID " + rdId + "  ▸" : "RustDesk ▸ открыть", f, Brushes.White, r1, center);
            if (rdPw != "") using (var br = new SolidBrush(Color.FromArgb(255, 222, 175))) Text3D(g, "постоянный пароль  " + Regex.Replace(rdPw, @"^(\d{3})(\d{3})$", "$1 $2"), f, br, new Rectangle(rRd.X, rRd.Y + 34, rRd.Width, 32), center);

        }
        using (var f = new Font("Segoe UI", 10.5f, FontStyle.Bold)) using (var br = new SolidBrush(Color.FromArgb(255, 222, 175)))
        {
            Text3D(g, updText != "" ? updText : "⟳ Обновить · " + Rel, f, br, rUpd, center);
            if (rdPw != "") Text3D(g, "⟳ Сменить пароль", f, br, rPwNew, center);
        }
        // внизу на картинке — ссылка на открытый код
        string url = SourceUrl.Replace("https://", "");
        using (var f = new Font("Segoe UI", 10f)) using (var fu = new Font("Segoe UI", 10f, FontStyle.Underline))
        {
            float a = g.MeasureString("Открытый код: ", f).Width, bw = g.MeasureString(url, fu).Width, x = (w - a - bw) / 2, y = h - 30;
            Text3D(g, "Открытый код: ", f, Brushes.White, new RectangleF(x, y, a + 4, 22), new StringFormat());
            using (var br = new SolidBrush(Color.FromArgb(255, 222, 175))) Text3D(g, url, fu, br, new RectangleF(x + a - 4, y, bw + 4, 22), new StringFormat());
            rLink = new Rectangle((int)(x + a - 4), (int)y, (int)bw, 22);
        }
    }

    void SetMode(bool isFull)
    {
        SuspendLayout();
        foreach (var c in full) c.Visible = isFull;
        pCompact.Visible = !isFull; lnkSrc.Visible = isFull;   // в компактном ссылка нарисована на картинке
        FormBorderStyle = isFull ? FormBorderStyle.Sizable : FormBorderStyle.None;   // компактный — своё тёмное окно со скруглёнными углами
        if (isFull) Region = null;
        string url = isFull ? SourceUrl : SourceUrl.Replace("https://", "");
        lnkSrc.Text = (isFull ? "Открытый код программы (проверить, что она делает): " : "Открытый код: ") + url;
        lnkSrc.LinkArea = new LinkArea(lnkSrc.Text.Length - url.Length, url.Length);
        lnkSrc.TextAlign = isFull ? ContentAlignment.MiddleLeft : ContentAlignment.MiddleCenter;
        lnkSrc.Font = new Font("Segoe UI", isFull ? 11f : 9.5f);
        lnkSrc.BackColor = isFull ? Color.White : Color.FromArgb(28, 22, 20); lnkSrc.ForeColor = isFull ? SystemColors.ControlText : Color.FromArgb(200, 190, 180);
        lnkSrc.LinkColor = isFull ? Color.FromArgb(0, 102, 204) : Color.FromArgb(255, 215, 160);
        if (isFull) { MinimumSize = new Size(760, 640); ClientSize = new Size(940, 860); }
        else { MinimumSize = new Size(420, 560); ClientSize = new Size(480, 623); Corners(); }
        try { Directory.CreateDirectory(GuiDir); if (isFull) File.WriteAllText(FullFlag, "подробный вид"); else File.Delete(FullFlag); } catch { }
        ResumeLayout(); FitColumns();
        if (IsHandleCreated) CenterToScreen();
    }

    void ShowCompact(Result r)
    {
        if (copied && (DateTime.Now - copiedAt).TotalSeconds > 6) copied = false;
        pCompact.Invalidate();
    }

    void FitColumns()
    {
        int w = lvChk.ClientSize.Width; if (w < 300) return;
        lvChk.Columns[0].Width = 290; lvChk.Columns[1].Width = Math.Max(200, w - 295);
        int ws = lvSrv.ClientSize.Width; lvSrv.Columns[0].Width = 320; lvSrv.Columns[1].Width = (ws - 325) / 2; lvSrv.Columns[2].Width = (ws - 325) / 2;
    }

    Button Btn(string t, Color c, int w)
    {
        var b = new Button { Text = t, Width = w, Height = 50, BackColor = c, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 11.5f, FontStyle.Bold), Margin = new Padding(4) };
        b.FlatAppearance.BorderSize = 0; return b;
    }

    // ---------- флаги и значки ----------
    static Bitmap FlagRu()
    {
        var b = new Bitmap(36, 24); using (var g = Graphics.FromImage(b))
        { g.FillRectangle(Brushes.White, 0, 0, 36, 8); using (var bl = new SolidBrush(Color.FromArgb(0, 57, 166))) g.FillRectangle(bl, 0, 8, 36, 8); using (var r = new SolidBrush(Color.FromArgb(213, 43, 30))) g.FillRectangle(r, 0, 16, 36, 8); g.DrawRectangle(Pens.LightGray, 0, 0, 35, 23); }
        return b;
    }
    static Bitmap FlagGe()
    {
        var b = new Bitmap(36, 24); using (var g = Graphics.FromImage(b)) using (var r = new SolidBrush(Color.FromArgb(255, 0, 0)))
        {
            g.FillRectangle(Brushes.White, 0, 0, 36, 24); g.FillRectangle(r, 15, 0, 6, 24); g.FillRectangle(r, 0, 9, 36, 6);
            foreach (var p in new[] { new Point(7, 4), new Point(28, 4), new Point(7, 19), new Point(28, 19) }) { g.FillRectangle(r, p.X - 1, p.Y - 3, 2, 6); g.FillRectangle(r, p.X - 3, p.Y - 1, 6, 2); }
            g.DrawRectangle(Pens.LightGray, 0, 0, 35, 23);
        }
        return b;
    }
    static Bitmap FlagFi()
    {
        var b = new Bitmap(36, 24); using (var g = Graphics.FromImage(b)) using (var bl = new SolidBrush(Color.FromArgb(0, 47, 108)))
        { g.FillRectangle(Brushes.White, 0, 0, 36, 24); g.FillRectangle(bl, 10, 0, 6, 24); g.FillRectangle(bl, 0, 9, 36, 6); g.DrawRectangle(Pens.LightGray, 0, 0, 35, 23); }
        return b;
    }
    static Bitmap FlagBy(string code)
    {
        switch ((code ?? "").Trim().ToLowerInvariant())
        {
            case "ru": return FlagRu();
            case "ge": return FlagGe();
            case "fi": return FlagFi();
        }
        var b = new Bitmap(36, 24); using (var g = Graphics.FromImage(b)) g.DrawRectangle(Pens.LightGray, 0, 0, 35, 23);
        return b;
    }
    static Bitmap Dot(Color c)
    {
        var b = new Bitmap(20, 20); using (var g = Graphics.FromImage(b)) using (var br = new SolidBrush(c))
        { g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias; g.FillEllipse(br, 2, 2, 16, 16); }
        return b;
    }

    // ---------- журнал на рабочем столе ----------
    static readonly string Header =
        "ЖУРНАЛ ДОСТУПА СПЕЦИАЛИСТОВ К ЭТОМУ КОМПЬЮТЕРУ (программа «" + AppName + "»)\r\n" +
        "Что это: вы сами установили программу, чтобы " + Org + " могли помочь вам удалённо.\r\n" +
        "Сюда пишется само: когда доступ включали и выключали, кто заходил (по какому ключу), откуда и какие команды выполнял.\r\n" +
        "Полные записи каждого входа (команды и ответы компьютера) — в папке C:\\ProgramData\\ClaudeTunnel\\sessions.\r\n" +
        "Этот файл можно отправить любому ИИ (ChatGPT, Claude, Алиса и др.) с вопросом «что делали на моём компьютере?».\r\n" +
        "Выключить доступ в любой момент — кнопка «ВЫКЛЮЧИТЬ» в программе «" + AppName + "».\r\n" +
        "Формат строки: дата время | событие | кто | откуда | подробности\r\n" +
        "--------------------------------------------------------------------------------\r\n";

    static void EnsureJournal()
    {
        lock (jlock) { try { if (!File.Exists(JournalPath)) File.WriteAllText(JournalPath, Header, new UTF8Encoding(true)); } catch { } }
    }
    static void Journal(DateTime? t, string ev, string who, string from, string det)
    {
        EnsureJournal();
        lock (jlock)
        {
            try { File.AppendAllText(JournalPath, (t ?? DateTime.Now).ToString("dd.MM.yyyy HH:mm:ss") + " | " + ev + " | " + who + " | " + from + " | " + det + "\r\n", new UTF8Encoding(true)); } catch { }
        }
    }
    static readonly Dictionary<string, string> FromMap = BuildFrom();
    static Dictionary<string, string> BuildFrom()
    {
        var d = new Dictionary<string, string>();
        d["127.0.0.1"] = d["::1"] = Pf.Get("tunnel_from", "через туннель (сервер " + SN + ")");
        foreach (var s in Pf.Sections("server"))
        {
            string lb = s.Get("label", s.Get("name", ""));
            if (s.Get("ip", "") != "") d[s.Get("ip", "")] = lb;
            if (s.Get("radmin", "") != "") d[s.Get("radmin", "")] = "Radmin: " + lb;
        }
        return d;
    }
    static string From(string ip) { string v; return ip != null && FromMap.TryGetValue(ip, out v) ? v : ip; }

    // входы и выходы из журнала Windows OpenSSH -> в журнал на рабочем столе
    static void SyncEvents()
    {
        try
        {
            string stf = Path.Combine(Dir, "gui_events.txt");
            long lastId = 0; try { long.TryParse(File.ReadAllText(stf).Trim(), out lastId); } catch { }
            string xp = lastId > 0 ? "*[System[(EventRecordID > " + lastId + ")]]" : "*[System[TimeCreated[timediff(@SystemTime) <= 259200000]]]";
            long maxId = lastId;
            using (var r = new EventLogReader(new EventLogQuery("OpenSSH/Operational", PathType.LogName, xp)))
            {
                EventRecord e;
                while ((e = r.ReadEvent()) != null)
                    using (e)
                    {
                        long id = e.RecordId ?? 0; if (id > maxId) maxId = id;
                        string m = string.Join(" ", e.Properties.Select(p => "" + p.Value));
                        var a = Regex.Match(m, @"Accepted publickey for (.+?) from (\S+) port \d+ ssh2: \S+ (SHA256:\S+)");
                        if (a.Success)
                        {
                            string who; if (!Keys.TryGetValue(a.Groups[3].Value, out who)) who = "НЕИЗВЕСТНЫЙ ключ " + a.Groups[3].Value;
                            Journal(e.TimeCreated, "ВХОД", who, From(a.Groups[2].Value), "вход Windows: " + a.Groups[1].Value);
                            continue;
                        }
                        var d = Regex.Match(m, @"Disconnected from (?:user )?(.+?) (\S+) port \d+");
                        if (d.Success) { Journal(e.TimeCreated, "ВЫХОД", "", From(d.Groups[2].Value), "вход Windows: " + d.Groups[1].Value); continue; }
                        if (Regex.IsMatch(m, "Failed publickey|Invalid user|Failed password")) Journal(e.TimeCreated, "ОТКАЗ ВО ВХОДЕ", "", "", m.Trim());
                    }
            }
            if (maxId > lastId) { Directory.CreateDirectory(Dir); File.WriteAllText(stf, maxId.ToString()); }
        }
        catch { }
    }

    // ---------- проверки ----------
    static long TcpMs(string ip, int port, int to)
    {
        var sw = Stopwatch.StartNew();
        try { using (var c = new TcpClient()) { var ar = c.BeginConnect(ip, port, null, null); if (!ar.AsyncWaitHandle.WaitOne(to)) return -1; c.EndConnect(ar); return Math.Max(1, sw.ElapsedMilliseconds); } }
        catch { return -1; }
    }
    static long PingMs(string ip, int to)
    {
        try { using (var p = new Ping()) { var r = p.Send(ip, to); if (r.Status == IPStatus.Success) return Math.Max(1, r.RoundtripTime); } } catch { }
        return -1;
    }
    static string RadminIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var a in ni.GetIPProperties().UnicastAddresses)
                    if (a.Address.AddressFamily == AddressFamily.InterNetwork && a.Address.ToString().StartsWith("26.")) return a.Address.ToString();
            }
        }
        catch { }
        return "";
    }
    static bool ServiceExists(string name) { try { using (var s = new ServiceController(name)) { var x = s.Status; return true; } } catch { return false; } }

    static int TaskState()   // -1 нет задачи, 0 выключена, 1 включена, 2 выполняется
    {
        try
        {
            dynamic s = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")); s.Connect();
            dynamic t = s.GetFolder("\\").GetTask(TaskName);
            if (!(bool)t.Enabled) return 0;
            return ((int)t.State) == 4 ? 2 : 1;
        }
        catch { return -1; }
    }
    static void TaskSet(bool on)
    {
        dynamic s = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")); s.Connect();
        dynamic t = s.GetFolder("\\").GetTask(TaskName);
        t.Enabled = on;
        if (on) t.Run(null); else { try { t.Stop(0); } catch { } }
    }
    static List<int> TunnelPids(out double upSec)
    {
        upSec = 0; var res = new List<int>();
        try
        {
            using (var q = new ManagementObjectSearcher("SELECT ProcessId,CommandLine,CreationDate FROM Win32_Process WHERE Name='ssh.exe'"))
                foreach (ManagementObject o in q.Get())
                {
                    string cl = "" + o["CommandLine"];
                    if (cl.IndexOf("ClaudeTunnel", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    if (cl.Contains(TunnelUser + "@")) { try { upSec = Math.Max(upSec, (DateTime.Now - ManagementDateTimeConverter.ToDateTime("" + o["CreationDate"])).TotalSeconds); } catch { } }
                    res.Add(Convert.ToInt32(o["ProcessId"]));
                }
        }
        catch { }
        return res;
    }
    static string Banner()
    {
        try
        {
            using (var c = new TcpClient())
            {
                var ar = c.BeginConnect("127.0.0.1", 22, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(3000)) return "(порт 22 не отвечает)";
                c.EndConnect(ar);
                var st = c.GetStream(); st.ReadTimeout = 5000; var b = new byte[80]; int n = st.Read(b, 0, 80);
                if (n <= 0) return "(соединение закрыто сразу)";
                return Encoding.ASCII.GetString(b, 0, n).Trim();
            }
        }
        catch (Exception ex) { return "(" + (ex.InnerException != null ? ex.InnerException.Message : ex.Message) + ")"; }
    }
    static string ReadShared(string path)
    {
        try { using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) using (var sr = new StreamReader(fs)) return sr.ReadToEnd(); }
        catch { return null; }
    }
    static string LogReason(out string lastLine)
    {
        lastLine = "";
        string t = ReadShared(Path.Combine(Dir, "ssh.log")); if (string.IsNullOrEmpty(t)) return null;
        var lines = t.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries); if (lines.Length == 0) return null;
        lastLine = lines[lines.Length - 1].Trim();
        string tail = string.Join("\n", lines.Skip(Math.Max(0, lines.Length - 6)));
        if (tail.Contains("Permission denied")) return "сервер " + SN + " не узнал ключ этого ПК — нажмите «ПОЧИНИТЬ»";
        if (tail.Contains("forwarding failed") || tail.Contains("remote port forwarding")) return "на сервере " + SN + " ещё висит прошлое подключение — подождите 1–2 минуты";
        if (tail.Contains("timed out")) return "сервер " + SN + " не отвечает: нет интернета, или провайдер/антивирус закрывает порт " + SrvPort + "";
        if (tail.Contains("Connection refused")) return "сервер " + SN + " отказал в соединении — напишите нам";
        if (tail.Contains("Could not resolve") || tail.Contains("No such host")) return "нет интернета (имя сервера не найдено)";
        if (tail.Contains("Host key verification failed") || tail.Contains("No host key is known")) return "отпечаток сервера не принят — нажмите «ПОЧИНИТЬ»";
        if (tail.Contains("UNPROTECTED PRIVATE KEY") || tail.Contains("Bad permissions")) return "неверные права на ключ — нажмите «ПОЧИНИТЬ»";
        if (tail.Contains("Connection reset") || tail.Contains("Connection closed")) return "связь с сервером " + SN + " обрывается (антивирус, VPN или провайдер)";
        return null;
    }

    Result Check()
    {
        var R = new Result(); var rows = R.Rows;
        // пинги до трёх серверов — параллельно
        string rip = RadminIp(); R.Radmin = rip;
        var pings = new string[servers.Length][];
        var ths = new List<Thread>();
        for (int i = 0; i < servers.Length; i++)
        {
            int k = i; var th = new Thread(() =>
            {
                var s = servers[k]; string inet, rad;
                long ms = PingMs(s.Ip, 1500);
                if (ms > 0) inet = ms + " мс";
                else if (s.TcpPort > 0 && (ms = TcpMs(s.Ip, s.TcpPort, 2000)) > 0) inet = ms + " мс (порт " + s.TcpPort + ")";
                else inet = "нет ответа";
                if (s.Radmin == "") rad = "—";
                else if (rip == "") rad = "Radmin не подключён";
                else { long rm = PingMs(s.Radmin, 1500); rad = rm > 0 ? rm + " мс  (" + s.Radmin + ")" : "нет ответа (" + s.Radmin + ")"; }
                pings[k] = new[] { inet, rad };
            }); th.IsBackground = true; th.Start(); ths.Add(th);
        }

        R.TaskSt = TaskState();
        double up; var pids = TunnelPids(out up);
        bool tunnelAlive = up >= 10;
        long net = TcpMs(SrvIp, SrvPort, 3000);
        string banner = ServiceExists("sshd") ? Banner() : "(SSH на этом ПК не установлен)";
        bool sshOk = banner.StartsWith("SSH-2.0");
        string pt = ReadShared(Path.Combine(Dir, "port.txt"));
        if (!string.IsNullOrEmpty(pt)) { var p = pt.Trim().Split(' '); if (p.Length >= 2) R.Port = p[1]; }
        string lastLine; string reason = LogReason(out lastLine);
        foreach (var th in ths) th.Join(4000);
        for (int i = 0; i < servers.Length; i++) R.Pings.Add(pings[i] ?? new[] { "...", "..." });

        rows.Add(new Row("Связь с сервером " + SN, net > 0 ? "есть, " + net + " мс" : "НЕТ — интернет или блокировка порта " + SrvPort + " (провайдер, антивирус)", net > 0 ? 1 : 0));
        string svc;
        int svcSt;
        if (!ServiceExists("sshd")) { svc = "не установлена — нажмите «ВКЛЮЧИТЬ»"; svcSt = 0; }
        else { using (var sc = new ServiceController("sshd")) { var stt = sc.Status; svc = stt == ServiceControllerStatus.Running ? "работает" : "не работает (" + stt + ") — нажмите «ПОЧИНИТЬ»"; svcSt = stt == ServiceControllerStatus.Running ? 1 : 0; } }
        rows.Add(new Row("Служба SSH на этом ПК", svc, svcSt));
        rows.Add(new Row("SSH отвечает", sshOk ? "да (" + banner + ")" : "НЕТ " + banner, sshOk ? 1 : 0));
        string ts = R.TaskSt == -1 ? "не установлена — нажмите «ВКЛЮЧИТЬ»" : R.TaskSt == 0 ? "ВЫКЛЮЧЕНА (кнопка «ВЫКЛЮЧИТЬ»)" : R.TaskSt == 2 ? "включена, работает" : "включена, перезапускается каждую минуту";
        rows.Add(new Row("Задача «" + TaskName + "»", ts, R.TaskSt == -1 ? 0 : R.TaskSt == 0 ? 3 : 1));
        rows.Add(new Row("Туннель до сервера " + SN, tunnelAlive ? "поднят, держится " + Dur(up) : pids.Count > 0 ? "подключается..." : "не поднят", tunnelAlive ? 1 : pids.Count > 0 ? 2 : 0));
        bool radSvc = ServiceExists("RvControlSvc");
        rows.Add(new Row("Radmin VPN (запасной путь)", rip != "" ? "подключён, адрес " + rip : radSvc ? "установлен, но не в сети" : "не установлен (не обязательно)", rip != "" ? 1 : radSvc ? 2 : 3));
        rows.Add(new Row("Лог для специалистов", sendInfo, sendSt));
        if (!string.IsNullOrEmpty(lastLine)) rows.Add(new Row("Последняя запись туннеля", lastLine.Length > 160 ? lastLine.Substring(0, 160) : lastLine, reason == null ? 3 : 0));

        bool radPath = rip != "" && sshOk;
        if (R.TaskSt == -1) { R.Overall = 0; R.Head = "ТУННЕЛЬ НЕ УСТАНОВЛЕН — нажмите «ВКЛЮЧИТЬ»"; }
        else if (R.TaskSt == 0) { R.Overall = 3; R.Head = "ДОСТУП ВЫКЛЮЧЕН — специалисты зайти не могут"; }
        else if (tunnelAlive && net > 0 && sshOk) { R.Overall = 1; R.Head = "ТУННЕЛЬ РАБОТАЕТ — доступ открыт"; }
        else if (tunnelAlive && !sshOk) { R.Overall = 2; R.Head = "Туннель есть, но SSH на ПК не отвечает — нажмите «ПОЧИНИТЬ»"; }
        else
        {
            string why = net <= 0 ? "нет связи с сервером " + SN + " (интернет, провайдер или антивирус)" : reason ?? (!sshOk ? "SSH на этом ПК не отвечает — нажмите «ПОЧИНИТЬ»" : pids.Count > 0 ? "подключается, подождите до 1 минуты" : "переподключается, подождите до 1 минуты");
            R.Overall = radPath ? 2 : 0;
            R.Head = "ТУННЕЛЬ НЕ ПОДНЯТ: " + why + (radPath ? "\nНо доступ есть через Radmin VPN " + rip : "");
        }
        SyncEvents();
        return R;
    }
    static string Dur(double s) { var t = TimeSpan.FromSeconds(s); return t.TotalHours >= 1 ? (int)t.TotalHours + " ч " + t.Minutes + " мин" : t.TotalMinutes >= 1 ? (int)t.TotalMinutes + " мин" : (int)s + " с"; }

    void StartCheck()
    {
        if (checking) return; checking = true;
        var th = new Thread(() =>
        {
            Result r = null; try { r = Check(); } catch (Exception ex) { r = new Result { Overall = 0, Head = "Ошибка проверки: " + ex.Message }; }
            try { BeginInvoke(new Action(() => { Show(r); checking = false; })); } catch { checking = false; }
        });
        th.IsBackground = true; th.Start();
    }

    void Show(Result r)
    {
        if (Environment.GetCommandLineArgs().Contains("--demo-busy") && !busy) { busy = true; stepN = 4; prog = progShown = 0.48; stepLine = "4/7 Личный ключ этого ПК..."; }   // снимок хода установки
        if (Environment.GetCommandLineArgs().Contains("--demo")) { r.TaskSt = 1; r.Overall = 1; r.Port = "22045"; }   // снимки для сайта: вид «открыт», ничего не включает
        last = r;
        if (!autoTried)
        {
            autoTried = true;
            if (!Demo && !busy && !Environment.GetCommandLineArgs().Contains("--autostart") && (r.TaskSt <= 0 || r.Overall == 0))
            {
                Log("Мост не открыт — открываю сам (запуск программы).");
                BeginInvoke(new Action(DoOn));
            }
        }
        Color[] cs = { Color.FromArgb(200, 35, 35), Color.FromArgb(25, 140, 55), Color.FromArgb(215, 140, 0), Color.FromArgb(110, 110, 110) };
        lblStatus.BackColor = cs[r.Overall]; lblStatus.Text = r.Head;
        lblStatus.Font = new Font("Segoe UI", r.Head.Length > 70 ? 15f : 19f, FontStyle.Bold);
        lblInfo.Text = "Номер для специалиста: " + (r.Port != "" ? r.Port : "—") + "     ПК: " + Environment.MachineName +
                       "\nRadmin: " + (r.Radmin != "" ? r.Radmin : "нет") + "     проверено " + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
        lvChk.BeginUpdate(); lvChk.Items.Clear();
        foreach (var row in r.Rows) { var it = new ListViewItem(row.Name, row.St); it.SubItems.Add(row.Value); lvChk.Items.Add(it); }
        lvChk.EndUpdate();
        for (int i = 0; i < r.Pings.Count && i < lvSrv.Items.Count; i++) { lvSrv.Items[i].SubItems[1].Text = r.Pings[i][0]; lvSrv.Items[i].SubItems[2].Text = r.Pings[i][1]; }
        bOn.Enabled = !busy && r.TaskSt != 1 && r.TaskSt != 2 || !busy && r.Overall == 0;
        bOff.Enabled = !busy && r.TaskSt > 0;
        bFix.Enabled = !busy;
        ShowCompact(r);
        // лог на сервер: при запуске, после установки и кнопок, и когда статус стал красным (не чаще раза в 10 минут)
        if (!busy && prevOverall > 0 && r.Overall == 0 && (DateTime.Now - lastAuto).TotalMinutes >= 10) { pending = "статус стал красным"; lastAuto = DateTime.Now; }
        prevOverall = r.Overall;
        if (pending != null && !busy) { string w = pending; pending = null; SendLog(w); }
    }

    // ---------- лог для специалистов на сервер (версия 102) ----------
    static readonly string GuiDir = Path.Combine(Dir, "gui");
    static readonly string NoLogFlag = Path.Combine(GuiDir, "nolog.flag");
    static readonly string SetupFlag = Path.Combine(GuiDir, "setup-pending.flag");   // есть — установка шла и не закончилась
    static readonly string FullFlag = Path.Combine(GuiDir, "full.flag");   // есть — окно открывается в подробном виде
    static readonly string AutoOffFlag = Path.Combine(GuiDir, "auto-off.flag");   // есть — человек сам снял галочку «Запуск с Windows», обратно не ставим
    static readonly string HostKeys = string.Join("", Pf.Sections("hostkeys").SelectMany(h => h.All("line")).Select(x => x + "\n"));
    static readonly object slock = new object();
    volatile string sendInfo = "ещё не отправлялся"; volatile int sendSt = 3;
    string pending = "запуск программы"; DateTime lastAuto = DateTime.MinValue; int prevOverall = -1;

    void SendLog(string why)
    {
        if (!chkSend.Checked) { sendInfo = "выключено галочкой — специалисты не увидят причину ошибки"; sendSt = 3; return; }
        string body = BuildLog(why);
        string ph = Regex.Replace(txtPhone.Text, @"\D", ""); if (!Regex.IsMatch(ph, @"^7\d{10}$")) ph = "0";
        sendInfo = "отправляю..."; sendSt = 2;
        var th = new Thread(() => SendWorker(why, body, ph)); th.IsBackground = true; th.Start();
    }

    void SendWorker(string why, string body, string ph)
    {
        lock (slock)
        {
            string outbox = Path.Combine(GuiDir, "outbox"), err;
            if (SshLog(ph, body, out err))
            {
                sendInfo = "отправлен " + DateTime.Now.ToString("HH:mm:ss") + " (" + why + ")"; sendSt = 1;
                Log("Лог отправлен специалистам на сервер " + SN + " (" + why + ").");
                Journal(null, "ЛОГ ОТПРАВЛЕН", "программа", "этот ПК", "специалистам на сервер " + SN + ": состояние туннеля и ошибки (" + why + "), без паролей и файлов");
                try { foreach (var f in Directory.GetFiles(outbox, "*.txt").OrderBy(x => x).Take(5)) { string e2; if (SshLog(ph, File.ReadAllText(f, Encoding.UTF8), out e2)) File.Delete(f); else break; } } catch { }
            }
            else
            {
                sendInfo = "не ушёл: " + err + " — отправлю позже"; sendSt = 2;
                Log("Лог на сервер " + SN + " не ушёл: " + err);
                try
                {
                    Directory.CreateDirectory(outbox);
                    var old = Directory.GetFiles(outbox, "*.txt").OrderBy(x => x).ToArray();
                    for (int i = 0; i < old.Length - 19; i++) File.Delete(old[i]);
                    int nl = body.IndexOf('\n');
                    File.WriteAllText(Path.Combine(outbox, DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") + ".txt"),
                        body.Substring(0, nl + 1) + "(лог отложен: в " + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss") + " не ушёл — " + err + ")\n" + body.Substring(nl + 1), new UTF8Encoding(false));
                }
                catch { }
            }
        }
    }

    static string SshPath()
    {
        return new[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"OpenSSH\ssh.exe"),
            Path.Combine(Dir, @"ssh95\Program Files\OpenSSH\ssh.exe"),   // свой 9.5 вместо встроенного 7.7, который рвёт вход (12539)
            Path.Combine(Environment.SystemDirectory, @"OpenSSH\ssh.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Sysnative\OpenSSH\ssh.exe") }.FirstOrDefault(File.Exists);
    }

    // ключ регистрации (общий, тот же, что во встроенном скрипте) и отпечаток сервера — в ProgramData\ClaudeTunnel\gui
    static void PrepareKey(string ek, string kh)
    {
        Directory.CreateDirectory(GuiDir);
        if (!File.Exists(ek))
        {
            var m = Regex.Match(Res("setup_core.ps1"), @"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----", RegexOptions.Singleline);
            File.WriteAllText(ek, m.Value.Replace("\r\n", "\n") + "\n", new UTF8Encoding(false));
        }
        // владелец Администраторы, доступ только SYSTEM и Администраторы — иначе ssh скажет «UNPROTECTED PRIVATE KEY»
        var acl = new FileSecurity(); acl.SetAccessRuleProtection(true, false);
        var adm = new SecurityIdentifier("S-1-5-32-544"); acl.SetOwner(adm);
        foreach (var sid in new[] { new SecurityIdentifier("S-1-5-18"), adm }) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        File.SetAccessControl(ek, acl);
        File.WriteAllText(kh, HostKeys, new UTF8Encoding(false));
    }

    static bool SshLog(string ph, string body, out string err)
    {
        err = "";
        string ssh = SshPath();
        if (ssh == null) { err = "на ПК нет программы ssh.exe (её ставит кнопка «ВКЛЮЧИТЬ»)"; return false; }
        string ek = Path.Combine(GuiDir, "enroll_key"), kh = Path.Combine(GuiDir, "known_hosts");
        try { PrepareKey(ek, kh); } catch (Exception ex) { err = "ключ: " + ex.Message; return false; }
        string pc = Regex.Replace(Environment.MachineName, @"[^A-Za-z0-9._-]", "_"); if (pc.Length > 40) pc = pc.Substring(0, 40);
        byte[] data = Encoding.UTF8.GetBytes(body);
        // два способа указать файлы — ssh 7.7 и новые читают пути по-разному (как в скрипте туннеля)
        foreach (var w in new[] { new[] { ek.Replace('\\', '/'), kh.Replace('\\', '/') }, new[] { "\"" + ek + "\"", "\"" + kh + "\"" } })
        {
            string args = "-T -p " + SrvPort + " -o StrictHostKeyChecking=yes -o HostKeyAlias=" + HostAlias + " -o HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256" +
                          " -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile=" + w[1] + " -i " + w[0] +
                          " " + EnrollUser + "@" + SrvIp + " \"log " + ph + " " + pc + "\"";
            try
            {
                var psi = new ProcessStartInfo(ssh, args) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
                using (var p = Process.Start(psi))
                {
                    string so = "", se = "";
                    var tO = new Thread(() => { try { so = p.StandardOutput.ReadToEnd(); } catch { } }); tO.IsBackground = true; tO.Start();
                    var tE = new Thread(() => { try { se = p.StandardError.ReadToEnd(); } catch { } }); tE.IsBackground = true; tE.Start();
                    try { p.StandardInput.BaseStream.Write(data, 0, data.Length); p.StandardInput.Close(); } catch { }
                    if (!p.WaitForExit(40000)) { try { p.Kill(); } catch { } err = "сервер " + SN + " не ответил за 40 с"; continue; }
                    tO.Join(3000); tE.Join(3000);
                    if (so.Contains("LOG=OK")) return true;
                    var ln = (so + "\n" + se).Split('\n').Select(x => x.Trim()).Where(x => x != "" && !x.StartsWith("**")).ToArray();
                    err = ln.Length > 0 ? ln[ln.Length - 1] : "нет ответа (код " + p.ExitCode + ")";
                    if (err.Length > 150) err = err.Substring(0, 150);
                }
            }
            catch (Exception ex) { err = ex.Message; }
        }
        return false;
    }

    static string WinName()
    {
        try
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                string name = "" + k.GetValue("ProductName"), build = "" + k.GetValue("CurrentBuild");
                int b; if (int.TryParse(build, out b) && b >= 22000) name = name.Replace("Windows 10", "Windows 11");
                return name + " " + (k.GetValue("DisplayVersion") ?? k.GetValue("ReleaseId") ?? "") + " (сборка " + build + "." + k.GetValue("UBR") + ")";
            }
        }
        catch { return Environment.OSVersion.ToString(); }
    }

    string BuildLog(string why)
    {
        var sb = new StringBuilder();
        sb.Append("STATUS: ").Append(last != null ? last.Head.Replace("\n", " / ") : "нет данных").Append("\n");
        sb.Append("Программа «" + AppName + "» ").Append(Rel).Append(" · повод: ").Append(why).Append("\n");
        sb.Append("Время ПК: ").Append(DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss zzz")).Append(" · ПК: ").Append(Environment.MachineName)
          .Append(" · пользователь: ").Append(Environment.UserName).Append(" · сотовый: ").Append(txtPhone.Text).Append("\n");
        sb.Append("Windows: ").Append(WinName()).Append(" · ").Append(Environment.Is64BitOperatingSystem ? "64" : "32").Append("-бит · .NET ").Append(Environment.Version).Append("\n");
        string ssh = SshPath(); string sv = ""; try { if (ssh != null) sv = FileVersionInfo.GetVersionInfo(ssh).ProductVersion; } catch { }
        sb.Append("ssh.exe: ").Append(ssh != null ? ssh + " " + sv : "нет").Append("\n");
        sb.Append("port.txt: ").Append((ReadShared(Path.Combine(Dir, "port.txt")) ?? "нет").Trim()).Append("\n\n");
        sb.Append(Report(0)).Append("\n");
        string sl = ReadShared(Path.Combine(Dir, "ssh.log"));
        if (!string.IsNullOrEmpty(sl)) { var a = sl.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries); sb.Append("--- ssh.log туннеля (последние 40 строк):\n"); foreach (var s in a.Skip(Math.Max(0, a.Length - 40))) sb.Append(s).Append("\n"); }
        var l = txtLog.Lines; sb.Append("--- окно программы (последние 400 строк):\n");
        foreach (var s in l.Skip(Math.Max(0, l.Length - 400))) sb.Append(s).Append("\n");
        string t = sb.ToString();
        while (Encoding.UTF8.GetByteCount(t) > 240000) t = t.Substring(0, 2000) + "\n…(середина обрезана)…\n" + t.Substring(t.Length - (t.Length - 2000) * 3 / 4);
        return t;
    }

    string Report(int tail = 25)
    {
        var sb = new StringBuilder();
        sb.AppendLine(Text + "   " + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"));
        if (last != null)
        {
            sb.AppendLine(last.Head.Replace("\n", " "));
            sb.AppendLine("Номер для специалиста: " + last.Port + "   Radmin: " + last.Radmin);
            foreach (var row in last.Rows) sb.AppendLine((row.St == 1 ? "[OK] " : row.St == 0 ? "[!!] " : "[--] ") + row.Name + ": " + row.Value);
            for (int i = 0; i < last.Pings.Count; i++) sb.AppendLine(servers[i].Name + ": интернет " + last.Pings[i][0] + "; Radmin " + last.Pings[i][1]);
        }
        var l = txtLog.Lines; sb.AppendLine("--- последние строки:"); foreach (var s in l.Skip(Math.Max(0, l.Length - tail))) sb.AppendLine(s);
        return sb.ToString();
    }

    void DoShot()
    {
        try
        {
            var b = new Bitmap(Width, Height);
            using (var g = Graphics.FromImage(b)) g.CopyFromScreen(Location, Point.Empty, Size);
            string f = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), AppName + " снимок " + DateTime.Now.ToString("yyyy-MM-dd HH-mm-ss") + ".png");
            b.Save(f, System.Drawing.Imaging.ImageFormat.Png);
            Clipboard.SetImage(b);
            pending = "кнопка СНИМОК ДЛЯ НАС"; StartCheck();
            MessageBox.Show(this, "Снимок сохранён на рабочий стол и скопирован.\nОткройте WhatsApp, нажмите Ctrl+V и отправьте нам.\n\n" + f, Text);
        }
        catch (Exception ex) { MessageBox.Show(this, "Снимок не получился: " + ex.Message + "\nСфотографируйте экран телефоном.", Text); }
    }

    void DoOn()
    {
        int st = TaskState();
        if (st == -1 || (last != null && last.Overall == 0 && st > 0)) { RunSetup("ВКЛЮЧИТЬ"); return; }
        try { TaskSet(true); Log("Доступ включён: задача «Claude туннель» включена и запущена."); Journal(null, "ДОСТУП ВКЛЮЧЁН", "клиент (кнопка)", "этот ПК", "задача «Claude туннель» включена"); }
        catch (Exception ex) { Log("Не включилось: " + ex.Message + " — запускаю полную установку"); RunSetup("ВКЛЮЧИТЬ"); return; }
        pending = "кнопка ВКЛЮЧИТЬ";
        StartCheck();
    }

    void DoOff()
    {
        if (MessageBox.Show(this, "Выключить доступ специалистов к этому компьютеру?\nВключить снова — кнопка «Включить».", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        try { TaskSet(false); } catch (Exception ex) { Log("Задача: " + ex.Message); }
        double up; foreach (int pid in TunnelPids(out up)) { try { Process.GetProcessById(pid).Kill(); } catch { } }
        Log("Доступ выключен: задача «" + TaskName + "» отключена, соединение с сервером " + SN + " разорвано.");
        Journal(null, "ДОСТУП ВЫКЛЮЧЕН", "клиент (кнопка)", "этот ПК", "задача отключена, туннель разорван");
        pending = "кнопка ВЫКЛЮЧИТЬ";
        StartCheck();
    }

    void BuildTray()
    {   // крестик сворачивает в трей (Михаил, 12491); выйти — правой кнопкой по значку «Выход»
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть", null, delegate { FromTray(); });
        menu.Items.Add("Выход", null, delegate { quitting = true; tray.Visible = false; Close(); });
        tray = new NotifyIcon { Icon = Icon, Text = AppName, ContextMenuStrip = menu, Visible = true };
        tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) FromTray(); };
        FormClosing += (s, e) =>
        {
            if (quitting || e.CloseReason != CloseReason.UserClosing || Environment.GetCommandLineArgs().Any(a => a.StartsWith("--demo"))) { tray.Visible = false; return; }
            e.Cancel = true; Hide();
            if (!trayTold) { trayTold = true; tray.ShowBalloonTip(4000, AppName, AppName + " работает здесь, у часов. Открыть — щёлкните значок, выйти — правой кнопкой «Выход».", ToolTipIcon.Info); }
        };
    }
    public void FromTray()
    {
        Show(); if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate(); BringToFront();
    }
    static int Schtasks(string args)
    {
        var p = Process.Start(new ProcessStartInfo("schtasks.exe", args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
        p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit(15000); return p.ExitCode;
    }
    static bool AutoGet() { try { return Schtasks("/Query /TN \"" + AutoTask + "\"") == 0; } catch { return false; } }
    void AutoSet(bool on)
    {   // задача при входе в Windows с правами администратора (программа их требует, обычная «Автозагрузка» её не пустит)
        string exe = Application.ExecutablePath, user = Environment.UserDomainName + "\\" + Environment.UserName;
        int rc = -1;
        try
        {
            rc = on ? Schtasks("/Create /F /TN \"" + AutoTask + "\" /TR \"\\\"" + exe + "\\\" --autostart\" /SC ONLOGON /DELAY 0000:20 /RL HIGHEST /IT /RU \"" + user + "\"")
                    : Schtasks("/Delete /F /TN \"" + AutoTask + "\"");
        }
        catch (Exception ex) { Log("Запуск с Windows: " + ex.Message); }
        autoOn = AutoGet();
        try { Directory.CreateDirectory(GuiDir); if (autoOn) File.Delete(AutoOffFlag); else if (!on) File.WriteAllText(AutoOffFlag, "галочку сняли " + DateTime.Now); } catch { }
        if (chkAuto != null && chkAuto.Checked != autoOn) chkAuto.Checked = autoOn;
        Log(on == autoOn ? (autoOn ? "Запуск с Windows включён: после перезагрузки " + AppName + " откроется сам (в трее) и доведёт незаконченную установку." : "Запуск с Windows выключен.")
                         : "Запуск с Windows не изменён, код schtasks " + rc);
        Journal(null, autoOn ? "ЗАПУСК С WINDOWS ВКЛЮЧЁН" : "ЗАПУСК С WINDOWS ВЫКЛЮЧЕН", "клиент (галочка)", "этот ПК", "");
    }

    void Progress(string s)
    {
        if (InvokeRequired) { try { BeginInvoke(new Action<string>(Progress), s); } catch { } return; }
        var m = Regex.Match(s, @"^(\d)/7 ");
        if (m.Success) { stepN = int.Parse(m.Groups[1].Value); prog = Math.Max(prog, (stepN - 1) / 7.0); }
        var w = Regex.Match(s, @"\((\d+) с\)");
        if (stepN == 7 && w.Success) prog = Math.Max(prog, 6 / 7.0 + Math.Min(0.9, int.Parse(w.Groups[1].Value) / 60.0) / 7);
        string t = s.Trim(); if (t.Length > 0) stepLine = t.Length > 48 ? t.Substring(0, 47) + "…" : t;
        if (pCompact != null) pCompact.Invalidate();
    }
    void AnimStart()
    {   // полоса растёт плавно: внутри шага сама подползает к его концу, по строке скрипта — прыгает
        if (anim == null) { anim = new System.Windows.Forms.Timer { Interval = 120 }; anim.Tick += (s, e) =>
        {
            if (busy) prog = Math.Min(Math.Max(prog, (stepN - 1) / 7.0) + 0.0012, stepN == 0 ? 0.04 : stepN / 7.0 - 0.012);
            progShown += (prog - progShown) * 0.25;
            if (!ShowProg) anim.Stop();
            if (pCompact != null) pCompact.Invalidate();
        }; }
        anim.Start();
    }

    void RunSetup(string why)
    {
        if (busy) return;
        busy = true; bOn.Enabled = bOff.Enabled = bFix.Enabled = false;
        try { Directory.CreateDirectory(GuiDir); File.WriteAllText(SetupFlag, why + " " + DateTime.Now); } catch { }
        stepN = 0; gotPort = false; retryAt = DateTime.MinValue; prog = progShown = 0; stepLine = "займёт 1–3 минуты"; doneAt = DateTime.MinValue; AnimStart();
        string ph = Regex.Replace(txtPhone.Text, @"\D", "");
        Log(""); Log("=== " + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss") + " установка туннеля (кнопка «" + why + "»), займёт 1–3 минуты...");
        Journal(null, "УСТАНОВКА", "клиент (кнопка «" + why + "»)", "этот ПК", "сотовый: " + (ph != "" ? ph : "не указан"));
        try
        {
            string tmp = Path.Combine(Path.GetTempPath(), "claude_tunnel_setup.ps1");
            File.WriteAllText(tmp, "[Console]::OutputEncoding = [Text.Encoding]::UTF8\r\n$ProgressPreference = 'SilentlyContinue'\r\n" + Res("setup_core.ps1") + "\r\n" + Res("setup_suffix.ps1"), new UTF8Encoding(true));
            var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File \"" + tmp + "\"")
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
            psi.EnvironmentVariables["CLAUDE_PHONE"] = ph;
            var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
            p.OutputDataReceived += (s, e) => { if (e.Data != null) { if (e.Data.Contains("НОМЕР КЛИЕНТА")) gotPort = true; Log(e.Data); Progress(e.Data); Journal(null, "  установка", "", "", e.Data); } };
            p.ErrorDataReceived += (s, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) { Log("ОШИБКА: " + e.Data); Journal(null, "  установка", "", "", "ОШИБКА: " + e.Data); } };
            p.Exited += (s, e) => { try { BeginInvoke(new Action(() => { busy = false; bFix.Enabled = true; doneOk = p.ExitCode == 0 && gotPort; doneAt = DateTime.Now; try { File.Delete(SetupFlag); } catch { } prog = 1;
                if (doneOk) retryN = 0; else { retryN++; retryAt = DateTime.Now.AddMinutes(5); Journal(null, "ОТКАЗ", "установка, попытка " + retryN, "этот ПК", "код " + p.ExitCode + ", повтор в " + retryAt.ToString("HH:mm")); }
                stepLine = doneOk ? "все 6 шагов пройдены" : "пробую снова сам — окно можно не закрывать"; Log("=== установка закончена. Смотрите статус вверху окна."); try { File.Delete(tmp); } catch { } pending = "установка (кнопка «" + why + "»), код выхода " + p.ExitCode; StartCheck(); })); } catch { } };
            p.Start(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
        }
        catch (Exception ex) { busy = false; bFix.Enabled = true; doneOk = false; doneAt = DateTime.Now; stepLine = "установка не запустилась"; Log("Не запустилась установка: " + ex.Message); }
    }

    // «комбайн» (Михаил, 12521): туннель не встал — ждём 5 минут, ловим новую версию, пробуем снова; каждый отказ уходит в журнал на сервер
    void Combine()
    {
        if (busy || updBusy) return;
        if (retryAt != DateTime.MinValue && last != null && last.TaskSt > 0 && last.Overall == 1) { retryAt = DateTime.MinValue; retryN = 0; return; }   // встал сам
        if (retryAt != DateTime.MinValue && DateTime.Now >= retryAt) { retryAt = DateTime.MinValue; CheckUpdate(false, () => RunSetup("повтор " + (retryN + 1))); return; }
        if (DateTime.Now >= updAt) { updAt = DateTime.Now.AddHours(1); CheckUpdate(false); }
        if (rdId == "" && !rdBusy && DateTime.Now.Second % 10 < 5) { rdBusy = true; ThreadPool.QueueUserWorkItem(_ => { try { ReadRdId(); } finally { rdBusy = false; } }); }
    }

    static Version Ver(string s) { var m = Regex.Match(s ?? "", @"\d+(\.\d+){0,3}"); Version v; return m.Success && Version.TryParse(m.Value.Contains(".") ? m.Value : m.Value + ".0", out v) ? v : new Version(0, 0); }

    // кнопка «Обновить» и проверка раз в час: на сервере файл .txt («103.9 SHA256»), качаем .exe, сверяем SHA256, подменяем себя и перезапускаемся
    void CheckUpdate(bool manual, Action after = null)
    {
        if (updBusy || UpdateUrl == "") { if (manual && UpdateUrl == "") { updText = "обновления выключены"; pCompact.Invalidate(); } if (after != null) after(); return; }
        updBusy = true; if (manual) { updText = "проверяю..."; pCompact.Invalidate(); }
        bool vis = Visible;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            string msg = ""; bool restart = false;
            try
            {
                System.Net.ServicePointManager.SecurityProtocol |= (System.Net.SecurityProtocolType)3072;   // TLS 1.2 на старых Windows
                using (var wc = new System.Net.WebClient())
                {
                    wc.Encoding = Encoding.UTF8;
                    var parts = wc.DownloadString(UpdateUrl + ".txt?t=" + DateTime.Now.Ticks).Trim().Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2 || Ver(parts[0]) <= Ver(Rel)) msg = "у вас последняя · " + Rel;
                    else
                    {
                        if (manual) BeginInvoke(new Action(() => { updText = "качаю " + parts[0] + "..."; pCompact.Invalidate(); }));
                        string tmp = Path.Combine(Path.GetTempPath(), "ryadom_new.exe");
                        wc.DownloadFile(UpdateUrl + ".exe?t=" + DateTime.Now.Ticks, tmp);
                        string sha; using (var h = SHA256.Create()) using (var fs = File.OpenRead(tmp)) sha = BitConverter.ToString(h.ComputeHash(fs)).Replace("-", "");
                        if (!sha.Equals(parts[1], StringComparison.OrdinalIgnoreCase)) { msg = "файл повреждён — не ставлю"; File.Delete(tmp); }
                        else
                        {
                            string cur = Application.ExecutablePath, cmd = Path.Combine(Path.GetTempPath(), "ryadom_update.cmd");
                            string args = vis ? "" : "--autostart";
                            File.WriteAllText(cmd, "@echo off\r\nping -n 4 127.0.0.1 >nul\r\nfor /l %%i in (1,1,10) do (copy /y \"" + tmp + "\" \"" + cur + "\" >nul 2>&1 && goto ok\r\nping -n 2 127.0.0.1 >nul)\r\n:ok\r\nstart \"\" \"" + cur + "\" " + args + "\r\ndel \"%~f0\"\r\n", Encoding.GetEncoding(866));
                            Journal(null, "ОБНОВЛЕНИЕ", Rel + " -> " + parts[0], "этот ПК", manual ? "кнопка «Обновить»" : "сама");
                            if (after != null) try { Directory.CreateDirectory(GuiDir); File.WriteAllText(SetupFlag, "повтор после обновления " + DateTime.Now); } catch { }   // новая версия сама продолжит установку
                            Process.Start(new ProcessStartInfo("cmd.exe", "/c \"" + cmd + "\"") { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden });
                            restart = true;
                        }
                    }
                }
            }
            catch (Exception ex) { msg = "нет связи с сервером обновлений"; try { BeginInvoke(new Action(() => Log("Обновление: " + ex.Message))); } catch { } }
            try
            {
                BeginInvoke(new Action(() =>
                {
                    updBusy = false;
                    if (restart) { quitting = true; tray.Visible = false; Close(); return; }
                    if (manual) { updText = msg; pCompact.Invalidate(); var t = new System.Windows.Forms.Timer { Interval = 6000 }; t.Tick += delegate { t.Stop(); t.Dispose(); updText = ""; pCompact.Invalidate(); }; t.Start(); }
                    if (after != null) after();
                }));
            }
            catch { updBusy = false; }
        });
    }

    static string RdExe() { foreach (var d in new[] { Environment.GetEnvironmentVariable("ProgramW6432"), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) }) { if (string.IsNullOrEmpty(d)) continue; var f = Path.Combine(d, "RustDesk\\rustdesk.exe"); if (File.Exists(f)) return f; } return null; }

    void OpenRustDesk()
    {
        var f = RdExe();
        if (f == null) { MessageBox.Show(this, "RustDesk ещё не установлен — нажмите «Включить», он поставится первым шагом.", AppName); return; }
        try { Process.Start(f); } catch (Exception ex) { MessageBox.Show(this, "RustDesk не открылся: " + ex.Message, AppName); }
    }

    // ID RustDesk — только номер, без пароля (пароль на фото не показываем, правило 3989)
    void ReadRdId()
    {
        string id = "";
        try
        {
            var toml = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk.toml");
            if (File.Exists(toml)) { var m = Regex.Match(File.ReadAllText(toml), @"(?m)^id\s*=\s*'?""?(\d{6,12})"); if (m.Success) id = m.Groups[1].Value; }
            var f = RdExe();
            if (id == "" && f != null)
            {
                var p = Process.Start(new ProcessStartInfo(f, "--get-id") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });
                var outp = p.StandardOutput.ReadToEndAsync(); if (p.WaitForExit(20000)) { var m = Regex.Match(outp.Result, @"\d{6,12}"); if (m.Success) id = m.Value; } else try { p.Kill(); } catch { }
            }
        }
        catch { }
        if (id == "") try { if (File.Exists(RdIdFile)) id = Regex.Match(File.ReadAllText(RdIdFile), @"\d{6,12}").Value; } catch { }
        else try { if (!File.Exists(RdIdFile) || File.ReadAllText(RdIdFile).Trim() != id) { Directory.CreateDirectory(Path.GetDirectoryName(RdIdFile)); File.WriteAllText(RdIdFile, id); } } catch { }
        if (id == "") return;
        string pw = RdPassword(id);
        id = Regex.Replace(id, @"(\d{3})(?=\d)", "$1 ");   // 123 456 789 — легче продиктовать
        try { BeginInvoke(new Action(() => { rdId = id; rdPw = pw; pCompact.Invalidate(); })); } catch { }
    }

    // постоянный пароль RustDesk (Михаил, 12527: пароль RustDesk можно и нужно в чат): ставим свой один раз, храним рядом
    // с ключами туннеля (только SYSTEM и администраторы), показываем в окне и пишем в журнал входов — специалисту не надо спрашивать
    void NewRdPassword()
    {
        if (!IsAdmin) { MessageBox.Show(this, "Сменить пароль RustDesk можно только с правами администратора: запустите Мост от администратора.", "Мост"); return; }
        if (MessageBox.Show(this, "Сменить постоянный пароль RustDesk?\nСтарый перестанет работать сразу.", "Мост", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        string id = rdId.Replace(" ", "");
        ThreadPool.QueueUserWorkItem(_ =>
        {
            string pw = RdPassword(id, true);
            try { BeginInvoke(new Action(() => { if (pw != "") rdPw = pw; else MessageBox.Show(this, "Не получилось сменить пароль — RustDesk не ответил.", "Мост"); pCompact.Invalidate(); })); } catch { }
        });
    }
    // щелчок по номеру — в буфер вся карточка ПК: агент по ней сразу сопоставит клиента и компьютер (Михаил, 12561)
    string ClipCard()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Мост " + Rel);
        sb.AppendLine("Номер для специалиста: " + last.Port);
        sb.AppendLine("ПК: " + Environment.MachineName + ", пользователь " + Environment.UserName);
        if (rdId != "") sb.AppendLine("RustDesk ID: " + rdId);
        if (rdPw != "") sb.AppendLine("Пароль RustDesk: " + rdPw);
        if (!string.IsNullOrEmpty(last.Radmin)) sb.AppendLine("Radmin: " + last.Radmin);
        return sb.ToString().TrimEnd();
    }
    static readonly string RdIdFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"ClaudeTunnel\rustdesk_id.txt");
    static readonly string RdPwFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"ClaudeTunnel\rustdesk_pw.txt");
    string RdPassword(string id, bool fresh = false)
    {
        if (Demo) return "481725";   // снимок для проверки — пароль на этом ПК не трогаем
        try
        {
            if (!fresh && File.Exists(RdPwFile)) { var old = File.ReadAllText(RdPwFile).Trim(); if (Regex.IsMatch(old, @"^\d{6}$") || old != "" && !IsAdmin) return old; }
            var f = RdExe(); if (f == null || !IsAdmin) return "";
            var b = new byte[6]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);   // 6 цифр, как код из СМС: диктуется голосом, 1 млн вариантов (12553, 12559; 4 цифры = 10 тыс. — слабо)
            string pw = new string(b.Select(x => (char)('0' + x % 10)).ToArray());
            var p = Process.Start(new ProcessStartInfo(f, "--password " + pw) { UseShellExecute = false, CreateNoWindow = true });
            if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return ""; }
            Directory.CreateDirectory(Path.GetDirectoryName(RdPwFile)); File.WriteAllText(RdPwFile, pw);
            try
            {
                var acl = new FileSecurity(); acl.SetAccessRuleProtection(true, false);
                foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                    acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(RdPwFile, acl);
            }
            catch { }
            Journal(null, "RUSTDESK", "ID " + id + ", пароль " + pw, "этот ПК", fresh ? "постоянный пароль сменён кнопкой ⟳" : "постоянный пароль поставлен программой");
            return pw;
        }
        catch { return ""; }
    }

    static string Res(string name)
    {
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) using (var r = new StreamReader(s, Encoding.UTF8)) return r.ReadToEnd().TrimStart('\uFEFF');
    }

    void Log(string s)
    {
        if (InvokeRequired) { try { BeginInvoke(new Action<string>(Log), s); } catch { } return; }
        txtLog.AppendText(s + "\r\n");
    }

    static string GuessPhone()
    {
        var m = Regex.Match(Path.GetFileName(Application.ExecutablePath), @"[78]\d{10}");
        if (m.Success) return "7" + m.Value.Substring(1);
        string pt = ReadShared(Path.Combine(Dir, "port.txt"));
        if (!string.IsNullOrEmpty(pt)) { var p = pt.Trim().Split(' '); if (p.Length > 0 && Regex.IsMatch(p[0], @"^7\d{10}$")) return p[0]; }
        return "";
    }
}

// профиль сборки: простой ini — [main] ключ = значение; повторяющиеся разделы [server.1], [server.2], [key.1] …; строки «; …» — комментарии
class Profile
{
    public string Name; readonly List<KeyValuePair<string, string>> kv = new List<KeyValuePair<string, string>>();
    readonly List<Profile> secs = new List<Profile>();
    public string Get(string k, string def)
    {
        if (Name != null) { foreach (var p in kv) if (p.Key == k) return p.Value; return def; }
        var m = secs.FirstOrDefault(x => x.Name == "main"); return m == null ? def : m.Get(k, def);
    }
    public IEnumerable<string> All(string k) { return kv.Where(p => p.Key == k).Select(p => p.Value); }
    public IEnumerable<Profile> Sections(string prefix) { return secs.Where(x => x.Name == prefix || x.Name.StartsWith(prefix + ".")); }
    public static Profile Load()
    {
        var root = new Profile(); Profile cur = null;
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("profile.ini"))
        {
            if (s == null) return root;
            using (var r = new StreamReader(s, Encoding.UTF8))
                for (string ln; (ln = r.ReadLine()) != null; )
                {
                    ln = ln.Trim().TrimStart('\uFEFF');
                    if (ln == "" || ln.StartsWith(";") || ln.StartsWith("#")) continue;
                    if (ln.StartsWith("[") && ln.EndsWith("]")) { cur = new Profile { Name = ln.Substring(1, ln.Length - 2).Trim().ToLowerInvariant() }; root.secs.Add(cur); continue; }
                    int e = ln.IndexOf('='); if (e <= 0 || cur == null) continue;
                    cur.kv.Add(new KeyValuePair<string, string>(ln.Substring(0, e).Trim().ToLowerInvariant(), ln.Substring(e + 1).Trim()));
                }
        }
        return root;
    }
}
