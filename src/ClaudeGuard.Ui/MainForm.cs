using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using ClaudeGuard.Core;

namespace ClaudeGuard.Ui;

// ======================================================================
//  Тема и базовые контролы
// ======================================================================

internal static class Theme
{
    public static readonly Color Bg = Color.FromArgb(13, 15, 19);
    public static readonly Color Card = Color.FromArgb(22, 25, 32);
    public static readonly Color Border = Color.FromArgb(38, 43, 54);
    public static readonly Color Text = Color.FromArgb(232, 234, 238);
    public static readonly Color Muted = Color.FromArgb(138, 146, 160);
    public static readonly Color Green = Color.FromArgb(52, 211, 153);
    public static readonly Color GreenHover = Color.FromArgb(90, 228, 176);
    public static readonly Color Red = Color.FromArgb(248, 113, 113);
    public static readonly Color Amber = Color.FromArgb(251, 191, 36);
    public static readonly Color Blue = Color.FromArgb(96, 165, 250);
    public static readonly Color DangerCard = Color.FromArgb(40, 23, 27);
    public static readonly Color Ghost = Color.FromArgb(30, 34, 43);
    public static readonly Color GhostHover = Color.FromArgb(40, 45, 57);

    public static readonly Font Title = new("Segoe UI Semibold", 16f);
    public static readonly Font Hero = new("Segoe UI Semibold", 18f);
    public static readonly Font Value = new("Segoe UI Semibold", 12f);
    public static readonly Font Body = new("Segoe UI", 9.5f);
    public static readonly Font Small = new("Segoe UI", 9f);
    public static readonly Font Semi = new("Segoe UI Semibold", 9.5f);
    public static readonly Font Mono = new("Consolas", 9f);

    public static GraphicsPath Round(RectangleF r, float radius)
    {
        float d = radius * 2;
        var p = new GraphicsPath();
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }
}

/// <summary>Скруглённая карточка с необязательной цветной полосой слева.</summary>
internal class Card : Panel
{
    private Color _fill = Theme.Card;
    private Color _accent = Color.Empty;

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public int Radius { get; set; } = 12;

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public Color Fill
    {
        get => _fill;
        set { _fill = value; Invalidate(); }
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public Color Accent
    {
        get => _accent;
        set { _accent = value; Invalidate(); }
    }

    public Card()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Bg;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        g.SmoothingMode = SmoothingMode.AntiAlias;

        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        using var path = Theme.Round(r, Radius);
        using (var fill = new SolidBrush(_fill)) g.FillPath(fill, path);

        if (!_accent.IsEmpty)
        {
            var state = g.Save();
            g.SetClip(path, CombineMode.Intersect);
            using (var b = new SolidBrush(_accent)) g.FillRectangle(b, 0, 0, 4, Height);
            g.Restore(state);
        }

        using (var pen = new Pen(Theme.Border)) g.DrawPath(pen, path);
        PaintExtra(g);
    }

    protected virtual void PaintExtra(Graphics g) { }
}

/// <summary>Главная карточка состояния: большой цветной индикатор + заголовок.</summary>
internal sealed class HeroCard : Card
{
    private Color _statusColor = Theme.Muted;
    private string _glyph = "…";

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public Color StatusColor
    {
        get => _statusColor;
        set { if (_statusColor != value) { _statusColor = value; Invalidate(); } }
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public string Glyph
    {
        get => _glyph;
        set { if (_glyph != value) { _glyph = value; Invalidate(); } }
    }

    protected override void PaintExtra(Graphics g)
    {
        const int d = 52;
        int x = 24, y = (Height - d) / 2;

        using (var halo = new SolidBrush(Color.FromArgb(38, _statusColor)))
            g.FillEllipse(halo, x - 8, y - 8, d + 16, d + 16);
        using (var body = new SolidBrush(_statusColor))
            g.FillEllipse(body, x, y, d, d);

        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        using var font = new Font("Segoe UI Symbol", 20f, FontStyle.Bold);
        using var brush = new SolidBrush(Theme.Bg);
        using var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        g.DrawString(_glyph, font, brush, new RectangleF(x, y, d, d), fmt);
    }
}

/// <summary>Плитка статуса: цветная точка, подпись, значение, пояснение.</summary>
internal sealed class Tile : Card
{
    private Color _dot = Theme.Muted;
    public readonly Label Caption = new();
    public readonly Label ValueLabel = new();
    public readonly Label Detail = new();

    public Tile(string caption)
    {
        Padding = new Padding(16, 12, 14, 10);

        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Color.Transparent,
            Margin = Padding.Empty
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        Caption.Text = caption;
        Caption.Dock = DockStyle.Fill;
        Caption.ForeColor = Theme.Muted;
        Caption.Font = Theme.Small;
        Caption.BackColor = Color.Transparent;
        Caption.Padding = new Padding(16, 0, 0, 0);
        Caption.TextAlign = ContentAlignment.MiddleLeft;

        ValueLabel.Dock = DockStyle.Fill;
        ValueLabel.Font = Theme.Value;
        ValueLabel.ForeColor = Theme.Text;
        ValueLabel.BackColor = Color.Transparent;
        ValueLabel.TextAlign = ContentAlignment.MiddleLeft;
        ValueLabel.AutoEllipsis = true;

        Detail.Dock = DockStyle.Fill;
        Detail.Font = Theme.Small;
        Detail.ForeColor = Theme.Muted;
        Detail.BackColor = Color.Transparent;
        Detail.AutoEllipsis = true;

        grid.Controls.Add(Caption, 0, 0);
        grid.Controls.Add(ValueLabel, 0, 1);
        grid.Controls.Add(Detail, 0, 2);
        Controls.Add(grid);
    }

    public void Set(string value, Color color, string detail)
    {
        _dot = color;
        ValueLabel.Text = value;
        ValueLabel.ForeColor = color;
        Detail.Text = detail;
        Invalidate();
    }

    protected override void PaintExtra(Graphics g)
    {
        using var b = new SolidBrush(_dot);
        g.FillEllipse(b, 16, Padding.Top + 7, 9, 9);
    }
}

internal sealed class BufferedListView : ListView
{
    public BufferedListView() => DoubleBuffered = true;
}

// ======================================================================
//  Главное окно
// ======================================================================

public sealed class MainForm : Form
{
    private readonly Config _cfg = Config.Load();
    private readonly System.Windows.Forms.Timer _statusTimer = new() { Interval = 1000 };
    private readonly System.Windows.Forms.Timer _logTimer = new() { Interval = 2500 };

    private readonly HeroCard _hero = new();
    private readonly Label _heroTitle = new();
    private readonly Label _heroSub = new();
    private readonly Tile _vpnTile = new("VPN (Happ + туннель)");
    private readonly Tile _protTile = new("Защита Claude");
    private readonly Tile _netTile = new("Сеть через туннель");
    private readonly Card _reasonCard = new();
    private readonly Label _reasonText = new();
    private readonly Label _reasonCode = new();
    private readonly Button _pauseBtn = new();
    private readonly Button _checkBtn = new();
    private readonly Button _launchBtn = new();
    private readonly Label _serviceInfo = new();
    private readonly BufferedListView _logView = new();
    private readonly NotifyIcon _tray = new();
    private readonly ToolStripMenuItem _trayStatus = new("Claude Guard") { Enabled = false };

    private static readonly Dictionary<int, Icon> IconCache = new();

    private GuardStatus _status;
    private bool _busy;
    private bool _restartHandled;
    private bool _reallyExit;
    private bool _hintShown;
    private bool _timersStarted;
    private bool _startHidden;
    private int _trayColor;
    private string _trayText = "";
    private string _lastLogSignature = "";

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    public MainForm()
    {
        Text = "Claude Guard";
        ClientSize = new Size(720, 680);
        MinimumSize = new Size(660, 600);
        BackColor = Theme.Bg;
        ForeColor = Theme.Text;
        Font = Theme.Body;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        Icon = IconFor(Theme.Green);

        _startHidden = Environment.GetCommandLineArgs()
            .Any(a => a.Equals("--minimized", StringComparison.OrdinalIgnoreCase));

        BuildUi();
        BuildTray();

        FormClosing += (_, e) =>
        {
            // закрытие крестиком — в трей; завершение сеанса Windows не блокируем
            if (!_reallyExit && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                if (!_hintShown)
                {
                    _hintShown = true;
                    _tray.ShowBalloonTip(2500, "Claude Guard", "Свёрнуто в трей. Защита продолжает работать.", ToolTipIcon.Info);
                }
            }
        };
        FormClosed += (_, _) =>
        {
            _statusTimer.Stop();
            _logTimer.Stop();
            _tray.Visible = false;
            _tray.Dispose();
        };
    }

    // Запуск свёрнутым в трей без мерцания окна (--minimized).
    protected override void SetVisibleCore(bool value)
    {
        if (_startHidden)
        {
            value = false;
            if (!IsHandleCreated) CreateHandle();
        }
        base.SetVisibleCore(value);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);

        try
        {
            int dark = 1;
            DwmSetWindowAttribute(Handle, 20, ref dark, sizeof(int)); // тёмный заголовок окна
        }
        catch { }

        if (_timersStarted) return;
        _timersStarted = true;
        _statusTimer.Tick += async (_, _) => await RefreshStatusAsync();
        _logTimer.Tick += async (_, _) => await RefreshLogAsync();
        _statusTimer.Start();
        _logTimer.Start();
        _ = RefreshStatusAsync();
        _ = RefreshLogAsync();
    }

    public void RestoreWindow()
    {
        _startHidden = false;
        if (!Visible) Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
        BringToFront();
        _ = RefreshStatusAsync();
        _ = RefreshLogAsync();
    }

    // ---------------- построение интерфейса ----------------

    private void BuildUi()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            BackColor = Theme.Bg,
            Padding = new Padding(20, 16, 20, 16)
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 5; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(root);

        // --- шапка ---
        var header = new Panel { Dock = DockStyle.Fill, Height = 56, BackColor = Theme.Bg, Margin = new Padding(0, 0, 0, 8) };
        _serviceInfo.Dock = DockStyle.Right;
        _serviceInfo.AutoSize = true;
        _serviceInfo.ForeColor = Theme.Muted;
        _serviceInfo.Font = Theme.Small;
        _serviceInfo.TextAlign = ContentAlignment.MiddleRight;
        _serviceInfo.Text = "служба: …";
        var title = new Label
        {
            Text = "Claude Guard",
            Font = Theme.Title,
            ForeColor = Theme.Text,
            AutoSize = true,
            Location = new Point(0, 2)
        };
        var subtitle = new Label
        {
            Text = "Защита Claude Desktop от утечки трафика при сбое VPN",
            Font = Theme.Small,
            ForeColor = Theme.Muted,
            AutoSize = true,
            Location = new Point(2, 34)
        };
        header.Controls.Add(_serviceInfo);
        header.Controls.Add(title);
        header.Controls.Add(subtitle);
        root.Controls.Add(header, 0, 0);

        // --- главная карточка ---
        _hero.Dock = DockStyle.Fill;
        _hero.Height = 112;
        _hero.Margin = new Padding(0, 0, 0, 10);
        _hero.Padding = new Padding(100, 20, 20, 14);
        _heroTitle.Dock = DockStyle.Top;
        _heroTitle.Height = 36;
        _heroTitle.Font = Theme.Hero;
        _heroTitle.ForeColor = Theme.Muted;
        _heroTitle.BackColor = Color.Transparent;
        _heroTitle.Text = "Инициализация";
        _heroSub.Dock = DockStyle.Fill;
        _heroSub.Font = Theme.Body;
        _heroSub.ForeColor = Theme.Muted;
        _heroSub.BackColor = Color.Transparent;
        _heroSub.Text = "Связь со службой…";
        _hero.Controls.Add(_heroSub);
        _hero.Controls.Add(_heroTitle);
        root.Controls.Add(_hero, 0, 1);

        // --- плитки статусов ---
        var tiles = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Height = 100,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0, 0, 0, 10)
        };
        for (int i = 0; i < 3; i++) tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        tiles.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _vpnTile.Dock = _protTile.Dock = _netTile.Dock = DockStyle.Fill;
        _vpnTile.Margin = new Padding(0, 0, 5, 0);
        _protTile.Margin = new Padding(5, 0, 5, 0);
        _netTile.Margin = new Padding(5, 0, 0, 0);
        tiles.Controls.Add(_vpnTile, 0, 0);
        tiles.Controls.Add(_protTile, 1, 0);
        tiles.Controls.Add(_netTile, 2, 0);
        root.Controls.Add(tiles, 0, 2);

        // --- причина ---
        _reasonCard.Dock = DockStyle.Fill;
        _reasonCard.Height = 78;
        _reasonCard.Margin = new Padding(0, 0, 0, 10);
        _reasonCard.Padding = new Padding(18, 10, 18, 8);
        _reasonText.Dock = DockStyle.Fill;
        _reasonText.Font = Theme.Body;
        _reasonText.ForeColor = Theme.Text;
        _reasonText.BackColor = Color.Transparent;
        _reasonText.Text = "Причина: —";
        _reasonCode.Dock = DockStyle.Bottom;
        _reasonCode.Height = 22;
        _reasonCode.Font = Theme.Mono;
        _reasonCode.ForeColor = Theme.Muted;
        _reasonCode.BackColor = Color.Transparent;
        _reasonCode.AutoEllipsis = true;
        _reasonCard.Controls.Add(_reasonText);
        _reasonCard.Controls.Add(_reasonCode);
        root.Controls.Add(_reasonCard, 0, 3);

        // --- кнопки ---
        var buttons = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Height = 44,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Bg,
            Margin = new Padding(0, 0, 0, 10)
        };
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 36));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 36));
        buttons.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        StyleButton(_pauseBtn, "Отключить защиту", Theme.Ghost, Theme.Red, Theme.GhostHover);
        StyleButton(_checkBtn, "Проверить сейчас", Theme.Ghost, Theme.Blue, Theme.GhostHover);
        StyleButton(_launchBtn, "Запустить Claude", Theme.Green, Theme.Bg, Theme.GreenHover);
        _launchBtn.Margin = Padding.Empty;
        _pauseBtn.Click += async (_, _) => await ToggleProtectionAsync();
        _checkBtn.Click += async (_, _) =>
        {
            _checkBtn.Enabled = false;
            try
            {
                await CallAsync("check", 3000);
                await Task.Delay(400);
                await RefreshStatusAsync();
            }
            finally { _checkBtn.Enabled = true; }
        };
        _launchBtn.Click += (_, _) => ClaudeApp.Launch(_cfg);
        buttons.Controls.Add(_pauseBtn, 0, 0);
        buttons.Controls.Add(_checkBtn, 1, 0);
        buttons.Controls.Add(_launchBtn, 2, 0);
        root.Controls.Add(buttons, 0, 4);

        // --- журнал ---
        var logCard = new Card { Dock = DockStyle.Fill, Padding = new Padding(14, 10, 14, 12), Margin = Padding.Empty };
        var logHeader = new Panel { Dock = DockStyle.Top, Height = 28, BackColor = Color.Transparent };
        var openLog = new LinkLabel
        {
            Text = "открыть файл",
            Dock = DockStyle.Right,
            AutoSize = true,
            LinkColor = Theme.Blue,
            ActiveLinkColor = Theme.Blue,
            Font = Theme.Small,
            TextAlign = ContentAlignment.MiddleRight,
            BackColor = Color.Transparent
        };
        openLog.LinkClicked += (_, _) => OpenLogFile();
        var logTitle = new Label
        {
            Text = "Журнал событий",
            Dock = DockStyle.Left,
            AutoSize = true,
            ForeColor = Theme.Muted,
            Font = Theme.Semi,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Color.Transparent
        };
        logHeader.Controls.Add(openLog);
        logHeader.Controls.Add(logTitle);

        _logView.Dock = DockStyle.Fill;
        _logView.View = View.Details;
        _logView.FullRowSelect = true;
        _logView.GridLines = false;
        _logView.HeaderStyle = ColumnHeaderStyle.None;
        _logView.BackColor = Theme.Card;
        _logView.ForeColor = Theme.Text;
        _logView.BorderStyle = BorderStyle.None;
        _logView.Font = Theme.Mono;
        _logView.Columns.Add("Время", 70);
        _logView.Columns.Add("Ур.", 56);
        _logView.Columns.Add("Событие", 400);
        _logView.Resize += (_, _) => FitLogColumns();
        logCard.Controls.Add(_logView);
        logCard.Controls.Add(logHeader);
        root.Controls.Add(logCard, 0, 5);
    }

    private void FitLogColumns()
    {
        if (_logView.Columns.Count != 3) return;
        int time = LogicalToDeviceUnits(70), lvl = LogicalToDeviceUnits(56);
        _logView.Columns[0].Width = time;
        _logView.Columns[1].Width = lvl;
        _logView.Columns[2].Width = Math.Max(LogicalToDeviceUnits(200), _logView.ClientSize.Width - time - lvl - 4);
    }

    private static void StyleButton(Button b, string text, Color fill, Color fore, Color hover)
    {
        b.Text = text;
        b.Dock = DockStyle.Fill;
        b.FlatStyle = FlatStyle.Flat;
        b.UseVisualStyleBackColor = false;
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.BorderColor = Theme.Border;
        b.FlatAppearance.MouseOverBackColor = hover;
        b.FlatAppearance.MouseDownBackColor = hover;
        b.BackColor = fill;
        b.ForeColor = fore;
        b.Font = Theme.Semi;
        b.Margin = new Padding(0, 0, 8, 0);
        b.Cursor = Cursors.Hand;
    }

    private void StylePause(bool protectionDisabled)
    {
        if (protectionDisabled)
        {
            StyleButton(_pauseBtn, "Включить защиту", Theme.Green, Theme.Bg, Theme.GreenHover);
        }
        else
        {
            StyleButton(_pauseBtn, "Отключить защиту", Theme.Ghost, Theme.Red, Theme.GhostHover);
        }
    }

    // ---------------- трей ----------------

    private void BuildTray()
    {
        _tray.Icon = IconFor(Theme.Muted);
        _tray.Text = "Claude Guard";
        _tray.Visible = true;
        _tray.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) RestoreWindow(); };

        var menu = new ContextMenuStrip();
        menu.Items.Add(_trayStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Открыть окно", null, (_, _) => RestoreWindow());
        menu.Items.Add("Проверить сейчас", null, async (_, _) => await CallAsync("check", 3000));
        menu.Items.Add("Запустить Claude", null, (_, _) => ClaudeApp.Launch(_cfg));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход из интерфейса", null, (_, _) =>
        {
            _reallyExit = true;
            Close();
        });
        _tray.ContextMenuStrip = menu;
    }

    /// <summary>Иконки кэшируются по цвету: GetHicon создаёт неуправляемый дескриптор,
    /// пересоздавать его каждую секунду нельзя (утечка GDI-объектов).</summary>
    private static Icon IconFor(Color color)
    {
        int key = color.ToArgb();
        if (IconCache.TryGetValue(key, out var cached)) return cached;

        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var fill = new SolidBrush(color);
            g.FillEllipse(fill, 3, 3, 26, 26);
            using var ring = new Pen(Color.FromArgb(200, 13, 15, 19), 3f);
            g.DrawEllipse(ring, 3, 3, 26, 26);
        }
        var icon = Icon.FromHandle(bmp.GetHicon());
        IconCache[key] = icon;
        return icon;
    }

    private void SetTray(Color c, string tooltip)
    {
        try
        {
            if (tooltip.Length > 62) tooltip = tooltip[..62];
            if (c.ToArgb() != _trayColor)
            {
                _trayColor = c.ToArgb();
                _tray.Icon = IconFor(c);
            }
            if (tooltip != _trayText)
            {
                _trayText = tooltip;
                _tray.Text = tooltip;
                _trayStatus.Text = tooltip;
            }
        }
        catch { }
    }

    // ---------------- обмен со службой ----------------

    private static async Task<GuardResponse> CallAsync(string cmd, int timeoutMs, int count = 0)
    {
        var task = Task.Run(() => Ipc.Call(new GuardRequest { Cmd = cmd, Count = count > 0 ? count : 200 }, timeoutMs));
        // исключение из «брошенной» задачи не должно оставаться необработанным
        _ = task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);

        var finished = await Task.WhenAny(task, Task.Delay(timeoutMs + 1500));
        if (finished != task) return null;
        try { return await task; }
        catch { return null; }
    }

    private async Task RefreshStatusAsync()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var resp = await CallAsync("status", 1500);
            if (resp == null || !resp.Ok || resp.Status == null)
            {
                _status = null;
                ApplyServiceDown();
                return;
            }

            _status = resp.Status;
            ApplyStatus(_status);

            if (_status.RestartPending && !_restartHandled)
            {
                _restartHandled = true;
                if (_cfg.AutoRestartClaude)
                {
                    ClaudeApp.Launch(_cfg);
                    await CallAsync("ack-restart", 2000);
                }
            }
            if (!_status.RestartPending) _restartHandled = false;
        }
        catch { /* UI не должен падать из-за сбоя обновления */ }
        finally { _busy = false; }
    }

    private async Task RefreshLogAsync()
    {
        if (!Visible) return;
        var resp = await CallAsync("log", 2000, 250);
        if (resp?.Log == null) return;

        var last = resp.Log.Length == 0 ? null : resp.Log[^1];
        var sig = last == null ? "" : $"{resp.Log.Length}:{last.Ts:O}:{last.Message}";
        if (sig == _lastLogSignature) return;
        _lastLogSignature = sig;

        // прокручивать вниз только если пользователь уже был внизу
        bool atBottom = _logView.Items.Count == 0 ||
                        _logView.Items[^1].Bounds.Bottom <= _logView.ClientSize.Height + 2;

        _logView.BeginUpdate();
        try
        {
            _logView.Items.Clear();
            foreach (var e in resp.Log)
            {
                var item = new ListViewItem(e.Ts.ToLocalTime().ToString("HH:mm:ss")) { ForeColor = LevelColor(e.Level) };
                item.SubItems.Add(e.Level);
                item.SubItems.Add(e.Code + " — " + e.Message);
                _logView.Items.Add(item);
            }
            FitLogColumns();
            if (atBottom && _logView.Items.Count > 0) _logView.Items[^1].EnsureVisible();
        }
        finally { _logView.EndUpdate(); }
    }

    private static Color LevelColor(string level) => level switch
    {
        "CRIT" or "ERROR" => Theme.Red,
        "WARN" => Theme.Amber,
        _ => Theme.Text
    };

    // ---------------- отображение состояния ----------------

    private void ApplyServiceDown()
    {
        SetHero("Служба не запущена", "Защита не работает. Запустите службу ClaudeGuard (нужны права администратора).",
            Theme.Red, "✕", danger: true);

        _vpnTile.Set("Неизвестно", Theme.Muted, "");
        _protTile.Set("Неизвестно", Theme.Muted, "");
        _netTile.Set("Неизвестно", Theme.Muted, "");
        _reasonText.Text = "Причина: служба недоступна";
        _reasonCode.Text = "SERVICE_UNAVAILABLE";

        StylePause(false);
        _pauseBtn.Enabled = false;
        _checkBtn.Enabled = false;
        _launchBtn.Enabled = false;

        _serviceInfo.Text = "служба: offline";
        _serviceInfo.ForeColor = Theme.Red;
        SetTray(Theme.Red, "Claude Guard: служба не запущена");
    }

    private void SetHero(string title, string sub, Color color, string glyph, bool danger)
    {
        _heroTitle.Text = title;
        _heroTitle.ForeColor = color;
        _heroSub.Text = sub;
        _hero.StatusColor = color;
        _hero.Glyph = glyph;
        _hero.Fill = danger ? Theme.DangerCard : Theme.Card;
    }

    private void ApplyStatus(GuardStatus s)
    {
        Color c;
        string title, sub, glyph;
        bool danger = false;

        switch (s.State)
        {
            case GuardState.Allowed:
                c = Theme.Green; title = "Защищено"; glyph = "✓";
                sub = "Claude работает только через VPN";
                break;
            case GuardState.Blocked when s.Vpn == VpnState.Down:
                c = Theme.Red; title = "VPN отключён"; glyph = "✕";
                sub = "Claude заблокирован системным firewall";
                break;
            case GuardState.Blocked:
                c = Theme.Amber; title = "Доступ заблокирован"; glyph = "!";
                sub = "Проверка туннеля не пройдена — Claude заблокирован";
                break;
            case GuardState.Checking:
                c = Theme.Blue; title = "Проверка VPN"; glyph = "…";
                sub = "Claude заблокирован до успешной проверки";
                break;
            case GuardState.Paused:
                c = Theme.Red; title = "Защита отключена"; glyph = "!"; danger = true;
                sub = "Claude НЕ защищён — трафик может идти напрямую";
                break;
            case GuardState.Error:
                c = Theme.Red; title = "Ошибка"; glyph = "✕";
                sub = string.IsNullOrEmpty(s.ReasonText) ? "Внутренняя ошибка службы" : s.ReasonText;
                break;
            default:
                c = Theme.Muted; title = "Инициализация"; glyph = "…";
                sub = "Ожидание данных от службы";
                break;
        }
        SetHero(title, sub, c, glyph, danger);

        // VPN
        var processes = s.Processes != null && s.Processes.Length > 0
            ? string.Join(" · ", s.Processes)
            : "процессы VPN не найдены";
        switch (s.Vpn)
        {
            case VpnState.Connected: _vpnTile.Set("Подключён", Theme.Green, processes); break;
            case VpnState.Down: _vpnTile.Set("Отключён", Theme.Red, processes); break;
            case VpnState.Checking: _vpnTile.Set("Проверяется", Theme.Blue, processes); break;
            default: _vpnTile.Set("Неизвестно", Theme.Amber, processes); break;
        }

        // Защита
        var fwDetail = s.RulesOk
            ? "firewall: правила активны" + (s.FirewallEnabled ? "" : " · WINDOWS FIREWALL ВЫКЛЮЧЕН")
            : "firewall: правила требуют восстановления";
        if (s.Protection == ProtectionState.Disabled)
            _protTile.Set("Отключена", Theme.Red, "правила firewall сняты");
        else if (s.State == GuardState.Allowed)
            _protTile.Set("Claude разрешён", Theme.Green, fwDetail);
        else
            _protTile.Set("Claude заблокирован", Theme.Amber, fwDetail);

        // Сеть
        var netDetail = $"tun: {s.TunAlias} {s.TunIp}".TrimEnd() +
                        (string.IsNullOrEmpty(s.PhysicalIp) ? "" : $" · напрямую: {s.PhysicalIp}");
        switch (s.Network)
        {
            case NetworkState.TunOk: _netTile.Set("Туннель работает", Theme.Green, netDetail); break;
            case NetworkState.NoTun: _netTile.Set("TUN отсутствует", Theme.Red, netDetail); break;
            case NetworkState.NoRoute: _netTile.Set("Маршрут не через VPN", Theme.Red, netDetail); break;
            case NetworkState.NoInternet: _netTile.Set("Нет доступа через туннель", Theme.Amber, netDetail); break;
            default: _netTile.Set("Неизвестно", Theme.Amber, netDetail); break;
        }

        // Причина
        _reasonText.Text = "Причина: " + (string.IsNullOrEmpty(s.ReasonText) ? "—" : s.ReasonText);
        var pids = s.ClaudePids != null && s.ClaudePids.Length > 0
            ? $"Claude PID: {string.Join(",", s.ClaudePids.Take(3))}"
            : "Claude не запущен";
        _reasonCode.Text = $"{s.ReasonCode} · с {s.Since.ToLocalTime():HH:mm:ss} ({Ago(s.Since)}) · проба {s.LastProbeMs} мс · {pids}";

        // Кнопки
        bool paused = s.Protection == ProtectionState.Disabled;
        StylePause(paused);
        _pauseBtn.Enabled = true;
        _checkBtn.Enabled = !paused;
        // в Blocked/Checking Claude всё равно будет закрыт службой — запуск бессмыслен
        _launchBtn.Enabled = s.State is GuardState.Allowed or GuardState.Paused;

        _serviceInfo.Text = $"служба: online · v{s.Version}";
        _serviceInfo.ForeColor = Theme.Green;
        SetTray(c, "Claude Guard: " + title);
    }

    private static string Ago(DateTimeOffset t)
    {
        var d = DateTimeOffset.Now - t;
        if (d < TimeSpan.Zero) d = TimeSpan.Zero;
        if (d.TotalMinutes < 1) return $"{(int)d.TotalSeconds} с";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes} мин";
        return $"{(int)d.TotalHours} ч {d.Minutes} мин";
    }

    // ---------------- действия ----------------

    private async Task ToggleProtectionAsync()
    {
        bool pausing = _status?.Protection != ProtectionState.Disabled;
        if (pausing)
        {
            var answer = MessageBox.Show(this,
                "Отключить защиту?\n\nClaude Desktop получит возможность выходить в интернет напрямую, " +
                "в обход VPN. Правила firewall будут удалены.\n\nВключить защиту обратно можно этой же кнопкой.",
                "Claude Guard — подтверждение",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return;
        }

        var cmd = pausing ? "pause" : "resume";
        _pauseBtn.Enabled = false;
        try
        {
            var resp = await CallAsync(cmd, 4000);
            if (resp == null)
            {
                MessageBox.Show(this, "Служба Claude Guard недоступна.", "Claude Guard",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (!resp.Ok && resp.Error != null && resp.Error.Contains("ELEVATION_REQUIRED"))
            {
                await RunElevatedAsync(cmd);
            }
            else if (!resp.Ok)
            {
                MessageBox.Show(this, "Не удалось выполнить команду: " + resp.Error, "Claude Guard",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        finally
        {
            _pauseBtn.Enabled = true;
            await RefreshStatusAsync();
        }
    }

    /// <summary>Повторяет команду отдельным процессом с правами администратора (UAC).</summary>
    private async Task RunElevatedAsync(string cmd)
    {
        try
        {
            var psi = new ProcessStartInfo(Environment.ProcessPath!, "--" + cmd)
            {
                UseShellExecute = true,
                Verb = "runas"
            };
            using var p = Process.Start(psi);
            if (p != null)
                await Task.WhenAny(p.WaitForExitAsync(), Task.Delay(20000));
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Для этого действия нужны права администратора.\n" + ex.Message,
                "Claude Guard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OpenLogFile()
    {
        try
        {
            // UI-процесс не инициализирует Log, поэтому ищем свежий файл в каталоге журналов сам
            string file = null;
            if (Directory.Exists(_cfg.LogDir))
            {
                file = Directory.GetFiles(_cfg.LogDir, "guard-*.log")
                    .OrderByDescending(p => File.GetLastWriteTime(p))
                    .FirstOrDefault();
            }

            if (file != null)
                Process.Start(new ProcessStartInfo("notepad.exe", $"\"{file}\"") { UseShellExecute = true });
            else
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_cfg.LogDir}\"") { UseShellExecute = true });
        }
        catch { }
    }
}
