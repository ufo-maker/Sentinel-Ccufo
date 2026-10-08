using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Sentinel
{
    public sealed class MainForm : Form
    {
        // 控件
        TableLayoutPanel _root, _bodyTbl, _columnTbl;
        Panel _topBar, _leftCol, _midCol, _rightCol, _statusBar;
        Label _lblRisk, _lblInbound, _lblThreat, _lblAttempt, _lblBreach;
        Label _lblPubIp, _lblPubGeo, _lblAdmin, _lblFw, _sbLeft, _sbRight;
        Panel _metaPanel = null!, _netPanel = null!;
        Label _tabThreat, _tabAction;
        FlowLayoutPanel _issueBox, _threatBox;
        Gauge _gauge;
        TableLayoutPanel _actionGrid;
        RichTextBox _console;
        Button _btnMonitor, _btnScan, _btnClear;
        NotifyIcon _tray;
        System.Windows.Forms.Timer _timerFast, _timerSlow;

        readonly Collector _collector = new();
        Snapshot _snap = new();
        readonly HashSet<string> _renderedThreats = new();
        int _logLines, _tabIndex;
        bool _busy, _forceFullThreatRender;
        DateTime _lastLogScan = DateTime.MinValue;
        Button[] _actionCards = Array.Empty<Button>();

        // 布局记忆
        int _colLeft = 300, _colMid = 470, _colRight = 560;

        /// <summary>左栏当前可用内容宽度（随拖动变化）</summary>
        int LeftContentWidth => Math.Max(Theme.P(150), (_issueBox?.ClientSize.Width ?? Theme.P(240)) - Theme.P(20));

        public MainForm()
        {
            Text = "Sentinel-Ccufo · SMB 暴露监控";
            BackColor = Theme.Bg0;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = Theme.Sz(1440, 900);
            MinimumSize = Theme.Sz(1040, 680);
            Font = Theme.Base;

            // 可缩放 / 可最大化 —— 修复问题 1、3
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = true;
            AutoScaleMode = AutoScaleMode.Dpi;
            DoubleBuffered = true;
            KeyPreview = true;

            // 允许最大化到当前屏幕工作区（避免超出屏幕被裁）
            AutoScaleDimensions = new SizeF(96f, 96f);

            Theme.InitScale(this);
            BuildUi();
            BuildTray();
            RestoreLayout();

            _timerFast = new System.Windows.Forms.Timer { Interval = 2000 };
            _timerFast.Tick += async (_, _) => await TickFastAsync();
            _timerFast.Start();

            _timerSlow = new System.Windows.Forms.Timer { Interval = 15000 };
            _timerSlow.Tick += async (_, _) => await TickSlowAsync();
            _timerSlow.Start();

            // Ctrl+滚轮调整缩放
            MouseEnter += (_, _) => { };
            KeyDown += (_, e) =>
            {
                if (e.Control && (e.KeyCode == Keys.Add || e.KeyCode == Keys.Subtract))
                {
                    ScaleStep(e.KeyCode == Keys.Add ? 0.1f : -0.1f);
                    e.Handled = true;
                }
            };

            FormClosing += (_, e) =>
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    SaveLayout();
                    HideToTray();
                }
            };
        }

        /// <summary>按比例调整整体缩放（Ctrl+ +/-）</summary>
        void ScaleStep(float delta)
        {
            var next = Math.Clamp(Theme.Scale + delta, 0.85f, 1.6f);
            if (Math.Abs(next - Theme.Scale) < 0.01f) return;
            Theme.InitScale(this);
            ClientSize = new Size(
                (int)(ClientSize.Width / Theme.Scale * next),
                (int)(ClientSize.Height / Theme.Scale * next));
            MinimumSize = Theme.Sz(1040, 680);
            ApplyFontScale();
            Log($"界面缩放已调整为 {Theme.Scale * 100:F0}%", "act");
        }

        void ApplyFontScale()
        {
            Font = Theme.Base;
            if (_lblRisk != null) _lblRisk.Font = Theme.SmallBold;
        }

        // ================================================================ UI
        void BuildUi()
        {
            _root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
                BackColor = Theme.Bg0, Padding = Padding.Empty
            };
            _root.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.P(48)));
            _root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            _root.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.P(30)));
            Controls.Add(_root);

            _topBar = BuildTopBar();
            _bodyTbl = BuildBody();
            _statusBar = BuildStatus();

            _root.Controls.Add(_topBar, 0, 0);
            _root.Controls.Add(_bodyTbl, 0, 1);
            _root.Controls.Add(_statusBar, 0, 2);
        }

        // ------------------------------------------------------------ 标题栏
        Panel BuildTopBar()
        {
            var p = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg1, Padding = new Padding(Theme.P(14), 0, Theme.P(10), 0) };
            p.Paint += (_, e) =>
            {
                using var pen = new Pen(Theme.Line, 1f);
                e.Graphics.DrawLine(pen, 0, p.Height - 1, p.Width, p.Height - 1);
            };

            // 盾牌图标（自绘）
            var icon = new Panel { Location = new Point(Theme.P(14), Theme.P(13)), Size = Theme.Sz(22, 22), BackColor = Color.Transparent };
            icon.Paint += (_, e) => DrawShield(e.Graphics, new Rectangle(0, 0, 22, 22), Theme.Cyan);
            p.Controls.Add(icon);

            var title = Lbl(new Point(Theme.P(42), Theme.P(10)), new Size(Theme.P(120), Theme.P(18)),
                "Sentinel", Theme.Bold(10f), Theme.Tx1);
            p.Controls.Add(title);

            var sub = Lbl(new Point(Theme.P(42), Theme.P(26)), new Size(Theme.P(200), Theme.P(16)),
                "SMB 暴露监控与处置", Theme.Small, Theme.Tx3);
            p.Controls.Add(sub);

            // 风险徽标（居中）
            _lblRisk = Lbl(new Point(0, Theme.P(14)), new Size(Theme.P(220), Theme.P(22)),
                "正在初始化…", Theme.SmallBold, Theme.Tx2, HorizontalAlignment.Center);
            _lblRisk.BackColor = Theme.Bg2;
            _lblRisk.Paint += (_, e) =>
            {
                var r = e.ClipRectangle;
                using var path = new GraphicsPath();
                int d = Theme.P(18);
                path.AddArc(r.X, r.Y, d, d, 180, 90);
                path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
                path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
                path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
                path.CloseFigure();
                using var b = new SolidBrush(Theme.Bg2);
                e.Graphics.FillPath(b, path);
                using var pen = new Pen(_lblRisk.BackColor == Theme.Bg2 ? Theme.Line : Theme.Red, 1f);
                e.Graphics.DrawPath(pen, path);
            };
            p.Controls.Add(_lblRisk);

            _btnScan = Btn("立即扫描", Theme.Sz(90, 28), Theme.Bg2, Theme.Tx1);
            _btnScan.FlatAppearance.BorderColor = Theme.Line;
            _btnScan.Click += async (_, _) => await TickFastAsync(true);
            p.Controls.Add(_btnScan);

            _btnMonitor = Btn("停止监控", Theme.Sz(90, 28), Color.FromArgb(60, 24, 30), Theme.Red);
            _btnMonitor.FlatAppearance.BorderColor = Color.FromArgb(90, 35, 45);
            _btnMonitor.Click += (_, _) => ToggleMonitor();
            p.Controls.Add(_btnMonitor);

            p.Resize += (_, _) => LayoutTopBar(p);
            LayoutTopBar(p);

            // 标题栏空白处双击 = 最大化/还原
            p.MouseDoubleClick += (_, e) =>
            {
                if (e.X < _btnScan.Left - Theme.P(10) && e.X > Theme.P(180))
                    ToggleMaximize();
            };

            // 提供系统级最大化能力
            p.MouseDown += (_, e) =>
            {
                if (e.Button == MouseButtons.Left)
                {
                    // 交给系统处理窗口拖动与最大化双击
                    Native.ReleaseCapture();
                    Native.SendMessage(Handle, 0xA1, new IntPtr(0x2), IntPtr.Zero);
                }
            };

            return p;
        }

        /// <summary>切换最大化 / 还原（问题3）</summary>
        void ToggleMaximize()
        {
            WindowState = WindowState == FormWindowState.Maximized
                ? FormWindowState.Normal
                : FormWindowState.Maximized;
        }

        /// <summary>绘制盾牌图标（矢量，任意尺寸清晰）</summary>
        static void DrawShield(Graphics g, Rectangle r, Color color)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float k = r.Height / 22f;
            using var path = new GraphicsPath();
            path.AddArc(r.X + 3 * k, r.Y + 2 * k, 16 * k, 16 * k, 180, 180);
            path.AddLine(new PointF(r.X + 11 * k, r.Y + 20 * k), new PointF(r.X + 11 * k, r.Y + 20 * k));
            path.CloseFigure();
            using var br = new SolidBrush(color);
            g.FillPath(br, path);
            using var ib = new SolidBrush(Theme.Bg1);
            g.FillRectangle(ib, r.X + 10 * k, r.Y + 7 * k, 2.2f * k, 6 * k);
            g.FillRectangle(ib, r.X + 10 * k, r.Y + 14.5f * k, 2.2f * k, 2.2f * k);
        }

        void LayoutTopBar(Panel p)
        {
            _lblRisk.Location = new Point(Math.Max(Theme.P(190), (p.Width - Theme.P(220)) / 2), Theme.P(13));
            _btnScan.Location = new Point(p.Width - Theme.P(212), Theme.P(10));
            _btnMonitor.Location = new Point(p.Width - Theme.P(114), Theme.P(10));
        }

        // ------------------------------------------------------------ 主体
        TableLayoutPanel BuildBody()
        {
            var wrap = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 1,
                BackColor = Theme.Bg0, Padding = Padding.Empty, Margin = Padding.Empty
            };
            wrap.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            wrap.Controls.Add(BuildColumns(), 0, 0);
            return wrap;
        }

        /// <summary>三栏 + 两个可拖拽分隔条 —— 修复问题 1「各部分不能拖动改变大小」</summary>
        Control BuildColumns()
        {
            _leftCol = BuildOverviewCol();
            _midCol = BuildMidCol();
            _rightCol = BuildConsoleCol();

            var splitL = MakeSplitter(0);
            var splitR = MakeSplitter(1);

            _columnTbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 5, RowCount = 1,
                BackColor = Theme.Bg0, Margin = Padding.Empty, Padding = Padding.Empty
            };
            _columnTbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            _columnTbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Theme.P(_colLeft)));
            _columnTbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Theme.P(8)));
            _columnTbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            _columnTbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Theme.P(8)));
            _columnTbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Theme.P(_colRight)));

            _columnTbl.Controls.Add(_leftCol, 0, 0);
            _columnTbl.Controls.Add(splitL, 1, 0);
            _columnTbl.Controls.Add(_midCol, 2, 0);
            _columnTbl.Controls.Add(splitR, 3, 0);
            _columnTbl.Controls.Add(_rightCol, 4, 0);

            // 列宽随窗口尺寸自适应：窄窗口优先压缩右栏
            // 只在「非拖动」状态下响应窗口尺寸变化。
            // 否则拖动分隔条 → SetCol → 触发 Resize → AutoFitColumns → 再 SetCol → 震荡。
            _columnTbl.Resize += (_, _) =>
            {
                if (_dragSide < 0 && !_adjusting) AutoFitColumns();
            };

            return _columnTbl;
        }

        bool _adjusting;

        /// <summary>设置列宽（加锁避免与 Resize 事件互相触发形成震荡）</summary>
        void SetCol(int idx, int w)
        {
            if (_columnTbl == null || w <= 0) return;
            _adjusting = true;
            try
            {
                var cs = _columnTbl.ColumnStyles[idx];
                if (Math.Abs(cs.Width - w) < 0.5f) return;   // 宽度没变就不写，阻断事件循环
                cs.Width = w;
            }
            finally { _adjusting = false; }
        }

        /// <summary>按当前窗口宽度重排三栏，保证中栏始终有足够空间。
    /// 仅在窗口宽度变化时调用（由 Resize 触发），拖动分隔条时不参与，避免与用户操作打架。
    /// </summary>
        void AutoFitColumns()
        {
            if (_columnTbl == null || _adjusting) return;

            int total = _columnTbl.Width;
            int minL = Theme.P(250), minR = Theme.P(340), minMid = Theme.P(400);
            if (total < minL + minR + minMid) return;

            // 保留用户已设定的左右栏宽度（_dragL/_dragR 优先），只做下限保护
            int l = Math.Clamp(_dragL > 0 ? _dragL : _colLeft, minL, total - minR - minMid);
            int r = Math.Clamp(_dragR > 0 ? _dragR : _colRight, minR, total - l - minMid);

            SetCol(0, l);
            SetCol(4, r);
            LayoutMiddle();
        }

        // 分隔条拖拽状态
        int _dragL, _dragR, _dragSide, _dragStartX, _dragStartL, _dragStartR;

        /// <summary>可拖拽分隔条。side: 0=调左栏, 1=调右栏
    /// 关键：用 MouseEventArgs 的相对坐标 + 鼠标捕获，不能依赖 Cursor.Position。
    /// 分隔条只有几像素宽，用全局坐标会导致鼠标移出控件后事件断流（表现为"自动右移/拖不动"）。
    /// </summary>
    Panel MakeSplitter(int side)
        {
            var p = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Theme.Bg0,
                Width = Theme.P(8),
                Cursor = Cursors.SizeWE,
                Margin = Padding.Empty
            };

            bool hover = false, dragging = false;

            p.Paint += (_, e) =>
            {
                var g = e.Graphics;
                var active = hover || dragging;
                using var br = new SolidBrush(active ? Color.FromArgb(34, 52, 76) : Theme.Bg0);
                g.FillRectangle(br, 0, 0, p.Width, p.Height);

                // 抓握点：中间竖条 + 上下两个箭头，视觉上明确"可拖"
                if (active)
                {
                    int cx = p.Width / 2;
                    using var pen = new Pen(Theme.Cyan, 1.5f);
                    g.DrawLine(pen, cx, Theme.P(14), cx, p.Height - Theme.P(14));
                    using var tri = new SolidBrush(Theme.Cyan);
                    int y = p.Height / 2;
                    g.FillPolygon(tri, new[]
                    {
                        new Point(cx - 3, y - 9), new Point(cx + 3, y - 9), new Point(cx, y - 4)
                    });
                    g.FillPolygon(tri, new[]
                    {
                        new Point(cx - 3, y + 9), new Point(cx + 3, y + 9), new Point(cx, y + 4)
                    });
                }
            };

            p.MouseEnter += (_, _) => { hover = true; p.Invalidate(); };
            p.MouseLeave += (_, _) => { if (!dragging) { hover = false; p.Invalidate(); } };

            p.MouseDown += (_, e) =>
            {
                if (e.Button != MouseButtons.Left) return;
                dragging = true;
                hover = true;
                _dragSide = side;

                // 记录按下时相对容器的坐标与当时的列宽，作为拖动基准
                _dragStartX = e.X;
                _dragStartL = (int)_columnTbl.ColumnStyles[0].Width;
                _dragStartR = (int)_columnTbl.ColumnStyles[4].Width;

                // 关键：捕获鼠标，即使光标移出分隔条也能持续收到 MouseMove
                p.Capture = true;
                p.Invalidate();
            };

            p.MouseMove += (_, e) =>
            {
                if (!dragging || _dragSide < 0) return;

                // 用相对坐标增量，与光标绝对位置无关
                int delta = e.X - _dragStartX;
                int total = _columnTbl.Width;

                if (_dragSide == 0)
                {
                    int minL = Theme.P(250);
                    int maxL = Math.Max(minL, total - Theme.P(340) - Theme.P(400));
                    int l = Math.Clamp(_dragStartL + delta, minL, maxL);
                    _dragL = l;
                    SetCol(0, l);
                }
                else
                {
                    // 右栏跟随手柄反向移动
                    int minR = Theme.P(320);
                    int maxR = Math.Max(minR, total - Theme.P(250) - Theme.P(400));
                    int r = Math.Clamp(_dragStartR - delta, minR, maxR);
                    _dragR = r;
                    SetCol(4, r);
                }
                LayoutMiddle();
            };

            void EndDrag(object? s, EventArgs e)
            {
                if (!dragging) return;
                dragging = false;
                p.Capture = false;
                _dragL = (int)_columnTbl.ColumnStyles[0].Width;
                _dragR = (int)_columnTbl.ColumnStyles[4].Width;
                _dragSide = -1;
                p.Invalidate();
                SaveLayout();
            }

            p.MouseUp += EndDrag;
            p.MouseCaptureChanged += (_, _) => { if (dragging) EndDrag(null, EventArgs.Empty); };
            return p;
        }

        /// <summary>中栏吃掉剩余宽度</summary>
        void LayoutMiddle()
        {
            if (_columnTbl == null) return;
            int total = _columnTbl.Width;
            int used = (int)_columnTbl.ColumnStyles[0].Width + (int)_columnTbl.ColumnStyles[4].Width + Theme.P(16);
            SetCol(2, Math.Max(Theme.P(360), total - used));
        }

        // ------------------------------------------------------------ 左栏
        Panel BuildOverviewCol()
        {
            var host = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = Padding.Empty };

            var card = new Card { Dock = DockStyle.Fill };
            var inner = new Panel
            {
                Dock = DockStyle.Fill, BackColor = Theme.Bg1,
                Padding = new Padding(Theme.P(14), Theme.P(12), Theme.P(12), Theme.P(12)),
                AutoScroll = true
            };
            card.Controls.Add(inner);
            host.Controls.Add(card);

            // 左栏所有控件改为 Dock=Fill + AutoSize，随栏宽自动伸缩（修复问题1：拖动后文字显示不全）
            var flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown,
                WrapContents = false, BackColor = Color.Transparent,
                AutoSize = false, Margin = Padding.Empty, Padding = Padding.Empty
            };
            inner.Controls.Add(flow);

            _gauge = new Gauge { Dock = DockStyle.Top, Height = Theme.P(152), Margin = Padding.Empty };
            flow.Controls.Add(_gauge);

            flow.Controls.Add(BuildStatGrid());
            flow.Controls.Add(BuildMetaPanel());
            flow.Controls.Add(BuildNetPanel());
            flow.Controls.Add(Section("风险项"));

            _issueBox = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.TopDown, WrapContents = false,
                BackColor = Color.Transparent, Margin = Padding.Empty
            };
            flow.Controls.Add(_issueBox);

            // 栏宽变化时同步刷新自适应控件（用局部 host，不能用尚未赋值的 _leftCol）
            host.SizeChanged += (_, _) => LayoutLeftColumn();
            LayoutLeftColumn();

            return host;
        }

        /// <summary>左栏宽度变化 → 重新计算需要自适应的控件尺寸</summary>
        void LayoutLeftColumn()
        {
            // 用 _issueBox 的父容器宽度，避免依赖 _leftCol（初始化阶段尚未赋值）
            if (_issueBox == null || _issueBox.Parent == null) return;
            int w = Math.Max(Theme.P(180), _issueBox.Parent.ClientSize.Width - Theme.P(4));
            _issueBox.Width = w;
            foreach (Control c in _issueBox.Controls) c.Width = w;
            LayoutMetaRows();
            LayoutNetRows();
        }

        void LayoutNetRows()
        {
            if (_netPanel == null || _netPanel.Controls.Count == 0) return;
            int total = _netPanel.ClientSize.Width;
            if (total <= 20) return;
            int nameW = Theme.P(76);
            int valW = Math.Max(Theme.P(60), total - nameW);
            for (int i = 0; i + 1 < _netPanel.Controls.Count; i += 2)
            {
                if (_netPanel.Controls[i] is Label k) k.Width = nameW;
                if (_netPanel.Controls[i + 1] is Label v)
                {
                    v.Location = new Point(nameW, v.Top);
                    v.Width = valW;
                }
            }
        }

        Control BuildStatGrid()
        {
            var p = new Panel { Dock = DockStyle.Top, Height = Theme.P(74), BackColor = Color.Transparent, Margin = new Padding(0, 0, 0, Theme.P(4)) };
            var tbl = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 2, BackColor = Color.Transparent, Margin = Padding.Empty };
            for (int i = 0; i < 4; i++) tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 58));
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 42));

            _lblInbound = StatCell(tbl, 0, 0, "公网入站", "重点");
            _lblThreat = StatCell(tbl, 0, 1, "威胁源", "");
            _lblAttempt = StatCell(tbl, 0, 2, "爆破尝试", "");
            _lblBreach = StatCell(tbl, 0, 3, "成功入侵", "重点");

            p.Controls.Add(tbl);
            return p;
        }

        Label StatCell(TableLayoutPanel tbl, int col, int row, string label, string tag)
        {
            var cell = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent, Margin = new Padding(0) };
            var v = Lbl(new Point(0, Theme.P(6)), new Size(Theme.P(62), Theme.P(30)), "0", Theme.Stat, Theme.Tx1, HorizontalAlignment.Center);
            var l = Lbl(new Point(0, Theme.P(38)), new Size(Theme.P(62), Theme.P(18)), label, Theme.Small, Theme.Tx3, HorizontalAlignment.Center);

            // 「重点」指标加一个顶部小标记，提示用户这两个最关键
            if (tag == "重点")
            {
                var mark = new Panel { BackColor = Theme.Amber, Location = new Point(Theme.P(26), 0), Size = Theme.Sz(10, 2) };
                cell.Controls.Add(mark);
            }
            cell.Controls.Add(v);
            cell.Controls.Add(l);
            tbl.Controls.Add(cell, col, row);
            return v;
        }

        Control BuildMetaPanel()
        {
            var p = new Panel
            {
                Dock = DockStyle.Top, Height = Theme.P(108), BackColor = Color.Transparent,
                Margin = new Padding(0, 0, 0, Theme.P(4))
            };
            _metaPanel = p;
            _lblPubIp = MetaRow(p, 0, "公网 IP");
            _lblPubGeo = MetaRow(p, 1, "归属地");
            _lblAdmin = MetaRow(p, 2, "管理员账户", true);
            _lblFw = MetaRow(p, 3, "防护规则", true);
            return p;
        }

        /// <summary>元信息行随左栏宽度重排（修复拖动后文字被裁）</summary>
        void LayoutMetaRows()
        {
            if (_metaPanel == null || _metaPanel.Controls.Count == 0) return;
            int total = _metaPanel.ClientSize.Width;
            if (total <= 20) return;
            int nameW = Theme.P(76);
            int valW = Math.Max(Theme.P(60), total - nameW);

            for (int i = 0; i + 1 < _metaPanel.Controls.Count; i += 2)
            {
                if (_metaPanel.Controls[i] is Label k) k.Width = nameW;
                if (_metaPanel.Controls[i + 1] is Label v)
                {
                    v.Location = new Point(nameW, v.Top);
                    v.Width = valW;
                }
            }
        }

        Label MetaRow(Panel p, int idx, string name, bool bordered = false)
        {
            int y = idx * Theme.P(26) + Theme.P(4);
            var k = Lbl(new Point(0, y), new Size(Theme.P(76), Theme.P(18)), name, Theme.Small, Theme.Tx3);
            var v = Lbl(new Point(Theme.P(78), y), new Size(Theme.P(150), Theme.P(18)), "检测中…", Theme.Small, Theme.Tx1);
            v.AutoEllipsis = true;
            v.TextAlign = ContentAlignment.MiddleLeft;
            v.Cursor = Cursors.Hand;
            v.Font = Theme.Small;
            var capturedName = name;
            v.Click += (_, _) =>
            {
                try
                {
                    if (v.Text != "—" && v.Text.Length > 3 && !v.Text.Contains("检测中"))
                        Clipboard.SetText(v.Text);
                    Log(v.Text != "—" ? $"已复制「{capturedName}」：{v.Text}" : $"{capturedName} 暂无可复制内容", "act");
                }
                catch { }
            };
            p.Controls.Add(k);
            p.Controls.Add(v);
            return v;
        }

        // -------------------------------------------------------- 网络信息
        Label _lblLanIp = null!, _lblMac = null!, _lblAdapter = null!, _lblNetType = null!;

        /// <summary>本机网络信息面板（问题2：放在左栏展示）</summary>
        Control BuildNetPanel()
        {
            // 注意：AutoSize 容器内不可用 Dock=Fill 的子面板（高度会算成 0 导致文字不显示）
            // 改为「标题 + 固定高度内容面板」的外层 TableLayout，显式分配行高
            var host = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 1,
                RowCount = 2,
                BackColor = Color.Transparent,
                Margin = Padding.Empty,
                Padding = Padding.Empty,
                Height = Theme.P(136)
            };
            host.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            host.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.P(26)));   // 标题
            host.RowStyles.Add(new RowStyle(SizeType.Percent, 100));           // 内容

            host.Controls.Add(Section("网络信息"), 0, 0);

            var p = new Panel
            {
                Dock = DockStyle.Fill, BackColor = Color.Transparent,
                Margin = Padding.Empty, Padding = Padding.Empty
            };
            _lblAdapter = MetaRow(p, 0, "网络适配器");
            _lblLanIp = MetaRow(p, 1, "内网 IP");
            _lblMac = MetaRow(p, 2, "物理地址");
            _lblNetType = MetaRow(p, 3, "连接类型");
            host.Controls.Add(p, 0, 1);

            _netPanel = p;
            RefreshNetInfo();
            return host;
        }

        /// <summary>读取本机网络信息（原生 API，毫秒级）</summary>
        void RefreshNetInfo()
        {
            try
            {
                var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                             && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback
                             && n.GetIPProperties().GatewayAddresses.Count > 0)
                    .OrderByDescending(n => n.Speed)
                    .ToList();

                if (nics.Count == 0)
                {
                    _lblAdapter.Text = "未检测到活动网卡";
                    _lblLanIp.Text = "—"; _lblMac.Text = "—"; _lblNetType.Text = "离线";
                    return;
                }

                var nic = nics[0];
                _lblAdapter.Text = Truncate(nic.Name, 16);
                _lblAdapter.ForeColor = Theme.Tx1;

                var ips = nic.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString()).ToList();
                _lblLanIp.Text = ips.Count > 0 ? string.Join(", ", ips) : "未分配 IPv4";
                _lblLanIp.ForeColor = ips.Count > 0 ? Theme.Tx1 : Theme.Tx3;

                _lblMac.Text = string.Join(" / ", nic.GetPhysicalAddress().GetAddressBytes()
                    .Select(b => b.ToString("X2")));
                _lblMac.ForeColor = Theme.Tx1;

                //连接类型：按网关与速率推断
                _lblNetType.Text = nic.Speed >= 1000
                    ? $"{nic.Speed / 1000} Mbps · 有线"
                    : $"{nic.Speed} Mbps · 无线";
                _lblNetType.ForeColor = Theme.Tx3;

                LayoutNetRows();
                LayoutMetaRows();
            }
            catch (Exception ex)
            {
                _lblAdapter.Text = "读取失败";
                _lblAdapter.ForeColor = Theme.Amber;
            }
        }

        static string Truncate(string s, int max)
            => string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..(max - 1)] + "…");

        // ------------------------------------------------------------ 中栏
        Panel BuildMidCol()
        {
            var host = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = Padding.Empty };
            var tbl = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Theme.Bg0, Margin = Padding.Empty, Padding = Padding.Empty };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.P(38)));  // Tab 头
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));           // 内容
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, Theme.P(196)));  // 动作区（固定够高）

            tbl.Controls.Add(BuildTabs(), 0, 0);
            tbl.Controls.Add(BuildMidBody(), 0, 1);
            tbl.Controls.Add(BuildActionBar(), 0, 2);
            host.Controls.Add(tbl);
            // 列表已就绪，再真正应用一次页签状态
            SwitchTab(0);
            return host;
        }

        Control BuildTabs()
        {
            var p = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg0, Margin = Padding.Empty };
            p.Paint += (_, e) =>
            {
                using var pen = new Pen(Theme.Line, 1f);
                e.Graphics.DrawLine(pen, 0, p.Height - 1, p.Width, p.Height - 1);
            };

            _tabThreat = TabButton("威胁源", new Point(Theme.P(14), Theme.P(7)));
            _tabAction = TabButton("一键处置", new Point(Theme.P(120), Theme.P(7)));
            _tabThreat.Click += (_, _) => SwitchTab(0);
            _tabAction.Click += (_, _) => SwitchTab(1);

            p.Controls.Add(_tabThreat);
            p.Controls.Add(_tabAction);
            _tabIndex = 0;
            _tabThreat.ForeColor = Theme.Cyan;
            _tabAction.ForeColor = Theme.Tx3;
            return p;
        }

        Label TabButton(string text, Point loc)
        {
            var l = Lbl(loc, new Size(Theme.P(96), Theme.P(26)), text, Theme.SmallBold, Theme.Tx3, HorizontalAlignment.Center);
            l.Cursor = Cursors.Hand;
            l.Tag = text;
            // 下划线只挂一次 Paint，用 Tag 文本判断是否为当前选中项
            l.Paint += (s, e) =>
            {
                bool active = ((string)l.Tag == "威胁源" && _tabIndex == 0)
                           || ((string)l.Tag == "一键处置" && _tabIndex == 1);
                if (!active) return;
                using var pen = new Pen(Theme.Cyan, 2f);
                e.Graphics.DrawLine(pen, Theme.P(10), l.Height - 2, l.Width - Theme.P(10), l.Height - 2);
            };
            return l;
        }

        void SwitchTab(int idx)
        {
            _tabIndex = idx;
            _tabThreat.ForeColor = idx == 0 ? Theme.Cyan : Theme.Tx3;
            _tabAction.ForeColor = idx == 1 ? Theme.Cyan : Theme.Tx3;
            _tabThreat.Invalidate();
            _tabAction.Invalidate();

            // 列表尚未创建时（初始化阶段）只切标签色
            if (_threatBox == null || _actionGrid == null) return;

            _threatBox.Visible = idx == 0;
            _actionGrid.Visible = idx == 1;
        }

        Control BuildMidBody()
        {
            var host = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = Padding.Empty };

            var card = new Card { Dock = DockStyle.Fill };
            var inner = new Panel
            {
                Dock = DockStyle.Fill, BackColor = Theme.Bg1,
                Padding = new Padding(Theme.P(12), Theme.P(10), Theme.P(10), Theme.P(10))
            };
            card.Controls.Add(inner);

            // 威胁列表
            _threatBox = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown,
                WrapContents = false, AutoScroll = true, BackColor = Color.Transparent,
                Padding = Padding.Empty, Margin = Padding.Empty, Visible = true
            };
            inner.Controls.Add(_threatBox);

            // 动作网格（独立页，不受高度裁切）
            _actionGrid = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3,
                BackColor = Color.Transparent, Visible = false,
                Padding = new Padding(Theme.P(2)), Margin = Padding.Empty
            };
            for (int i = 0; i < 2; i++) _actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            for (int i = 0; i < 3; i++) _actionGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 33.33f));

            BuildActionButtons();
            inner.Controls.Add(_actionGrid);

            host.Controls.Add(card);
            return host;
        }

        void BuildActionButtons()
        {
            var defs = new (string title, string desc, Color accent, bool primary, Func<ActionResult> act)[]
            {
                ("紧急加固", "解锁账户 → 启用局域网专用防护 → 封禁全部当前威胁 IP",
                 Theme.Red, true,
                 () => Actions.EmergencyHarden(_snap.AttackIps)),
                ("解锁账户", "解除账户锁定状态，让正确密码重新生效",
                 Theme.Cyan, false,
                 () => Actions.UnlockAccount()),
                ("局域网防护", "放行内网访问，同时阻断所有公网入站（推荐）",
                 Theme.Green, false,
                 () => Actions.EnableLanOnly()),
                ("解除防护", "恢复为完全放行状态（不建议长期使用）",
                 Theme.Amber, false,
                 () => Actions.DisableLanOnly()),
                ("踢出连接", "重启 Server 服务，立即释放全部 SMB 会话",
                 Theme.Amber, false,
                 () => Actions.DropConnections()),
                ("立即扫描", "强制刷新所有监控数据",
                 Theme.Purple, false,
                 null),
            };

            var list = new List<Button>();
            for (int i = 0; i < defs.Length; i++)
            {
                var d = defs[i];
                var btn = ActionCardButton(d.title, d.desc, d.accent, d.primary);
                var idx = i;
                var act = d.act;
                btn.Click += async (_, _) =>
                {
                    if (act == null) { await TickFastAsync(true); return; }
                    await RunAsync(d.title, act);
                };
                _actionGrid.Controls.Add(btn, i % 2, i / 2);
                list.Add(btn);
            }
            _actionCards = list.ToArray();
        }

        /// <summary>动作卡片 —— 用 Button 承载以获得完整交互反馈（悬停/按下/禁用）</summary>
        Button ActionCardButton(string title, string desc, Color accent, bool primary)
        {
            var btn = new Button
            {
                Dock = DockStyle.Fill,
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.TopLeft,
                Font = Theme.SmallBold,
                Cursor = Cursors.Hand,
                Margin = new Padding(Theme.P(4)),
                Padding = new Padding(Theme.P(12), Theme.P(10), Theme.P(10), Theme.P(8)),
                BackColor = primary ? Color.FromArgb(34, 22, 27) : Theme.Bg2,
                ForeColor = Theme.Tx1,
                UseVisualStyleBackColor = false
            };
            btn.FlatAppearance.BorderSize = 1;

            string tip = $"{title}\r\n\r\n{desc}\r\n\r\n点击执行";

            btn.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                bool hover = btn.Focused || btn.ClientRectangle.Contains(btn.PointToClient(Cursor.Position));

                var bg = primary
                    ? (hover ? Color.FromArgb(46, 28, 34) : Color.FromArgb(34, 22, 27))
                    : (hover ? Theme.BgHover : Theme.Bg2);
                var border = primary ? Color.FromArgb(96, 42, 50) : (hover ? Theme.Line : Theme.LineSoft);

                using var path = RoundedPath(new Rectangle(0, 0, btn.Width - 1, btn.Height - 1), Theme.P(10));
                using var br = new SolidBrush(bg);
                g.FillPath(br, path);
                using var pen = new Pen(border, 1f);
                g.DrawPath(pen, path);

                // 左侧强调条
                using var bar = new SolidBrush(accent);
                g.FillRectangle(bar, Theme.P(2), Theme.P(12), Theme.P(3), btn.Height - Theme.P(26));

                // 标题
                var tf = Theme.SmallBold;
                using var tb = new SolidBrush(primary ? accent : Theme.Tx1);
                g.DrawString(title, tf, tb, Theme.P(16), Theme.P(12));

                // 描述（自动换行，最多 3 行）
                var df = Theme.Small;
                using var db = new SolidBrush(Theme.Tx3);
                var rect = new RectangleF(Theme.P(16), Theme.P(32), btn.Width - Theme.P(28), btn.Height - Theme.P(38));
                using var brf = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.LineLimit };
                g.DrawString(desc, df, db, rect, brf);

                // 底部提示
                using var hint = new SolidBrush(hover ? accent : Theme.Tx4);
                g.DrawString(hover ? "▶ 点击执行" : "点击执行",
                    new Font("Microsoft YaHei UI", 7.5f * Theme.Scale, FontStyle.Regular),
                    hint, Theme.P(16), btn.Height - Theme.P(19));
            };

            btn.MouseEnter += (_, _) => btn.Invalidate();
            btn.MouseLeave += (_, _) => btn.Invalidate();
            btn.EnabledChanged += (_, _) => btn.Invalidate();
            btn.Tag = tip;
            return btn;
        }

        /// <summary>动作区（底部常驻的三个快捷按钮）</summary>
        Control BuildActionBar()
        {
            var card = new Card { Dock = DockStyle.Fill, Margin = new Padding(Theme.P(8), Theme.P(4), Theme.P(8), Theme.P(8)) };
            var inner = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg1, Padding = new Padding(Theme.P(12), Theme.P(8), Theme.P(12), Theme.P(8)) };

            var top = Lbl(new Point(Theme.P(2), Theme.P(6)), new Size(Theme.P(120), Theme.P(16)), "快捷操作", Theme.SmallBold, Theme.Tx3);
            inner.Controls.Add(top);

            // 三个高频按钮横排
            var row = new TableLayoutPanel
            {
                Dock = DockStyle.Bottom, ColumnCount = 3, RowCount = 1,
                BackColor = Color.Transparent, Height = Theme.P(54), Margin = Padding.Empty
            };
            for (int i = 0; i < 3; i++) row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));

            var b1 = QuickButton("紧急加固", Theme.Red, true,
                () => RunAsync("紧急加固", () => Actions.EmergencyHarden(_snap.AttackIps)));
            var b2 = QuickButton("解锁账户", Theme.Cyan, false, () => RunAsync("解锁管理员账户", Actions.UnlockAccount));
            var b3 = QuickButton("局域网防护", Theme.Green, false, () => RunAsync("启用局域网专用防护", Actions.EnableLanOnly));
            row.Controls.Add(b1, 0, 0);
            row.Controls.Add(b2, 1, 0);
            row.Controls.Add(b3, 2, 0);
            inner.Controls.Add(row);

            card.Controls.Add(inner);
            return card;
        }

        Button QuickButton(string text, Color accent, bool primary, Action onClick)
        {
            var btn = new Button
            {
                Dock = DockStyle.Fill, FlatStyle = FlatStyle.Flat,
                Text = text, Font = Theme.SmallBold, Cursor = Cursors.Hand,
                ForeColor = primary ? accent : Theme.Tx1,
                BackColor = primary ? Color.FromArgb(40, 24, 30) : Theme.Bg2,
                Margin = new Padding(Theme.P(4), 0, Theme.P(4), 0)
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = primary ? Color.FromArgb(96, 42, 50) : Theme.Line;

            bool hover = false;
            btn.MouseEnter += (_, _) => { hover = true; btn.BackColor = hover ? (primary ? Color.FromArgb(56, 32, 40) : Theme.BgHover) : btn.BackColor; };
            btn.MouseLeave += (_, _) => { btn.BackColor = primary ? Color.FromArgb(40, 24, 30) : Theme.Bg2; };
            btn.Click += (_, _) => onClick();
            return btn;
        }

        // ------------------------------------------------------------ 右栏
        Panel BuildConsoleCol()
        {
            var host = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = Padding.Empty };
            var card = new Card { Dock = DockStyle.Fill };

            var head = new Panel { Dock = DockStyle.Top, Height = Theme.P(38), BackColor = Theme.Bg1 };
            var t = Lbl(new Point(Theme.P(14), Theme.P(11)), new Size(Theme.P(140), Theme.P(18)), "命令执行记录", Theme.SmallBold, Theme.Tx1);
            head.Controls.Add(t);

            var cnt = Lbl(new Point(Theme.P(140), Theme.P(12)), new Size(Theme.P(80), Theme.P(16)), "0 条", Theme.Small, Theme.Tx4);
            cnt.Name = "logCount";
            head.Controls.Add(cnt);

            _btnClear = Btn("清空", Theme.Sz(48, 24), Theme.Bg2, Theme.Tx2);
            _btnClear.FlatAppearance.BorderColor = Theme.Line;
            _btnClear.Click += (_, _) => { _console.Clear(); _logLines = 0; Log("日志已清空", "act"); };
            head.Controls.Add(_btnClear);

            // 打开日志目录 —— 查看所有落盘的完整输出
            var btnDir = Btn("日志目录", Theme.Sz(64, 24), Theme.Bg2, Theme.Cyan);
            btnDir.FlatAppearance.BorderColor = Theme.Line;
            btnDir.Click += (_, _) =>
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(OutputFormatter.LogDir)
                    { UseShellExecute = true });
                    Log("已打开日志目录：" + OutputFormatter.LogDir, "act");
                }
                catch (Exception ex) { Log("打开目录失败：" + ex.Message, "err"); }
            };
            head.Controls.Add(btnDir);

            // 导出当前面板内容
            var btnExp = Btn("导出", Theme.Sz(48, 24), Theme.Bg2, Theme.Tx2);
            btnExp.FlatAppearance.BorderColor = Theme.Line;
            btnExp.Click += (_, _) => ExportConsole();
            head.Controls.Add(btnExp);

            void LayoutHead()
            {
                if (btnExp != null) btnExp.Location = new Point(head.Width - Theme.P(184), Theme.P(7));
                btnDir.Location = new Point(head.Width - Theme.P(130), Theme.P(7));
                _btnClear.Location = new Point(head.Width - Theme.P(64), Theme.P(7));
            }
            head.Resize += (_, _) => LayoutHead();
            LayoutHead();
            card.Controls.Add(head);

            _console = new RichTextBox
            {
                Dock = DockStyle.Fill, BackColor = Color.FromArgb(10, 13, 20),
                ForeColor = Theme.Tx2, BorderStyle = BorderStyle.None,
                Font = Theme.Mono, ReadOnly = true, WordWrap = true,
                ScrollBars = RichTextBoxScrollBars.Both, DetectUrls = false,
                Margin = Padding.Empty
            };
            _console.Enter += (_, _) => _console.Focus();
            card.Controls.Add(_console);
            card.Controls.SetChildIndex(_console, 0);
            head.BringToFront();

            host.Controls.Add(card);
            return host;
        }

        // ------------------------------------------------------------ 状态栏
        Panel BuildStatus()
        {
            var p = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg1 };
            p.Paint += (_, e) =>
            {
                using var pen = new Pen(Theme.Line, 1f);
                e.Graphics.DrawLine(pen, 0, 0, p.Width, 0);
            };

            _sbLeft = Lbl(new Point(Theme.P(14), Theme.P(7)), new Size(Theme.P(560), Theme.P(16)), "正在初始化…", Theme.Small, Theme.Tx3);
            _sbRight = Lbl(new Point(0, Theme.P(7)), new Size(Theme.P(360), Theme.P(16)), "", Theme.Small, Theme.Tx4, HorizontalAlignment.Right);
            p.Controls.Add(_sbLeft);
            p.Controls.Add(_sbRight);

            p.Resize += (_, _) => LayoutStatus(p);
            LayoutStatus(p);
            return p;
        }

        void LayoutStatus(Panel p)
        {
            _sbRight.Location = new Point(Math.Max(0, p.Width - Theme.P(364)), Theme.P(7));
        }

        // ================================================================ 托盘
        void BuildTray()
        {
            _tray = new NotifyIcon
            {
                Icon = IconFactory.CreateShield(Theme.Cyan, false),
                Text = "Sentinel-Ccufo · SMB 监控运行中",
                Visible = true
            };
            var menu = new ContextMenuStrip { BackColor = Theme.Bg2, ForeColor = Theme.Tx1, Font = Theme.Base };
            menu.Items.Add("打开主界面", null, (_, _) => RestoreWindow());
            menu.Items.Add("立即扫描", null, async (_, _) => await TickFastAsync(true));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("退出", null, (_, _) => { SaveLayout(); _timerFast.Stop(); _timerSlow.Stop(); _tray.Visible = false; Application.Exit(); });
            _tray.ContextMenuStrip = menu;
            _tray.DoubleClick += (_, _) => RestoreWindow();
        }

        FormWindowState _preHideState = FormWindowState.Normal;

        void RestoreWindow()
        {
            ShowInTaskbar = true;
            Show();
            // 恢复为隐藏前的窗口状态（若之前是最大化则回最大化），而不是强制 Normal
            WindowState = _preHideState == FormWindowState.Minimized
                ? FormWindowState.Normal
                : _preHideState;
            Activate();
        }

        void HideToTray()
        {
            // 记录隐藏前的状态，唤回时恢复（否则最大化状态会丢失）
            if (WindowState != FormWindowState.Minimized)
                _preHideState = WindowState;
            Hide();
            ShowInTaskbar = false;
            _tray.ShowBalloonTip(1800, "Sentinel-Ccufo",
                "已最小化到托盘，继续在后台监控。右键菜单可退出。", ToolTipIcon.Info);
        }

        void ToggleMonitor()
        {
            if (_timerFast.Enabled)
            {
                _timerFast.Stop();
                _btnMonitor.Text = "启动监控";
                _btnMonitor.FlatAppearance.BorderColor = Theme.Line;
                _btnMonitor.ForeColor = Theme.Tx1;
                _btnMonitor.BackColor = Theme.Bg2;
                Log("已停止实时监控", "warn");
            }
            else
            {
                _timerFast.Start();
                _btnMonitor.Text = "停止监控";
                _btnMonitor.FlatAppearance.BorderColor = Color.FromArgb(90, 35, 45);
                _btnMonitor.ForeColor = Theme.Red;
                _btnMonitor.BackColor = Color.FromArgb(60, 24, 30);
                Log("已启动实时监控，间隔 2 秒", "ok");
            }
        }

        // ================================================================ 采集
        async Task TickFastAsync(bool manual = false)
        {
            if (_busy) return;
            _busy = true;
            try
            {
                var snap = new Snapshot();
                // 仅手动扫描时记录命令详情，避免每2 秒刷屏
                _collector.TraceCommands = manual;
                await Task.Run(() => _collector.CollectFast(snap));
                _snap = snap;
                RenderSnapshot(snap, manual);
                UpdateTray(snap);

                if (manual && _collector.Executed.Count > 0)
                    RenderScanCommands(_collector.Executed);
            }
            catch (Exception ex) { Log("采集异常: " + ex.Message, "err"); }
            finally { _busy = false; }
        }

        /// <summary>渲染本轮扫描实际执行的命令（完整不截断命令本身，输出按分级）</summary>
        void RenderScanCommands(List<CmdResult> cmds)
        {
            Log($"──── 本轮扫描执行了 {cmds.Count} 条命令 ────", "act");
            foreach (var c in cmds)
            {
                Log($"[{c.Label}]", c.Ok ? "ok" : "err", c.Cmd, c.Raw, c.ElapsedMs);
            }
        }

        async Task TickSlowAsync()
        {
            if (_busy) return;
            _busy = true;
            try
            {
                var r = Cmd.Run("wevtutil qe Security /c:200 /rd:true /f:xml", "安全日志（最近 200 条）", 25000);
                var ev = ParseEvents(r.Raw);
                // 安全日志量大，仅在有攻击记录时输出，避免日常刷屏
                if (ev.Any(e => e.Id == 4624 || e.Id == 4625))
                    Log($"[安全日志] 4625 失败 {ev.Count(e => e.Id == 4625)} 条 / 4624 成功 {ev.Count(e => e.Id == 4624)} 条",
                        "ok", r.Cmd, r.Raw, r.ElapsedMs);
                _snap.FailedAttempts = ev.Where(e => e.Id == 4625 && !Collector.IsPrivate(e.Ip))
                                    .Select(e => e.Ip).Distinct().Count();
                _snap.SuccessLogins = ev.Count(e => e.Id == 4624);
                foreach (var e in ev.Where(e => e.Id == 4625 && !Collector.IsPrivate(e.Ip)))
                {
                    _snap.AttackIps.Add(e.Ip);
                    if (!string.IsNullOrEmpty(e.User)) _snap.Accounts.Add(e.User);
                }
                Collector.Assess(_snap);
                _forceFullThreatRender = true;
                RenderSnapshot(_snap, false);
                RefreshNetInfo();   // 网络信息每 15 秒刷新（拔线/换网络可感知）
            }
            catch (Exception ex) { Log("日志分析异常: " + ex.Message, "err"); }
            finally { _busy = false; }
        }

        sealed class Ev { public int Id; public string Ip = ""; public string User = ""; }

        static List<Ev> ParseEvents(string xml)
        {
            var list = new List<Ev>();
            if (string.IsNullOrEmpty(xml)) return list;
            try
            {
                var doc = System.Xml.Linq.XDocument.Parse(xml);
                foreach (var e in doc.Descendants("Event"))
                {
                    if (!int.TryParse(e.Element("System")?.Element("EventID")?.Value, out var id)) continue;
                    if (id != 4624 && id != 4625) continue;
                    var d = e.Element("EventData");
                    list.Add(new Ev
                    {
                        Id = id,
                        Ip = d?.Elements("Data").FirstOrDefault(x => x.Attribute("Name")?.Value == "IpAddress")?.Value ?? "",
                        User = d?.Elements("Data").FirstOrDefault(x => x.Attribute("Name")?.Value == "TargetUserName")?.Value ?? ""
                    });
                }
            }
            catch { /* XML 解析失败忽略 */ }
            return list;
        }

        // ================================================================ 渲染
        void RenderSnapshot(Snapshot s, bool manual)
        {
            var accent = s.RiskLevel switch
            {
                "critical" or "high" => Theme.Red,
                "medium" => Theme.Amber,
                _ => Theme.Green
            };
            _lblRisk.Text = "  " + (s.RiskLevel switch
            {
                "critical" => "严重风险 · 正在被攻击",
                "high" => "高风险 · 需立即处理",
                "medium" => "中等风险 · 存在薄弱点",
                _ => "安全 · 防护已生效"
            }) + "  ";
            _lblRisk.ForeColor = accent;

            _gauge.Value = s.RiskScore;
            _gauge.Accent = accent;
            _gauge.Invalidate();

            SetStat(_lblInbound, s.InboundRisk.Count, s.InboundRisk.Count > 0 ? Theme.Red : Theme.Green);
            SetStat(_lblThreat, s.AttackIps.Count, s.AttackIps.Count > 0 ? Theme.Amber : Theme.Green);
            SetStat(_lblAttempt, s.FailedAttempts, s.FailedAttempts > 0 ? Theme.Amber : Theme.Green);
            SetStat(_lblBreach, s.SuccessLogins, s.SuccessLogins > 0 ? Theme.Red : Theme.Green);

            _lblPubIp.Text = string.IsNullOrEmpty(s.PublicIp) ? "查询中…" : s.PublicIp;
            _lblPubIp.ForeColor = Theme.Tx1;
            _lblPubGeo.Text = string.IsNullOrEmpty(s.PublicGeo) ? "—" : s.PublicGeo;
            _lblPubGeo.ForeColor = string.IsNullOrEmpty(s.PublicGeo) ? Theme.Tx3 : Theme.Tx1;

            // 账户状态：文字 + 颜色 + 悬浮详情三重提示
            _lblAdmin.Text = s.AccountLocked ? "已锁定 · 密码将失效" : s.AccountDisabled ? "已禁用" : "正常";
            _lblAdmin.ForeColor = s.AccountLocked ? Theme.Red : s.AccountDisabled ? Theme.Amber : Theme.Green;
            _lblAdmin.Font = s.AccountLocked ? Theme.SmallBold : Theme.Small;
            _lblAdmin.ForeColor = s.AccountLocked ? Theme.Red : s.AccountDisabled ? Theme.Amber : Theme.Green;

            bool hard = s.HasLanOnlyRule && s.HasBlockAllRule;
            _lblFw.Text = hard ? "已加固" : s.LegacyEnabledRules > 0 ? "未加固" : "部分配置";
            _lblFw.ForeColor = hard ? Theme.Green : Theme.Amber;
            _lblFw.Font = hard ? Theme.SmallBold : Theme.Small;

            RenderIssues(s);
            RenderThreats(s);

            var ports = s.ListeningPorts.Count > 0 ? string.Join(",", s.ListeningPorts) : "无";
            _sbLeft.Text = $"监控中· 采集 {s.ElapsedMs}ms   监听端口 {ports}   威胁源 {s.AttackIps.Count}   最后更新 {s.Time:HH:mm:ss}";
            _sbRight.Text = $"{Theme.Scale * 100:F0}% 缩放 (Ctrl +/－)   双击托盘图标可唤出";
            var cnt = _root.Controls.Find("logCount", true).FirstOrDefault() as Label;
            if (cnt != null) cnt.Text = _logLines + " 行";

            if (manual) Log($"扫描完成，耗时 {s.ElapsedMs}ms · 入站 {s.InboundRisk.Count} 条 · 威胁源 {s.AttackIps.Count} 个", "ok");
        }

        void SetStat(Label l, int v, Color c) { l.Text = v.ToString(); l.ForeColor = c; }

        void RenderIssues(Snapshot s)
        {
            if (_issueBox.Controls.Count == s.Issues.Count)
            {
                bool same = true;
                for (int i = 0; i < s.Issues.Count && same; i++)
                    same = (_issueBox.Controls[i].Tag as string) == s.Issues[i];
                if (same) return;
            }

            _issueBox.SuspendLayout();
            _issueBox.Controls.Clear();

            if (s.Issues.Count == 0)
            {
                var ok = IssueItem("✓ 未发现风险项，防护状态良好", Theme.Green, "保持当前配置即可");
                _issueBox.Controls.Add(ok);
            }
            else
            {
                // 每条风险配一句「怎么办」，而不是只报错
                foreach (var issue in s.Issues) _issueBox.Controls.Add(IssueItem(issue, IssueColor(s), IssueAdvice(issue)));
            }
            _issueBox.ResumeLayout();
        }

        static Color IssueColor(Snapshot s) => s.RiskLevel switch
        {
            "critical" or "high" => Theme.Red,
            "medium" => Theme.Amber,
            _ => Theme.Tx3
        };

        static string IssueAdvice(string issue)
        {
            if (issue.Contains("公网入站")) return "建议：切到「一键处置」点「紧急加固」，可一键封禁并加固";
            if (issue.Contains("已锁定")) return "建议：点底部「解锁账户」，解除后正确密码即可生效";
            if (issue.Contains("无防护规则")) return "建议：点底部「局域网防护」，一次性根治";
            if (issue.Contains("文件和打印机共享")) return "建议：执行「局域网防护」会自动禁用该规则组";
            if (issue.Contains("登录成功")) return "⚠ 请立即确认该登录是否为本人操作";
            return "";
        }

        Control IssueItem(string title, Color accent, string advice)
        {
            // 高度按文字实际行数计算，杜绝裁字
            int titleH = Theme.P(18);
            int advH = 0;
            if (advice.Length > 0)
                advH = Math.Max(Theme.P(20), MeasureLines(advice, LeftContentWidth, Theme.Small) * Theme.P(15) + Theme.P(4));

            int boxH = advice.Length > 0 ? Theme.P(27) + advH + Theme.P(8) : titleH + Theme.P(12);

            var p = new Panel
            {
                Width = LeftContentWidth + Theme.P(20), Height = boxH,
                BackColor = Theme.Bg2, Margin = new Padding(0, 0, 0, Theme.P(6)), Tag = title
            };
            p.Paint += (s, e) =>
            {
                using var br = new SolidBrush(accent);
                e.Graphics.FillRectangle(br, 0, 0, Theme.P(3), p.Height);
            };

            var t = Lbl(new Point(Theme.P(10), Theme.P(7)), new Size(Theme.P(244), Theme.P(18)), title, Theme.Small, Theme.Tx1);
            t.AutoEllipsis = true;
            p.Controls.Add(t);

            if (advice.Length > 0)
            {
                // 用 Graphics 实测文字换行后的真实高度，避免固定高度裁切文字
                int textW = LeftContentWidth;
                int lineH = Theme.P(15);
                int lines = MeasureLines(advice, textW, Theme.Small);
                int advBoxH = Math.Max(Theme.P(20), lines * lineH + Theme.P(4));

                var a = new Label
                {
                    Location = new Point(Theme.P(10), Theme.P(27)),
                    Size = new Size(textW, advBoxH),
                    ForeColor = Theme.Tx3,
                    Font = Theme.Small,
                    BackColor = Color.Transparent,
                    Text = advice,
                    AutoEllipsis = false,
                };
                p.Controls.Add(a);
            }
            return p;
        }

        /// <summary>用Graphics 测量文本在给定宽度下需几行（DrawString 会自动换行）</summary>
        static int MeasureLines(string text, int width, Font font)
        {
            using var bmp = new Bitmap(1, 1);
            using var g = Graphics.FromImage(bmp);
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            var sz = g.MeasureString(text, font, new SizeF(width, 0));
            float lineH = font.GetHeight(g);
            return Math.Max(1, (int)Math.Ceiling(sz.Height / lineH));
        }

        void RenderThreats(Snapshot s)
        {
            var ips = s.AttackIps.OrderBy(x => x).ToList();
            if (!_forceFullThreatRender && ips.SequenceEqual(_renderedThreats)) return;
            _forceFullThreatRender = false;
            _renderedThreats.Clear();
            foreach (var i in ips) _renderedThreats.Add(i);

            _threatBox.SuspendLayout();
            _threatBox.Controls.Clear();

            if (ips.Count == 0)
            {
                var p = new Panel { Width = Theme.P(460), Height = Theme.P(220), BackColor = Color.Transparent };
                p.Paint += (_, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    using var br = new SolidBrush(Color.FromArgb(24, 46, 40));
                    g.FillEllipse(br, Theme.P(180), Theme.P(40), Theme.P(100), Theme.P(100));
                    var okF = Theme.Bold(26f);
                    using var tb = new SolidBrush(Theme.Green);
                    g.DrawString("✓", okF, tb, Theme.P(204), Theme.P(62));
                    using var t1 = new SolidBrush(Theme.Tx1);
                    g.DrawString("当前未检测到威胁", Theme.SmallBold, t1, Theme.P(160), Theme.P(158));
                    using var t2 = new SolidBrush(Theme.Tx3);
                    g.DrawString("445 端口无公网连接 · 账户状态正常 · 防护已生效",
                        Theme.Small, t2, Theme.P(112), Theme.P(180));
                };
                _threatBox.Controls.Add(p);
            }
            else
            {
                foreach (var ip in ips) _threatBox.Controls.Add(BuildThreatCard(ip, s));
            }
            _threatBox.ResumeLayout();
        }

        Control BuildThreatCard(string ip, Snapshot s)
        {
            int connCount = s.InboundRisk.Count(c => c.RemoteIp == ip);
            var card = new Panel
            {
                Width = Theme.P(452), Height = Theme.P(92),
                BackColor = Theme.Bg2, Margin = new Padding(0, 0, 0, Theme.P(8))
            };
            card.Paint += (_, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                var rect = new Rectangle(0, 0, card.Width - 1, card.Height - 1);
                using var path = RoundedPath(rect, Theme.P(10));
                using var br = new SolidBrush(card.BackColor);
                g.FillPath(br, path);
                using var pen = new Pen(connCount > 0 ? Color.FromArgb(88, 40, 46) : Theme.LineSoft, 1f);
                g.DrawPath(pen, path);
                using var bar = new SolidBrush(connCount > 0 ? Theme.Red : Theme.Amber);
                g.FillRectangle(bar, 0, Theme.P(14), Theme.P(3), card.Height - Theme.P(28));
            };

            var ipLbl = Lbl(new Point(Theme.P(14), Theme.P(11)), new Size(Theme.P(260), Theme.P(20)), ip, Theme.MonoBold, Theme.Tx1);
            card.Controls.Add(ipLbl);

            var sev = Lbl(new Point(Theme.P(300), Theme.P(11)), new Size(Theme.P(138), Theme.P(20)),
                connCount > 0 ? "● 正在攻击" : "○ 历史爆破",
                Theme.SmallBold, connCount > 0 ? Theme.Red : Theme.Amber, HorizontalAlignment.Right);
            card.Controls.Add(sev);

            var geo = state_geoCache.TryGetValue(ip, out var g2) && !string.IsNullOrEmpty(g2)
                ? g2 : "归属地查询中…";
            var info = Lbl(new Point(Theme.P(14), Theme.P(35)), new Size(Theme.P(300), Theme.P(18)),
                $"活跃连接 {connCount}    爆破尝试 {s.FailedAttempts}    端口 445", Theme.Small, Theme.Tx3);
            card.Controls.Add(info);

            var geoLbl = Lbl(new Point(Theme.P(14), Theme.P(55)), new Size(Theme.P(300), Theme.P(18)),
                geo, Theme.Small, Theme.Tx4);
            geoLbl.AutoEllipsis = true;
            card.Controls.Add(geoLbl);

            var btn = Btn("立即封禁", Theme.Sz(84, 28), Color.FromArgb(58, 24, 30), Theme.Red);
            btn.FlatAppearance.BorderColor = Color.FromArgb(96, 36, 46);
            btn.Location = new Point(card.Width - Theme.P(100), Theme.P(56));
            btn.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            string cur = ip;
            btn.Click += async (_, _) => await RunAsync($"封禁 {cur}", () => Actions.BlockIp(cur));
            card.Controls.Add(btn);

            if (!state_geoCache.ContainsKey(ip)) _ = FetchGeoAsync(ip, geoLbl);
            return card;
        }

        readonly Dictionary<string, string> state_geoCache = new();

        async Task FetchGeoAsync(string ip, Label target)
        {
            var res = await Task.Run(() => Actions.LookupIpOnly(ip));
            if (!string.IsNullOrEmpty(res))
            {
                state_geoCache[ip] = res;
                if (!IsDisposed && target != null && !target.IsDisposed)
                {
                    target.Text = res;
                    target.ForeColor = Theme.Tx3;
                }
            }
        }

        // ================================================================ 动作
        async Task RunAsync(string label, Func<ActionResult> act)
        {
            if (_busy) { Log("上一个操作尚未完成，请稍候", "warn"); return; }
            _busy = true;
            SetEnabled(false);
            Log($"▶ {label} — 开始执行", "act");

            try
            {
                var res = await Task.Run(act);
                for (int i = 0; i < res.Steps.Count; i++)
                {
                    var st = res.Steps[i];
                    Log($"[步骤 {i + 1}/{res.Steps.Count}] {st.Title}", st.Ok ? "ok" : "err", st.Cmd, st.Raw, st.ElapsedMs);
                }
                Log(res.Ok ? $"✓ {label} — 全部完成" : $"✗ {label} — 部分步骤失败", res.Ok ? "ok" : "err");
                if (res.Ok) MessageBox.Show(this, $"{label} 执行成功。", "Sentinel-Ccufo",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { Log($"✗ {label} — 异常: {ex.Message}", "err"); }
            finally
            {
                _busy = false;
                SetEnabled(true);
                await TickFastAsync(true);
            }
        }

        void SetEnabled(bool on)
        {
            foreach (var b in _actionCards) b.Enabled = on;
            foreach (Control c in _threatBox.Controls)
                foreach (Control x in c.Controls) x.Enabled = on;
        }

        // ================================================================ 日志
        void Log(string text, string kind, string cmd = "", string raw = "", long ms = 0)
        {
            if (IsDisposed || _console == null || _console.IsDisposed) return;
            if (InvokeRequired) { try { BeginInvoke(() => Log(text, kind, cmd, raw, ms)); } catch { } return; }

            Color accent = kind switch
            {
                "err" => Theme.Red,
                "warn" => Theme.Amber,
                "act" => Theme.Cyan,
                "ok" => Theme.Tx2,
                _ => Theme.Tx4
            };

            void Put(string s, Color c)
            {
                _console.SelectionStart = _console.TextLength;
                _console.SelectionLength = 0;
                _console.SelectionColor = c;
                _console.AppendText(s);
            }

            Put(DateTime.Now.ToString("HH:mm:ss") + "  ", Theme.Tx4);
            Put(text, accent);
            if (ms > 0) Put($"  ({ms}ms)", Theme.Tx4);
            Put("\n", Theme.Tx2);

            // 命令永远完整显示（审计依据），不截断
            if (!string.IsNullOrEmpty(cmd))
            {
                Put("  > " + cmd + "\n", Theme.Cyan);
                // 元信息行：字符数 + 行数 + 分级提示，让用户不看全量也知道规模
                if (!string.IsNullOrEmpty(raw))
                {
                    int lines = raw.Split('\n').Length;
                    Put($"    {raw.Length:N0} 字符 / {lines:N0} 行", Theme.Tx4);
                    var lv = OutputFormatter.Classify(raw.Length);
                    if (lv == OutputFormatter.Level.FileOnly) Put("  · 已落盘", Theme.Amber);
                    else if (lv == OutputFormatter.Level.HeadTail) Put("  · 已掐头去尾", Theme.Tx4);
                    Put("\n", Theme.Tx2);
                    _logLines++;
                }
            }

            if (!string.IsNullOrEmpty(raw))
            {
                // 关键：界面不再按固定 800 字符硬切（会把 netsh 上万行规则砍到只剩开头）
                // 改为 OutputFormatter 分级：小输出内联 / 中等掐头去尾 / 大输出落盘
                var level = OutputFormatter.Classify(raw.Length);
                var shown = OutputFormatter.ForDisplay(raw, out var filePath);

                foreach (var ln in shown.Split('\n')) Put("  " + ln.TrimEnd('\r') + "\n", Theme.Tx3);
                _logLines += shown.Split('\n').Length + 2;

                if (level == OutputFormatter.Level.FileOnly)
                    LogOpenFileHint(filePath, raw.Length);
                else if (level == OutputFormatter.Level.HeadTail)
                    LogMidHint(filePath, raw.Length);
            }
            else _logLines += 1;

            // 环形缓冲：超出时整段裁掉最早的内容（保留命令与摘要，丢弃大块输出）
            if (_logLines > 1200)
            {
                var keep = _console.Text;
                int idx = keep.IndexOf('\n', 600);
                if (idx > 0) _console.Text = "…（早期日志已自动归档，完整记录见日志目录）\r\n" + keep[(idx + 1)..];
                _logLines = 600;
            }
            _console.SelectionStart = _console.TextLength;
            _console.ScrollToCaret();

            var cnt = _root?.Controls.Find("logCount", true).FirstOrDefault() as Label;
            if (cnt != null) cnt.Text = _logLines + " 行";
        }

        /// <summary>导出当前控制台内容到文件（含命令原文，便于事后审计）</summary>
        void ExportConsole()
        {
            try
            {
                using var sfd = new SaveFileDialog
                {
                    Title = "导出日志",
                    Filter = "文本文件|*.txt|所有文件|*.*",
                    FileName = $"Sentinel-Ccufo-日志-{DateTime.Now:yyyyMMdd_HHmm}.txt"
                };
                if (sfd.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(sfd.FileName, _console.Text, Encoding.UTF8);
                Log($"已导出到：{sfd.FileName}", "ok");
            }
            catch (Exception ex) { Log("导出失败：" + ex.Message, "err"); }
        }

        /// <summary>大输出：提示已落盘，并提供点击打开</summary>
        void LogOpenFileHint(string filePath, int rawLen)
        {
            if (string.IsNullOrEmpty(filePath)) return;
            _console.SelectionStart = _console.TextLength;
            _console.SelectionLength = 0;
            _console.SelectionColor = Theme.Cyan;
            _console.AppendText("  [ 点击此处用默认编辑器打开完整输出 ]\n");
            _logLines++;

            int start = _console.TextLength - 44;
            Action open = () =>
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(filePath) { UseShellExecute = true });
                    Log($"已用默认程序打开：{Path.GetFileName(filePath)}", "act");
                }
                catch (Exception ex) { Log($"打开失败：{ex.Message}", "err"); }
            };
            _console.MouseClick += (s, e) =>
            {
                if (e.Button == MouseButtons.Left && _console.SelectionStart <= start + 44 && _console.SelectionStart >= start)
                {
                    _console.Select(start, 44);
                    open();
                }
            };
            _console.Cursor = Cursors.Hand;
        }

        /// <summary>中等输出：提示可查看完整文件</summary>
        void LogMidHint(string filePath, int rawLen)
        {
            _console.SelectionStart = _console.TextLength;
            _console.SelectionLength = 0;
            _console.SelectionColor = Theme.Tx4;
            _console.AppendText($"  完整输出（{rawLen:N0} 字符）可通过「导出日志」查看\r\n");
            _logLines++;
        }

        void UpdateTray(Snapshot s)
        {
            var alert = s.InboundRisk.Count > 0 || s.AccountLocked;
            var old = _tray.Icon;
            _tray.Icon = IconFactory.CreateShield(Theme.Cyan, alert);
            if (old != null) old.Dispose();

            _tray.Text = alert
                ? $"Sentinel · 警示：{(s.AccountLocked ? "账户已锁定" : $"{s.InboundRisk.Count} 条公网入站")}"
                : $"Sentinel · 安全（风险 {s.RiskScore}）";

            if (alert && DateTime.Now - _lastLogScan > TimeSpan.FromSeconds(10))
            {
                _lastLogScan = DateTime.Now;
                _tray.ShowBalloonTip(3000, "Sentinel-Ccufo 安全警示",
                    s.AccountLocked
                        ? "管理员账户已被锁定，正确密码将无法通过。\r\n请打开主界面执行「解锁账户」。"
                        : $"检测到 {s.InboundRisk.Count} 条来自公网的 SMB 连接。\r\n建议立即执行「紧急加固」。",
                    ToolTipIcon.Warning);
            }
        }

        // ================================================================ 布局记忆
        void SaveLayout()
        {
            try
            {
                if (_columnTbl != null)
                {
                    _colLeft = (int)_columnTbl.ColumnStyles[0].Width;
                    _colRight = (int)_columnTbl.ColumnStyles[4].Width;
                }
                var ini = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Sentinel.ini");
                System.IO.File.WriteAllLines(ini, new[]
                {
                    $"Left={Left}", $"Top={Top}",
                    $"W={Width}", $"H={Height}",
                    $"ColL={_colLeft}", $"ColR={_colRight}",
                    $"Scale={Theme.Scale}", $"Max={(WindowState == FormWindowState.Maximized ? 1 : 0)}"
                });
            }
            catch { }
        }

        void RestoreLayout()
        {
            try
            {
                var ini = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Sentinel.ini");
                if (!System.IO.File.Exists(ini)) return;
                var kv = new Dictionary<string, string>();
                foreach (var ln in System.IO.File.ReadAllLines(ini))
                {
                    var i = ln.IndexOf('=');
                    if (i > 0) kv[ln[..i].Trim()] = ln[(i + 1)..].Trim();
                }
                var sc = new Size(1440, 900);
                bool wantMax = kv.TryGetValue("Max", out var mx) && mx == "1";

                if (kv.TryGetValue("W", out var w) && int.TryParse(w, out var wi)) sc.Width = Math.Max(1040, wi);
                if (kv.TryGetValue("H", out var hh) && int.TryParse(hh, out var hi)) sc.Height = Math.Max(680, hi);
                StartPosition = FormStartPosition.Manual;
                if (kv.TryGetValue("Left", out var l) && int.TryParse(l, out var li)) Left = li;
                if (kv.TryGetValue("Top", out var t) && int.TryParse(t, out var ti)) Top = ti;

                // 恢复列宽（需等布局完成后再应用）
                if (kv.TryGetValue("ColL", out var cl) && int.TryParse(cl, out var clv)) _colLeft = clv;
                if (kv.TryGetValue("ColR", out var cr) && int.TryParse(cr, out var crv)) _colRight = crv;

                if (wantMax) WindowState = FormWindowState.Maximized;

                BeginInvoke(new Action(() =>
                {
                    _dragL = _colLeft;
                    _dragR = _colRight;
                    AutoFitColumns();
                }));
            }
            catch { }
        }

        // ================================================================ 辅助
        static GraphicsPath RoundedPath(Rectangle r, int radius)
        {
            var p = new GraphicsPath();
            int d = radius * 2;
            if (d <= 0) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        static Label Lbl(Point loc, Size sz, string text, Font f, Color c,
                        HorizontalAlignment ha = HorizontalAlignment.Left)
            => new()
            {
                Location = loc, Size = sz, Text = text, Font = f, ForeColor = c,
                BackColor = Color.Transparent,
                TextAlign = ha == HorizontalAlignment.Center ? ContentAlignment.MiddleCenter
                         : ha == HorizontalAlignment.Right ? ContentAlignment.MiddleRight
                         : ContentAlignment.MiddleLeft,
                AutoEllipsis = false
            };

        static Button Btn(string text, Size sz, Color bg, Color fg)
            => new()
            {
                Text = text, Size = sz, FlatStyle = FlatStyle.Flat,
                BackColor = bg, ForeColor = fg,
                TextAlign = ContentAlignment.MiddleCenter,
                Cursor = Cursors.Hand, UseVisualStyleBackColor = false,
                Margin = Padding.Empty
            };

        Label Section(string t)
            => new()
            {
                Text = t, Font = Theme.SmallBold, ForeColor = Theme.Tx3,
                BackColor = Color.Transparent, Height = Theme.P(24), Width = Theme.P(268),
                TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(0, Theme.P(2), 0, Theme.P(2))
            };

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timerFast?.Dispose();
                _timerSlow?.Dispose();
                _tray?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}