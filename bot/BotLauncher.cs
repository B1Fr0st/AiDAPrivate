using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using System.Threading;
using Microsoft.Win32;

public class BotLauncher : Form
{
    private NotifyIcon trayIcon;
    private ContextMenu trayMenu;
    private RichTextBox consoleOutput;
    private Process botProcess;
    private volatile bool shuttingDown = false;

    // Path to the bot folder containing bot.js and package.json
    private readonly string projectPath = Path.GetDirectoryName(
        System.Reflection.Assembly.GetExecutingAssembly().Location);

    public BotLauncher()
    {
        this.Text = "AiDA License Bot Console";
        this.Icon = SystemIcons.Shield;
        this.Size = new Size(900, 600);
        this.BackColor = Color.FromArgb(24, 24, 28);
        this.ForeColor = Color.FromArgb(0, 255, 136);
        this.ShowInTaskbar = true;

        consoleOutput = new RichTextBox();
        consoleOutput.Dock = DockStyle.Fill;
        consoleOutput.BackColor = Color.FromArgb(24, 24, 28);
        consoleOutput.ForeColor = Color.FromArgb(200, 200, 210);
        consoleOutput.Font = new Font("Cascadia Code", 10F, FontStyle.Regular, GraphicsUnit.Point,
            ((byte)(0)));
        if (!IsFontInstalled("Cascadia Code"))
            consoleOutput.Font = new Font("Consolas", 10);
        consoleOutput.ReadOnly = true;
        consoleOutput.BorderStyle = BorderStyle.None;
        this.Controls.Add(consoleOutput);

        trayMenu = new ContextMenu();
        trayMenu.MenuItems.Add("Show Console", new EventHandler(OnShow));
        trayMenu.MenuItems.Add("-");
        trayMenu.MenuItems.Add("Restart Bot", new EventHandler(OnRestart));
        trayMenu.MenuItems.Add("-");
        var startupItem = new MenuItem("Run on Startup");
        startupItem.Checked = IsStartupEnabled();
        startupItem.Click += new EventHandler((s, e) => ToggleStartup(startupItem));
        trayMenu.MenuItems.Add(startupItem);
        trayMenu.MenuItems.Add("-");
        trayMenu.MenuItems.Add("Exit", new EventHandler(OnExit));

        trayIcon = new NotifyIcon();
        trayIcon.Text = "AiDA License Bot";
        trayIcon.Icon = SystemIcons.Shield;
        trayIcon.ContextMenu = trayMenu;
        trayIcon.Visible = true;
        trayIcon.MouseDoubleClick += new MouseEventHandler(OnShow);

        this.Resize += new EventHandler(OnResize);
        this.Load += new EventHandler(OnLoad);
        this.FormClosing += new FormClosingEventHandler(OnFormClosing);
    }

    private void OnLoad(object sender, EventArgs e)
    {
        this.WindowState = FormWindowState.Minimized;
        this.ShowInTaskbar = false;
        this.Hide();

        Thread backgroundThread = new Thread(StartBotSequence);
        backgroundThread.IsBackground = true;
        backgroundThread.Start();
    }

    private void StartBotSequence()
    {
        Log("═══════════════════════════════════════════");
        Log("  AiDA License Bot — Starting up...");
        Log("═══════════════════════════════════════════");
        Log("Project path: " + projectPath);

        // Install dependencies if node_modules missing
        if (!Directory.Exists(Path.Combine(projectPath, "node_modules")))
        {
            Log("node_modules not found — running npm install...");
            RunProcess("cmd.exe", "/c npm install", projectPath);
        }

        // Start bot with auto-restart
        while (!shuttingDown)
        {
            Log("Starting bot: node bot.js");
            StartBotProcess(projectPath);

            if (botProcess != null)
            {
                botProcess.WaitForExit();
                int code = botProcess.ExitCode;
                Log("Bot exited with code: " + code);
            }

            if (shuttingDown) break;

            Log("Bot crashed — restarting in 5 seconds...");
            Thread.Sleep(5000);
        }
    }

    private void RunProcess(string fileName, string arguments, string workingDirectory)
    {
        try
        {
            Process p = new Process();
            p.StartInfo.FileName = fileName;
            p.StartInfo.Arguments = arguments;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.WorkingDirectory = workingDirectory;

            p.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Log(e.Data); };
            p.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Log("ERR: " + e.Data); };

            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();
            Log("Process exited with code: " + p.ExitCode);
        }
        catch (Exception ex)
        {
            Log("Failed to run command: " + ex.Message);
        }
    }

    private void StartBotProcess(string workingDirectory)
    {
        try
        {
            botProcess = new Process();
            botProcess.StartInfo.FileName = "node";
            botProcess.StartInfo.Arguments = "bot.js";
            botProcess.StartInfo.RedirectStandardOutput = true;
            botProcess.StartInfo.RedirectStandardError = true;
            botProcess.StartInfo.UseShellExecute = false;
            botProcess.StartInfo.CreateNoWindow = true;
            botProcess.StartInfo.WorkingDirectory = workingDirectory;

            botProcess.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Log(e.Data); };
            botProcess.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Log("ERR: " + e.Data); };

            botProcess.Start();
            botProcess.BeginOutputReadLine();
            botProcess.BeginErrorReadLine();
        }
        catch (Exception ex)
        {
            Log("CRITICAL: " + ex.Message);
        }
    }

    private void Log(string message)
    {
        if (string.IsNullOrEmpty(message)) return;
        if (consoleOutput.InvokeRequired)
        {
            try { consoleOutput.Invoke(new Action<string>(Log), message); }
            catch { }
        }
        else
        {
            string timestamp = DateTime.Now.ToString("[HH:mm:ss] ");
            consoleOutput.SelectionStart = consoleOutput.TextLength;
            consoleOutput.SelectionColor = Color.FromArgb(100, 100, 120);
            consoleOutput.AppendText(timestamp);
            consoleOutput.SelectionColor = message.StartsWith("ERR")
                ? Color.FromArgb(255, 80, 80)
                : Color.FromArgb(200, 200, 210);
            consoleOutput.AppendText(message + Environment.NewLine);
            consoleOutput.ScrollToCaret();
        }
    }

    // ── Startup Registration ──────────────────────────────────────────────────

    private const string STARTUP_KEY = "AiDALicenseBot";

    private bool IsStartupEnabled()
    {
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false))
            {
                return key != null && key.GetValue(STARTUP_KEY) != null;
            }
        }
        catch { return false; }
    }

    private void ToggleStartup(MenuItem item)
    {
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true))
            {
                if (item.Checked)
                {
                    key.DeleteValue(STARTUP_KEY, false);
                    item.Checked = false;
                    Log("Removed from Windows startup.");
                }
                else
                {
                    string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                    key.SetValue(STARTUP_KEY, "\"" + exePath + "\"");
                    item.Checked = true;
                    Log("Added to Windows startup.");
                }
            }
        }
        catch (Exception ex)
        {
            Log("Startup toggle failed: " + ex.Message);
        }
    }

    private bool IsFontInstalled(string fontName)
    {
        using (var f = new Font(fontName, 10))
            return f.Name.Equals(fontName, StringComparison.OrdinalIgnoreCase);
    }

    // ── Window Events ─────────────────────────────────────────────────────────

    private void OnResize(object sender, EventArgs e)
    {
        if (this.WindowState == FormWindowState.Minimized)
        {
            this.Hide();
            this.ShowInTaskbar = false;
        }
    }

    private void OnShow(object sender, EventArgs e)
    {
        this.Show();
        this.WindowState = FormWindowState.Normal;
        this.ShowInTaskbar = true;
        this.Activate();
    }

    private void OnRestart(object sender, EventArgs e)
    {
        Log("Manual restart requested...");
        try
        {
            if (botProcess != null && !botProcess.HasExited)
            {
                botProcess.Kill();
                botProcess.WaitForExit(3000);
            }
        }
        catch { }
        // The auto-restart loop in StartBotSequence will pick it up
    }

    private void OnFormClosing(object sender, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            this.WindowState = FormWindowState.Minimized;
            this.Hide();
            this.ShowInTaskbar = false;
        }
    }

    private void OnExit(object sender, EventArgs e)
    {
        shuttingDown = true;

        try
        {
            if (botProcess != null && !botProcess.HasExited)
            {
                botProcess.Kill();
                botProcess.WaitForExit(3000);
            }
        }
        catch { }

        if (trayIcon != null)
        {
            trayIcon.Visible = false;
            trayIcon.Dispose();
        }

        Application.Exit();
    }

    [STAThread]
    static void Main()
    {
        // Single-instance check
        bool created;
        using (var mutex = new Mutex(true, "AiDA_License_Bot_Mutex", out created))
        {
            if (!created)
            {
                MessageBox.Show("AiDA License Bot is already running.",
                    "AiDA", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new BotLauncher());
        }
    }
}
