// SCUTNetLogin 安装程序（自包含，无外部依赖）
// 由 csc 编译：C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
// 注意：保持 C# 5 兼容（无字符串插值、无 null 条件运算符、无异步）。
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SCUTNetLogin.Setup
{
    internal static class Program
    {
        private const string AppName = "SCUT 校园网认证";
        private const string AppId = "SCUTNetLogin";
        private const string AppVersion = "1.0.0";
        private const string Publisher = "SCUTNetLogin";
        private const string PayloadResource = "installer_payload.zip";
        private const string AppExeName = "SCUTNetLogin.exe";
        private const string UninstallExeName = "uninstall.exe";

        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e)
            {
                MessageBox.Show("发生错误：" + e.Exception.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            };

            if (!IsAdministrator())
            {
                MessageBox.Show("本程序需要管理员权限，请右键“以管理员身份运行”。",
                                AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // 卸载判定：exe 名为 uninstall.exe（用户双击/设置里卸载），或显式带 /uninstall 参数。
            // 避免用户双击 uninstall.exe 时不带参数而错进安装界面。
            string exeName = Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]);
            bool isUninstaller = exeName.Equals("uninstall", StringComparison.OrdinalIgnoreCase)
                                 || (args != null && args.Length > 0
                                     && args[0].Equals("/uninstall", StringComparison.OrdinalIgnoreCase));
            if (isUninstaller)
            {
                Uninstall();
                return;
            }

            Application.Run(new InstallForm());
        }

        private static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id)
                    .IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        // ============================================================
        // 卸载
        // ============================================================

        private static void Uninstall()
        {
            string appDir = AskUninstallDir();
            if (appDir == null)
                return;

            if (MessageBox.Show("确定要卸载 " + AppName + " 吗？", AppName,
                                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            bool keepData = MessageBox.Show(
                "卸载后是否保留配置文件和运行日志？\n（保留 config.ini，下次安装后无需重新配置）",
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;

            try
            {
                RemoveShortcuts();
                RemoveUninstallRegistry();
            }
            catch { /* 清理失败不阻塞卸载 */ }

            if (keepData)
            {
                // 删除除 config.ini 与 log 目录之外的所有文件
                try
                {
                    foreach (string f in Directory.GetFiles(appDir))
                    {
                        string name = Path.GetFileName(f);
                        if (string.Equals(name, "config.ini", StringComparison.OrdinalIgnoreCase))
                            continue;
                        TryDelete(f);
                    }
                    foreach (string d in Directory.GetDirectories(appDir))
                    {
                        if (string.Equals(Path.GetFileName(d), "log", StringComparison.OrdinalIgnoreCase))
                            continue;
                        TryDeleteRecursive(d);
                    }
                }
                catch { }
                // 剩余内容（config.ini / log + 卸载器）延迟自删
                SpawnDelayedSelfDelete(appDir);
            }
            else
            {
                SpawnDelayedSelfDelete(appDir);
            }

            MessageBox.Show("已卸载。", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private static string AskUninstallDir()
        {
            // 从卸载注册表读取安装路径
            string dir = null;
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(UninstallKeyPath()))
                {
                    if (k != null)
                        dir = k.GetValue("InstallLocation") as string;
                }
            }
            catch { }
            if (string.IsNullOrEmpty(dir))
            {
                string guess = Path.Combine(ProgramFilesDir(), AppId);
                if (Directory.Exists(guess))
                    dir = guess;
            }
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                MessageBox.Show("未找到程序安装目录，无法卸载。", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }
            return dir;
        }

        private static void SpawnDelayedSelfDelete(string appDir)
        {
            try
            {
                // 延迟删除：先等自身结束，再整目录删除
                string cmd = "ping -n 2 127.0.0.1 >nul 2>&1 & rd /s /q \"" + appDir + "\"";
                Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
            }
            catch { }
        }

        private static void RemoveShortcuts()
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            TryDelete(Path.Combine(desktop, AppName + ".lnk"));
            string startMenu = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppId);
            TryDeleteRecursive(startMenu);
        }

        private static void RemoveUninstallRegistry()
        {
            try { Registry.LocalMachine.DeleteSubKeyTree(UninstallKeyPath(), false); }
            catch { }
        }

        private static string UninstallKeyPath()
        {
            return @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + AppId;
        }

        private static string ProgramFilesDir()
        {
            // x64 进程：SpecialFolder.ProgramFiles == C:\Program Files
            return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        }

        // ============================================================
        // 安装界面
        // ============================================================

        private sealed class InstallForm : Form
        {
            private TextBox txtDir;
            private CheckBox chkDesktop;
            private CheckBox chkStartMenu;
            private CheckBox chkRun;
            private Button btnInstall;
            private Button btnCancel;
            private ProgressBar progress;
            private Label lblStatus;

            public InstallForm()
            {
                Text = AppName + " 安装程序";
                FormBorderStyle = FormBorderStyle.FixedDialog;
                MaximizeBox = false;
                MinimizeBox = false;
                StartPosition = FormStartPosition.CenterScreen;
                ClientSize = new Size(440, 300);
                Font = new Font("Microsoft YaHei", 9F);
                try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

                Label lblTitle = new Label();
                lblTitle.Text = AppName;
                lblTitle.Font = new Font("Microsoft YaHei", 14F, FontStyle.Bold);
                lblTitle.Location = new Point(20, 16);
                lblTitle.AutoSize = true;

                Label lblDesc = new Label();
                lblDesc.Text = "华南理工大学 802.1X 校园网认证客户端  v" + AppVersion;
                lblDesc.Location = new Point(20, 48);
                lblDesc.AutoSize = true;
                lblDesc.ForeColor = Color.FromArgb(100, 116, 139);

                Label lblDir = new Label();
                lblDir.Text = "安装目录：";
                lblDir.Location = new Point(20, 84);
                lblDir.AutoSize = true;

                txtDir = new TextBox();
                txtDir.Text = Path.Combine(ProgramFilesDir(), AppId);
                txtDir.Location = new Point(20, 104);
                txtDir.Width = 400;

                chkDesktop = new CheckBox();
                chkDesktop.Text = "创建桌面快捷方式";
                chkDesktop.Checked = true;
                chkDesktop.Location = new Point(20, 140);
                chkDesktop.AutoSize = true;

                chkStartMenu = new CheckBox();
                chkStartMenu.Text = "创建开始菜单快捷方式";
                chkStartMenu.Checked = true;
                chkStartMenu.Location = new Point(20, 166);
                chkStartMenu.AutoSize = true;

                chkRun = new CheckBox();
                chkRun.Text = "安装完成后启动程序";
                chkRun.Checked = true;
                chkRun.Location = new Point(20, 192);
                chkRun.AutoSize = true;

                progress = new ProgressBar();
                progress.Style = ProgressBarStyle.Marquee;
                progress.Visible = false;
                progress.Location = new Point(20, 224);
                progress.Width = 400;
                progress.Height = 14;

                lblStatus = new Label();
                lblStatus.Text = "";
                lblStatus.Location = new Point(20, 246);
                lblStatus.AutoSize = true;
                lblStatus.ForeColor = Color.FromArgb(100, 116, 139);

                btnInstall = new Button();
                btnInstall.Text = "安装";
                btnInstall.Size = new Size(96, 32);
                btnInstall.Location = new Point(204, 270);
                btnInstall.Click += delegate { InstallAsync(); };

                btnCancel = new Button();
                btnCancel.Text = "取消";
                btnCancel.Size = new Size(96, 32);
                btnCancel.Location = new Point(324, 270);
                btnCancel.Click += delegate { Close(); };

                Controls.Add(lblTitle);
                Controls.Add(lblDesc);
                Controls.Add(lblDir);
                Controls.Add(txtDir);
                Controls.Add(chkDesktop);
                Controls.Add(chkStartMenu);
                Controls.Add(chkRun);
                Controls.Add(progress);
                Controls.Add(lblStatus);
                Controls.Add(btnInstall);
                Controls.Add(btnCancel);
            }

            private void SetBusy(bool busy)
            {
                txtDir.Enabled = !busy;
                chkDesktop.Enabled = !busy;
                chkStartMenu.Enabled = !busy;
                chkRun.Enabled = !busy;
                btnInstall.Enabled = !busy;
                btnCancel.Enabled = !busy;
                progress.Visible = busy;
                progress.MarqueeAnimationSpeed = 30;
            }

            private void InstallAsync()
            {
                string targetDir = txtDir.Text.Trim();
                if (targetDir.Length == 0)
                {
                    MessageBox.Show("请填写安装目录。", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // 检测正在运行的程序
                Process[] running = Process.GetProcessesByName(AppId);
                if (running.Length > 0)
                {
                    DialogResult r = MessageBox.Show(
                        "检测到程序正在运行。\n继续安装需要先结束它（若已连接校园网，连接会中断）。\n是否结束程序？",
                        AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (r != DialogResult.Yes)
                        return;
                    foreach (Process p in running)
                        TryKill(p);
                }

                // Npcap 检测
                if (!NpcapInstalled())
                {
                    DialogResult r = MessageBox.Show(
                        "未检测到 Npcap 驱动！\n本程序发送 802.1X 认证包依赖 Npcap，请安装 Npcap 并勾选\n\"Support raw 802.1X traffic\" 后重新安装。\n\n是否打开 Npcap 官方下载页？",
                        AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                    if (r == DialogResult.Yes)
                    {
                        try { Process.Start("https://npcap.com/#download"); } catch { }
                    }
                }

                SetBusy(true);
                lblStatus.Text = "正在安装...";
                Application.DoEvents();

                try
                {
                    Directory.CreateDirectory(targetDir);

                    Assembly asm = Assembly.GetExecutingAssembly();
                    using (Stream s = asm.GetManifestResourceStream(PayloadResource))
                    {
                        if (s == null)
                            throw new InvalidOperationException("内部错误：安装包数据缺失 (payload.zip)");
                        using (ZipArchive zip = new ZipArchive(s, ZipArchiveMode.Read))
                        {
                            foreach (ZipArchiveEntry entry in zip.Entries)
                            {
                                if (string.IsNullOrEmpty(entry.Name))
                                    continue; // 目录条目
                                string dest = Path.Combine(targetDir, entry.FullName);
                                string full = Path.GetFullPath(dest);
                                if (!full.StartsWith(Path.GetFullPath(targetDir), StringComparison.OrdinalIgnoreCase))
                                    throw new InvalidOperationException("非法的压缩包路径：" + entry.FullName);
                                Directory.CreateDirectory(Path.GetDirectoryName(full));
                                using (Stream es = entry.Open())
                                using (FileStream fs = File.Create(full))
                                {
                                    es.CopyTo(fs);
                                }
                            }
                        }
                    }
                    lblStatus.Text = "正在创建快捷方式...";
                    Application.DoEvents();

                    if (chkDesktop.Checked)
                        CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), AppName + ".lnk"),
                                       Path.Combine(targetDir, AppExeName), targetDir);
                    if (chkStartMenu.Checked)
                        CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), AppId, AppName + ".lnk"),
                                       Path.Combine(targetDir, AppExeName), targetDir);

                    lblStatus.Text = "正在注册卸载信息...";
                    Application.DoEvents();

                    // 卸载器 = 自身副本
                    string self = Application.ExecutablePath;
                    File.Copy(self, Path.Combine(targetDir, UninstallExeName), true);

                    WriteUninstallRegistry(targetDir);

                    lblStatus.Text = "完成";
                    MessageBox.Show("安装完成！", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);

                    if (chkRun.Checked)
                    {
                        try { Process.Start(Path.Combine(targetDir, AppExeName)); } catch { }
                    }
                    Close();
                }
                catch (Exception ex)
                {
                    SetBusy(false);
                    lblStatus.Text = "";
                    MessageBox.Show("安装失败：" + ex.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            private static void TryKill(Process p)
            {
                try { p.Kill(); p.WaitForExit(3000); }
                catch { }
            }

            private static bool NpcapInstalled()
            {
                try
                {
                    string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    if (File.Exists(Path.Combine(sys, "Npcap", "wpcap.dll")))
                        return true;
                    if (File.Exists(Path.Combine(sys, "wpcap.dll")))
                        return true;
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst"))
                    {
                        if (k != null)
                            return true;
                    }
                }
                catch { }
                return false;
            }

            private static void WriteUninstallRegistry(string targetDir)
            {
                using (RegistryKey k = Registry.LocalMachine.CreateSubKey(UninstallKeyPath()))
                {
                    k.SetValue("DisplayName", AppName);
                    k.SetValue("DisplayVersion", AppVersion);
                    k.SetValue("Publisher", Publisher);
                    k.SetValue("DisplayIcon", "\"" + targetDir + "\\" + AppExeName + "\"");
                    k.SetValue("InstallLocation", targetDir);
                    k.SetValue("UninstallString", "\"" + targetDir + "\\" + UninstallExeName + "\" /uninstall");
                    k.SetValue("QuietUninstallString", "\"" + targetDir + "\\" + UninstallExeName + "\" /uninstall");
                    k.SetValue("NoModify", 1);
                    k.SetValue("NoRepair", 1);
                }
            }

            private static void CreateShortcut(string linkPath, string target, string workDir)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(linkPath));
                    Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                    if (shellType == null)
                        return;
                    object shell = Activator.CreateInstance(shellType);
                    object lnk = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell,
                                                        new object[] { linkPath });
                    Type lt = lnk.GetType();
                    lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { target });
                    lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { workDir });
                    lt.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { target + ",0" });
                    lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { AppName });
                    lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
                }
                catch { }
            }
        }

        private static void TryDelete(string path)
        {
            try { File.Delete(path); } catch { }
        }

        private static void TryDeleteRecursive(string path)
        {
            try
            {
                if (Directory.Exists(path))
                    Directory.Delete(path, true);
            }
            catch { }
        }
    }
}
