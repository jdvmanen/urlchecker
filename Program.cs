using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using Microsoft.Win32;

namespace UrlChecker
{
    internal static class Program
    {
        private static readonly HashSet<string> KnownShorteners = new(StringComparer.OrdinalIgnoreCase)
        {
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
            "rb.gy", "cutt.ly", "goo.gl", "rebrand.ly", "shorturl.at", "t.ly", "linktr.ee"
        };

        [STAThread]
        static void Main(string[] args)
        {
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (args.Length == 0 || string.IsNullOrWhiteSpace(args[0]))
            {
                Application.Run(new SettingsForm());
                return;
            }

            // Verplicht een geldige API-sleutel vóórdat er links kunnen worden geopend
            string currentApiKey = GetConfigValue("VtApiKey");
            if (string.IsNullOrWhiteSpace(currentApiKey))
            {
                MessageBox.Show(
                    "Er is nog geen VirusTotal API-sleutel ingesteld.\n\nVul eerst een geldige sleutel in om UrlChecker te kunnen gebruiken.",
                    "API-sleutel vereist",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);

                Application.Run(new SettingsForm());

                if (string.IsNullOrWhiteSpace(GetConfigValue("VtApiKey")))
                {
                    return; // Nog steeds geen sleutel ingevuld: stop proces, open niets
                }
            }

            string rawUrl = args[0].Trim();

            if (!rawUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !rawUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                rawUrl = "https://" + rawUrl;
            }

            bool wasUnwrapped;
            string effectiveUrl = UnwrapSecurityUrl(rawUrl, out wasUnwrapped);

            bool wasShortened;
            effectiveUrl = ResolveShortenerUrl(effectiveUrl, out wasShortened);

            Uri uri;
            try
            {
                uri = new Uri(effectiveUrl);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ongeldige URL:\n{effectiveUrl}\n\nFout: {ex.Message}", "Ongeldige URL", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string host = uri.Host;
            string mainDomain = ExtractMainDomain(host);

            if (ListManager.IsWhitelisted(mainDomain, host))
            {
                using var quickForm = new WhitelistNoticeForm(rawUrl, mainDomain);
                Application.Run(quickForm);
                return;
            }

            using var form = new UrlPromptForm(rawUrl, effectiveUrl, host, mainDomain, wasUnwrapped, wasShortened);
            Application.Run(form);
        }

        public static string GetConfigValue(string keyName)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\UrlChecker\Config");
                return key?.GetValue(keyName) as string ?? "";
            }
            catch { return ""; }
        }

        private static string UnwrapSecurityUrl(string inputUrl, out bool unwrapped)
        {
            unwrapped = false;
            try
            {
                var uri = new Uri(inputUrl);

                if (uri.Host.EndsWith("safelinks.protection.outlook.com", StringComparison.OrdinalIgnoreCase))
                {
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    string? target = query["url"];
                    if (!string.IsNullOrEmpty(target))
                    {
                        unwrapped = true;
                        return target;
                    }
                }

                if (uri.Host.Contains("urldefense.proofpoint.com", StringComparison.OrdinalIgnoreCase))
                {
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    string? target = query["u"];
                    if (!string.IsNullOrEmpty(target))
                    {
                        target = target.Replace("_", "/").Replace("-", "%");
                        unwrapped = true;
                        return HttpUtility.UrlDecode(target);
                    }
                }
            }
            catch { }

            return inputUrl;
        }

        private static string ResolveShortenerUrl(string inputUrl, out bool wasRedirected)
        {
            wasRedirected = false;

            try
            {
                var uri = new Uri(inputUrl);
                string mainDomain = ExtractMainDomain(uri.Host);

                if (!KnownShorteners.Contains(uri.Host) && !KnownShorteners.Contains(mainDomain))
                {
                    return inputUrl;
                }

                var handler = new HttpClientHandler { AllowAutoRedirect = false };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) UrlChecker/1.0");

                string currentUrl = inputUrl;
                int maxHops = 5;

                while (maxHops-- > 0)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Head, currentUrl);
                    using var response = client.Send(request);

                    int statusCode = (int)response.StatusCode;
                    if (statusCode >= 300 && statusCode <= 399)
                    {
                        var location = response.Headers.Location;
                        if (location != null)
                        {
                            Uri nextUri = location.IsAbsoluteUri ? location : new Uri(new Uri(currentUrl), location);
                            currentUrl = nextUri.ToString();
                            wasRedirected = true;
                            continue;
                        }
                    }
                    break;
                }

                return currentUrl;
            }
            catch
            {
                return inputUrl;
            }
        }

        public static string ExtractMainDomain(string host)
        {
            if (IPAddress.TryParse(host, out _)) return host;

            host = host.Trim().TrimEnd('.');
            string[] parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 2) return host;

            string[] doubleExtensions = { "co.uk", "com.au", "co.nz", "org.uk", "gov.uk" };
            string lastTwo = $"{parts[^2]}.{parts[^1]}".ToLowerInvariant();

            foreach (var ext in doubleExtensions)
            {
                if (lastTwo == ext && parts.Length >= 3)
                {
                    return $"{parts[^3]}.{parts[^2]}.{parts[^1]}";
                }
            }

            return $"{parts[^2]}.{parts[^1]}";
        }
    }

    public static class BrowserLauncher
    {
        public record BrowserOption(string Name, string Exe);

        public static readonly BrowserOption[] BrowserOptions = new[]
        {
            new BrowserOption("Microsoft Edge", "msedge.exe"),
            new BrowserOption("Google Chrome", "chrome.exe"),
            new BrowserOption("Mozilla Firefox", "firefox.exe")
        };

        public static void OpenUrl(string url, string? forcedBrowserExe = null)
        {
            string exe = forcedBrowserExe ?? GetSavedBrowserExe();
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = $"\"{url}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fout bij openen van browser ({exe}):\n{ex.Message}", "Fout", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public static string GetSavedBrowserExe()
        {
            string name = LoadSavedBrowser();
            var opt = BrowserOptions.FirstOrDefault(b => b.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            return opt?.Exe ?? "msedge.exe";
        }

        public static string LoadSavedBrowser()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\UrlChecker\Config");
                return key?.GetValue("SelectedBrowser") as string ?? "Microsoft Edge";
            }
            catch { return "Microsoft Edge"; }
        }

        public static void SaveBrowserPreference(string browserName)
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(@"Software\UrlChecker\Config");
                key?.SetValue("SelectedBrowser", browserName);
            }
            catch { }
        }
    }

    public static class ListManager
    {
        private const string RegBasePath = @"Software\UrlChecker\Lists";

        public static HashSet<string> LoadList(string listName)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"{RegBasePath}\{listName}");
                if (key != null)
                {
                    foreach (var val in key.GetValueNames())
                    {
                        if (!string.IsNullOrWhiteSpace(val)) set.Add(val.Trim());
                    }
                }
            }
            catch { }
            return set;
        }

        public static void SaveList(string listName, IEnumerable<string> items)
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree($@"{RegBasePath}\{listName}", false);
                using var key = Registry.CurrentUser.CreateSubKey($@"{RegBasePath}\{listName}");
                if (key != null)
                {
                    foreach (var item in items)
                    {
                        if (!string.IsNullOrWhiteSpace(item))
                            key.SetValue(item.Trim().ToLowerInvariant(), 1);
                    }
                }
            }
            catch { }
        }

        public static void AddToList(string listName, string domain)
        {
            domain = domain.Trim().ToLowerInvariant();
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey($@"{RegBasePath}\{listName}");
                key?.SetValue(domain, 1);
            }
            catch { }
        }

        public static void RemoveFromList(string listName, string domain)
        {
            domain = domain.Trim().ToLowerInvariant();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"{RegBasePath}\{listName}", true);
                key?.DeleteValue(domain, false);
            }
            catch { }
        }

        public static bool IsWhitelisted(string mainDomain, string host) => MatchesList("Whitelist", mainDomain, host);
        public static bool IsBlacklisted(string mainDomain, string host) => MatchesList("Blacklist", mainDomain, host);
        public static bool IsGraylisted(string mainDomain, string host) => MatchesList("Graylist", mainDomain, host);

        private static bool MatchesList(string listName, string mainDomain, string host)
        {
            var list = LoadList(listName);
            if (list.Contains(mainDomain) || list.Contains(host)) return true;
            return list.Any(item => item.StartsWith("*.") && host.EndsWith(item[1..], StringComparison.OrdinalIgnoreCase));
        }
    }

    public class WhitelistNoticeForm : Form
    {
        private readonly string _rawUrl;
        private readonly System.Windows.Forms.Timer _timer = new();
        private readonly ProgressBar _progressBar;
        private int _elapsedMs = 0;
        private const int TotalDurationMs = 1500;
        private const int StepIntervalMs = 30;

        public WhitelistNoticeForm(string rawUrl, string domain)
        {
            _rawUrl = rawUrl;
            _timer.Interval = StepIntervalMs;

            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);

            Text = "UrlChecker - Vertrouwd domein";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            BackColor = Color.FromArgb(248, 250, 252);

            MinimumSize = new Size(820, 210);
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(28, 22, 28, 22)
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var pnlTop = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Margin = new Padding(0, 0, 0, 16)
            };

            var lblBadge = new Label
            {
                Text = "✓ WHITELIST",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(21, 128, 61),
                BackColor = Color.FromArgb(220, 252, 231),
                Padding = new Padding(8, 4, 8, 4),
                AutoSize = true,
                Margin = new Padding(0, 2, 14, 0)
            };

            var lblDomain = new Label
            {
                Text = domain,
                Font = new Font("Segoe UI", 14F, FontStyle.Bold),
                ForeColor = Color.FromArgb(15, 23, 42),
                AutoSize = true
            };

            var lblSubtext = new Label
            {
                Text = "— browser wordt direct geopend...",
                Font = new Font("Segoe UI", 11F, FontStyle.Regular),
                ForeColor = Color.FromArgb(100, 116, 139),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.None,
                Margin = new Padding(8, 0, 0, 0)
            };

            pnlTop.Controls.AddRange(new Control[] { lblBadge, lblDomain, lblSubtext });

            _progressBar = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Height = 16,
                Minimum = 0,
                Maximum = TotalDurationMs,
                Value = 0,
                Margin = new Padding(0, 0, 0, 18)
            };

            var pnlBottom = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            pnlBottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            pnlBottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            var btnCancel = new Button
            {
                Text = "Annuleren",
                AutoSize = true,
                Height = 36,
                Padding = new Padding(16, 0, 16, 0),
                BackColor = Color.White,
                Font = new Font("Segoe UI", 9.5F)
            };
            btnCancel.Click += (s, e) =>
            {
                _timer.Stop();
                Close();
            };

            var btnNow = new Button
            {
                Text = "Nu openen",
                AutoSize = true,
                Height = 36,
                Padding = new Padding(20, 0, 20, 0),
                Margin = new Padding(10, 0, 0, 0),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold)
            };
            btnNow.Click += (s, e) => LaunchAndClose();

            var buttonFlow = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Anchor = AnchorStyles.Right,
                Margin = new Padding(0)
            };
            buttonFlow.Controls.AddRange(new Control[] { btnCancel, btnNow });

            pnlBottom.Controls.Add(buttonFlow, 1, 0);

            mainLayout.Controls.Add(pnlTop, 0, 0);
            mainLayout.Controls.Add(_progressBar, 0, 1);
            mainLayout.Controls.Add(pnlBottom, 0, 2);

            Controls.Add(mainLayout);

            _timer.Tick += (s, e) =>
            {
                _elapsedMs += StepIntervalMs;
                if (_elapsedMs >= TotalDurationMs)
                {
                    _timer.Stop();
                    LaunchAndClose();
                }
                else
                {
                    _progressBar.Value = Math.Min(_elapsedMs, TotalDurationMs);
                }
            };

            Shown += (s, e) => _timer.Start();
        }

        private void LaunchAndClose()
        {
            BrowserLauncher.OpenUrl(_rawUrl);
            Close();
        }
    }

    public class UrlPromptForm : Form
    {
        private readonly string _rawUrl;
        private readonly string _effectiveUrl;
        private readonly string _mainDomain;
        private readonly ComboBox _cboBrowser;
        private readonly bool _isBlacklisted;
        private readonly bool _isGraylisted;
        private readonly Label _lblVtBadge;
        private readonly Button _btnWhitelist;
        private readonly Button _btnOpen;
        private string _vtReportUrl = "";

        public UrlPromptForm(string rawUrl, string effectiveUrl, string host, string mainDomain, bool wasUnwrapped, bool wasShortened)
        {
            _rawUrl = rawUrl;
            _effectiveUrl = effectiveUrl;
            _mainDomain = mainDomain;

            _isBlacklisted = ListManager.IsBlacklisted(mainDomain, host);
            _isGraylisted = !_isBlacklisted && ListManager.IsGraylisted(mainDomain, host);

            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);

            Text = "UrlChecker - Beveiligingscontrole";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            BackColor = Color.FromArgb(248, 250, 252);

            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            MinimumSize = new Size(820, 0);

            Font = new Font("Segoe UI", 9.5F, FontStyle.Regular, GraphicsUnit.Point);

            var rootLayout = new TableLayoutPanel
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                Padding = new Padding(28, 22, 28, 22)
            };

            if (_isBlacklisted)
            {
                rootLayout.Controls.Add(CreateBannerPanel(
                    "⛔ GEBLOKKEERD (Blacklist)",
                    "Dit domein staat op je zwarte lijst. Openen is permanent uitgeschakeld.",
                    Color.FromArgb(254, 242, 242), Color.FromArgb(220, 38, 38)));
            }
            else if (_isGraylisted)
            {
                rootLayout.Controls.Add(CreateBannerPanel(
                    "⚠️ LET OP (Graylist)",
                    "Een link naar dit domein is eerder geweigerd of geannuleerd.",
                    Color.FromArgb(254, 252, 232), Color.FromArgb(202, 138, 4)));
            }

            var pnlHeader = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Margin = new Padding(0, 0, 0, 14)
            };

            var lblHeaderIcon = new Label
            {
                Text = _isBlacklisted ? "🛡️" : "🔗",
                Font = new Font("Segoe UI Emoji", 14F),
                AutoSize = true,
                Margin = new Padding(0, 0, 8, 0)
            };

            var lblHeaderTitle = new Label
            {
                Text = _isBlacklisted ? "Toegang tot link geblokkeerd" : "Wil je deze link openen?",
                Font = new Font("Segoe UI Semibold", 13.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(15, 23, 42),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.None
            };
            pnlHeader.Controls.AddRange(new Control[] { lblHeaderIcon, lblHeaderTitle });
            rootLayout.Controls.Add(pnlHeader);

            var cardPanel = new Panel
            {
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                AutoSize = true,
                Dock = DockStyle.Fill,
                Padding = new Padding(18, 14, 18, 14),
                Margin = new Padding(0, 0, 0, 18)
            };

            var cardLayout = new TableLayoutPanel
            {
                AutoSize = true,
                Dock = DockStyle.Fill,
                ColumnCount = 1
            };

            var pnlDomain = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = true,
                Margin = new Padding(0, 0, 0, 4)
            };

            var lblDomainTag = new Label
            {
                Text = "HOOFDDOMEIN",
                Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(100, 116, 139),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.None,
                Margin = new Padding(0, 2, 8, 0)
            };

            var lblMainDomain = new Label
            {
                Text = mainDomain,
                Font = new Font("Segoe UI", 13F, FontStyle.Bold),
                ForeColor = _isBlacklisted ? Color.FromArgb(220, 38, 38) : Color.FromArgb(30, 64, 175),
                AutoSize = true
            };
            pnlDomain.Controls.AddRange(new Control[] { lblDomainTag, lblMainDomain });

            if (wasUnwrapped)
            {
                var lblUnwrappedBadge = new Label
                {
                    Text = "Safe Links ontcijferd",
                    Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
                    ForeColor = Color.FromArgb(21, 128, 61),
                    BackColor = Color.FromArgb(220, 252, 231),
                    Padding = new Padding(6, 2, 6, 2),
                    AutoSize = true,
                    Margin = new Padding(10, 2, 0, 0)
                };
                pnlDomain.Controls.Add(lblUnwrappedBadge);
            }

            if (wasShortened)
            {
                var lblShortenedBadge = new Label
                {
                    Text = "🔗 Shortener ontrafeld",
                    Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
                    ForeColor = Color.FromArgb(2, 132, 199),
                    BackColor = Color.FromArgb(224, 242, 254),
                    Padding = new Padding(6, 2, 6, 2),
                    AutoSize = true,
                    Margin = new Padding(10, 2, 0, 0)
                };
                pnlDomain.Controls.Add(lblShortenedBadge);
            }

            _lblVtBadge = new Label
            {
                Text = "⏳ VirusTotal: Controleren...",
                Font = new Font("Segoe UI Semibold", 8F),
                ForeColor = Color.FromArgb(71, 85, 105),
                BackColor = Color.FromArgb(241, 245, 249),
                Padding = new Padding(6, 3, 6, 3),
                AutoSize = true,
                Cursor = Cursors.Hand,
                Margin = new Padding(10, 2, 0, 0)
            };
            _lblVtBadge.Click += OnBadgeClickOpenReport;
            pnlDomain.Controls.Add(_lblVtBadge);

            cardLayout.Controls.Add(pnlDomain);

            var lblHostInfo = new Label
            {
                Text = $"Host: {host}",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Regular),
                ForeColor = Color.FromArgb(100, 116, 139),
                AutoSize = true,
                Margin = new Padding(0, 0, 0, 12)
            };
            cardLayout.Controls.Add(lblHostInfo);

            var line = new Panel
            {
                Height = 1,
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(226, 232, 240),
                Margin = new Padding(0, 0, 0, 10)
            };
            cardLayout.Controls.Add(line);

            var lblUrlTitle = new Label
            {
                Text = "DOEL-URL",
                Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(100, 116, 139),
                AutoSize = true,
                Margin = new Padding(0, 0, 0, 4)
            };
            cardLayout.Controls.Add(lblUrlTitle);

            var lblFullUrl = new Label
            {
                Text = _effectiveUrl,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Regular),
                ForeColor = Color.FromArgb(30, 41, 59),
                AutoSize = true,
                MaximumSize = new Size(740, 0),
                Margin = new Padding(0, 0, 0, 4)
            };
            cardLayout.Controls.Add(lblFullUrl);

            cardPanel.Controls.Add(cardLayout);
            rootLayout.Controls.Add(cardPanel);

            var pnlOptionsRow = new TableLayoutPanel
            {
                AutoSize = true,
                ColumnCount = 3,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 20)
            };
            pnlOptionsRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pnlOptionsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            pnlOptionsRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            var pnlBrowser = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Margin = new Padding(0)
            };

            var lblBrowser = new Label
            {
                Text = "Openen met:",
                Font = new Font("Segoe UI Semibold", 9.5F),
                ForeColor = Color.FromArgb(51, 65, 85),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.None,
                Margin = new Padding(0, 0, 10, 0)
            };

            _cboBrowser = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = 340,
                Font = new Font("Segoe UI", 9.5F),
                Anchor = AnchorStyles.None,
                Enabled = !_isBlacklisted
            };
            foreach (var opt in BrowserLauncher.BrowserOptions) _cboBrowser.Items.Add(opt.Name);

            string savedBrowser = BrowserLauncher.LoadSavedBrowser();
            int selectedIdx = Array.FindIndex(BrowserLauncher.BrowserOptions, b => string.Equals(b.Name, savedBrowser, StringComparison.OrdinalIgnoreCase));
            _cboBrowser.SelectedIndex = selectedIdx >= 0 ? selectedIdx : 0;
            _cboBrowser.SelectedIndexChanged += (s, e) =>
            {
                if (_cboBrowser.SelectedItem is string sel) BrowserLauncher.SaveBrowserPreference(sel);
            };

            pnlBrowser.Controls.AddRange(new Control[] { lblBrowser, _cboBrowser });
            pnlOptionsRow.Controls.Add(pnlBrowser, 0, 0);

            var btnManageLists = new LinkLabel
            {
                Text = "⚙ Lijsten & Instellingen...",
                Font = new Font("Segoe UI", 9F),
                AutoSize = true,
                Anchor = AnchorStyles.Right | AnchorStyles.None,
                LinkColor = Color.FromArgb(37, 99, 235),
                Margin = new Padding(0)
            };
            btnManageLists.LinkClicked += (s, e) =>
            {
                this.Hide();
                using (var settings = new SettingsForm(_mainDomain))
                {
                    settings.ShowDialog();
                }
                this.Show();
                this.BringToFront();
            };
            pnlOptionsRow.Controls.Add(btnManageLists, 2, 0);
            rootLayout.Controls.Add(pnlOptionsRow);

            var buttonBar = new TableLayoutPanel
            {
                AutoSize = true,
                ColumnCount = 5,
                RowCount = 1,
                Dock = DockStyle.Fill,
                Margin = new Padding(0)
            };
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            buttonBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            var btnCopy = new Button
            {
                Text = "Kopieer URL",
                AutoSize = true,
                Height = 36,
                Padding = new Padding(12, 0, 12, 0),
                BackColor = Color.White
            };
            btnCopy.Click += (s, e) =>
            {
                Clipboard.SetText(_effectiveUrl);
                btnCopy.Text = "✓ Gekopieerd";
            };

            _btnWhitelist = new Button
            {
                Text = _isBlacklisted ? "✓ Altijd vertrouwen" : "⏳ Wachten op scan...",
                AutoSize = true,
                Height = 36,
                Padding = new Padding(12, 0, 12, 0),
                Margin = new Padding(8, 0, 0, 0),
                BackColor = Color.White,
                ForeColor = Color.FromArgb(21, 128, 61),
                Enabled = false
            };
            _btnWhitelist.Click += (s, e) =>
            {
                ListManager.AddToList("Whitelist", _mainDomain);
                ListManager.RemoveFromList("Graylist", _mainDomain);
                OpenInSelectedBrowser();
            };

            var btnBlock = new Button
            {
                Text = "⛔ Altijd blokkeren",
                AutoSize = true,
                Height = 36,
                Padding = new Padding(12, 0, 12, 0),
                Margin = new Padding(8, 0, 0, 0),
                BackColor = Color.White,
                ForeColor = Color.FromArgb(185, 28, 28)
            };
            btnBlock.Click += (s, e) =>
            {
                ListManager.AddToList("Blacklist", _mainDomain);
                ListManager.RemoveFromList("Graylist", _mainDomain);
                ListManager.RemoveFromList("Whitelist", _mainDomain);
                Close();
            };

            var rightButtons = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Margin = new Padding(0)
            };

            var btnCancel = new Button
            {
                Text = _isBlacklisted ? "Sluiten" : "Annuleren",
                DialogResult = DialogResult.Cancel,
                AutoSize = true,
                Height = 36,
                Padding = new Padding(16, 0, 16, 0),
                Margin = new Padding(0, 0, 8, 0),
                BackColor = Color.White
            };
            btnCancel.Click += (s, e) =>
            {
                if (!_isBlacklisted) ListManager.AddToList("Graylist", _mainDomain);
                Close();
            };

            _btnOpen = new Button
            {
                Text = _isBlacklisted ? "Openen" : "Controleren...",
                DialogResult = DialogResult.OK,
                Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold),
                AutoSize = true,
                Height = 36,
                Padding = new Padding(22, 0, 22, 0),
                Margin = new Padding(0),
                BackColor = Color.FromArgb(148, 163, 184),
                ForeColor = Color.White,
                Enabled = false
            };
            _btnOpen.Click += (s, e) =>
            {
                ListManager.RemoveFromList("Graylist", _mainDomain);
                OpenInSelectedBrowser();
            };

            rightButtons.Controls.AddRange(new Control[] { btnCancel, _btnOpen });

            buttonBar.Controls.Add(btnCopy, 0, 0);
            buttonBar.Controls.Add(_btnWhitelist, 1, 0);
            buttonBar.Controls.Add(btnBlock, 2, 0);
            buttonBar.Controls.Add(rightButtons, 4, 0);

            rootLayout.Controls.Add(buttonBar);
            Controls.Add(rootLayout);

            CancelButton = btnCancel;

            Shown += async (s, e) => await AutoCheckVirusTotalAsync();
        }

        private async Task AutoCheckVirusTotalAsync()
        {
            if (_isBlacklisted)
            {
                _lblVtBadge.Text = "⛔ Geblokkeerd domein";
                _btnOpen.Enabled = false;
                _btnWhitelist.Enabled = false;
                return;
            }

            using var sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(_effectiveUrl));
            string urlId = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            _vtReportUrl = $"https://www.virustotal.com/gui/url/{urlId}";

            string apiKey = GetVtApiKey();

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                BlockDueToApiError("⛔ Geen API-sleutel ingesteld");
                return;
            }

            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(6) };
                client.DefaultRequestHeaders.Add("x-apikey", apiKey);

                var response = await client.GetAsync($"https://www.virustotal.com/api/v3/urls/{urlId}");

                // API auth of quotum fout direct blokkeren
                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    BlockDueToApiError("⛔ API-sleutel ongeldig (401)");
                    return;
                }
                if (response.StatusCode == (HttpStatusCode)429)
                {
                    BlockDueToApiError("⛔ VirusTotal limiet bereikt (429)");
                    return;
                }

                // Fallback naar domeinreputatie bij 404 (onbekende volledige url)
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    _vtReportUrl = $"https://www.virustotal.com/gui/domain/{_mainDomain}";
                    response = await client.GetAsync($"https://www.virustotal.com/api/v3/domains/{_mainDomain}");

                    if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                    {
                        BlockDueToApiError("⛔ API-sleutel ongeldig (401)");
                        return;
                    }
                    if (response.StatusCode == (HttpStatusCode)429)
                    {
                        BlockDueToApiError("⛔ VirusTotal limiet bereikt (429)");
                        return;
                    }

                    if (response.StatusCode == HttpStatusCode.NotFound)
                    {
                        _lblVtBadge.Text = "ℹ️ VirusTotal: Nieuwe URL & Domein (onbekend)";
                        _lblVtBadge.ForeColor = Color.FromArgb(100, 116, 139);
                        _lblVtBadge.BackColor = Color.FromArgb(241, 245, 249);
                        ApplyScanResult(clean: true, badScores: 0);
                        return;
                    }
                }

                if (!response.IsSuccessStatusCode)
                {
                    BlockDueToApiError($"⚠️ VirusTotal fout: {(int)response.StatusCode}");
                    return;
                }

                string json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                var dataAttributes = doc.RootElement.GetProperty("data").GetProperty("attributes");
                var stats = dataAttributes.GetProperty("last_analysis_stats");

                int malicious = stats.GetProperty("malicious").GetInt32();
                int suspicious = stats.GetProperty("suspicious").GetInt32();
                int badScores = malicious + suspicious;

                if (badScores == 0)
                {
                    _lblVtBadge.Text = "✓ VirusTotal: Veilig (0 alerts)";
                    _lblVtBadge.ForeColor = Color.FromArgb(21, 128, 61);
                    _lblVtBadge.BackColor = Color.FromArgb(220, 252, 231);
                    ApplyScanResult(clean: true, badScores: 0);
                }
                else
                {
                    _lblVtBadge.Text = $"⚠️ VirusTotal: VERDACHT ({badScores} alerts)";
                    _lblVtBadge.ForeColor = Color.FromArgb(185, 28, 28);
                    _lblVtBadge.BackColor = Color.FromArgb(254, 226, 226);
                    ApplyScanResult(clean: false, badScores: badScores);
                }
            }
            catch
            {
                BlockDueToApiError("⚠️ Geen verbinding met VirusTotal");
            }
        }

        private void BlockDueToApiError(string errorMessage)
        {
            _lblVtBadge.Text = $"{errorMessage} (Klik om in te stellen)";
            _lblVtBadge.ForeColor = Color.FromArgb(185, 28, 28);
            _lblVtBadge.BackColor = Color.FromArgb(254, 226, 226);
            _lblVtBadge.Cursor = Cursors.Hand;

            // Knoppen volledig blokkeren
            _btnOpen.Text = "Geblokkeerd (API fout)";
            _btnOpen.BackColor = Color.FromArgb(148, 163, 184);
            _btnOpen.Enabled = false;

            _btnWhitelist.Text = "Geen scan mogelijk";
            _btnWhitelist.Enabled = false;

            AcceptButton = null;

            _lblVtBadge.Click -= OnBadgeClickOpenReport;
            _lblVtBadge.Click += (s, e) =>
            {
                using var settings = new SettingsForm(_mainDomain);
                settings.ShowDialog();
            };
        }

        private void ApplyScanResult(bool clean, int badScores)
        {
            if (_isBlacklisted) return;

            if (clean)
            {
                _btnOpen.Text = "Openen";
                _btnOpen.BackColor = Color.FromArgb(37, 99, 235);
                _btnOpen.Enabled = true;

                _btnWhitelist.Text = "✓ Altijd vertrouwen";
                _btnWhitelist.Enabled = true;

                AcceptButton = _btnOpen;
            }
            else
            {
                _btnOpen.Text = "⚠️ Toch openen";
                _btnOpen.BackColor = Color.FromArgb(220, 38, 38);
                _btnOpen.Enabled = true;

                _btnWhitelist.Text = "⛔ Geblokkeerd wegens detectie";
                _btnWhitelist.Enabled = false;

                AcceptButton = null;
            }
        }

        private void OnBadgeClickOpenReport(object? sender, EventArgs e) => OpenVtReport();

        private void OpenVtReport()
        {
            if (!string.IsNullOrEmpty(_vtReportUrl))
            {
                int idx = _cboBrowser.SelectedIndex;
                string exe = (idx >= 0 && idx < BrowserLauncher.BrowserOptions.Length)
                    ? BrowserLauncher.BrowserOptions[idx].Exe
                    : "msedge.exe";
                BrowserLauncher.OpenUrl(_vtReportUrl, exe);
            }
        }

        private static string GetVtApiKey() => Program.GetConfigValue("VtApiKey");

        private Panel CreateBannerPanel(string title, string text, Color bg, Color border)
        {
            var pnl = new Panel
            {
                BackColor = bg,
                BorderStyle = BorderStyle.FixedSingle,
                AutoSize = true,
                Dock = DockStyle.Fill,
                Padding = new Padding(14, 10, 14, 10),
                Margin = new Padding(0, 0, 0, 14)
            };

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1 };
            layout.Controls.Add(new Label
            {
                Text = title,
                Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold),
                ForeColor = border,
                AutoSize = true
            });
            layout.Controls.Add(new Label
            {
                Text = text,
                Font = new Font("Segoe UI", 9F),
                ForeColor = Color.FromArgb(71, 85, 105),
                AutoSize = true,
                Margin = new Padding(0, 2, 0, 0)
            });

            pnl.Controls.Add(layout);
            return pnl;
        }

        private void OpenInSelectedBrowser()
        {
            int idx = _cboBrowser.SelectedIndex;
            string exe = (idx >= 0 && idx < BrowserLauncher.BrowserOptions.Length)
                ? BrowserLauncher.BrowserOptions[idx].Exe
                : "msedge.exe";

            BrowserLauncher.OpenUrl(_rawUrl, exe);
            Close();
        }
    }

    public class SettingsForm : Form
    {
        private readonly TabControl _tabs;
        private readonly ListBox _lstWhitelist;
        private readonly ListBox _lstGraylist;
        private readonly ListBox _lstBlacklist;
        private readonly TextBox _txtNewDomain;
        private readonly TextBox _txtApiKey;

        public SettingsForm(string? prefillDomain = null)
        {
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);

            Text = "UrlChecker - Lijsten & Instellingen";

            var screenArea = Screen.FromPoint(Cursor.Position).WorkingArea;
            int targetWidth = (int)(screenArea.Width * 0.75);
            int targetHeight = (int)(screenArea.Height * 0.75);
            ClientSize = new Size(Math.Max(800, targetWidth), Math.Max(550, targetHeight));

            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = false;
            TopMost = true;
            BackColor = Color.FromArgb(248, 250, 252);
            Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(24)
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            _tabs = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI Semibold", 10.5F, FontStyle.Bold)
            };

            _lstWhitelist = CreateListBox();
            _lstGraylist = CreateListBox();
            _lstBlacklist = CreateListBox();

            _tabs.TabPages.Add(CreateTabPage("✓ Whitelist (Direct openen)", _lstWhitelist));
            _tabs.TabPages.Add(CreateTabPage("⚠️ Graylist (Geweigerd)", _lstGraylist));
            _tabs.TabPages.Add(CreateTabPage("⛔ Blacklist (Geblokkeerd)", _lstBlacklist));

            LoadAllLists();

            var pnlAdd = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = false,
                Margin = new Padding(0, 14, 0, 10)
            };

            var lblDomainInput = new Label
            {
                Text = "Domein toevoegen:",
                Font = new Font("Segoe UI Semibold", 10F),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.None,
                Margin = new Padding(0, 0, 10, 0)
            };

            _txtNewDomain = new TextBox
            {
                Width = 360,
                Font = new Font("Segoe UI", 10.5F),
                Text = prefillDomain ?? ""
            };
            _txtNewDomain.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    e.SuppressKeyPress = true;
                    AddDomainToCurrentTab();
                }
            };

            var btnAdd = new Button
            {
                Text = "+ Toevoegen",
                AutoSize = true,
                Height = 34,
                BackColor = Color.White,
                Font = new Font("Segoe UI Semibold", 9.5F),
                Padding = new Padding(12, 0, 12, 0),
                Margin = new Padding(10, 0, 0, 0)
            };
            btnAdd.Click += (s, e) => AddDomainToCurrentTab();

            var btnRemove = new Button
            {
                Text = "🗑 Verwijderen",
                AutoSize = true,
                Height = 34,
                Margin = new Padding(10, 0, 0, 0),
                BackColor = Color.White,
                ForeColor = Color.FromArgb(185, 28, 28),
                Font = new Font("Segoe UI Semibold", 9.5F),
                Padding = new Padding(12, 0, 12, 0)
            };
            btnRemove.Click += (s, e) => RemoveSelectedFromCurrentTab();

            pnlAdd.Controls.AddRange(new Control[] { lblDomainInput, _txtNewDomain, btnAdd, btnRemove });

            var pnlApiKey = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = false,
                Margin = new Padding(0, 0, 0, 14)
            };

            var lblApiKey = new Label
            {
                Text = "VirusTotal API-Key:",
                Font = new Font("Segoe UI Semibold", 9.5F),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.None,
                Margin = new Padding(0, 0, 10, 0)
            };

            _txtApiKey = new TextBox
            {
                Width = 360,
                Font = new Font("Segoe UI", 9.5F),
                Text = Program.GetConfigValue("VtApiKey")
            };

            var btnSaveKey = new Button
            {
                Text = "Sleutel opslaan",
                AutoSize = true,
                Height = 30,
                BackColor = Color.White,
                Font = new Font("Segoe UI", 9F),
                Padding = new Padding(8, 0, 8, 0),
                Margin = new Padding(10, 0, 0, 0)
            };
            btnSaveKey.Click += (s, e) =>
            {
                SaveApiKey(_txtApiKey.Text.Trim());
                btnSaveKey.Text = "✓ Opgeslagen";
            };

            pnlApiKey.Controls.AddRange(new Control[] { lblApiKey, _txtApiKey, btnSaveKey });

            var btnClose = new Button
            {
                Text = "Sluiten",
                DialogResult = DialogResult.OK,
                Anchor = AnchorStyles.Right,
                Height = 36,
                Width = 110,
                BackColor = Color.White,
                Font = new Font("Segoe UI Semibold", 10F)
            };
            btnClose.Click += (s, e) => Close();

            mainLayout.Controls.Add(_tabs, 0, 0);
            mainLayout.Controls.Add(pnlAdd, 0, 1);
            mainLayout.Controls.Add(pnlApiKey, 0, 2);
            mainLayout.Controls.Add(btnClose, 0, 3);

            Controls.Add(mainLayout);
        }

        private TabPage CreateTabPage(string title, ListBox listBox)
        {
            var page = new TabPage(title);
            listBox.Dock = DockStyle.Fill;
            page.Controls.Add(listBox);
            return page;
        }

        private ListBox CreateListBox()
        {
            return new ListBox
            {
                IntegralHeight = false,
                Font = new Font("Segoe UI", 11F, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle,
                ItemHeight = 26
            };
        }

        private void LoadAllLists()
        {
            PopulateListBox(_lstWhitelist, ListManager.LoadList("Whitelist"));
            PopulateListBox(_lstGraylist, ListManager.LoadList("Graylist"));
            PopulateListBox(_lstBlacklist, ListManager.LoadList("Blacklist"));
        }

        private void PopulateListBox(ListBox lb, IEnumerable<string> items)
        {
            lb.Items.Clear();
            foreach (var item in items.OrderBy(x => x)) lb.Items.Add(item);
        }

        private string GetCurrentListName()
        {
            return _tabs.SelectedIndex switch
            {
                0 => "Whitelist",
                1 => "Graylist",
                _ => "Blacklist"
            };
        }

        private ListBox GetCurrentListBox()
        {
            return _tabs.SelectedIndex switch
            {
                0 => _lstWhitelist,
                1 => _lstGraylist,
                _ => _lstBlacklist
            };
        }

        private void AddDomainToCurrentTab()
        {
            string domain = _txtNewDomain.Text.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(domain)) return;

            if (domain.StartsWith("http://") || domain.StartsWith("https://"))
            {
                if (Uri.TryCreate(domain, UriKind.Absolute, out var u)) domain = u.Host;
            }

            string listName = GetCurrentListName();
            ListManager.AddToList(listName, domain);
            _txtNewDomain.Clear();
            LoadAllLists();
        }

        private void RemoveSelectedFromCurrentTab()
        {
            var lb = GetCurrentListBox();
            if (lb.SelectedItem is string domain)
            {
                ListManager.RemoveFromList(GetCurrentListName(), domain);
                LoadAllLists();
            }
        }

        private static void SaveApiKey(string apiKey)
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(@"Software\UrlChecker\Config");
                key?.SetValue("VtApiKey", apiKey);
            }
            catch { }
        }
    }
}