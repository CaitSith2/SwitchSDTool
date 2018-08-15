using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using CTR;
using Microsoft.Win32;

namespace SwitchSDTool
{
    public partial class Form1 : Form
    {
        private byte[] _sdKey;

        private readonly Dictionary<string, Ticket> _tickets = new Dictionary<string, Ticket>();
        private readonly Dictionary<string, CNMT> _cnmtFiles = new Dictionary<string, CNMT>();
        private readonly Dictionary<string, string> _titleNames = new Dictionary<string, string>();

        public Form1()
        {
            InitializeComponent();
        }

       

        private void btnSelectSD_Click(object sender, EventArgs e)
        {
            fbdSDCard.ShowNewFolderButton = false;
            var result = fbdSDCard.ShowDialog();
            if (result != DialogResult.OK)
            {
                return;
            }

            var split = fbdSDCard.SelectedPath.PathSplit();
            var rootFolder = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar, "Nintendo", "Contents",
                "registered");
            var baseFolder = Path.Combine(fbdSDCard.SelectedPath, "Nintendo", "Contents", "registered");
            if (Directory.Exists(rootFolder))
            {
                Configuration.Data.SDpath = rootFolder;
                Configuration.Data.SDPrivateFile = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar, "Nintendo", "Contents", "private");
            }
            else if (Directory.Exists(baseFolder))
            {
                Configuration.Data.SDpath = baseFolder;
                Configuration.Data.SDPrivateFile = Path.Combine(fbdSDCard.SelectedPath, "Nintendo", "Contents", "private");
            }
            else
            {
                Configuration.Data.SDpath = fbdSDCard.SelectedPath;
                Configuration.Data.SDPrivateFile = Path.Combine(Path.GetDirectoryName(fbdSDCard.SelectedPath) ?? String.Empty, "private");
            }

        }

        private void btdDecryption_Click(object sender, EventArgs e)
        {
            fbdDecryptionPath.ShowNewFolderButton = true;
            var result = fbdDecryptionPath.ShowDialog();
            if (result != DialogResult.OK)
                return;

            Configuration.Data.Decryptionpath = fbdDecryptionPath.SelectedPath;
        }

        private void btnFindSDKey_Click(object sender, EventArgs e)
        {
            if (Configuration.Data.SystemPath == null) return;
            var sdkeyfile = Path.Combine(Configuration.Data.SystemPath, "save", "8000000000000043");
            if (!File.Exists(Configuration.Data.SDPrivateFile))
            {
                UpdateStatus("Nintendo Switch SD Card not present");
                return;
            }
            if (!File.Exists(sdkeyfile))
            {
                UpdateStatus("Nintendo Switch System NAND Drive not present");
                return;
            }

            try
            {
                var privateBytes = File.ReadAllBytes(Configuration.Data.SDPrivateFile);
                var sdBytes = File.ReadAllBytes(sdkeyfile);

                for (var i = 0; i < sdBytes.Length - 16; i++)
                {
                    var match = true;
                    for (var j = 0; j < 16 && match; j++)
                    {
                        match &= privateBytes[j] == sdBytes[i + j];
                    }

                    if (!match) continue;

                    Array.Copy(sdBytes, i + 16, privateBytes, 0, 16);
                    //File.WriteAllBytes("sdkey", privateBytes);
                    _sdKey = privateBytes;
                    txtSDKey.Text = _sdKey.ToHexString();
                    UpdateStatus(@"SD Key loaded");
                    btnFindSDKey.Enabled = false;
                    return;
                }

                UpdateStatus("SD Key Not loaded - SD Card does NOT Match Nintendo Switch NAND Dump");
            }
            catch (Exception ex)
            {
                UpdateStatus("SD Key not loaded - Check message box above for details",
                    $@"Could not load SD Key due to an Exception:{Environment.NewLine}{ex.Message}{Environment.NewLine}{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
            }
        }

        private void btnSelectSystemPath_Click(object sender, EventArgs e)
        {
            fbdSDCard.ShowNewFolderButton = false;
            var result = fbdSDCard.ShowDialog();
            if (result != DialogResult.OK)
                return;

            var split = fbdSDCard.SelectedPath.PathSplit();
            var rootFolder = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar, "save", "8000000000000043");

            if (File.Exists(rootFolder))
                Configuration.Data.SystemPath = split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar;
            else
                Configuration.Data.SystemPath = fbdSDCard.SelectedPath;
        }

        private void btnLoadRSAKEK_Click(object sender, EventArgs e)
        {
            CheckKeys();
            var rsakek = Configuration.Data.ETicketRSAKEK.ToByte();
            if (!Configuration.VerifyETicketRSAKEK())
            {
                UpdateStatus(@"Bad E-Ticket RSA Key Encryption Key");
                return;
            }

            txtRSAKEK.Text = @"-------- eticket_rsa_kek redacted --------";
            UpdateStatus(@"E-Ticket RSA Key Encryption Key loaded successfully");
            txtRSAKEK.Enabled = false;

            if (!File.Exists("PRODINFO.BIN"))
            {
                UpdateStatus(@"PRODINFO.bin missing.");
                return;
            };
            
            using (var prodinfo = File.OpenRead("PRODINFO.BIN"))
            {
                if (prodinfo.Length < 0x8000)
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly");
                    return;
                }

                var magic = new byte[4];
                var hash = new byte[32];
                var ctr = new byte[16];

                var rsa_D = new byte[0x101];
                var rsa_N = new byte[0x101];
                var rsa_E = new byte[4];

                prodinfo.Read(magic, 0, 4);
                if (!magic.Compare(Encoding.ASCII.GetBytes("CAL0")))
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly - Invalid CAL0 magic!");
                    return;
                }


                prodinfo.Seek(4, SeekOrigin.Current);
                prodinfo.Read(magic, 0, 4);
                var size = BitConverter.ToInt32(magic, 0);

                var data = new byte[size];

                prodinfo.Seek(0x20, SeekOrigin.Begin);
                prodinfo.Read(hash, 0, 0x20);
                prodinfo.Read(data, 0, size);
                if (!SHA256.Create().ComputeHash(data).Compare(hash))
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly - Invalid CAL0 hash!");
                    return;
                }

                data = new byte[0x230];
                prodinfo.Seek(0x3890, SeekOrigin.Begin);
                prodinfo.Read(ctr, 0, 16);
                prodinfo.Read(data, 0, 0x230);
                data = new AesCtr(ctr).CreateDecryptor(rsakek).TransformFinalBlock(data, 0, data.Length).Reverse().ToArray();
                Array.Copy(data, 0x130, rsa_D, 0, rsa_D.Length - 1);
                Array.Copy(data, 0x30, rsa_N, 0, rsa_N.Length - 1);
                Array.Copy(data, 0x2C, rsa_E, 0, rsa_E.Length);

                

                BigInteger test = 0xCAFEBABE;
                var d = new BigInteger(rsa_D);
                var n = new BigInteger(rsa_N);
                var be = new BigInteger(rsa_E);

                var encrypted = BigInteger.ModPow(test, d, n);
                var decrypted = BigInteger.ModPow(encrypted, be, n);
                if (decrypted != test)
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly - RSA Key failed to decrypt correctly.");
                    return;
                }
                Ticket.RsaN = n;
                Ticket.RsaD = d;
                Ticket.RsaE = be;

                btnLoadRSAKEK.Enabled = false;
                UpdateStatus("RSA Key extracted successfully from PRODINFO.bin");
                Application.DoEvents();
            }
        }

        private Dictionary<int, string> _messageBox = new Dictionary<int, string>();

        private void UpdateStatus(string status, params string[] messageArgs)
        {
            if (status.Equals(lblStatus.Text))
            {
                Application.DoEvents();
                return;
            }
            
            lblStatus.Text = status;
            listStatus.Items.Add(lblStatus.Text);
            listStatus.TopIndex = listStatus.Items.Count - 1;

            if (messageArgs == null || messageArgs.Length == 0)
            {
                Application.DoEvents();
                return;
            }

            var message = messageArgs.Aggregate(string.Empty, (current, m) => current + m);
            _messageBox[listStatus.Items.Count - 1] = message;

            Application.DoEvents();
        }

        private void AppendStatus(string status, params string[] messageArgs)
        {
            lblStatus.Text += status;
            listStatus.Items[listStatus.Items.Count - 1] += status;

            if (messageArgs == null || messageArgs.Length == 0)
            {
                Application.DoEvents();
                return;
            }

            _messageBox.TryGetValue(listStatus.Items.Count - 1, out var message);
            if (message == null)
                message = string.Empty;
            message += messageArgs.Aggregate(string.Empty, (current, m) => current + m);
            _messageBox[listStatus.Items.Count - 1] = message;

            Application.DoEvents();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            lblStatus.Text = "";
            tsProgressText.Text = "";
            listStatus.TopIndex = listStatus.Items.Count - 1;
            Configuration.ReadConfiguration();
            Configuration.SetLanguageOrder(tvLanguage);
            var size = Configuration.Data.GameIconSize;
            if (!((GameIconSize[]) Enum.GetValues(typeof(GameIconSize))).Contains(size))
                size = GameIconSize.Medium;
            SetGameImages(size);
            Size = Configuration.Data.MainFormSize;

            if (!CheckNetFramework())
            {
                UpdateStatus("ERROR: Microsoft .NET Framework 4.7.1 or later is required. Please install it.");
                splitContainerTop.Panel1.Enabled = false;
                tcTabs.Enabled = false;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (Ticket.RsaE != 0x10001)
            {
                btnLoadRSAKEK_Click(null, null);
                if (Ticket.RsaE != 0x10001)
                {
                    UpdateStatus("Cannot Dump tickets without RSA KEK");
                    return;
                }
            }

            if (!File.Exists(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e1")) ||
                !File.Exists(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e2")))
            {
                UpdateStatus("Nintendo Switch NAND not mounted.");
                return;
            }

            UpdateStatus("Dumping Tickets");

            var size = 0x4000;
            var data = new byte[size];

            var commonTicketLength = new FileInfo(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e1")).Length;
            InitializeProgress((ulong)(commonTicketLength +
                                       new FileInfo(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e2")).Length), true);
            using (var ticketdata = File.OpenRead(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e1")))
            {
                long ticketstart = -1;
                
                for (var i = 0; i < ticketdata.Length && ticketstart < 0; i += 0x100)
                {
                    if (i % size == 0)
                    {
                        SetProgress((ulong)i);
                        ticketdata.Read(data, 0, size);
                    }
                    if (data[0 + (i % size)] != 4 || data[1 + (i % size)] != 0 || data[2 + (i % size)] != 1 || data[3 + (i % size)] != 0) continue;
                    ticketstart = i;
                }


                if (ticketstart >= 0)
                {
                    ticketdata.Seek(ticketstart, SeekOrigin.Begin);

                    for (var i = 0; i < ticketdata.Length - ticketstart; i += 0x400)
                    {
                        if (i % size == 0)
                        {
                            SetProgress((ulong) (ticketstart + i));
                            ticketdata.Read(data, 0, size);
                        }
                        if (data[0 + (i % size)] != 4 || data[1 + (i % size)] != 0 || data[2 + (i % size)] != 1 || data[3 + (i % size)] != 0) continue;

                        try
                        {
                            var ticket = new Ticket(data.Skip(i % size).Take(0x400).ToArray());
                            _tickets[ticket.TitleID.ToHexString()] = ticket;
                        }
                        catch
                        {
                            //
                        }

                        
                    }
                }
            }

            using (var ticketdata = File.OpenRead(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e2")))
            {
                long ticketstart = -1;
                for (var i = 0; i < ticketdata.Length && ticketstart < 0; i += 0x100)
                {
                    if (i % size == 0)
                    {
                        SetProgress((ulong)(commonTicketLength + i));
                        ticketdata.Read(data, 0, size);
                    }
                    if (data[0 + (i % size)] != 4 || data[1 + (i % size)] != 0 || data[2 + (i % size)] != 1 || data[3 + (i % size)] != 0) continue;
                    ticketstart = i;
                }

                bool firstTicket = false;
                if (ticketstart >= 0)
                {
                    ticketdata.Seek(ticketstart, SeekOrigin.Begin);

                    for (var i = 0; i < ticketdata.Length - ticketstart; i += 0x400)
                    {
                        if (i % size == 0)
                        {
                            SetProgress((ulong)(commonTicketLength + ticketstart + i));
                            ticketdata.Read(data, 0, size);
                        }
                        if (data[0 + (i % size)] != 4 || data[1 + (i % size)] != 0 || data[2 + (i % size)] != 1 || data[3 + (i % size)] != 0) continue;

                        try
                        {
                            var ticket = new Ticket(data.Skip(i % size).Take(0x400).ToArray());
                            if (!firstTicket && !ticket.Anonymize())
                            {
                                UpdateStatus($"Done. {_tickets.Count} Tickets dumped");
                                UpdateStatus($"Cannot extract personal tickets - {ticket.AnonymizeError}");
                                HideProgress();
                                btnLoadRSAKEK.Enabled = true;
                                Ticket.RsaD = BigInteger.Zero;
                                Ticket.RsaN = BigInteger.Zero;
                                Ticket.RsaE = BigInteger.Zero;
                                return;
                            }

                            _tickets[ticket.TitleID.ToHexString()] = ticket;
                            firstTicket = true;
                        }
                        catch
                        {
                            //
                        }


                    }
                }
            }

            HideProgress();
            UpdateStatus($"Done. {_tickets.Count} Tickets dumped");
        }

        private static readonly Dictionary<string, byte[]> _keyHashes = new Dictionary<string, byte[]>
        {
            {"sd_card_nca_key_source", "2E751CECF7D93A2B957BD5FFCB082FD038CC2853219DD3092C6DAB9838F5A7CC".ToByte()},
            {"sd_card_kek_source", "6B2ED877C2C52334AC51E59ABFA7EC457F4A7D01E46291E9F2EAA45F011D24B7".ToByte()},
            {"master_key_00", "0EE359BE3C864BB0782E1D70A718A0342C551EED28C369754F9C4F691BECF7CA".ToByte()},
            {"aes_key_generation_source", "FBD10056999EDC7ACDB96098E47E2C3606230270D23281E671F0F389FC5BC585".ToByte()},
            {"aes_kek_generation_source", "FC02B9D37B42D7A1452E71444F1F700311D1132E301A83B16062E72A78175085".ToByte()},

            {"header_key", "8E03DE24818D96CE4F2A09B43AF979E679974F7570713A61EED8B314864A11D5".ToByte()},
            {"key_area_key_application_source", "04AD66143C726B2A139FB6B21128B46F56C553B2B3887110304298D8D0092D9E".ToByte()},
            {"key_area_key_ocean_source", "FD434000C8FF2B26F8E9A9D2D2C12F6BE5773CBB9DC86300E1BD99F8EA33A417".ToByte()},
            {"key_area_key_system_source", "1F17B1FD51AD1C2379B58F152CA4912EC2106441E51722F38700D5937A1162F7".ToByte()},

            {"master_key_01", "4FE707B7E4ABDAF727C894AAF13B1351BFE2AC90D875F73B2E20FA94B9CC661E".ToByte()},
            {"master_key_02", "79277C0237A2252EC3DFAC1F7C359C2B3D121E9DB15BB9AB4C2B4408D2F3AE09".ToByte()},
            {"master_key_03", "4F36C565D13325F65EE134073C6A578FFCB0008E02D69400836844EAB7432754".ToByte()},
            {"master_key_04", "75FF1D95D26113550EE6FCC20ACB58E97EDEB3A2FF52543ED5AEC63BDCC3DA50".ToByte()},
        };

        private bool KeysTxtHasRequiredKeys(string filename)
        {
            var keys = new Dictionary<string, byte[]>();
            using (var sr = new StreamReader(new FileStream(filename, FileMode.Open)))
            {
                while (!sr.EndOfStream)
                {
                    var line = sr.ReadLine();
                    if (line == null) continue;
                    var split = line.Split(new[] {",", "="}, StringSplitOptions.None).Select(x => x.ToLowerInvariant().Trim()).ToArray();
                    if (split.Length != 2) continue;
                    keys[split[0]] = split[1].ToByte();
                }
            }

            foreach (var keyname in _keyHashes.Keys)
            {
                if (!keys.TryGetValue(keyname, out var keyData))
                {
                    UpdateStatus($"Keys.txt is missing {keyname}");
                    return false;
                }

                if (!SHA256.Create().ComputeHash(keyData).ToHexString().Equals(_keyHashes[keyname].ToHexString()))
                {
                    UpdateStatus($"{keyname} in Keys.txt is invalid");
                    return false;
                }
            }

            if (!Configuration.VerifyETicketRSAKEK() && keys.TryGetValue("eticket_rsa_kek", out var rsaKeyData))
                txtRSAKEK.Text = rsaKeyData.ToHexString();

            return true;

        }

        private bool CheckKeys()
        {
            var keys = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (File.Exists(Path.Combine(keys, ".switch", "Prod.keys")))
            {
                return KeysTxtHasRequiredKeys(Path.Combine(keys, ".switch", "Prod.keys"));
            }

            if (File.Exists("keys.txt"))
            {
                var result = KeysTxtHasRequiredKeys("keys.txt");
                if (!result) return false;

                Directory.CreateDirectory(Path.Combine(keys, ".switch"));
                File.Copy("keys.txt", Path.Combine(keys, ".switch", "Prod.keys"));
                return true;
            }

            UpdateStatus(@"Keys.txt missing.");
            return false;
        }

        private bool VerifyNCAFile(string fileName)
        {
            var hash = SHA256.Create();

            InitializeProgress((ulong) new FileInfo(fileName).Length);
            using (var sr = new BinaryReader(new FileStream(fileName, FileMode.Open)))
            {
                byte[] bytes;
                do
                {
                    bytes = sr.ReadBytes(0x100000);
                    if (bytes.Length == 0x100000)
                        hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                    else
                        hash.TransformFinalBlock(bytes, 0, bytes.Length);
                    UpdateProgress((ulong)bytes.LongLength);
                } while (bytes.Length == 0x100000);
            }

            return fileName.ToLowerInvariant().Contains(hash.Hash.Take(16).ToArray().ToHexString().ToLowerInvariant());
        }

        private string _message = string.Empty;
        private string _error = string.Empty;

        private void StartProcess(Process p, string filename = null)
        {
            _message = string.Empty;
            _error = string.Empty;

            p.Start();
            var message = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEndAsync();

            while (!p.HasExited)
            {
                Application.DoEvents();
                Thread.Sleep(10);
                p.Refresh();
                if(!string.IsNullOrEmpty(filename) && File.Exists(filename))
                    SetProgress((ulong) new FileInfo(filename).Length);
            }

            _message = message.Result;
            _error = error.Result;
        }


        private void btnDecryptNCA_Click(object sender, EventArgs e)
        {
            if (!CheckKeys()) return;
            if (_sdKey == null)
            {
                btnFindSDKey_Click(null, null);
                if (_sdKey == null)
                {
                    UpdateStatus("Cannot Decrypt NCAs from SD card without a valid SD Key");
                }
            }

            var ncadir = Path.Combine("tools", "nca");
            if (!Directory.Exists(ncadir))
                Directory.CreateDirectory(ncadir);

            if (!Directory.Exists(Configuration.Data.Decryptionpath))
                Directory.CreateDirectory(Configuration.Data.Decryptionpath);

            var p = new Process
            {
                StartInfo =
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    FileName = Path.Combine("Tools", "hactool.exe"),
                    CreateNoWindow = true
                }
            };

            var ncaFiles = Configuration.GetSDDirectories;
            if (ncaFiles.Length == 0)
            {
                UpdateStatus("No NCAs present on SD card");
                return;
            }

            UpdateStatus("Decrypting NCA Files from SD Card");
            foreach (var nca in ncaFiles)
            {
                // ReSharper disable once AssignNullToNotNullAttribute
                var ncafile = $@"{Path.Combine(Configuration.Data.Decryptionpath, Path.GetFileName(nca))}";
                if (File.Exists(ncafile)) continue;

                var ncaFileParts = Directory.GetFiles(nca).OrderBy(x => x).ToList();
                var file = ncaFileParts[0];

                if (ncaFileParts.Count > 1)
                {
                    UpdateStatus($@"Processing {Path.GetFileName(nca)} - Joining");
                    file = $@"{Path.Combine(Configuration.Data.Decryptionpath, Path.GetFileName(nca))}.nax0";

                    InitializeProgress((ulong) ncaFileParts.Sum(x => new FileInfo(x).Length));
                    try
                    {
                        using (var sw = new BinaryWriter(new FileStream(file, FileMode.Create)))
                        {
                            foreach (var part in ncaFileParts)
                            {
                                using (var sr = new BinaryReader(new FileStream(part, FileMode.Open)))
                                {
                                    byte[] bytes;
                                    do
                                    {
                                        bytes = sr.ReadBytes(0x100000);
                                        if (bytes.Length <= 0) continue;

                                        sw.Write(bytes);
                                        UpdateProgress((ulong) bytes.LongLength);
                                    } while (bytes.Length > 0);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        AppendStatus(", Failed. Check message box above to see why.",
                            $@"Failed to Join ""{Path.GetFileName(nca)}"" due to an exception:{Environment.NewLine}{ex.Message}{Environment.NewLine}{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                        try
                        {
                            if (File.Exists(file) && file.EndsWith(".nax0"))
                                File.Delete(file);
                        }
                        catch
                        {
                            //
                        }

                        continue;
                    }

                    AppendStatus(", Done. Decrypting");

                }
                else
                {
                    UpdateStatus($@"Processing {Path.GetFileName(nca)} - Decrypting");
                }

                InitializeProgress((ulong) ncaFileParts.Sum(x => new FileInfo(x).Length));
                p.StartInfo.Arguments =
                    $@"-t nax0 --sdseed={_sdKey.ToHexString()} --sdpath=""/registered/{Path.GetFileName(Path.GetDirectoryName(nca))}/{
                            Path.GetFileName(nca)
                        }"" --plaintext=""{ncafile}"" ""{file}""";
                StartProcess(p, ncafile);

                if (File.Exists(file) && file.EndsWith(".nax0"))
                    File.Delete(file);

                if (_message.Contains("Error: NAX0 key derivation failed."))
                {
                    AppendStatus(", Failed: Bad SD Key");

                    if (File.Exists(ncafile))
                        File.Delete(ncafile);
                    _sdKey = null;
                    btnFindSDKey.Enabled = true;
                    break;
                }

                if (p.ExitCode != 0)
                {
                    AppendStatus(", Failed: Check Message log above to see why.",
                        $@"hactool {p.StartInfo.Arguments}{Environment.NewLine}Standard Output: {_message}{
                                Environment.NewLine
                            }Error Output: {_error}{Environment.NewLine}{Environment.NewLine}");

                    if (File.Exists(ncafile))
                        File.Delete(ncafile);

                    continue;
                }

                AppendStatus(", Done. Verifying");

                if (!VerifyNCAFile(ncafile))
                {
                    AppendStatus(", Verification Failed: File is corrupt.");

                    if (File.Exists(ncafile))
                        File.Delete(ncafile);

                    continue;
                }

                AppendStatus(", Verified");
            }

            HideProgress();
            UpdateStatus($@"NCA Decryption completed.");
        }

        private void ClearGameImageLists()
        {
            _cnmtFiles.Clear();
            _titleNames.Clear();
            tvGames.Nodes.Clear();

            ilGamesExtraSmall.Images.Clear();
            ilGamesSmall.Images.Clear();
            ilGames.Images.Clear();
            ilGamesLarge.Images.Clear();
            ilGamesExtraLarge.Images.Clear();
            GameImagesAdd(new Bitmap(pbGameIcon.InitialImage));
            pbGameIcon.Image = ilGamesExtraLarge.Images[0];
        }

        private void GameImagesAdd(Bitmap b)
        {
            ilGamesExtraSmall.Images.Add(b);
            ilGamesSmall.Images.Add(b);
            ilGames.Images.Add(b);
            ilGamesLarge.Images.Add(b);
            ilGamesExtraLarge.Images.Add(b);
        }

        private void ReadControlInfo(string ncadir, string titleID, Process p)
        {
            var titleIDBytes = titleID.ToByte();
            titleIDBytes[6] &= 0xE0;
            titleIDBytes[7] = 0;
            var newTitleID = titleIDBytes.ToHexString();

            titleIDBytes = titleID.ToByte();
            var type = (titleIDBytes[6] & 0x1F) == 0x08 && titleIDBytes[7] == 0x00
                ? "Update"
                : ((titleIDBytes[6] & 0x1F) == 0x00 && titleIDBytes[7] == 0x00 ? "Base Game" : "DLC");

            if (_titleNames.ContainsKey(newTitleID))
            {
                var node = tvGames.Nodes.Find(newTitleID, false).FirstOrDefault();

                var basenode = node?.Nodes.Find($"{titleID} - [{type}]", false).FirstOrDefault();
                if (basenode != null) return;

                node = node?.Nodes.Add(titleID, $"{titleID} - [{type}]");
                if (node == null)
                    return;

                node.Tag = titleID;
                node.ImageIndex = node.Parent.ImageIndex;
                node.SelectedImageIndex = node.Parent.SelectedImageIndex;
                return;
            }

            if (p == null)
            {
                var gameNode = tvGames.Nodes.Add(newTitleID, "Unknown");

                var gameNode1 = gameNode.Nodes.Add(newTitleID, $"{titleID} - [{type}]");
                gameNode1.Tag = titleID;

                gameNode.ImageIndex = gameNode.SelectedImageIndex = 0;
                gameNode1.ImageIndex = gameNode1.SelectedImageIndex = 0;

                return;
            }
            StartProcess(p);

            using (var control = File.OpenRead(Path.Combine(ncadir, "control.nacp")))
            {
                for(var i = 0; i < 15; i++)
                {
                    var node = tvLanguage.Nodes[i];
                    var offset = (int)node.Tag * 0x300;
                    control.Seek(offset, SeekOrigin.Begin);
                    var titlenameBytes = new byte[0x200];
                    control.Read(titlenameBytes, 0, 0x200);

                    var titlename = Encoding.UTF8.GetString(titlenameBytes);
                    if (String.IsNullOrEmpty(titlename)) continue;
                    var index = titlename.IndexOf("\0", StringComparison.Ordinal);
                    if (index == 0) continue;
                    if (index > 0) titlename = titlename.Substring(0, index);
                    
                    _titleNames[newTitleID] = titlename;
                    var gameNode = tvGames.Nodes.Add(newTitleID, titlename);
                    var lname = node.Text.Replace(" ", "");
                    lname = Path.Combine(ncadir, $"icon_{lname}.dat");
                    GameImagesAdd(LoadBitmapUnlocked(lname));
                    gameNode.ImageIndex = gameNode.SelectedImageIndex = ilGames.Images.Count - 1;


                    var gameNode1 = gameNode.Nodes.Add(newTitleID, $"{titleID} - [{type}]");
                    gameNode1.Tag = titleID;
                    gameNode1.ImageIndex = gameNode1.SelectedImageIndex = ilGames.Images.Count - 1;

                    break;
                }
            }

            foreach (var ncadirfile in Directory.GetFiles(ncadir))
                File.Delete(ncadirfile);
        }

        private Bitmap LoadBitmapUnlocked(string file_name)
        {
            using (Bitmap bm = new Bitmap(file_name))
            {
                return new Bitmap(bm);
            }
        }


        private void btnPackNSP_Click(object sender, EventArgs e)
        {
            //if (!CheckKeys()) return;

            if (_tickets.Count == 0)
            {
                button1_Click(null, null);
                if (_tickets.Count == 0)
                {
                    UpdateStatus("No tickets present. Cannot Pack NSPs");
                    return;
                }
            }

            if (Configuration.GetDecryptedNCAFiles.Length == 0)
            {
                btnDecryptNCA_Click(null, null);
                if (Configuration.GetDecryptedNCAFiles.Length == 0)
                {
                    UpdateStatus("No Decrypted NCAs present. Cannot pack NSPs");
                    return;
                }
            }

            if (_cnmtFiles.Count == 0)
            {
                btnParseNCA_Click(null, null);
                if (_cnmtFiles.Count == 0)
                {
                    UpdateStatus("No Titles present on SD card. Cannot Pack NSPs");
                    return;
                }
            }

            Directory.CreateDirectory(Configuration.Data.NSPPath);
            var packed = 0;

            foreach (var cnmt in _cnmtFiles.Values)
            {
                if (PackNSP(cnmt))
                    packed++;
            }

            HideProgress();
            UpdateStatus($@"{packed} NSPs packed");
        }

        private bool PackNSP(string titleID)
        {
            return _cnmtFiles.TryGetValue(titleID, out var cnmt) && PackNSP(cnmt);
        }

        private bool PackNSP(CNMT cnmt)
        {
            var tid = cnmt.TitleID;

            if (!_titleNames.TryGetValue(tid.ToHexString(), out var titleName))
            {
                tid[6] &= 0xE0;
                tid[7] = 0;

                if (!_titleNames.TryGetValue(tid.ToHexString(), out titleName))
                    titleName = "Unknown";
            }

            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (cnmt.Type)
            {
                case CNMT.packTypes.Application:
                    titleName += $@" [{cnmt.TitleID.ToHexString().ToUpperInvariant()}][v{cnmt.Version}].nsp";
                    break;
                case CNMT.packTypes.Patch:
                    titleName += $@" [UPD][{cnmt.TitleID.ToHexString().ToUpperInvariant()}][v{cnmt.Version}].nsp";
                    break;
                default:
                    titleName += $@" [DLC][{cnmt.TitleID.ToHexString().ToUpperInvariant()}][v{cnmt.Version}].nsp";
                    break;
            }

            if (!_tickets.TryGetValue(cnmt.TitleID.ToHexString(), out var ticket))
            {
                UpdateStatus($@"{titleName} cannot be packed. Ticket missing.");
                return false;
            }

            UpdateStatus($@"Packing {titleName}");

            var status = Pack(ticket, cnmt, titleName);
            AppendStatus(status.Item2[0],status.Item2.Skip(1).ToArray());

            return status.Item1;
        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            Configuration.WriteConfiguration();
        }

        private void btnSelectNSPPath_Click(object sender, EventArgs e)
        {
            fbdDecryptionPath.ShowNewFolderButton = true;
            var result = fbdDecryptionPath.ShowDialog();
            if (result != DialogResult.OK)
                return;

            Configuration.Data.NSPPath = fbdDecryptionPath.SelectedPath;
        }

        private ulong _progressMod;
        private ulong _progressDivisor;
        private Double _progressCurrent;
        private Double _progressMax;
        private bool _displayPercentage;
        private void InitializeProgress(ulong max, bool percent=false)
        {
            _progressCurrent = 0;
            _progressMax = max;
            _displayPercentage = percent;

            try
            {
                _progressDivisor = 1;
                while (max > int.MaxValue)
                {
                    max /= 2;
                    _progressDivisor *= 2;
                }

                _progressMod = 0;
                tsProgress.Visible = true;
                tsProgress.Value = 0;
                tsProgress.Maximum = (int) max;
            }
            catch
            {
                tsProgress.Visible = false;
            }
            
            Application.DoEvents();
        }

        private void UpdateProgress(ulong progress)
        {
            if (!tsProgress.Visible) return;

            _progressCurrent += progress;
            if (_progressCurrent > _progressMax)
                _progressCurrent = _progressMax;

            progress += _progressMod;
            _progressMod = progress % _progressDivisor;

            progress /= _progressDivisor;
            if ((tsProgress.Value + (int) progress) > tsProgress.Maximum)
                tsProgress.Value = tsProgress.Maximum;
            else
                tsProgress.Value += (int)progress;
            
            Application.DoEvents();
        }

        private void SetProgress(ulong progress)
        {
            if (!tsProgress.Visible) return;

            _progressCurrent = progress;
            if (_progressCurrent > _progressMax)
                _progressCurrent = _progressMax;

            _progressMod = progress % _progressDivisor;
            progress /= _progressDivisor;

            if (progress > (ulong) tsProgress.Maximum)
                tsProgress.Value = tsProgress.Maximum;
            else
                tsProgress.Value = (int)progress;
            
            Application.DoEvents();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            if (!tsProgress.Visible) return;

            if (_displayPercentage)
            {
                tsProgressText.Text = $@"{_progressCurrent / _progressMax:0.00 %} - ";
                return;
            }
            var designations = new List<string>
            {
                "",
                "KiB",
                "MiB",
                "GiB",
                "TiB",
                "PiB",
                "EiB",
                "ZiB",
                "YiB"
            };
            var current = _progressCurrent;
            var max = _progressMax;

            while (max > 1000 && designations.Count > 1)
            {
                current /= 1024;
                max /= 1024;
                designations.RemoveAt(0);
            }

            if(designations[0] == "" || designations[0] == "KiB" || designations[0] == "MiB")
                tsProgressText.Text = $@"{Math.Round(current):0} / {Math.Round(max):0} {designations[0]} - ";
            else
                tsProgressText.Text = $@"{current:0.00} / {max:0.00} {designations[0]} - ";
        }

        private void HideProgress()
        {
            tsProgress.Visible = false;
            tsProgressText.Text = "";
            Application.DoEvents();
        }

        public (bool, string[]) Pack(Ticket ticket, CNMT cnmt, string baseTitle)
        {
            try
            {
                try
                {
                    if (File.Exists(Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters())))
                        return (false, new [] {" - Already packed"} );
                    if (!ticket.Anonymize())
                        return (false, new[] { $" - {ticket.AnonymizeError}" });
                }
                catch
                {
                    //
                }


                var types = new List<CNMT.ncaTypes>
                {
                    CNMT.ncaTypes.Program,
                    CNMT.ncaTypes.LegalInformation,
                    CNMT.ncaTypes.Data,
                    CNMT.ncaTypes.HtmlDocument,
                    CNMT.ncaTypes.Control
                };

                var exitEntries = new List<CNMT.Entry>();
                exitEntries.AddRange(from type in types
                    from entry in cnmt.Entries
                    where entry.Type == type
                    where !File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    select entry);
                if (exitEntries.Any())
                {
                    return (false, new[]
                    {
                        " - Failed.",
                        $@"Failed to pack because the following NCAs are missing:{Environment.NewLine}{string.Join(Environment.NewLine, exitEntries.Select(x => x.ID.ToHexString() + ".nca"))}{Environment.NewLine}{Environment.NewLine}"
                    });
                }

                types.Remove(CNMT.ncaTypes.Control);
                types.Add(CNMT.ncaTypes.DeltaFragment);

                var startingEntries = new List<CNMT.Entry>();
                var controlEntries = new List<CNMT.Entry>();
                startingEntries.AddRange(from type in types
                    from entry in cnmt.Entries
                    where entry.Type == type
                    where File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    select entry);
                controlEntries.AddRange(from entry in cnmt.Entries
                    where entry.Type == CNMT.ncaTypes.Control
                    where File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    select entry);

                var packFiles = new List<string>
                {
                    ticket.RightsID.ToHexString() + ".cert",
                    ticket.RightsID.ToHexString() + ".tik",
                    cnmt.CnmtFileName,
                    cnmt.XmlFileName
                };

                packFiles.InsertRange(2, from entry in startingEntries select entry.ID.ToHexString() + ".nca");
                packFiles.AddRange(from entry in controlEntries select entry.ID.ToHexString() + ".nca");

                var fileSizes = new List<ulong>
                {
                    0x700,
                    0x2C0,
                    (ulong) cnmt.CnmtFileData.Length,
                    (ulong) cnmt.XmlString.Length
                };

                fileSizes.InsertRange(2, from entry in startingEntries select entry.Size);
                fileSizes.AddRange(from entry in controlEntries select entry.Size);

                var nspFileName = Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters());
                using (var nspFile = new FileStream(nspFileName,
                    FileMode.Create))
                {
                    using (var sw = new BinaryWriter(nspFile))
                    {
                        var stringTable = String.Join("\0", packFiles);
                        var headerSize = 0x10 + (packFiles.Count * 0x18) + stringTable.Length;
                        var remainder = 0x10 - (headerSize % 0x10);

                        var stringTableOffsets = new List<uint>();
                        ulong offset = 0;
                        foreach (var f in packFiles)
                        {
                            stringTableOffsets.Add((uint) offset);
                            offset += (ulong) (f.Length + 1);
                        }

                        var fileOffsets = new List<ulong>();
                        offset = 0;
                        foreach (var f in fileSizes)
                        {
                            fileOffsets.Add(offset);
                            offset += f;
                        }

                        InitializeProgress(offset);

                        sw.Write(new char[] {'P', 'F', 'S', '0'});
                        sw.Write(BitConverter.GetBytes(packFiles.Count));
                        sw.Write(BitConverter.GetBytes(stringTable.Length + remainder));
                        sw.Write(new byte[4]);

                        for (var i = 0; i < packFiles.Count; i++)
                        {
                            sw.Write(BitConverter.GetBytes(fileOffsets[i]));
                            sw.Write(BitConverter.GetBytes(fileSizes[i]));
                            sw.Write(BitConverter.GetBytes(stringTableOffsets[i]));
                            sw.Write(new byte[4]);
                        }

                        sw.Write(Encoding.ASCII.GetBytes(stringTable));
                        sw.Write(new byte[remainder]);


                        if (cnmt.Type == CNMT.packTypes.Patch)
                        {
                            sw.Write(Ticket.XS20);
                            sw.Write(Ticket.CA3);
                        }
                        else
                        {
                            sw.Write(Ticket.CA3);
                            sw.Write(Ticket.XS20);
                        }

                        sw.Write(ticket.Data.Take(0x2C0).ToArray());

                        Application.DoEvents();

                        foreach (var entry in startingEntries)
                        {
                            WriteNCAtoNSP(nspFile, sw, entry);
                        }

                        sw.Write(cnmt.CnmtFileData);
                        sw.Write(cnmt.XmlString);

                        foreach (var entry in controlEntries)
                        {
                            WriteNCAtoNSP(nspFile, sw, entry);
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                try
                {
                    if (File.Exists(Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters())))
                        File.Delete(Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters()));
                }
                catch
                { 
                    //
                }
                return (false, new [] { " - Failed",
                    $@"Failed to Pack ""{baseTitle}",
                    $@""" due to an exception:{Environment.NewLine}{ex.Message}{Environment.NewLine}{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}" });
            }

            return (true, new [] { " - Completed" });
        }

        private void WriteNCAtoNSP(FileStream nspFile, BinaryWriter sw, CNMT.Entry entry)
        {
            var hash = SHA256.Create();
            using (var ncaFile =
                new FileStream(
                    Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"),
                    FileMode.Open))
            {
                using (var sr = new BinaryReader(ncaFile))
                {
                    byte[] bytes;
                    do
                    {
                        bytes = sr.ReadBytes(0x100000);
                        if (bytes.Length <= 0) continue;

                        sw.Write(bytes);
                        SetProgress((ulong)nspFile.Length);
                        //UpdateProgress((ulong)bytes.Length);
                        hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                    } while (bytes.Length > 0);

                    hash.TransformFinalBlock(bytes, 0, bytes.Length);
                }

                if (!hash.Hash.ToArray().ToHexString().Equals(entry.Hash.ToHexString()))
                    throw new Exception($@"{entry.ID.ToHexString()}.nca is corrupted.");
            }
        }

        private void btnParseNCA_Click(object sender, EventArgs e)
        {
            if (!CheckKeys()) return;
            UpdateStatus($@"Parsing Decrypted NCA files");

            var ncadir = Path.Combine("tools", "nca");
            if (!Directory.Exists(ncadir))
                Directory.CreateDirectory(ncadir);

            if (!Directory.Exists(Configuration.Data.Decryptionpath))
                Directory.CreateDirectory(Configuration.Data.Decryptionpath);

            var p = new Process
            {
                StartInfo =
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    FileName = Path.Combine("Tools", "hactool.exe"),
                    CreateNoWindow = true
                }
            };

            var ncaFiles = Configuration.GetDecryptedNCAFiles;
            InitializeProgress((ulong)ncaFiles.Length);
            ClearGameImageLists();

            var controls = new List<CNMT>();
            var metas = new List<CNMT>();

            for (var j = 0; j < ncaFiles.Length; j++)
            {
                var ncafile = ncaFiles[j];
                SetProgress((ulong)j + 1);
                var filelen = new FileInfo(ncafile).Length;
                if (filelen > 0x8000)
                    continue;

                p.StartInfo.Arguments = $@"""{ncafile}""";
                StartProcess(p);

                var match1 = Regex.Match(_message, "Content Type: *(.*)\n");
                var match2 = Regex.Match(_message, "Title ID: *(.*)\n");
                if (!match1.Success || !match2.Success || !match1.Groups[1].Value.Trim().Equals("Meta")) continue;
                if (_error.Contains("Error: section 0 is corrupted!"))
                {
                    UpdateStatus($"Unable to Extract Title Meta Data from {Path.GetFileName(ncafile)}");
                    continue;
                }

                // = ncafile;
                p.StartInfo.Arguments =
                    $@"--header={Path.Combine(ncadir, "Header.bin")} --section0dir={
                            Path.Combine(ncadir, "section0")
                        } ""{ncafile}""";
                StartProcess(p);

                var header = File.ReadAllBytes(Path.Combine(ncadir, "Header.bin"));
                var files = Directory.GetFiles(Path.Combine(ncadir, "section0"));
                var section0 = File.ReadAllBytes(files[0]);
                var cnmt = new CNMT(header, section0, ncafile);

                if (!_cnmtFiles.TryGetValue(match2.Groups[1].Value.Trim(), out var oldcnmt) || oldcnmt.Version < cnmt.Version)
                    _cnmtFiles[match2.Groups[1].Value.Trim()] = cnmt;
                else
                    continue;

                File.Delete(Path.Combine(ncadir, "Header.bin"));
                foreach (var f in files)
                    File.Delete(f);
                Directory.Delete(Path.Combine(ncadir, "section0"));

                
                var controldata = cnmt.Entries.FirstOrDefault(x => x.Type == CNMT.ncaTypes.Control);
                if (controldata == null) metas.Add(cnmt);
                else controls.Add(cnmt);
            }

            tvGames.Visible = false;
            InitializeProgress((ulong) _cnmtFiles.Count);
            ulong count = 0;

            controls = controls.OrderByDescending(x => (x.TitleID[6] & 0x1F) == 0x08 && x.TitleID[7] == 0x00).ToList();

            foreach (var cnmt in controls)
            {
                var controldata = cnmt.Entries.First(x => x.Type == CNMT.ncaTypes.Control);
                p.StartInfo.Arguments = $@"""{Path.Combine(Configuration.Data.Decryptionpath, controldata.ID.ToHexString() + ".nca")}"" --romfsdir={ncadir}";
                ReadControlInfo(ncadir, cnmt.TitleID.ToHexString(), p);
                SetProgress(++count);
            }

            foreach (var cnmt in metas)
            {
                ReadControlInfo(ncadir, cnmt.TitleID.ToHexString(), null);
                SetProgress(++count);
            }

            tvGames.Sort();
            tvGames.Visible = true;

            HideProgress();
            UpdateStatus($@"NCA Parsing completed - {_cnmtFiles.Count} Titles present");
        }

        private void btnLanguageUp_Click(object sender, EventArgs e)
        {
            var node = tvLanguage.SelectedNode;
            if (node == null) return;
            node.MoveUp();
            tvLanguage.SelectedNode = node;

        }

        private void btnLanguageDown_Click(object sender, EventArgs e)
        {
            var node = tvLanguage.SelectedNode;
            if (node == null) return;
            node.MoveDown();
            tvLanguage.SelectedNode = node;
        }

        private void txtRSAKEK_TextChanged(object sender, EventArgs e)
        {
            if (Configuration.VerifyETicketRSAKEK()) return;
            Configuration.Data.ETicketRSAKEK = txtRSAKEK.Text;
            if (!Configuration.VerifyETicketRSAKEK()) return;
            UpdateStatus("ETicket RSA KEK is correct.");
        }

        private void btnSmallerIcon_Click(object sender, EventArgs e)
        {
            SetGameImages(Configuration.Data.GameIconSize, false);
        }

        private void btnLargerIcons_Click(object sender, EventArgs e)
        {
            SetGameImages(Configuration.Data.GameIconSize, true);
        }

        private void SetGameImages(GameIconSize size, bool? larger = null)
        {
            ImageList imagelist;
            switch (size)
            {
                case GameIconSize.ExtraSmall when larger.HasValue && !larger.Value:
                case GameIconSize.Small when larger.HasValue && !larger.Value:
                case GameIconSize.ExtraSmall when !larger.HasValue:
                    imagelist = ilGamesExtraSmall;
                    size = GameIconSize.ExtraSmall;
                    break;

                    
                case GameIconSize.Medium when larger.HasValue && !larger.Value:
                case GameIconSize.ExtraSmall when larger.HasValue && larger.Value:
                case GameIconSize.Small when !larger.HasValue:
                defaultIconSize:
                    imagelist = ilGamesSmall;
                    size = GameIconSize.Small;
                    break;

                case GameIconSize.Large when larger.HasValue && !larger.Value:
                case GameIconSize.Small when larger.HasValue && larger.Value:
                case GameIconSize.Medium when !larger.HasValue:
                    imagelist = ilGames;
                    size = GameIconSize.Medium;
                    break;

                case GameIconSize.ExtraLarge when larger.HasValue && !larger.Value:
                case GameIconSize.Medium when larger.HasValue && larger.Value:
                case GameIconSize.Large when !larger.HasValue:
                    imagelist = ilGamesLarge;
                    size = GameIconSize.Large;
                    break;

                case GameIconSize.Large when larger.HasValue && larger.Value:
                case GameIconSize.ExtraLarge when larger.HasValue && larger.Value:
                case GameIconSize.ExtraLarge when !larger.HasValue:
                    imagelist = ilGamesExtraLarge;
                    size = GameIconSize.ExtraLarge;
                    break;
                default:
                    if(larger.HasValue)
                        return;
                    goto defaultIconSize;
            }
            Configuration.Data.GameIconSize = size;

            tvGames.Visible = false;
            tvGames.ImageList = imagelist;
            tvGames.Indent = (int)size + 3;
            btnSmallerIcon.Text = $@"{Math.Max((int)size / 2, 16)}x{Math.Max((int)size / 2, 16)} Icons";
            btnLargerIcons.Text = $@"{Math.Min((int)size * 2, 256)}x{Math.Min((int)size * 2, 256)} Icons";
            tvGames.Visible = true;
        }

        private void btnPackSelectedNSP_Click(object sender, EventArgs e)
        {
            if (_tickets.Count == 0)
            {
                button1_Click(null, null);
                if (_tickets.Count == 0)
                {
                    UpdateStatus("No tickets present. Cannot Pack NSPs");
                    return;
                }
            }

            if (tvGames.SelectedNode == null) return;
            if (tvGames.SelectedNode.Parent == null)    //Root node selected. Pack all items within the root node.
            {
                for (var i = 0; i < tvGames.SelectedNode.Nodes.Count; i++)
                {
                    if (tvGames.SelectedNode.Nodes[i].Tag is string titleID)
                        PackNSP(titleID);
                }
            }
            else    //Child node selected. Pack just that item only.
            {
                if (tvGames.SelectedNode.Tag is string titleID)
                    PackNSP(titleID);
                else
                    UpdateStatus("Cannot pack item");
            }
            HideProgress();
        }

        private void Form1_SizeChanged(object sender, EventArgs e)
        {
            Configuration.Data.MainFormSize = Size;
        }

        private void listStatus_SelectedIndexChanged(object sender, EventArgs e)
        {
            txtMessage.Text = _messageBox.TryGetValue(listStatus.SelectedIndex, out var message) && message != null
                ? message
                : string.Empty;

            txtMessage.Visible = txtMessage.Text != string.Empty;
            pbGameIcon.Visible = txtMessage.Text == string.Empty;
        }

        private void btnDeleteFromSD_Click(object sender, EventArgs e)
        {
            if (tvGames.SelectedNode == null) return;
            var result =
                MessageBox.Show(
                    $@"Are you sure you wish to delete {Environment.NewLine}""{(tvGames.SelectedNode.Parent != null ? $"{tvGames.SelectedNode.Parent.Text} - " : "")}{tvGames.SelectedNode.Text}""{Environment.NewLine}from your SD card? This Action cannot be undone.",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result == DialogResult.No) return;

            if (tvGames.SelectedNode.Parent == null)    //Root node selected. Pack all items within the root node.
            {
                for (var i = 0; i < tvGames.SelectedNode.Nodes.Count; i++)
                {
                    if (tvGames.SelectedNode.Nodes[i].Tag is string titleID && _cnmtFiles.TryGetValue(titleID, out var cnmt))
                        DeleteSDFile(cnmt, tvGames.SelectedNode.Nodes[i]);
                }

                if(cbDeleteLocal.Checked)
                    tvGames.Nodes.Remove(tvGames.SelectedNode);
            }
            else    //Child node selected. Pack just that item only.
            {
                if (tvGames.SelectedNode.Tag is string titleID && _cnmtFiles.TryGetValue(titleID, out var cnmt))
                    DeleteSDFile(cnmt, tvGames.SelectedNode);
                var parent = tvGames.SelectedNode.Parent;

                if (!cbDeleteLocal.Checked) return;
                parent.Nodes.Remove(tvGames.SelectedNode);
                if (parent.Nodes.Count == 0)
                    tvGames.Nodes.Remove(parent);
            }
        }

        private void DeleteSDFile(CNMT cnmt, TreeNode childNode)
        {
            var sdcard = Configuration.GetSDDirectories;
            var deleteSuccess = true;
            UpdateStatus($@"Deleting {childNode.Parent.Text} - {childNode.Text}");
            string ncafile;
            foreach (var entry in cnmt.Entries)
            {
                ncafile = sdcard.FirstOrDefault(x => x.Contains(entry.ID.ToHexString()));
                if (ncafile != null)
                    deleteSuccess &= DeleteSDNCA(ncafile);
                else
                    deleteSuccess &= DeleteLocalNCA(entry.ID.ToHexString() + ".nca");
            }

            ncafile = sdcard.FirstOrDefault(x => x.Contains(cnmt.CnmtFileName.Replace(".cnmt.nca","")));
            if (ncafile != null)
                deleteSuccess &= DeleteSDNCA(ncafile);
            else
                deleteSuccess &= DeleteLocalNCA(cnmt.CnmtFileName.Replace(".cnmt.nca", ".nca"));

            _cnmtFiles.Remove(cnmt.TitleID.ToHexString());

            AppendStatus(deleteSuccess
                ? " - Completed"
                : " - Failed, Check message box to see what files could not be deleted");
        }

        private bool DeleteSDNCA(string ncafile)
        {
            bool result = true;
            try
            {
                foreach (var file in Directory.GetFiles(ncafile))
                    File.Delete(file);
                Directory.Delete(ncafile);
                try
                {
                    var ncafileroot = Path.GetDirectoryName(ncafile);
                    if (Directory.GetDirectories(ncafileroot).Length == 0)
                        Directory.Delete(ncafileroot);
                }
                catch (Exception ex)
                {
                    AppendStatus(string.Empty,
                        $@"[WARNING] - Failed to delete directory {Path.GetDirectoryName(ncafile)}:{Environment.NewLine}",
                        $@"{ex.Message}{Environment.NewLine}Stack Trace:{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                }

                result &= DeleteLocalNCA(Path.GetFileName(ncafile));
            }
            catch (Exception ex)
            {
                AppendStatus(string.Empty,
                    $@"[FATAL] - Failed to delete SD Card copy of {ncafile} due to an exception:{Environment.NewLine}",
                    $@"{ex.Message}{Environment.NewLine}Stack Trace:{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                return false;
            }

            return result;
        }

        private bool DeleteLocalNCA(string ncafilename)
        {
            if (!cbDeleteLocal.Checked)
                return true;

            try
            {
                if (File.Exists(Path.Combine(Configuration.Data.Decryptionpath, ncafilename)))
                    File.Delete(Path.Combine(Configuration.Data.Decryptionpath, ncafilename));
            }
            catch (Exception ex)
            {
                AppendStatus(string.Empty,
                    $@"[FATAL] - Failed to delete local copy of {ncafilename} due to an exception:{Environment.NewLine}",
                    $@"{ex.Message}{Environment.NewLine}Stack Trace:{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                return false;
            }

            return true;
        }

        private void tcTabs_Selected(object sender, TabControlEventArgs e)
        {
            
        }

        private void tvGames_NodeMouseClick(object sender, TreeNodeMouseClickEventArgs e)
        {

        }

        private void tvGames_AfterSelect(object sender, TreeViewEventArgs e)
        {
            var index = tvGames.SelectedNode?.ImageIndex;
            pbGameIcon.Image = !index.HasValue 
                ? new Bitmap(1, 1) 
                : ilGamesExtraLarge.Images[index.Value];
        }

        private void tvGames_NodeMouseDoubleClick(object sender, TreeNodeMouseClickEventArgs e)
        {
            btnPackSelectedNSP_Click(null, null);
        }

        private static bool CheckNetFramework()
        {
            using (var ndpKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\"))
            {
                if (ndpKey == null) return false;
                var releaseKey = Convert.ToInt32(ndpKey.GetValue("Release"));
                return releaseKey >= 461308;
            }
        }
    }
}
