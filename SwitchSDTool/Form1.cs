using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using CTR;
using SwitchSDTool.Properties;
using LibHac;
using LibHac.Nand;
using LibHac.IO.Save;
using LibHac.Npdm;
using LibHac.IO;
using Application = System.Windows.Forms.Application;

#pragma warning disable IDE1006 // Naming Styles
namespace SwitchSDTool
{
    public partial class Form1 : Form
    {
        private byte[] _sdKey;

        private readonly Dictionary<string, Ticket> _tickets = new Dictionary<string, Ticket>();
        private readonly Dictionary<string, string> _commonTickets = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _personalTickets = new Dictionary<string, string>();
        private readonly Dictionary<string, Cnmt> _cnmtFiles = new Dictionary<string, Cnmt>();
        private readonly Dictionary<string, CnmtContentEntry> _cnmtNcaFiles = new Dictionary<string, CnmtContentEntry>();
        private readonly Dictionary<string, string> _titleNames = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _databaseTitleNames = new Dictionary<string, string>();
        private readonly Dictionary<int, ControlNACP> _controlNACP = new Dictionary<int, ControlNACP>();
        private readonly Dictionary<string, DateTime> _titleReleaseDate = new Dictionary<string, DateTime>();

        private IFileSystem _sdFileSystem;
        private IFileSystem _systemNandFileSystem;

        private Keyset _keyset = new Keyset();

        private int _ticketsNotInDB;
        private readonly HashSet<string> _personalTitleIDs = new HashSet<string>();

        private readonly string _fixedKeys = Path.Combine("Tools", "FixedKeys.txt");
        private readonly string _profileKeys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".switch", "prod.keys");

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

            _sdKey = null;
            btnFindSDKey.Enabled = true;

            string[] split = fbdSDCard.SelectedPath.PathSplit();
            var rootFolder = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar, "Nintendo", "Contents");
            var baseFolder = Path.Combine(fbdSDCard.SelectedPath, "Nintendo", "Contents");
            var nandRootFolder = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar, "Contents");
            var nandBaseFolder = Path.Combine(fbdSDCard.SelectedPath, "Contents");
            if (Directory.Exists(nandRootFolder))
            {
                Configuration.Data.SDpath = nandRootFolder;
            }
            else if (Directory.Exists(nandBaseFolder))
            {
                Configuration.Data.SDpath = nandBaseFolder;
            }
            else if (Directory.Exists(rootFolder))
            {
                Configuration.Data.SDpath = rootFolder;
            }
            else if (Directory.Exists(baseFolder))
            {
                Configuration.Data.SDpath = baseFolder;
            }
            else
            {
                Configuration.Data.SDpath = fbdSDCard.SelectedPath;
            }
            _sdFileSystem = new FileSystem(Configuration.Data.SDpath);
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
            if (!_sdFileSystem.FileExists("private"))
            {
                _sdKey = null;
                UpdateStatus(@"User NAND Partition mounted");
                btnFindSDKey.Enabled = false;
                return;
            }

            var sdkeyfile = Path.Combine("save", "8000000000000043");
            if (!_systemNandFileSystem.FileExists(sdkeyfile))
            {
                UpdateStatus("Nintendo Switch System NAND Drive not present");
                return;
            }

            try
            {
                byte[] privateBytes;
                byte[] sdBytes;

                using (var sr = new BinaryReader(_sdFileSystem.OpenFile("private", FileMode.Open, FileAccess.Read)))
                    privateBytes = sr.ReadBytes(16);

                var sdKeyData = _systemNandFileSystem.OpenFile(sdkeyfile, FileMode.Open, FileAccess.Read);
                var sdKeySave = new SaveData(_keyset, new StreamStorage(sdKeyData, true), IntegrityCheckLevel.ErrorOnInvalid, true);
                using (var sr = new BinaryReader(sdKeySave.OpenFile("/private").AsStream()))
                    //using (var sr = new BinaryReader(sdKeyData))
                    sdBytes = sr.ReadBytes((int) sr.BaseStream.Length);

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

            cbRSAKey.SelectedIndex = -1;

            btnFindSDKey.Enabled = true;
            _sdKey = null;

            string[] split = fbdSDCard.SelectedPath.PathSplit();

            if (new FileSystem(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar).DirectoryExists("save"))
                Configuration.Data.SystemPath = split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar;
            else
                Configuration.Data.SystemPath = fbdSDCard.SelectedPath;
        }

        private void btnLoadRSAKEK_Click(object sender, EventArgs e)
        {
            CheckKeys();
            byte[] rsakek = Configuration.Data.ETicketRSAKEK.ToByte();

            if (!File.Exists("PRODINFO.BIN"))
            {
                UpdateStatus(@"PRODINFO.bin missing.");
                return;
            }
            
            using (var prodinfo = File.OpenRead("PRODINFO.BIN"))
            {
                if (prodinfo.Length < 0x8000)
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly");
                    return;
                }

                byte[] magic = new byte[4];
                byte[] hash = new byte[32];
                byte[] ctr = new byte[16];

                byte[] rsaD = new byte[0x101];
                byte[] rsaN = new byte[0x101];
                byte[] rsaE = new byte[4];

                prodinfo.Read(magic, 0, 4);
                if (!magic.Compare(Encoding.ASCII.GetBytes("CAL0")))
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly - Invalid CAL0 magic!");
                    return;
                }


                prodinfo.Seek(4, SeekOrigin.Current);
                prodinfo.Read(magic, 0, 4);
                var size = BitConverter.ToInt32(magic, 0);

                byte[] data = new byte[size];

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
                Array.Copy(data, 0x130, rsaD, 0, rsaD.Length - 1);
                Array.Copy(data, 0x30, rsaN, 0, rsaN.Length - 1);
                Array.Copy(data, 0x2C, rsaE, 0, rsaE.Length);

                Ticket.UpdateRSAKey(new BigInteger(rsaD), new BigInteger(rsaN), new BigInteger(rsaE));
                if (!Ticket.ValidRSAKey)
                {
                    UpdateStatus(@"PRODINFO.bin corrupted or not decrypted correctly - RSA Key failed to decrypt correctly.");
                    return;
                }

                data = new byte[0x18];
                prodinfo.Seek(0x250, SeekOrigin.Begin);
                prodinfo.Read(data, 0, 0x18);
                var serialNumber = Encoding.UTF8.GetString(data);
                var index = serialNumber.IndexOf("\0", StringComparison.Ordinal);
                if (index > 0) serialNumber = serialNumber.Substring(0, index);

                if (!cbRSAKey.Items.Contains(serialNumber))
                {
                    cbRSAKey.Items.Add(serialNumber);
                    Configuration.Data.RSAKeys[serialNumber] = $"{rsaN.ToHexString()},{rsaD.ToHexString()},{rsaE.ToHexString()}";
                }

                cbRSAKey.SelectedItem = serialNumber;

                btnLoadRSAKEK.Enabled = false;
                UpdateStatus("RSA Key extracted successfully from PRODINFO.bin");

                //RSA_KEK confirmed to be likely correct because it successfully decrypted the RSA Key contained within PRODINFO.bin.
                txtRSAKEK.Text = @"-------- eticket_rsa_kek redacted --------";
                txtRSAKEK.Enabled = false;
                Application.DoEvents();
            }
        }

        private readonly Dictionary<int, string> _messageBox = new Dictionary<int, string>();

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
#if DEBUG
            button2.Visible = true;
            button3.Visible = true;
#else
            button2.Visible = false;
            button3.Visible = false;
#endif

            Directory.CreateDirectory("Tools");
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

            string[] generatedKeys = ValidKeySizes.Keys.Where(x => x.EndsWith("_")).ToArray();
            foreach (var key in generatedKeys)
            {
                var keysize = ValidKeySizes[key];
                ValidKeySizes.Remove(key);
                for (var i = 0; i < 32; i++)
                {
                    ValidKeySizes[key + $"{i:00}"] = keysize;
                }
            }

            List<string> keysToRemove = new List<string>();
            foreach (var serial in Configuration.Data.RSAKeys.Keys)
            {
                string[] split = Configuration.Data.RSAKeys[serial].Split(',').Where(x => x.Trim().ToByte().Length != 0).Select(x => x.Trim()).ToArray();
                if (split.Length != 3)
                {
                    keysToRemove.Add(serial);
                    continue;
                }

                Ticket.UpdateRSAKey(new BigInteger(split[1].ToByte()), new BigInteger(split[0].ToByte()), new BigInteger(split[2].ToByte()));
                if (Ticket.ValidRSAKey)
                    cbRSAKey.Items.Add(serial);
                else
                    keysToRemove.Add(serial);
            }
            cbRSAKey.SelectedIndex = 0;

            foreach (var serial in keysToRemove)
                Configuration.Data.RSAKeys.Remove(serial);

            txtTitleKeyURL.Text = Configuration.Data.TitleKeyDataBaseURL ?? string.Empty;

            _sdFileSystem = new FileSystem(Configuration.Data.SDpath ?? "");
            _systemNandFileSystem = new FileSystem(Configuration.Data.SystemPath ?? "");
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (!Ticket.ValidRSAKey)
            {
                btnLoadRSAKEK_Click(null, null);
                if (!Ticket.ValidRSAKey && cbRSAKey.Items.Count < 2)
                {
                    UpdateStatus("Cannot Dump tickets without RSA KEK");
                    return;
                }
            }

            UpdateStatus("Dumping Tickets");
            var count = _tickets.Count;

            if(_systemNandFileSystem.FileExists(Path.Combine("save", "80000000000000e1")))
                using (var stream = _systemNandFileSystem.OpenFile(Path.Combine("save", "80000000000000e1"), FileMode.Open, FileAccess.Read))
                {
                    var commonTickets = new SaveData(_keyset, new StreamStorage(stream, true), IntegrityCheckLevel.ErrorOnInvalid, true );
                    var ticketList = new BinaryReader(commonTickets.OpenFile("/ticket_list.bin").AsStream());
                    var tickets = new BinaryReader(commonTickets.OpenFile("/ticket.bin").AsStream());
                    var titleID = ticketList.ReadUInt64();
                    while(titleID != ulong.MaxValue)
                    {
                        ticketList.BaseStream.Position += 0x18;
                        var ticket = new Ticket(tickets.ReadBytes(0x400));
                        _tickets[ticket.TitleID.ToHexString()] = ticket;
                        titleID = ticketList.ReadUInt64();
                        _commonTickets[ticket.RightsID.ToHexString()] = ticket.TitleKey.ToHexString();
                    }
                }


            if (_systemNandFileSystem.FileExists(Path.Combine("save", "80000000000000e2")))
                using (var stream = _systemNandFileSystem.OpenFile(Path.Combine("save", "80000000000000e2"), FileMode.Open, FileAccess.Read))
                {
                    var personalTickets = new SaveData(_keyset, new StreamStorage(stream, true), IntegrityCheckLevel.ErrorOnInvalid, true);
                    var ticketList = new BinaryReader(personalTickets.OpenFile("/ticket_list.bin").AsStream());
                    var tickets = new BinaryReader(personalTickets.OpenFile("/ticket.bin").AsStream());

                    var firstTicket = false;
                    var titleID = ticketList.ReadUInt64();
                    var personalcount = 0UL;
                    while (titleID != ulong.MaxValue)
                    {
                        ticketList.BaseStream.Position += 0x18;
                        titleID = ticketList.ReadUInt64();
                        personalcount++;
                    }

                    ticketList.BaseStream.Position = 0;
                    ticketList = new BinaryReader(new MemoryStream(ticketList.ReadBytes(0x20 * (int)(personalcount + 1))));
                    tickets = new BinaryReader(new MemoryStream(tickets.ReadBytes(0x400 * (int) personalcount)));

                    
                    titleID = ticketList.ReadUInt64();
                    InitializeProgress(personalcount);

                    while (titleID != ulong.MaxValue)
                    {
                        UpdateProgress(1);
                        ticketList.BaseStream.Position += 0x18;
                        var ticket = new Ticket(tickets.ReadBytes(0x400));

                        firstTicket |= ticket.Anonymize();
                        if (!firstTicket)
                        {
                            for (var j = 1; j < cbRSAKey.Items.Count && !firstTicket; j++)
                            {
                                cbRSAKey.SelectedIndex = j;
                                firstTicket |= ticket.Anonymize();
                            }

                            if (!firstTicket)
                            {
                                UpdateStatus($"Done. {_tickets.Count} Tickets dumped");
                                UpdateStatus($"Cannot extract personal tickets - {ticket.AnonymizeError}");
                                btnLoadRSAKEK.Enabled = true;
                                return;
                            }
                        }

                        if (_personalTitleIDs.Add(ticket.TitleID.ToHexString())) _ticketsNotInDB++;

                        _tickets[ticket.TitleID.ToHexString()] = ticket;
                        _personalTickets[ticket.RightsID.ToHexString()] = ticket.TitleKey.ToHexString();
                        titleID = ticketList.ReadUInt64();
                    }

                    InitializeProgress(personalcount);
                    Parallel.ForEach(_tickets.Values, (t) =>
                    {
                        t.Anonymize();
                        UpdateProgress(1);
                    });
                }

            if (_systemNandFileSystem.FileExists(Path.Combine("save", "80000000000000e3")))
                using (var stream = _systemNandFileSystem.OpenFile(Path.Combine("save", "80000000000000e3"), FileMode.Open, FileAccess.Read))
                {
                    var ticketReleaseDates = new SaveData(_keyset, new StreamStorage(stream, true), IntegrityCheckLevel.ErrorOnInvalid, true);
                    var ticketList = new BinaryReader(ticketReleaseDates.OpenFile("/ticket_list.bin").AsStream());
                    var titleID = ticketList.ReadUInt64();
                    while (titleID != ulong.MaxValue)
                    {
                        ticketList.BaseStream.Position += 0x18;

                        var utctime = ticketList.ReadUInt64();
                        _titleReleaseDate[$"{titleID:x16}".ToByte().Reverse().ToArray().ToHexString()] = 
                            new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(utctime).ToLocalTime();

                        ticketList.BaseStream.Position += 0xD8;
                        titleID = ticketList.ReadUInt64();
                    }
                }

            HideProgress();
            var dbResult = _databaseTitleNames.Count > 0 ? $"{_ticketsNotInDB} Tickets not in database. " : "";
            UpdateStatus($"Done. {_tickets.Count - count} new tickets dumped. {dbResult}{_tickets.Count} Tickets total.");
        }

        private static readonly Dictionary<string, int> ValidKeySizes = new Dictionary<string, int>
        {
            {"aes_kek_generation_source", 16},
            {"aes_key_generation_source", 16},
            {"key_area_key_application_source", 16},
            {"key_area_key_ocean_source", 16},
            {"key_area_key_system_source", 16},
            {"titlekek_source", 16},
            {"header_kek_source", 16},
            {"header_key_source", 32},
            {"header_key", 32},
            {"package2_key_source", 16},
            {"sd_card_kek_source", 16},
            {"sd_card_nca_key_source", 32},
            {"sd_card_save_key_source", 32},
            {"master_key_source", 16},
            {"keyblob_mac_key_source", 16},
            {"secure_boot_key", 16},
            {"tsec_key", 16},
            {"beta_nca0_exponent", 256},

            {"keyblob_key_source_", 16},
            {"keyblob_key_", 16},
            {"keyblob_mac_key_", 16},
            {"encrypted_keyblob_", 176},
            {"keyblob_", 144},
            {"master_key_", 16},
            {"package1_key_", 16},
            {"package2_key_", 16},
            {"titlekek_", 16},
            {"key_area_key_application_", 16},
            {"key_area_key_ocean_", 16},
            {"key_area_key_system_", 16},
            {"eticket_rsa_kek", 16 }
            
        };

        private (bool,string) KeysTxtHasRequiredKeys(string filename)
        {
            Dictionary<string, byte[]> keys = new Dictionary<string, byte[]>();
            using (var sr = new StreamReader(new FileStream(filename, FileMode.Open)))
            {
                var keyname = string.Empty;
                var keyvalue = string.Empty;
                while (!sr.EndOfStream)
                {
                    var line = sr.ReadLine();
                    if (line == null) continue;
                    string[] split = line.Split(new[] {",", "="}, StringSplitOptions.None).Select(x => x.ToLowerInvariant().Trim()).ToArray();
                    switch (split.Length)
                    {
                        case 1 when keyname == string.Empty:
                            continue;
                        case 1:
                            keyvalue += Regex.Replace(split[0], @"\s+", "");
                            break;
                        case 2:
                            keyname = split[0];
                            keyvalue = Regex.Replace(split[1], @"\s+", "");
                            break;
                        default:
                            continue;
                    }
                    if (keyvalue.Any(x => !"0123456789ABCDEFabcdef".Contains(x))) continue;

                    if(!ValidKeySizes.TryGetValue(keyname, out var keysize) || keyvalue.ToByte().Length == keysize)
                        keys[keyname] = keyvalue.ToByte();
                }
            }

            foreach (var keyName in ValidKeySizes.Keys)
            {
                var keyvalue = ValidKeySizes[keyName];
                if (keys.TryGetValue(keyName, out byte[] keyBytes) && keyBytes.Length != keyvalue)
                    keys.Remove(keyName);
            }

            //Code that verifies keys were equal to the required keys had to be redacted permanently.

            if (keys.TryGetValue("eticket_rsa_kek", out byte[] rsaKeyData))
                txtRSAKEK.Text = rsaKeyData.ToHexString();

            var keysText = string.Empty;
            foreach (KeyValuePair<string, byte[]> kvp in keys)
            {
                keysText += $@"{kvp.Key}={kvp.Value.ToHexString()}{Environment.NewLine}";
            }

            return (true,keysText);

        }

        private bool CheckKeys()
        {
            if (File.Exists(_fixedKeys))
            {
                var result = KeysTxtHasRequiredKeys(_fixedKeys);
                if (result.Item1 && !File.Exists("keys.txt"))
                {
                    _keyset = ExternalKeys.ReadKeyFile(_fixedKeys);
                    if (_sdKey != null) _keyset.SetSdSeed(_sdKey);
                    return true;
                }
            }

            if (File.Exists(_profileKeys))
            {
                var result = KeysTxtHasRequiredKeys(_profileKeys);
                if (!result.Item1) return false;
                string filename;
                try
                {
                    File.WriteAllText(_fixedKeys, result.Item2);
                    filename = _fixedKeys;
                }
                catch
                {
                    filename = _profileKeys;
                }

                _keyset = ExternalKeys.ReadKeyFile(filename);
                if (_sdKey != null) _keyset.SetSdSeed(_sdKey);
                return true;
            }

            if (File.Exists("keys.txt"))
            {
                var result = KeysTxtHasRequiredKeys("keys.txt");
                if (!result.Item1) return false;
                string filename;

                try
                {
                    File.WriteAllText(_fixedKeys, result.Item2);
                    filename = _fixedKeys;
                }
                catch
                {
                    filename = "keys.txt";
                }

                //Directory.CreateDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".switch"));
                //File.Copy("keys.txt", _profileKeys);
                _keyset = ExternalKeys.ReadKeyFile(filename);
                if (_sdKey != null) _keyset.SetSdSeed(_sdKey);
                return true;
            }

            UpdateStatus(@"Keys.txt missing.");
            return false;
        }

        public static string[] GetSDDirectories(IFileSystem fs)
        {
            try
            {
                return fs.GetFileSystemEntries("", "*.nca", SearchOption.AllDirectories);
            }
            catch
            {
                return new string[0];
            }
        }

        private void btnDecryptNCA_Click(object sender, EventArgs e)
        {
            if (!CheckKeys())
            {
                UpdateStatus("Cannot proceed without valid keys.");
                return;
            }
            if (_sdKey == null)
            {
                btnFindSDKey_Click(null, null);
                CheckKeys();
                
                if (_sdKey == null)
                    UpdateStatus("Cannot Decrypt NCAs from SD card without a valid SD Key. Assuming USER Nand with decrypted files is mounted instead.");
            }

            if (!Directory.Exists(Configuration.Data.Decryptionpath))
                Directory.CreateDirectory(Configuration.Data.Decryptionpath);

            string[] ncaFiles = GetSDDirectories(_sdFileSystem);
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
                var hash = SHA256.Create();

                try
                {
                    using (var naxfile = OpenSplitNcaStream(nca))
                    {
                        if (naxfile == null) continue;
                        using (var ncaData = new Nca(_keyset, naxfile, true))
                        {
                            if (ncaData.Header.ContentType != ContentType.Control &&
                                ncaData.Header.ContentType != ContentType.Meta)
                                continue;
                        }

                        UpdateStatus($@"Processing {Path.GetFileName(nca)} - Decrypting");
                        InitializeProgress((ulong) naxfile.Length);

                        naxfile.AsStream(true).Position = 0;

                        using (var sw = new BinaryWriter(new FileStream(ncafile, FileMode.Create)))
                        {
                            using (var sr = new BinaryReader(naxfile.AsStream(true)))
                            {
                                byte[] bytes;
                                do
                                {
                                    bytes = sr.ReadBytes(0x100000);
                                    if (bytes.Length <= 0) continue;

                                    sw.Write(bytes);
                                    UpdateProgress((ulong) bytes.LongLength);
                                    hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                                } while (bytes.Length > 0);
                            }

                            hash.TransformFinalBlock(new byte[0], 0, 0);
                        }

                        var result = nca.ToLowerInvariant()
                            .Contains(hash.Hash.Take(16).ToArray().ToHexString().ToLowerInvariant());

                        if (!result)
                        {
                            AppendStatus(", Verification Failed: File is corrupt.");

                            if (File.Exists(ncafile))
                                File.Delete(ncafile);

                            continue;
                        }

                        AppendStatus(", Done.");
                    }
                }
                catch (Exception ex)
                {
                    UpdateStatus($"Failed to Decrypt NCA file \"{Path.GetFileName(Path.GetDirectoryName(nca))}/{Path.GetFileName(nca)}\" due to an exception:", 
                        $"Exception: {ex.Message}{Environment.NewLine}", 
                        $"Stack Trace:{ex.StackTrace}");
                }

            }

            HideProgress();
            UpdateStatus(@"NCA Decryption completed.");
        }


        private Storage OpenSplitNcaStream(string path)
        {
            List<string> files = new List<string>();
            IList<IStorage> streams = new List<IStorage>();

            if (_sdFileSystem.DirectoryExists(path))
            {
                while (true)
                {
                    var partName = Path.Combine(path, $"{files.Count:D2}");
                    if (!_sdFileSystem.FileExists(partName)) break;

                    files.Add(partName);
                }
            }
            else if (_sdFileSystem.FileExists(path))
            {
                files.Add(path);
            }
            else
            {
                throw new FileNotFoundException("Could not find the input file or directory");
            }

            foreach (var file in files)
            {
                streams.Add(new StreamStorage(_sdFileSystem.OpenFile(file, FileMode.Open, FileAccess.Read), true));
            }

            IStorage stream;
            switch (streams.Count)
            {
                case 0:
                    return null;
                case 1:
                    stream = streams[0];
                    break;
                default:
                    stream = new ConcatenationStorage(streams, true);
                    //stream = new CombinationStream(streams);
                    break;
            }

            bool isNax0;
            var basestream = stream.AsStream();
            using (var sr = new BinaryReader(basestream, Encoding.Default, true))
            {
                basestream.Position = 0x20;
                isNax0 = sr.ReadUInt32() == 0x3058414E;
                basestream.Position = 0;
            }

            if (isNax0 && _sdKey == null)
            {
                btnFindSDKey_Click(null, null);
                CheckKeys();
            }

            return isNax0 
                ? new Nax0(_keyset, stream, $@"/registered/{Path.GetFileName(Path.GetDirectoryName(path))?.ToUpperInvariant()}/{Path.GetFileName(path)?.ToLowerInvariant()}", false).BaseStorage.WithAccess(FileAccess.Read, true) 
                : stream.WithAccess(FileAccess.Read, true);
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
            _controlNACP.Clear();
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

        private void UpdateImage(Bitmap b, int index)
        {
            ilGamesExtraSmall.Images[index] = new Bitmap(b, new Size(16, 16));
            ilGamesSmall.Images[index] = new Bitmap(b, new Size(32, 32));
            ilGames.Images[index] = new Bitmap(b, new Size(64, 64));
            ilGamesLarge.Images[index] = new Bitmap(b, new Size(128, 128));
            ilGamesExtraLarge.Images[index] = new Bitmap(b, new Size(256,256));
        }

        private void ReadControlInfo(string titleID, CnmtContentEntry entry)
        {
            byte[] titleIDBytes = titleID.ToByte();
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
                if (node == null)
                {
                    node = tvGames.Nodes.Add(newTitleID, $"{_titleNames[newTitleID]} - {newTitleID}");
                    node.ImageIndex = node.SelectedImageIndex = 0;
                    node.Tag = newTitleID;
                }

                string nodeTitle;
                if (_databaseTitleNames.TryGetValue(titleID, out var dbTitleName) && type.Equals("DLC"))
                    nodeTitle = $"{dbTitleName} - {titleID} - [{type}]";
                else
                    nodeTitle = $"{titleID} - [{type}]";

                for (var i = 0; i < node.Nodes.Count; i++)
                {
                    if (!node.Nodes[i].Text.Equals(nodeTitle)) continue;
                    return;
                }

                node = node.Nodes.Add(titleID, nodeTitle);

                node.Tag = titleID;
                node.ImageIndex = node.Parent.ImageIndex;
                node.SelectedImageIndex = node.Parent.SelectedImageIndex;
                
                return;
            }

            if (entry == null)
            {
                if (!_databaseTitleNames.TryGetValue(newTitleID, out var titleName)) titleName = "Unknown";
                var node = tvGames.Nodes.Find(newTitleID, false).FirstOrDefault();

                if (node == null)
                {
                    node = tvGames.Nodes.Add(newTitleID, $"{titleName} - {newTitleID}");
                    node.Tag = newTitleID;
                }

                string nodeTitle;
                if (_databaseTitleNames.TryGetValue(titleID, out var dbTitleName) && type.Equals("DLC"))
                    nodeTitle = $"{dbTitleName} - {titleID} - [{type}]";
                else
                    nodeTitle = $"{titleID} - [{type}]";

                for (var i = 0; i < node.Nodes.Count; i++)
                {
                    if (!node.Nodes[i].Text.Equals(nodeTitle)) continue;
                    return;
                }

                var gameNode1 = node.Nodes.Add(titleID, nodeTitle);
                gameNode1.Tag = titleID;

                node.ImageIndex = node.SelectedImageIndex = 0;
                gameNode1.ImageIndex = gameNode1.SelectedImageIndex = 0;

                return;
            }
            var ncaFile = new Nca(_keyset, new StreamStorage(File.Open(Path.Combine(Configuration.Data.Decryptionpath, entry.NcaId.ToHexString() + ".nca"), FileMode.Open, FileAccess.Read), false), false);
            var section = ncaFile.OpenSection(0, false, IntegrityCheckLevel.ErrorOnInvalid, false);
            var romfs = new Romfs(section);
            var nacp = new ControlNACP(romfs, newTitleID);
            ncaFile.Dispose();

            var titleIconPair = nacp.GetTitleNameIcon(tvLanguage);

            _titleNames[newTitleID] = titleIconPair.Item1;
            var gameNode = tvGames.Nodes.Add(newTitleID, $"{titleIconPair.Item1}");
            gameNode.Tag = newTitleID;
            gameNode.ToolTipText = $@"{titleIconPair.Item1}{Environment.NewLine}{titleIconPair.Item2}{
                Environment.NewLine}{titleIconPair.Item3}{Environment.NewLine}{titleIconPair.Item4}";
            

            GameImagesAdd(titleIconPair.Item5);
            gameNode.ImageIndex = gameNode.SelectedImageIndex = ilGames.Images.Count - 1;
            {
                string nodeTitle;
                if (_databaseTitleNames.TryGetValue(titleID, out var dbTitleName) && type.Equals("DLC"))
                    nodeTitle = $"{dbTitleName} - {titleID} - [{type}]";
                else
                    nodeTitle = $"{titleID} - [{type}]";

                var gameNode1 = gameNode.Nodes.Add(titleID, nodeTitle);
                gameNode1.Tag = titleID;
                gameNode1.ImageIndex = gameNode1.SelectedImageIndex = ilGames.Images.Count - 1;
            }

            _controlNACP[ilGames.Images.Count - 1] = nacp;

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
                var result = PackNSP(cnmt);
                if (result)
                    packed++;
            }

            HideProgress();
            UpdateStatus($@"{packed} NSPs packed");
        }

        // ReSharper disable once UnusedMethodReturnValue.Local
        private bool PackNSP(string titleID)
        {
            return _cnmtFiles.TryGetValue(titleID, out var cnmt) && PackNSP(cnmt);
        }

        private bool PackNSP(Cnmt cnmt)
        {
            byte[] tid = $"{cnmt.TitleId:x16}".ToByte();

            var result = cnmt.Type == TitleType.AddOnContent
                ? _databaseTitleNames.TryGetValue(tid.ToHexString(), out var titleName) 
                : _titleNames.TryGetValue(tid.ToHexString(), out titleName);

            if (!result)
            {
                tid[6] &= 0xE0;
                tid[7] = 0;
                if (!_titleNames.TryGetValue(tid.ToHexString(), out titleName) && !_databaseTitleNames.TryGetValue(tid.ToHexString(), out titleName))
                    titleName = "Unknown";
            }

            var nsxTitleName = titleName;
            _tickets.TryGetValue($"{cnmt.TitleId:x16}", out var ticket);

            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (cnmt.Type)
            {
                case TitleType.Application:
                    titleName += $@" [{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsp";
                    nsxTitleName += $@" [{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsx";
                    break;
                case TitleType.Patch:
                    titleName += $@" [UPD][{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsp";
                    nsxTitleName += $@" [{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsx";
                    break;
                case TitleType.AddOnContent:
                    titleName += $@" [DLC][{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsp";
                    nsxTitleName += $@" [{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsx";
                    break;

                default:
                    UpdateStatus($"Cannot pack {titleName} - Content type not supported");
                    return false;
            }

            

            UpdateStatus($@"Packing {(ticket == null ? nsxTitleName : titleName)}");

            (bool, string[]) status = Pack(ticket, $"{cnmt.TitleId:x16}", titleName, nsxTitleName);
            AppendStatus(status.Item2[0],status.Item2.Skip(1).ToArray());
            if (ticket == null && _titleReleaseDate.TryGetValue($"{cnmt.TitleId:x16}", out var releaseDate) && DateTime.Now >= releaseDate)
            {
                AppendStatus(" - The ticket for this title should be retrievable now.");
            }

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
        private double _progressCurrent;
        private double _progressMax;
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
                tsProgress.Style = ProgressBarStyle.Continuous;
                tsProgress.Value = 0;
                tsProgress.Maximum = (int) max;
            }
            catch
            {
                tsProgress.Visible = false;
            }
            
            Application.DoEvents();
        }

        private void SpinProgressBar()
        {
            tsProgress.Visible = true;
            tsProgress.Style = ProgressBarStyle.Marquee;
        }


        private readonly List<ulong> _progressUpdates = new List<ulong>();
        private void UpdateProgress(ulong progress)
        {
            if (!tsProgress.Visible) return;
            

            _progressCurrent += progress;
            if (_progressCurrent > _progressMax)
                _progressCurrent = _progressMax;

            progress += _progressMod;
            _progressMod = progress % _progressDivisor;

            progress /= _progressDivisor;

            if (txtGameInfo.InvokeRequired)
            {
                lock(_progressUpdates)
                    _progressUpdates.Add(progress);
                return;
            }

            lock (_progressUpdates)
            {
                progress += _progressUpdates.Aggregate(0UL, (a, c) => a + c);
                _progressUpdates.Clear();
            }

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
            List<string> designations = new List<string>
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

        public (bool, string[]) ReplaceTitleKey(Ticket ticket, string baseTitle, string nsxTitle)
        {
            try
            {
                //Rename the file.
                File.Move(Path.Combine(Configuration.Data.NSPPath, nsxTitle.StripIllegalCharacters()), Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters()));

                using (var nsxfile = File.Open(Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters()), FileMode.Open, FileAccess.ReadWrite))
                {
                    byte[] nsxTitleKey = "5B5449544C45204B455920484552455D".ToByte();
                    var keyFound = false;
                    var offset = 0;

                    using (var br = new BinaryReader(nsxfile, Encoding.UTF8, true))
                    {
                        while (nsxfile.Position != nsxfile.Length && !keyFound)
                        {
                            var data = br.ReadBytes(0x100010);
                            if (nsxfile.Position != nsxfile.Length)
                                nsxfile.Position -= 0x10; //Move back 16 bytes for the next pass.

                            for (var i = 0; i < (data.Length - 0x10); i++)
                            {
                                var match = true;
                                for (var j = 0; j < nsxTitleKey.Length && match; j++)
                                {
                                    match &= nsxTitleKey[j] == data[i + j];
                                }

                                if (!match) continue;

                                keyFound = true;
                                offset += i;
                                break;
                            }

                            if (!keyFound)
                                offset += 0x100000;
                        }
                    }

                    if (!keyFound) return (false, new[] {" - NSX was not created with this tool"});

                    nsxfile.Position = offset;
                    using (var bw = new BinaryWriter(nsxfile))
                    {
                        bw.Write(ticket.TitleKey);
                    }

                    return (true, new[] {" - Key successfully added to NSX file."});
                }
            }
            catch
            {
                return (false, new[] {" - Failed to add title key to NSX"});
            }
        }

        public (bool, string[]) Pack(Ticket ticket, string cnmtTitleID, string baseTitle, string nsxTitle)
        {
            try
            {
                try
                {
                    if (File.Exists(Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters())))
                        return (false, new[] { " - Already packed" });

                    if (ticket != null && !ticket.Anonymize())
                        return (false, new[] { $" - {ticket.AnonymizeError}" });

                    if (File.Exists(Path.Combine(Configuration.Data.NSPPath, nsxTitle.StripIllegalCharacters())))
                    {
                        return ticket != null 
                            ? ReplaceTitleKey(ticket, baseTitle, nsxTitle) 
                            : (false, new[] { " - Already packed" });
                    }
                }
                catch
                {
                    //
                }

                var cnmt = _cnmtFiles[cnmtTitleID];
                var cnmtNcaFile = _cnmtNcaFiles[cnmtTitleID];


                List<CnmtContentType> types = new List<CnmtContentType>
                {
                    CnmtContentType.Program,
                    CnmtContentType.LegalInformation,
                    CnmtContentType.Data,
                    CnmtContentType.HtmlDocument,
                    CnmtContentType.Control
                };

                string[] sdfiles = GetSDDirectories(_sdFileSystem);

                List<CnmtContentEntry> exitEntries = new List<CnmtContentEntry>();
                exitEntries.AddRange(from type in types
                    from entry in cnmt.ContentEntries
                    where entry.Type == type
                    //where !File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    where sdfiles.All(x => !x.ToLowerInvariant().EndsWith($"{entry.NcaId.ToHexString()}.nca"))
                    select entry);
                if (exitEntries.Any())
                {
                    return (false, new[]
                    {
                        " - Failed.",
                        $@"Failed to pack because the following NCAs are missing:{Environment.NewLine}{string.Join(Environment.NewLine, exitEntries.Select(x => x.NcaId.ToHexString() + ".nca"))}{Environment.NewLine}{Environment.NewLine}"
                    });
                }

                types.Remove(CnmtContentType.Control);
                types.Add(CnmtContentType.DeltaFragment);

                List<CnmtContentEntry> startingEntries = new List<CnmtContentEntry>();
                List<CnmtContentEntry> controlEntries = new List<CnmtContentEntry>();
                startingEntries.AddRange(from type in types
                    from entry in cnmt.ContentEntries
                    where entry.Type == type
                    //where File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    where sdfiles.Any(x => x.ToLowerInvariant().EndsWith(entry.NcaId.ToHexString() + ".nca"))
                    select entry);
                controlEntries.AddRange(from entry in cnmt.ContentEntries
                    where entry.Type == CnmtContentType.Control
                    //where File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    where sdfiles.Any(x => x.ToLowerInvariant().EndsWith(entry.NcaId.ToHexString() + ".nca"))
                    select entry);


                if (ticket == null)
                {
                    baseTitle = nsxTitle;
                    List<string> ncafilenames = sdfiles.Where(x => x.ToLowerInvariant().EndsWith(cnmtNcaFile.NcaId.ToHexString() + ".nca")).ToList();
                    ncafilenames.AddRange(sdfiles.Where(x => cnmt.ContentEntries.Any(y => x.ToLowerInvariant().EndsWith(y.NcaId.ToHexString() + ".nca"))));

                    foreach (var ncafilename in ncafilenames)
                    {
                        using (var ncafile = new Nca(_keyset, OpenSplitNcaStream(ncafilename), false))
                        {
                            if (!ncafile.HasRightsId) continue;
                            ticket = new Ticket(ncafile.Header.RightsId.ToHexString(), "5B5449544C45204B455920484552455D");
                            break;
                        }
                    }

                    if (ticket == null)
                    {
                        return (false, new [] { " - Couldn't create blank .nsx ticket" });
                    }
                }


                List<string> packFiles = new List<string>
                {
                    ticket.RightsID.ToHexString() + ".cert",
                    ticket.RightsID.ToHexString() + ".tik",
                    $"{cnmtNcaFile.NcaId.ToHexString()}.cnmt.nca",
                };

                packFiles.InsertRange(2, from entry in startingEntries select entry.NcaId.ToHexString() + ".nca");
                packFiles.AddRange(from entry in controlEntries select entry.NcaId.ToHexString() + ".nca");

                List<ulong> fileSizes = new List<ulong>
                {
                    0x700,
                    0x2C0,
                    (ulong) cnmtNcaFile.Size,
                };

                fileSizes.InsertRange(2, from entry in startingEntries select (ulong)entry.Size);
                fileSizes.AddRange(from entry in controlEntries select (ulong)entry.Size);

                var nspFileName = Path.Combine(Configuration.Data.NSPPath, baseTitle.StripIllegalCharacters());
                using (var nspFile = new FileStream(nspFileName,
                    FileMode.Create))
                {
                    using (var sw = new BinaryWriter(nspFile))
                    {
                        var stringTable = string.Join("\0", packFiles);
                        var headerSize = 0x10 + (packFiles.Count * 0x18) + stringTable.Length;
                        var remainder = 0x10 - (headerSize % 0x10);

                        List<uint> stringTableOffsets = new List<uint>();
                        ulong offset = 0;
                        foreach (var f in packFiles)
                        {
                            stringTableOffsets.Add((uint) offset);
                            offset += (ulong) (f.Length + 1);
                        }

                        List<ulong> fileOffsets = new List<ulong>();
                        offset = 0;
                        foreach (var f in fileSizes)
                        {
                            fileOffsets.Add(offset);
                            offset += f;
                        }

                        InitializeProgress(offset);

                        sw.Write(new[] {'P', 'F', 'S', '0'});
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


                        if (cnmt.Type == TitleType.Patch)
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
                            WriteNcaToNSP(nspFile, sw, entry);
                        }

                        WriteNcaToNSP(nspFile, sw, cnmtNcaFile);
                        //sw.Write(xml);

                        foreach (var entry in controlEntries)
                        {
                            WriteNcaToNSP(nspFile, sw, entry);
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

        private void WriteNcaToNSP(Stream nspFile, BinaryWriter sw, CnmtContentEntry entry)
        {
            var hash = SHA256.Create();
            var filename = GetSDDirectories(_sdFileSystem).FirstOrDefault(x => x.ToLowerInvariant().EndsWith(entry.NcaId.ToHexString() + ".nca"));
            if(filename == null)
                throw new Exception($@"{entry.NcaId.ToHexString()}.nca does not exist.");

            using (var ncaFile = OpenSplitNcaStream(filename))
            {
                if(ncaFile == null)
                    throw new Exception($@"{entry.NcaId.ToHexString()}.nca does not exist.");

                using (var sr = new BinaryReader(ncaFile.AsStream()))
                {
                    while (sr.BaseStream.Position != sr.BaseStream.Length)
                    {
                        byte[] bytes = sr.ReadBytes((int)Math.Min(sr.BaseStream.Length - sr.BaseStream.Position, 0x100000));
                        if (bytes.Length <= 0) continue;

                        sw.Write(bytes);
                        SetProgress((ulong)nspFile.Length);
                        //UpdateProgress((ulong)bytes.Length);
                        hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                    }

                    hash.TransformFinalBlock(new byte[0], 0, 0);
                }

                if (!hash.Hash.ToArray().ToHexString().Equals(entry.Hash.ToHexString()))
                    throw new Exception($@"{entry.NcaId.ToHexString()}.nca is corrupted.");
            }
        }

        private void btnParseNCA_Click(object sender, EventArgs e)
        {
            if (!CheckKeys()) return;
           
            UpdateStatus(@"Parsing Decrypted NCA files");

            var ncaDir = Path.Combine("tools", "nca");
            if (!Directory.Exists(ncaDir))
                Directory.CreateDirectory(ncaDir);

            if (!Directory.Exists(Configuration.Data.Decryptionpath))
                Directory.CreateDirectory(Configuration.Data.Decryptionpath);

            string[] ncaFiles = Configuration.GetDecryptedNCAFiles;
            InitializeProgress((ulong)ncaFiles.Length);
            ClearGameImageLists();

            List<Cnmt> controls = new List<Cnmt>();
            List<Cnmt> metas = new List<Cnmt>();

            for (var j = 0; j < ncaFiles.Length; j++)
            {
                var ncafile = ncaFiles[j];
                SetProgress((ulong)j + 1);

                using (var ncaStream = File.Open(ncafile, FileMode.Open, FileAccess.Read))
                {
                    try
                    {
                        using (var ncaData = new Nca(_keyset, new StreamStorage(ncaStream, true), true))
                        {
                            if (ncaData.Header.ContentType != ContentType.Meta)
                                continue;
                            var section = ncaData.OpenSection(0, false, IntegrityCheckLevel.ErrorOnInvalid, false);
                            var pfs = new Pfs(section);
                            var cnmt = new Cnmt(pfs.OpenFile(pfs.Files[0]).AsStream());
                            if (!_cnmtFiles.TryGetValue($"{cnmt.TitleId:x16}", out var oldcnmt) || oldcnmt.TitleVersion.Version < cnmt.TitleVersion.Version)
                                _cnmtFiles[$"{cnmt.TitleId:x16}"] = cnmt;
                            else
                                continue;

                            ncaStream.Position = 0;
                            var entry = new CnmtContentEntry
                            {
                                NcaId = Path.GetFileNameWithoutExtension(ncafile).ToByte(),
                                Type = CnmtContentType.Meta,
                                Size = ncaStream.Length,
                                Hash = SHA256.Create().ComputeHash(ncaStream)
                            };
                            _cnmtNcaFiles[$"{cnmt.TitleId:x16}"] = entry;

                            var controldata = cnmt.ContentEntries.FirstOrDefault(x => x.Type == CnmtContentType.Control);
                            if (controldata == null) metas.Add(cnmt);
                            else controls.Add(cnmt);
                        }
                    }
                    catch (Exception ex)
                    {
                        UpdateStatus($"Could not process {Path.GetFileName(ncafile)} due to the following Exception: {ex.Message}.",
                            $"Exception: {ex.Message}{Environment.NewLine}Stack Trace:{ex.StackTrace}");
                    }
                }
            }



            tvGames.Visible = false;
            InitializeProgress((ulong) _cnmtFiles.Count);
            ulong count = 0;

            controls = controls.OrderByDescending(x => (x.TitleId & 0x1FFFUL) == 0x800UL).ToList();
            controls.AddRange(metas);

            foreach (var cnmt in controls)
            {
                var controldata = cnmt.ContentEntries.FirstOrDefault(x => x.Type == CnmtContentType.Control);
                ReadControlInfo($"{cnmt.TitleId:x16}", controldata);
                SetProgress(++count);
            }

            tvGames.Sort();
            tvGames.Visible = true;

            HideProgress();

            UpdateStatus($@"NCA Parsing completed - {_cnmtFiles.Count} Titles present.");
        }

        private void btnLanguageUp_Click(object sender, EventArgs e)
        {
            var node = tvLanguage.SelectedNode;
            if (node == null) return;
            node.MoveUp();
            tvLanguage.SelectedNode = node;
            UpdateTitleIcons();
        }

        private void btnLanguageDown_Click(object sender, EventArgs e)
        {
            var node = tvLanguage.SelectedNode;
            if (node == null) return;
            node.MoveDown();
            tvLanguage.SelectedNode = node;
            UpdateTitleIcons();
        }

        private void UpdateTitleIcons()
        {
            for (var i = 0; i < tvGames.Nodes.Count; i++)
            {
                if (!_controlNACP.TryGetValue(tvGames.Nodes[i].ImageIndex, out var nacp)) continue;
                var data = nacp.GetTitleNameIcon(tvLanguage);
                _titleNames[nacp.BaseTitleID] = data.Item1;

                tvGames.Nodes[i].Text = data.Item1;
                tvGames.Nodes[i].ToolTipText =
                    $@"{data.Item1}{Environment.NewLine}{data.Item2}{Environment.NewLine
                        }{data.Item3}{Environment.NewLine}{data.Item4}";
                UpdateImage(data.Item5, tvGames.Nodes[i].ImageIndex);
            }
        }

        private void txtRSAKEK_TextChanged(object sender, EventArgs e)
        {
            if (txtRSAKEK.Text.All(x => "0123456789ABCDEFabcdef".Contains(x)) && txtRSAKEK.Text.Length == 32)
                Configuration.Data.ETicketRSAKEK = txtRSAKEK.Text;
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
                // ReSharper disable ConditionIsAlwaysTrueOrFalse
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
                // ReSharper restore ConditionIsAlwaysTrueOrFalse
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
            scGameIconInfo.Visible = txtMessage.Text == string.Empty;
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

        private void DeleteSDFile(Cnmt cnmt, TreeNode childNode)
        {
            string[] sdcard = GetSDDirectories(_sdFileSystem);
            var deleteSuccess = true;
            UpdateStatus($@"Deleting {childNode.Parent.Text} - {childNode.Text}");
            var tid = $"{cnmt.TitleId:x16}";
            List<CnmtContentEntry> entries = cnmt.ContentEntries.ToList();
            entries.Add(_cnmtNcaFiles[tid]);
            foreach (var entry in entries)
            {
                var ncafile = sdcard.FirstOrDefault(x => x.ToLowerInvariant().Contains(entry.NcaId.ToHexString()));
                if (ncafile != null && _sdFileSystem is FileSystem)
                    deleteSuccess &= DeleteSdNca(ncafile);
                else
                    deleteSuccess &= DeleteLocalNca(entry.NcaId.ToHexString() + ".nca");
            }

            _cnmtFiles.Remove(tid);
            _cnmtNcaFiles.Remove(tid);

            AppendStatus(deleteSuccess
                ? " - Completed"
                : " - Failed, Check message box to see what files could not be deleted");
        }

        private bool DeleteSdNca(string ncaFile)
        {
            var result = true;
            try
            {
                foreach (var file in Directory.GetFiles(ncaFile))
                    File.Delete(file);
                Directory.Delete(ncaFile);
                try
                {
                    var ncafileroot = Path.GetDirectoryName(ncaFile);
                    if (ncafileroot != null && Directory.GetDirectories(ncafileroot).Length == 0)
                        Directory.Delete(ncafileroot);
                }
                catch (Exception ex)
                {
                    AppendStatus(string.Empty,
                        $@"[WARNING] - Failed to delete directory {Path.GetDirectoryName(ncaFile)}:{Environment.NewLine}",
                        $@"{ex.Message}{Environment.NewLine}Stack Trace:{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                }

                result &= DeleteLocalNca(Path.GetFileName(ncaFile));
            }
            catch (Exception ex)
            {
                AppendStatus(string.Empty,
                    $@"[FATAL] - Failed to delete SD Card copy of {ncaFile} due to an exception:{Environment.NewLine}",
                    $@"{ex.Message}{Environment.NewLine}Stack Trace:{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                return false;
            }

            return result;
        }

        private bool DeleteLocalNca(string ncaFileName)
        {
            if (!cbDeleteLocal.Checked)
                return true;

            try
            {
                if (File.Exists(Path.Combine(Configuration.Data.Decryptionpath, ncaFileName)))
                    File.Delete(Path.Combine(Configuration.Data.Decryptionpath, ncaFileName));
            }
            catch (Exception ex)
            {
                AppendStatus(string.Empty,
                    $@"[FATAL] - Failed to delete local copy of {ncaFileName} due to an exception:{Environment.NewLine}",
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
            tvGames_AfterSelect(null, null);
        }

        private TreeNode _previouslySelectedParentNode;
        private TreeNode _previouslySelectedNode;
        private void tvGames_AfterSelect(object sender, TreeViewEventArgs e)
        {
            if (_previouslySelectedNode == tvGames.SelectedNode) return;
            _previouslySelectedNode = tvGames.SelectedNode;

            var result = _controlNACP.TryGetValue(tvGames.SelectedNode?.ImageIndex ?? 0, out var nacp);
            var data = result
                ? nacp.GetTitleNameIcon(tvLanguage)
                : (string.Empty, string.Empty, string.Empty, string.Empty, Resources.Ultra_microSDXC_UHS_I_A1_front);
            List<Languages> languages = result
                ? nacp.Languages
                : new List<Languages>();

            pbGameIcon.Image = data.Item5;
            txtGameInfo.Text = !result 
                ? string.Empty
                    : $@"Game: {data.Item1}{Environment.NewLine
                    }Developer: {data.Item2}{Environment.NewLine
                    }Version: {data.Item3}{Environment.NewLine
                    }Base Title ID: {data.Item4}{Environment.NewLine}";

            txtGameInfo.Text += AddNcaMetaInfo();

            if (_previouslySelectedParentNode == (tvGames.SelectedNode?.Parent ?? tvGames.SelectedNode)) return;
            _previouslySelectedParentNode = tvGames.SelectedNode?.Parent ?? tvGames.SelectedNode;
            for (var i = 0; i < 15; i++)
            {
                var language = (Languages) tvLanguage.Nodes[i].Tag;
                tvLanguage.Nodes[i].ImageIndex = tvLanguage.Nodes[i].SelectedImageIndex =
                    languages.Contains(language) ? 1 : 0;
            }
        }

        private void tvGames_NodeMouseDoubleClick(object sender, TreeNodeMouseClickEventArgs e)
        {
            btnPackSelectedNSP_Click(null, null);
        }

        private void tvGames_MouseHover(object sender, EventArgs e)
        {
            toolTip1.RemoveAll();
            var selNode = tvGames.GetNodeAt(tvGames.PointToClient(Cursor.Position));
            if (!string.IsNullOrEmpty((selNode?.Parent ?? selNode)?.ToolTipText))
            {
                toolTip1.SetToolTip(tvGames, (selNode.Parent ?? selNode).ToolTipText);
            }
        }

        private void tvLanguage_AfterSelect(object sender, TreeViewEventArgs e)
        {
            var gameNode = tvGames.SelectedNode;
            var languageNode = tvLanguage.SelectedNode;
            if (gameNode == null || languageNode == null) return;
            if (!_controlNACP.TryGetValue(gameNode.ImageIndex, out var nacp)) return;

            if (languageNode.ImageIndex == 0)
            {
                var data = nacp.GetTitleNameIcon(tvLanguage);
                pbGameIcon.Image = data.Item5;
                txtGameInfo.Text = $@"Game: {data.Item1}{Environment.NewLine
                    }Developer: {data.Item2}{Environment.NewLine
                    }Version: {data.Item3}{Environment.NewLine
                    }Base Title ID: {data.Item4}{Environment.NewLine}";
            }
            else
            {
                var index = (int) languageNode.Tag;
                pbGameIcon.Image = nacp.Icons[index];
                txtGameInfo.Text = $@"Game: {nacp.TitleNames[index]}{Environment.NewLine
                    }Developer: {nacp.DeveloperNames[index]}{Environment.NewLine
                    }Version: {nacp.Version}{Environment.NewLine
                    }Base Title ID: {nacp.BaseTitleID}{Environment.NewLine}";
            }

            txtGameInfo.Text += AddNcaMetaInfo();
        }

        private string AddNcaMetaInfo()
        {
            if(tvGames.SelectedNode?.Parent == null)
                return string.Empty;

            var titlekey = $@"Title Key: Not Available{Environment.NewLine}";
            if (_tickets.TryGetValue((string) tvGames.SelectedNode.Tag, out var ticket) && ticket.Anonymize())
                titlekey = $@"Title Key: {ticket.TitleKey.ToHexString()}{Environment.NewLine}";

            var releasedate = "";
            if (_titleReleaseDate.TryGetValue((string) tvGames.SelectedNode.Tag, out var releastDateTime))
                releasedate = $@"Release Date: {releastDateTime}{Environment.NewLine}";

            var output = $@"{releasedate}{Environment.NewLine}";
            var cnmt = _cnmtFiles[(string) tvGames.SelectedNode.Tag];
            List<CnmtContentEntry> entries = cnmt.ContentEntries.ToList();
            entries.Insert(0, _cnmtNcaFiles[$"{cnmt.TitleId:x16}"]);

            output += $@"Title ID: {tvGames.SelectedNode.Tag}{Environment.NewLine}";
            output += titlekey;
            output += $@"Type: {cnmt.Type}{Environment.NewLine}{Environment.NewLine}";
            
            string[] sdFiles = GetSDDirectories(_sdFileSystem);
            foreach (var entry in entries)
            {
                if (sdFiles.All(x => !x.EndsWith($"{entry.NcaId.ToHexString()}.nca"))) continue;
                output += $@"{entry.NcaId.ToHexString() + ".nca"} ({entry.Type}){Environment.NewLine}";
            }

            return output;
        }

        private void tvLanguage_MouseClick(object sender, MouseEventArgs e)
        {
            tvLanguage_AfterSelect(null, null);
        }

        private void cbRSAKey_SelectedIndexChanged(object sender, EventArgs e)
        {
            Ticket.UpdateRSAKey();
            btnLoadRSAKEK.Enabled = true;
            if (cbRSAKey.SelectedIndex < 0) cbRSAKey.SelectedIndex = 0;
            if (cbRSAKey.SelectedIndex == 0) return;

            var item = cbRSAKey.SelectedItem;
            if (item is string serialNumber && Configuration.Data.RSAKeys.TryGetValue(serialNumber, out var keys))
            {
                string[] split = keys.Split(',');
                btnLoadRSAKEK.Enabled = !(split.Length == 3 && split.All(x => x.ToByte().Length != 0));

                if (!btnLoadRSAKEK.Enabled)
                {
                    Ticket.UpdateRSAKey(new BigInteger(split[1].ToByte()), new BigInteger(split[0].ToByte()), new BigInteger(split[2].ToByte()));
                    return;
                }
            }

            Ticket.UpdateRSAKey();
            cbRSAKey.Items.Remove(item);
        }

        private void txtTitleKeyURL_TextChanged(object sender, EventArgs e)
        {
            Configuration.Data.TitleKeyDataBaseURL = txtTitleKeyURL.Text;
        }

        private void btnGetTitleKeys_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(Configuration.Data.TitleKeyDataBaseURL)) return;
            try
            {
                UpdateStatus("Retrieving Title Key database");
                var count = _tickets.Count;
                var myHttpWebRequest =
                    (HttpWebRequest) WebRequest.Create(Configuration.Data.TitleKeyDataBaseURL);
                myHttpWebRequest.MaximumAutomaticRedirections = 1;
                myHttpWebRequest.AllowAutoRedirect = true;
                myHttpWebRequest.Timeout = 30000;
                Task<WebResponse> httpWebResponseAsync = myHttpWebRequest.GetResponseAsync();

                SpinProgressBar();
                while (!httpWebResponseAsync.IsCanceled && !httpWebResponseAsync.IsCompleted &&
                       !httpWebResponseAsync.IsFaulted)
                {
                    Application.DoEvents();
                }
                
                if (httpWebResponseAsync.IsFaulted || httpWebResponseAsync.IsCanceled)
                {
                    if(httpWebResponseAsync.Exception != null)
                        throw httpWebResponseAsync.Exception;
                    UpdateStatus("Database update failed for an unknown reason.");
                    HideProgress();
                    return;
                }
                var myHttpWebResponse = (HttpWebResponse)httpWebResponseAsync.Result;

                if (myHttpWebResponse.StatusCode == HttpStatusCode.OK)
                {
                    var stream = myHttpWebResponse.GetResponseStream();
                    if (stream == null)
                    {
                        HideProgress();
                        return;
                    }
                    using (var sr = new StreamReader(stream))
                    {
                        while (!sr.EndOfStream)
                        {
                            var line = sr.ReadLine();
                            if (line == null) continue;

                            string[] split = line.Split('|');
                            if (split.Length < 3 || (split[0].ToByte()?.Length ?? 0) != 16 || (split[1].ToByte()?.Length ?? 0) != 16)
                                continue;
                            split[2] = string.Join("|", split.Skip(2));

                            byte[] typeBytes = split[0].Substring(12, 4).ToByte();
                            typeBytes[0] &= 0x1F;
                            if (typeBytes[0] == 0x08 && typeBytes[1] == 0x00)
                                continue;   //Do NOT ADD update title keys to the ticket list. the resulting tickets won't be signed,
                                            //and therefore will not work on ALL unmodified switch consoles.

                            if (!_personalTitleIDs.Add(split[0].Substring(0, 16).ToLowerInvariant()) &&
                                !_databaseTitleNames.ContainsKey(split[0].Substring(0, 16).ToLowerInvariant()))
                                _ticketsNotInDB--;

                            _tickets[split[0].Substring(0, 16).ToLowerInvariant()] = new Ticket(split[0], split[1]);
                            _databaseTitleNames[split[0].Substring(0, 16).ToLowerInvariant()] = split[2];
                        }
                    }
                }

                var dbresult = _personalTickets.Count > 0 ? $"{_ticketsNotInDB} Tickets not in database. " : "";
                UpdateStatus(
                    $"{_tickets.Count - count} New Title Keys retrieved. {dbresult}{_tickets.Count} Tickets total.");
            }
            catch (Exception ex)
            {
                UpdateStatus("Updating of database failed due to an exception:",
                    $"Updating of database failed due to an exception: {ex.Message}{Environment.NewLine}",
                    $"Stack Trace: {ex.StackTrace}");
            }
            HideProgress();
        }

        private void btnGetTitleKeys_Click_1(object sender, EventArgs e)
        {
            var titlekeydump = string.Empty;

            UpdateStatus("Extracting Personal Title Key log");

            KeyValuePair<string, string>[] tickets = _personalTickets.ToList().Where(x => !_databaseTitleNames.ContainsKey(x.Key.Substring(0,16))).ToArray();
            InitializeProgress((ulong) tickets.Length);

            for(var i = 0; i < tickets.Length; i++)
            {
                UpdateProgress(1);
                KeyValuePair<string, string> ticket = tickets[i];

                titlekeydump += $"Ticket {i}:{Environment.NewLine}";
                titlekeydump += $"    Rights ID: {ticket.Key}{Environment.NewLine}";
                titlekeydump += $"    Title ID:  {ticket.Key.Substring(0,16)}{Environment.NewLine}";
                titlekeydump += $"    Title key:  {ticket.Value}{Environment.NewLine}";
            }

            HideProgress();
            if (titlekeydump == string.Empty)
            {
                AppendStatus(_databaseTitleNames.Count == 0 
                    ? " - No Title keys to show" 
                    : " - All Title keys already exist in the database");
                return;
            }

            try
            {
                File.WriteAllText("personal_keys.txt", titlekeydump);
                AppendStatus(" - Title keys saved to personal_keys.txt", titlekeydump);
            }
            catch
            {
                AppendStatus(" - Failed to write personal_keys.txt");
                UpdateStatus("Click this log entry to see Personal key dump", titlekeydump);
            }
        }

        private Stream _encStream;
        private void button2_Click(object sender, EventArgs e)
        {
            /*
            var nandsystemfilename = "C:\\Users\\CaitSith2\\Desktop\\SD Swap\\Switch\\Backup\\rawnand.bin";
            _encStream?.Dispose();
            _encStream = File.Open(nandsystemfilename, FileMode.Open, FileAccess.Read);


            try{_encStream.Position = -1; }
            catch (Exception ex) { UpdateStatus("Failed to set position before beginning of file using Position = -1",$"{ex.GetType()}: {ex.Message}{Environment.NewLine}{ex.StackTrace}"); }
            try{_encStream.Seek(-_encStream.Length - 1, SeekOrigin.End);}
            catch (Exception ex) { UpdateStatus("Failed to set position before beginning of file using Seek(-Length-1, SeekOrigin.End)", $"{ex.GetType()}: {ex.Message}{Environment.NewLine}{ex.StackTrace}"); }

            _encStream.Position = 0;
            byte[] biskey = File.ReadAllBytes("biskey.bin");

            _keyset.bis_keys[2] = biskey;
            _keyset.bis_keys[3] = biskey;
            var nand = new Nand(_encStream, _keyset);
            _sdFileSystem = nand.OpenUserPartition();
            _systemNandFileSystem = nand.OpenSystemPartition();*/



            /*using ()
            {
                

                /*var xts = XtsAes128.Create(biskey);
                var decStream = new RandomAccessSectorStream(new XtsSectorStream(encStream, xts, 0x4000, 0), true);
                FatFileSystem fat = new FatFileSystem(decStream, Ownership.None);
                NandPartition system = new NandPartition(fat);
                ListFiles(system, "\\");
            }*/
        }

        // ReSharper disable once UnusedMember.Local
        private void ListFiles(NandPartition partition, string path)
        {
            UpdateStatus(path);
            foreach (var dir in partition.Fs.GetDirectories(path))
                ListFiles(partition, dir);
            foreach (var file in partition.Fs.GetFiles(path))
                UpdateStatus(file);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            /*for (var i = 0; i < 100; i++)
            {
                button1_Click(null, null);
                UpdateStatus($"Iteration {i + 1} of 100");
            }*/

            UpdateStatus("Extracting Savefiles");
            foreach (var file in _systemNandFileSystem.GetFileSystemEntries("save", "*"))
            {
                try
                {
                    var savefilename = Path.GetFileName(file);
                    var savewritepath = $"SYSTEM-SAVE\\{savefilename}";
                    UpdateStatus($"Extracting \"{savefilename}\" - ");
                    using (var stream = _systemNandFileSystem.OpenFile(file, FileMode.Open, FileAccess.Read))
                    {
                        var savefiledata = new SaveData(_keyset, new StreamStorage(stream, true), IntegrityCheckLevel.ErrorOnInvalid, false);
                        savefiledata.Extract(savewritepath);
                    }
                    AppendStatus("Done.");
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                        AppendStatus(ex.Message, $"{ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
                    else
                        AppendStatus($"Unknown error in {Path.GetFileName(file)}", $"{ex.GetType().Name}: {ex.Message}");
                }
            }
            UpdateStatus("Done");

        }

        private void btnExtractCommonKeys_Click(object sender, EventArgs e)
        {
            var titlekeydump = string.Empty;
            var formattedtitlekeydump = string.Empty;

            UpdateStatus("Extracting Common Title Key log");
            KeyValuePair<string, string>[] tickets = _commonTickets.ToList().Where(x => !_databaseTitleNames.ContainsKey(x.Key.Substring(0, 13) + "000")).ToArray();
            InitializeProgress((ulong)tickets.Length);

            for (var i = 0; i < tickets.Length; i++)
            {
                UpdateProgress(1);
                KeyValuePair<string, string> ticket = tickets[i];

                titlekeydump += $"Ticket {i}:{Environment.NewLine}";
                titlekeydump += $"    Rights ID: {ticket.Key}{Environment.NewLine}";
                titlekeydump += $"    Title ID:  {ticket.Key.Substring(0, 16)}{Environment.NewLine}";
                titlekeydump += $"    Title key:  {ticket.Value}{Environment.NewLine}";

                if (!_titleNames.TryGetValue(ticket.Key.Substring(0, 13) + "000", out var gameTitle))
                    gameTitle = "Unknown";
                formattedtitlekeydump += $"{ticket.Key}|{ticket.Value}|{gameTitle}";
            }

            HideProgress();
            if (titlekeydump == string.Empty)
            {
                AppendStatus(_databaseTitleNames.Count == 0
                    ? " - No Title keys to show"
                    : " - All Base game Title keys already exist in the database");
                return;
            }

            try
            {
                File.WriteAllText("common_keys.txt", titlekeydump);
                File.WriteAllText("formatted_common_keys.txt",formattedtitlekeydump);
                AppendStatus(" - Title keys saved to common_keys.txt and formatted_common_keys.txt", titlekeydump);
            }
            catch
            {
                AppendStatus(" - Failed to write at least one of common_keys.txt and formatted_common_keys.txt");
                UpdateStatus("Click this log entry to see common key dump", titlekeydump);
                UpdateStatus("Click this log entry to see formatted common key dump", formattedtitlekeydump);
            }
        }
    }
}
