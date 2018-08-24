using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using CTR;
using Microsoft.Win32;
using SwitchSDTool.Properties;
using libhac;
using libhac.Savefile;
using libhac.Streams;
using Application = System.Windows.Forms.Application;

namespace SwitchSDTool
{
    public partial class Form1 : Form
    {
        private byte[] _sdKey;

        private readonly Dictionary<string, Ticket> _tickets = new Dictionary<string, Ticket>();
        private readonly Dictionary<string, Ticket> _personalTickets = new Dictionary<string, Ticket>();
        private readonly Dictionary<string, Cnmt> _cnmtFiles = new Dictionary<string, Cnmt>();
        private readonly Dictionary<string, CnmtContentEntry> _cnmtNcaFiles = new Dictionary<string, CnmtContentEntry>();
        private readonly Dictionary<string, string> _titleNames = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _databaseTitleNames = new Dictionary<string, string>();
        private readonly Dictionary<int, ControlNACP> _controlNACP = new Dictionary<int, ControlNACP>();
        private readonly Dictionary<string, DateTime> _titleReleaseDate = new Dictionary<string, DateTime>();

        private readonly Keyset _keyset = new Keyset();

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

            var split = fbdSDCard.SelectedPath.PathSplit();
            var rootFolder = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar, "Nintendo", "Contents",
                "registered");
            var baseFolder = Path.Combine(fbdSDCard.SelectedPath, "Nintendo", "Contents", "registered");
            var nandRootFolder = Path.Combine(split[0] + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar,
                "Contents", "registered");
            var nandBaseFolder = Path.Combine(fbdSDCard.SelectedPath, "Contents", "registered");
            if (Directory.Exists(nandRootFolder))
            {
                Configuration.Data.SDpath = nandRootFolder;
                Configuration.Data.SDPrivateFile = null;
            }
            else if (Directory.Exists(nandBaseFolder))
            {
                Configuration.Data.SDpath = nandBaseFolder;
                Configuration.Data.SDPrivateFile = null;
            }
            else if (Directory.Exists(rootFolder))
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
            if (Configuration.Data.SDPrivateFile == null)
            {
                if (Directory.Exists(Configuration.Data.SDpath))
                {
                    _sdKey = null;
                    UpdateStatus(@"User NAND Partition mounted");
                    btnFindSDKey.Enabled = false;
                }
                return;
            }
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

                data = new byte[0x18];
                prodinfo.Seek(0x250, SeekOrigin.Begin);
                prodinfo.Read(data, 0, 0x18);
                var serialNumber = Encoding.UTF8.GetString(data);
                var index = serialNumber.IndexOf("\0", StringComparison.Ordinal);
                if (index > 0) serialNumber = serialNumber.Substring(0, index);

                if (!cbRSAKey.Items.Contains(serialNumber))
                {
                    cbRSAKey.Items.Add(serialNumber);
                    Configuration.Data.RSAKeys[serialNumber] = $"{rsa_N.ToHexString()},{rsa_D.ToHexString()},{rsa_E.ToHexString()}";
                }

                cbRSAKey.SelectedItem = serialNumber;

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

            if (Configuration.VerifyETicketRSAKEK())
            {
                txtRSAKEK.Text = @"-------- eticket_rsa_kek redacted --------";
                txtRSAKEK.Enabled = false;
            }

            var generatedKeys = _validKeySizes.Keys.Where(x => x.EndsWith("_")).ToArray();
            foreach (var key in generatedKeys)
            {
                var keysize = _validKeySizes[key];
                _validKeySizes.Remove(key);
                for (var i = 0; i < 32; i++)
                {
                    _validKeySizes[key + $"{i:00}"] = keysize;
                }
            }

            var keysToRemove = new List<string>();
            foreach (var serial in Configuration.Data.RSAKeys.Keys)
            {
                var split = Configuration.Data.RSAKeys[serial].Split(',').Where(x => x.Trim().ToByte().Length != 0).Select(x => x.Trim()).ToArray();
                if (split.Length != 3)
                {
                    keysToRemove.Add(serial);
                    continue;
                }
                var N = new BigInteger(split[0].ToByte());
                var D = new BigInteger(split[1].ToByte());
                var E = new BigInteger(split[2].ToByte());
                BigInteger test = 0xCAFEBABE;
                var encrypted = BigInteger.ModPow(test, D, N);
                var decrypted = BigInteger.ModPow(encrypted, E, N);
                if (decrypted != test || E != 0x10001)
                {
                    keysToRemove.Add(serial);
                }
                else
                {
                    cbRSAKey.Items.Add(serial);
                }
            }

            foreach (var serial in keysToRemove)
                Configuration.Data.RSAKeys.Remove(serial);

            txtTitleKeyURL.Text = Configuration.Data.TitleKeyDataBaseURL ?? string.Empty;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (Ticket.RsaE != 0x10001)
            {
                btnLoadRSAKEK_Click(null, null);
                if (Ticket.RsaE != 0x10001 && cbRSAKey.Items.Count < 2)
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
            var count = _tickets.Count;

            using (var stream = File.Open(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e1"), FileMode.Open, FileAccess.Read))
            {
                var commonTickets = new Savefile(stream);
                var ticketList = new BinaryReader(commonTickets.OpenFile("/ticket_list.bin"));
                var titleIDs = new List<string>();
                while (true)
                {
                    var titleID = ticketList.ReadUInt64();
                    if (titleID == ulong.MaxValue) break;
                    titleIDs.Add($"{titleID:x16}".ToByte().Reverse().ToArray().ToHexString());
                    ticketList.BaseStream.Position += 0x18;
                }

                var tickets = new BinaryReader(commonTickets.OpenFile("/ticket.bin"));
                foreach(var tid in titleIDs)
                {
                    _tickets[tid] = new Ticket(tickets.ReadBytes(0x400));
                }

                /*var ticketList = new BinaryReader(commonTickets.OpenFile("/ticket_list.bin"));
                var tickets = new BinaryReader(commonTickets.OpenFile("/ticket.bin"));
                ulong titleID;
                do
                {
                    titleID = ticketList.ReadUInt64();
                    if (titleID == ulong.MaxValue) continue;
                    ticketList.BaseStream.Position += 0x18;
                    _tickets[$"{titleID:x16}"] = new Ticket(tickets.ReadBytes(0x400));
                } while (titleID != ulong.MaxValue);*/
            }

            using (var stream = File.Open(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e2"), FileMode.Open, FileAccess.Read))
            {
                var personalTickets = new Savefile(stream);
                var ticketList = new BinaryReader(personalTickets.OpenFile("/ticket_list.bin"));
                var titleIDs = new List<string>();
                while (true)
                {
                    var titleID = ticketList.ReadUInt64();
                    if (titleID == ulong.MaxValue) break;
                    titleIDs.Add($"{titleID:x16}".ToByte().Reverse().ToArray().ToHexString());
                    ticketList.BaseStream.Position += 0x18;
                }

                var tickets = new BinaryReader(personalTickets.OpenFile("/ticket.bin"));
                bool firstTicket = false;
                foreach (var tid in titleIDs)
                {
                    var ticket = new Ticket(tickets.ReadBytes(0x400));
                    var ticketHash = SHA256.Create().ComputeHash(ticket.Data);

                    if (!firstTicket)
                    {
                        firstTicket = ticket.Anonymize();

                        for (var j = 1; j < cbRSAKey.Items.Count && !firstTicket; j++)
                        {
                            cbRSAKey.SelectedIndex = j;
                            cbRSAKey_SelectedIndexChanged(null, null);
                            firstTicket |= ticket.Anonymize();
                        }

                        if (!firstTicket)
                        {
                            UpdateStatus($"Done. {_tickets.Count} Tickets dumped");
                            UpdateStatus($"Cannot extract personal tickets - {ticket.AnonymizeError}");
                            btnLoadRSAKEK.Enabled = true;
                            Ticket.RsaD = BigInteger.Zero;
                            Ticket.RsaN = BigInteger.Zero;
                            Ticket.RsaE = BigInteger.Zero;
                            return;
                        }
                    }

                    if (_personalTitleIDs.Add(ticket.TitleID.ToHexString())) _ticketsNotInDB++;

                    _tickets[tid] = ticket;
                    _personalTickets[ticketHash.ToHexString()] = ticket;

                }
            }

            if(File.Exists(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e3")))
                using (var stream = File.Open(Path.Combine(Configuration.Data.SystemPath, "save", "80000000000000e3"), FileMode.Open, FileAccess.Read))
                {
                    var ticketReleaseDates = new Savefile(stream);
                    var ticketList = new BinaryReader(ticketReleaseDates.OpenFile("/ticket_list.bin"));
                    while (true)
                    {
                        var titleID = ticketList.ReadUInt64();
                        if (titleID == ulong.MaxValue) break;
                        ticketList.BaseStream.Position += 0x18;

                        var utctime = ticketList.ReadUInt64();
                        _titleReleaseDate[$"{titleID:x16}".ToByte().Reverse().ToArray().ToHexString()] = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(utctime).ToLocalTime();
                        ticketList.BaseStream.Position += 0xD8;
                    }
                }

            var dbresult = _databaseTitleNames.Count > 0 ? $"{_ticketsNotInDB} Tickets not in database. " : "";
            UpdateStatus($"Done. {_tickets.Count - count} new tickets dumped. {dbresult}{_tickets.Count} Tickets total.");
        }

        private static readonly Dictionary<string, byte[]> _keyHashes = new Dictionary<string, byte[]>
        {
            {"sd_card_nca_key_source", "***REMOVED***".ToByte()},
            {"sd_card_kek_source", "***REMOVED***".ToByte()},
            {"master_key_00", "***REMOVED***".ToByte()},
            {"aes_key_generation_source", "***REMOVED***".ToByte()},
            {"aes_kek_generation_source", "***REMOVED***".ToByte()},

            {"header_key", "***REMOVED***".ToByte()},
            {"key_area_key_application_source", "***REMOVED***".ToByte()},
            {"key_area_key_ocean_source", "***REMOVED***".ToByte()},
            {"key_area_key_system_source", "***REMOVED***".ToByte()},

            {"master_key_01", "***REMOVED***".ToByte()},
            {"master_key_02", "***REMOVED***".ToByte()},
            {"master_key_03", "***REMOVED***".ToByte()},
            {"master_key_04", "***REMOVED***".ToByte()},
        };

        private static readonly Dictionary<string, int> _validKeySizes = new Dictionary<string, int>
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
            var keys = new Dictionary<string, byte[]>();
            using (var sr = new StreamReader(new FileStream(filename, FileMode.Open)))
            {
                var keyname = string.Empty;
                var keyvalue = string.Empty;
                while (!sr.EndOfStream)
                {
                    var line = sr.ReadLine();
                    if (line == null) continue;
                    var split = line.Split(new[] {",", "="}, StringSplitOptions.None).Select(x => x.ToLowerInvariant().Trim()).ToArray();
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

                    if(!_validKeySizes.TryGetValue(keyname, out var keysize) || keyvalue.ToByte().Length == keysize)
                        keys[keyname] = keyvalue.ToByte();
                }
            }

            foreach (var keyname in _validKeySizes.Keys)
            {
                var keyvalue = _validKeySizes[keyname];
                if (keys.TryGetValue(keyname, out var keyBytes) && keyBytes.Length != keyvalue)
                    keys.Remove(keyname);
            }

            foreach (var keyname in _keyHashes.Keys)
            {
                if (!keys.TryGetValue(keyname, out var keyData))
                {
                    UpdateStatus($"Keys.txt is missing {keyname}");
                    return (false,null);
                }

                if (!SHA256.Create().ComputeHash(keyData).ToHexString().Equals(_keyHashes[keyname].ToHexString()))
                {
                    UpdateStatus($"{keyname} in Keys.txt is invalid");
                    return (false,null);
                }
            }

            if (!Configuration.VerifyETicketRSAKEK() && keys.TryGetValue("eticket_rsa_kek", out var rsaKeyData))
                txtRSAKEK.Text = rsaKeyData.ToHexString();

            var keysText = string.Empty;
            foreach (var kvp in keys)
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
                    ExternalKeys.ReadKeyFile(_fixedKeys, keyset: _keyset);
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
                ExternalKeys.ReadKeyFile(filename, keyset: _keyset);
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
                ExternalKeys.ReadKeyFile(filename, keyset: _keyset);
                if (_sdKey != null) _keyset.SetSdSeed(_sdKey);
                return true;
            }

            UpdateStatus(@"Keys.txt missing.");
            return false;
        }

        private void btnDecryptNCA_Click(object sender, EventArgs e)
        {
            if (!CheckKeys()) return;
            if (_sdKey == null)
            {
                btnFindSDKey_Click(null, null);
                if (_sdKey == null)
                {
                    UpdateStatus("Cannot Decrypt NCAs from SD card without a valid SD Key. Assuming USER Nand with decrypted files is mounted instead.");
                }
                else
                {
                    if (!CheckKeys())
                    {
                        UpdateStatus("Cannot proceed without valid keys.");
                        return;
                    }
                }
            }

            if (!Directory.Exists(Configuration.Data.Decryptionpath))
                Directory.CreateDirectory(Configuration.Data.Decryptionpath);

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
                if (ncaFileParts.Count == 0)
                {
                    UpdateStatus($@"Cannot decrypt {Path.GetFileName(nca)} as the directory is empty - Click me and check message for details.",
                        $@"Directory ""{nca}"" is empty.");
                    continue;
                }
                var hash = SHA256.Create();
                if (_sdKey == null)
                {
                    UpdateStatus($@"Processing {Path.GetFileName(nca)} - Verifying");
                    

                    InitializeProgress((ulong) ncaFileParts.Sum(x => new FileInfo(x).Length));
                    try
                    {
                        using (var sw = new BinaryWriter(new FileStream(ncafile, FileMode.Create)))
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
                                        hash.TransformBlock(bytes, 0, bytes.Length, bytes, 0);
                                    } while (bytes.Length > 0);
                                }
                            }

                            hash.TransformFinalBlock(new byte[0], 0, 0);
                        }
                    }
                    catch (Exception ex)
                    {
                        AppendStatus(", Failed. Check message box above to see why.",
                            $@"Failed to Verify ""{Path.GetFileName(nca)}"" due to an exception:{Environment.NewLine}{
                                    ex.Message
                                }{Environment.NewLine}{ex.StackTrace}{Environment.NewLine}{Environment.NewLine}");
                        try
                        {
                            if (File.Exists(ncafile))
                                File.Delete(ncafile);
                        }
                        catch
                        {
                            //
                        }

                        continue;
                    }


                    var result = nca.ToLowerInvariant()
                        .Contains(hash.Hash.Take(16).ToArray().ToHexString().ToLowerInvariant());

                    if (!result)
                    {
                        AppendStatus($", Failed. NCA File {Path.GetFileName(nca)} is either corrupted or encrypted.");
                        if (File.Exists(ncafile))
                            File.Delete(ncafile);
                    }
                    else
                    {
                        AppendStatus(", Done.");
                    }

                    continue;
                }
                
                using (var naxfile = new Nax0(_keyset, OpenSplitNcaStream(nca), $@"/registered/{Path.GetFileName(Path.GetDirectoryName(nca))}/{Path.GetFileName(nca)}", false))
                {
                    using (var ncaData = new Nca(_keyset, naxfile.Stream, true))
                    {
                        if (ncaData.Header.ContentType != ContentType.Control &&
                            ncaData.Header.ContentType != ContentType.Meta)
                            continue;
                    }
                    UpdateStatus($@"Processing {Path.GetFileName(nca)} - Decrypting");
                    InitializeProgress((ulong)ncaFileParts.Sum(x => new FileInfo(x).Length));

                    naxfile.Stream.Position = 0;

                    using (var sw = new BinaryWriter(new FileStream(ncafile, FileMode.Create)))
                    {
                        using (var sr = new BinaryReader(naxfile.Stream))
                        {
                            byte[] bytes;
                            do
                            {
                                bytes = sr.ReadBytes(0x100000);
                                if (bytes.Length <= 0) continue;

                                sw.Write(bytes);
                                UpdateProgress((ulong)bytes.LongLength);
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

            HideProgress();
            UpdateStatus($@"NCA Decryption completed.");
        }

        private static Stream OpenSplitNcaStream(string path)
        {
            List<string> files = new List<string>();
            List<Stream> streams = new List<Stream>();

            if (Directory.Exists(path))
            {
                while (true)
                {
                    var partName = Path.Combine(path, $"{files.Count:D2}");
                    if (!File.Exists(partName)) break;

                    files.Add(partName);
                }
            }
            else if (File.Exists(path))
            {
                if (Path.GetFileName(path) != "00")
                {
                    return File.Open(path, FileMode.Open, FileAccess.Read);
                }
                files.Add(path);
            }
            else
            {
                throw new FileNotFoundException("Could not find the input file or directory");
            }

            foreach (var file in files)
            {
                streams.Add(File.Open(file, FileMode.Open, FileAccess.Read));
            }

            if (streams.Count == 0) return null;

            var stream = new CombinationStream(streams);
            return stream;
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
            var ncaFile = new Nca(_keyset, File.Open(Path.Combine(Configuration.Data.Decryptionpath, entry.NcaId.ToHexString() + ".nca"),FileMode.Open, FileAccess.Read), false);
            var section = ncaFile.OpenSection(0, false);
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

        private bool PackNSP(Cnmt cnmt)
        {
            var tid = $"{cnmt.TitleId:x16}".ToByte();

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

            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (cnmt.Type)
            {
                case TitleType.Application:
                    titleName += $@" [{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsp";
                    break;
                case TitleType.Patch:
                    titleName += $@" [UPD][{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsp";
                    break;
                default:
                    titleName += $@" [DLC][{cnmt.TitleId:X16}][v{cnmt.TitleVersion.Version}].nsp";
                    break;
            }

            if (!_tickets.TryGetValue($"{cnmt.TitleId:x16}", out var ticket))
            {
                UpdateStatus($@"{titleName} cannot be packed. Ticket missing.");
                return false;
            }

            UpdateStatus($@"Packing {titleName}");

            var status = Pack(ticket, $"{cnmt.TitleId:x16}", titleName);
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

        public (bool, string[]) Pack(Ticket ticket, string cnmtTitleID, string baseTitle)
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

                var cnmt = _cnmtFiles[cnmtTitleID];
                var cnmtNcaFile = _cnmtNcaFiles[cnmtTitleID];


                var types = new List<CnmtContentType>
                {
                    CnmtContentType.Program,
                    CnmtContentType.LegalHtml,
                    CnmtContentType.Data,
                    CnmtContentType.OfflineManualHtml,
                    CnmtContentType.Control
                };

                var sdfiles = Configuration.GetSDDirectories;

                var exitEntries = new List<CnmtContentEntry>();
                exitEntries.AddRange(from type in types
                    from entry in cnmt.ContentEntries
                    where entry.Type == type
                    //where !File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    where sdfiles.All(x => !x.EndsWith($"{entry.NcaId.ToHexString()}.nca"))
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
                types.Add(CnmtContentType.UpdatePatch);

                var startingEntries = new List<CnmtContentEntry>();
                var controlEntries = new List<CnmtContentEntry>();
                startingEntries.AddRange(from type in types
                    from entry in cnmt.ContentEntries
                    where entry.Type == type
                    //where File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    where sdfiles.Any(x => x.EndsWith(entry.NcaId.ToHexString() + ".nca"))
                    select entry);
                controlEntries.AddRange(from entry in cnmt.ContentEntries
                    where entry.Type == CnmtContentType.Control
                    //where File.Exists(Path.Combine(Configuration.Data.Decryptionpath, entry.ID.ToHexString() + ".nca"))
                    where sdfiles.Any(x => x.EndsWith(entry.NcaId.ToHexString() + ".nca"))
                    select entry);

                var packFiles = new List<string>
                {
                    ticket.RightsID.ToHexString() + ".cert",
                    ticket.RightsID.ToHexString() + ".tik",
                    $"{cnmtNcaFile.NcaId.ToHexString()}.cnmt.nca",
                };

                packFiles.InsertRange(2, from entry in startingEntries select entry.NcaId.ToHexString() + ".nca");
                packFiles.AddRange(from entry in controlEntries select entry.NcaId.ToHexString() + ".nca");

                var fileSizes = new List<ulong>
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
                            WriteNCAtoNSP(nspFile, sw, entry);
                        }

                        WriteNCAtoNSP(nspFile, sw, cnmtNcaFile);
                        //sw.Write(xml);

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

        private void WriteNCAtoNSP(FileStream nspFile, BinaryWriter sw, CnmtContentEntry entry)
        {
            var hash = SHA256.Create();
            var filename = Configuration.GetSDDirectories.FirstOrDefault(x => x.EndsWith(entry.NcaId.ToHexString() + ".nca"));
            if(filename == null)
                throw new Exception($@"{entry.NcaId.ToHexString()}.nca does not exist.");

            using (var ncaFile = new Nax0(_keyset, OpenSplitNcaStream(filename), $@"/registered/{Path.GetFileName(Path.GetDirectoryName(filename))}/{Path.GetFileName(filename)}", false))
            {
                using (var sr = new BinaryReader(ncaFile.Stream))
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
                    throw new Exception($@"{entry.NcaId.ToHexString()}.nca is corrupted.");
            }
        }

        private void btnParseNCA_Click(object sender, EventArgs e)
        {
            if (_sdKey == null)
            {
                btnFindSDKey_Click(null, null);
            }
            if (_sdKey == null || !CheckKeys()) return;
           
            UpdateStatus($@"Parsing Decrypted NCA files");

            var ncadir = Path.Combine("tools", "nca");
            if (!Directory.Exists(ncadir))
                Directory.CreateDirectory(ncadir);

            if (!Directory.Exists(Configuration.Data.Decryptionpath))
                Directory.CreateDirectory(Configuration.Data.Decryptionpath);

            var ncaFiles = Configuration.GetDecryptedNCAFiles;
            InitializeProgress((ulong)ncaFiles.Length);
            ClearGameImageLists();

            var controls = new List<Cnmt>();
            var metas = new List<Cnmt>();

            for (var j = 0; j < ncaFiles.Length; j++)
            {
                var ncafile = ncaFiles[j];
                SetProgress((ulong)j + 1);

                using (var ncaStream = File.Open(ncafile, FileMode.Open, FileAccess.Read))
                {
                    using (var ncaData = new Nca(_keyset, ncaStream, true))
                    {
                        if (ncaData.Header.ContentType != ContentType.Meta)
                            continue;
                        var section = ncaData.OpenSection(0, false);
                        var pfs = new Pfs(section);
                        var cnmt = new Cnmt(pfs.OpenFile(pfs.Files[0]));
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
            var sdcard = Configuration.GetSDDirectories;
            var deleteSuccess = true;
            UpdateStatus($@"Deleting {childNode.Parent.Text} - {childNode.Text}");
            var tid = $"{cnmt.TitleId:x16}";
            var entries = cnmt.ContentEntries.ToList();
            entries.Add(_cnmtNcaFiles[tid]);
            foreach (var entry in entries)
            {
                var ncafile = sdcard.FirstOrDefault(x => x.Contains(entry.NcaId.ToHexString()));
                if (ncafile != null)
                    deleteSuccess &= DeleteSDNCA(ncafile);
                else
                    deleteSuccess &= DeleteLocalNCA(entry.NcaId.ToHexString() + ".nca");
            }

            _cnmtFiles.Remove(tid);
            _cnmtNcaFiles.Remove(tid);

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
            var languages = result
                ? nacp.Languages
                : new List<Languages>();

            pbGameIcon.Image = data.Item5;
            txtGameInfo.Text = !result 
                ? string.Empty
                    : $@"Game: {data.Item1}{Environment.NewLine
                    }Devloper: {data.Item2}{Environment.NewLine
                    }Version: {data.Item3}{Environment.NewLine
                    }Base Title ID: {data.Item4}{Environment.NewLine}";

            txtGameInfo.Text += AddNCAMetaInfo();

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
                    }Devloper: {data.Item2}{Environment.NewLine
                    }Version: {data.Item3}{Environment.NewLine
                    }Base Title ID: {data.Item4}{Environment.NewLine}";
            }
            else
            {
                var index = (int) languageNode.Tag;
                pbGameIcon.Image = nacp.Icons[index];
                txtGameInfo.Text = $@"Game: {nacp.TitleNames[index]}{Environment.NewLine
                    }Devloper: {nacp.DeveloperNames[index]}{Environment.NewLine
                    }Version: {nacp.Version}{Environment.NewLine
                    }Base Title ID: {nacp.BaseTitleID}{Environment.NewLine}";
            }

            txtGameInfo.Text += AddNCAMetaInfo();
        }

        private string AddNCAMetaInfo()
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
            var entries = cnmt.ContentEntries.ToList();
            entries.Insert(0, _cnmtNcaFiles[$"{cnmt.TitleId:x16}"]);

            output += $@"Title ID: {tvGames.SelectedNode.Tag}{Environment.NewLine}";
            output += titlekey;
            output += $@"Type: {cnmt.Type}{Environment.NewLine}{Environment.NewLine}";
            
            var sdFiles = Configuration.GetSDDirectories;
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

        private void cbRSAKey_TextChanged(object sender, EventArgs e)
        {
            if (Configuration.Data.RSAKeys.TryGetValue(cbRSAKey.Text.ToUpperInvariant(), out _))
            {
                cbRSAKey.SelectedItem = cbRSAKey.Text.ToUpperInvariant();
                cbRSAKey_SelectedIndexChanged(sender, e);
            }
        }

        private void cbRSAKey_SelectedIndexChanged(object sender, EventArgs e)
        {
            var item = cbRSAKey.SelectedItem;
            if (item is string serialNumber && Configuration.Data.RSAKeys.TryGetValue(serialNumber, out var keys))
            {
                var split = keys.Split(',');
                if (split.Length == 3 && split.All(x => x.ToByte().Length != 0))
                {
                    Ticket.RsaN = new BigInteger(split[0].ToByte());
                    Ticket.RsaD = new BigInteger(split[1].ToByte());
                    Ticket.RsaE = new BigInteger(split[2].ToByte());
                    btnLoadRSAKEK.Enabled = false;
                    return;
                }
            }

            Ticket.RsaN = BigInteger.Zero;
            Ticket.RsaD = BigInteger.Zero;
            Ticket.RsaE = BigInteger.Zero;
            btnLoadRSAKEK.Enabled = true;
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
                HttpWebRequest myHttpWebRequest =
                    (HttpWebRequest) WebRequest.Create(Configuration.Data.TitleKeyDataBaseURL);
                myHttpWebRequest.MaximumAutomaticRedirections = 1;
                myHttpWebRequest.AllowAutoRedirect = true;
                myHttpWebRequest.Timeout = 30000;
                var httpWebResponseAsync = myHttpWebRequest.GetResponseAsync();

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
                HttpWebResponse myHttpWebResponse = (HttpWebResponse)httpWebResponseAsync.Result;

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

                            var split = line.Split('|');
                            if (split.Length < 3 || split[0].ToByte().Length != 16 || split[1].ToByte().Length != 16)
                                continue;
                            split[2] = string.Join("|", split.Skip(2));

                            var typeBytes = split[0].Substring(12, 4).ToByte();
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

            UpdateStatus("Extracting Title Key log");
            var tickets = _personalTickets.Values.Where(x => !_databaseTitleNames.ContainsKey(x.TitleID.ToHexString())).ToArray();
            InitializeProgress((ulong) tickets.Length);

            for(var i = 0; i < tickets.Length; i++)
            {
                UpdateProgress(1);
                var ticket = tickets[i];
                if (!ticket.Anonymize())
                {
                    for (var j = 1; j < cbRSAKey.Items.Count; j++)
                    {
                        cbRSAKey.SelectedIndex = j;
                        cbRSAKey_SelectedIndexChanged(null, null);
                        if (ticket.Anonymize()) break;
                    }

                    if (!ticket.Anonymize())
                        continue;
                }

                if (ticket.Data[0x140] == 0 && ticket.Data[0x141] == 0 && ticket.Data[0x142] == 0 && ticket.Data[0x143] == 0)
                    continue;

                var issuer = Encoding.UTF8.GetString(ticket.Data.Skip(0x140).Take(0x40).ToArray());
                var index = issuer.IndexOf("\0", StringComparison.Ordinal);
                if (index > 0) issuer = issuer.Substring(0, index);

                if (!issuer.StartsWith("Root"))
                    titlekeydump += $"Unknown Ticket verifier: {issuer}{Environment.NewLine}";

                titlekeydump += $"Ticket {i}:{Environment.NewLine}";
                titlekeydump += $"    Rights ID: {ticket.RightsID.ToHexString()}{Environment.NewLine}";
                titlekeydump += $"    Title ID:  {ticket.TitleID.ToHexString()}{Environment.NewLine}";
                titlekeydump += $"    Titlekey:  {ticket.TitleKey.ToHexString()}{Environment.NewLine}";
            }

            HideProgress();
            if (titlekeydump == string.Empty)
            {
                UpdateStatus("No Title keys to show");
                return;
            }

            try
            {
                File.WriteAllText("personal_keys.txt", titlekeydump);
                UpdateStatus("Title keys saved to personal_keys.txt", titlekeydump);
            }
            catch
            {
                UpdateStatus("Click this log entry to see Title key dump", titlekeydump);
            }
        }
    }
}
