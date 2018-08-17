using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Windows.Forms;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SwitchSDTool
{
    public class ConfigurationData
    {
        public string SDpath = "SD\\Nintendo\\Contents\\registered";
        public string SDPrivateFile = "SD\\Nintendo\\Contents\\private";
        public string Decryptionpath = "Decrypted";

        // ReSharper disable once InconsistentNaming
        public string NSPPath = "NSP";
        public string SystemPath = "SYSTEM"; //"A" + Path.VolumeSeparatorChar + Path.DirectorySeparatorChar;

        public string ETicketRSAKEK = "Replace me with the actual eticket_rsa_kek.";
        public List<Languages> LanguageOrder = new List<Languages>();
        public GameIconSize GameIconSize = GameIconSize.Small;
        public Size MainFormSize = new Size(932, 595);

        public Dictionary<string, string> RSAKeys =
            new Dictionary<string, string>();
    }

    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public enum Languages
    {
        [Description("American English")] AmericanEnglish = 0,
        [Description("British English")] BritishEnglish,
        Japanese,
        French,
        German,
        [Description("Latin American Spanish")] LatinAmericanSpanish,
        Spanish,
        Italian,
        Dutch,
        [Description("Canadian French")] CanadianFrench,
        Portuguese,
        Russian,
        Korean,
        Taiwanese,
        Chinese
    };

    public enum GameIconSize
    {
        ExtraSmall = 16,
        Small = 32,
        Medium = 64,
        Large = 128,
        ExtraLarge = 256
    }

    public static class Configuration
    {
        public static ConfigurationData Data = new ConfigurationData();

        private static readonly Languages[] Languages = (Languages[]) Enum.GetValues(typeof(Languages));

        public static void SetLanguageOrder(TreeView languageView)
        {
            Data.LanguageOrder.AddRange(Languages);
            Data.LanguageOrder = Data.LanguageOrder.Distinct().ToList();

            languageView.Nodes.Clear();

            foreach (var l in Data.LanguageOrder)
            {
                var node = languageView.Nodes.Add(l.ToString(), l.StringValueOf());
                node.Tag = l;
            }
        }

        // ReSharper disable once InconsistentNaming
        public static bool VerifyETicketRSAKEK()
        {
            var rsakek = Data.ETicketRSAKEK.ToByte();
            return rsakek != null && SHA256.Create().ComputeHash(rsakek).Compare("46CCCF288286E31C931379DE9EFA288C95C9A15E40B00A4C563A8BE244ECE515".ToByte());
        }

        private static readonly string ConfigurationFile = Path.Combine("Tools", "Configuration.json");

        public static void ReadConfiguration()
        {
            if (!File.Exists(ConfigurationFile))
            {
                WriteConfiguration();
                return;
            }

            try
            {
                Data = JsonConvert.DeserializeObject<ConfigurationData>(File.ReadAllText(ConfigurationFile), new StringEnumConverter());
            }
            catch
            {
                Data = new ConfigurationData();
                WriteConfiguration();
            }
        }

        public static void WriteConfiguration()
        {
            try
            {
                File.WriteAllText(ConfigurationFile, JsonConvert.SerializeObject(Data,Formatting.Indented, new StringEnumConverter()));
            }
            catch
            {
                //
            }
        }

        public static string[] GetSDDirectories
        {
            get
            {
                if (string.IsNullOrEmpty(Data.SDpath) || !Directory.Exists(Data.SDpath))
                    return new string[0];

                var root = Directory.GetDirectories(Data.SDpath);
                var directories = new List<string>();
                foreach (var r in root)
                    directories.AddRange(Directory.GetDirectories(r));
                return directories.OrderBy(x => x).ToArray();
            }
        }

        // ReSharper disable once InconsistentNaming
        public static string[] GetDecryptedNCAFiles
        {
            get
            {
                if(string.IsNullOrEmpty(Data.Decryptionpath))
                    return new string[0];

                if (!Directory.Exists(Data.Decryptionpath))
                    Directory.CreateDirectory(Data.Decryptionpath);

                return Directory.GetFiles(Data.Decryptionpath);
            }
        }
    }
}