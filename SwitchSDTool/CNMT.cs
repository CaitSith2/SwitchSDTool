using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace SwitchSDTool
{
    public class CNMT
    {
        public enum packTypes
        {
            SystemProgram = 1,
            SystemData,
            SystemUpdate,
            BootImagePackage,
            BootImagePackageSafe,
            Application = 0x80,
            Patch,
            AddOnContent,
            Delta
        }

        public enum ncaTypes
        {
            Meta,
            Program,
            Data,
            Control,
            HtmlDocument,
            LegalInformation,
            DeltaFragment
        }


        private readonly byte[] _header;
        private readonly byte[] _section0;
        public readonly string Path;

        public packTypes Type => (packTypes) _section0[0x0C];
        public byte[] TitleID => _section0.Take(8).Reverse().ToArray();
        public uint Version => (uint) (_section0[11] << 24 | _section0[10] << 16 | _section0[9] << 8 | _section0[8]);

        public ulong SystemVersion
        {
            get
            {
                ulong result = 0;
                for (var i = 0x2F; i >= 0x28; i--)
                {
                    result <<= 8;
                    result |= _section0[i];
                }

                return result;
            }
        }

        public ulong DLSystemVersion
        {
            get
            {
                ulong result = 0;
                for (var i = 0x1F; i >= 0x18; i--)
                {
                    result <<= 8;
                    result |= _section0[i];
                }

                return result;
            }
        }

        public byte MKeyRev => _header[0x220];

        public byte[] Digest => _section0.Skip(_section0.Length - 0x20).ToArray();

        public Entry[] Entries { get; private set; }
        public byte[] XmlString { get; }
        public string XmlFileName { get; private set; }
        public string CnmtFileName { get; private set; }
        public byte[] CnmtFileData { get; private set; }

        public class Entry
        {
            public byte[] Hash;
            public byte[] ID;
            public ulong Size;
            public ncaTypes Type;
        }

        private Entry[] Parse()
        {
            var tableOffset = _section0[0x0F] << 8 | _section0[0x0E];
            var entryCount = _section0[0x11] << 8 | _section0[0x10];
            var entries = new Entry[entryCount];
            for (int i = 0; i < entryCount; i++)
            {
                var localOffset = 0x20 + tableOffset + (0x38 * i);

                entries[i] = new Entry
                {
                    Hash = _section0.Skip(localOffset + 0x00).Take(0x20).ToArray(),
                    ID = _section0.Skip(localOffset + 0x20).Take(0x10).ToArray(),
                    Size = 0,
                    Type = (ncaTypes) (_section0[localOffset + 0x37] << 8 | _section0[localOffset + 0x36])
                };
                /*Size = (ulong) (_section0[localOffset + 0x35] << 40 | _section0[localOffset + 0x34] << 32 |
                                     _section0[localOffset + 0x33] << 24 | _section0[localOffset + 0x32] << 16 |
                                     _section0[localOffset + 0x31] << 8 | _section0[localOffset + 0x30]),*/
                for (var j = 0x35; j >= 0x30; j--)
                {
                    entries[i].Size <<= 8;
                    entries[i].Size |= _section0[localOffset + j];
                }
            }

            Entries = entries;
            return entries;
        }

        private byte[] GenXML()
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = new XmlTextWriter(stream, Encoding.UTF8))
                {
                    writer.Formatting = Formatting.Indented;
                    writer.WriteStartDocument();
                    {
                        writer.WriteStartElement("ContentMeta");
                        {
                            writer.WriteStartElement("Type");
                            writer.WriteString(Type.ToString());
                            writer.WriteEndElement();

                            writer.WriteStartElement("Id");
                            writer.WriteString("0x" + TitleID.ToHexString());
                            writer.WriteEndElement();

                            writer.WriteStartElement("Version");
                            writer.WriteString(Version.ToString());
                            writer.WriteEndElement();

                            writer.WriteStartElement("RequiredDownloadSystemVersion");
                            writer.WriteString(DLSystemVersion.ToString());
                            writer.WriteEndElement();

                            var entries = Parse();
                            foreach (var entry in entries)
                            {
                                writer.WriteStartElement("Content");
                                {
                                    writer.WriteStartElement("Type");
                                    writer.WriteString(entry.Type.ToString());
                                    writer.WriteEndElement();

                                    writer.WriteStartElement("Id");
                                    writer.WriteString(entry.ID.ToHexString());
                                    writer.WriteEndElement();

                                    writer.WriteStartElement("Size");
                                    writer.WriteString(entry.Size.ToString());
                                    writer.WriteEndElement();

                                    writer.WriteStartElement("Hash");
                                    writer.WriteString(entry.Hash.ToHexString());
                                    writer.WriteEndElement();

                                    writer.WriteStartElement("KeyGeneration");
                                    writer.WriteString(MKeyRev.ToString());
                                    writer.WriteEndElement();
                                }
                                writer.WriteEndElement();
                            }

                            writer.WriteStartElement("Content");
                            {
                                writer.WriteStartElement("Type");
                                writer.WriteString(ncaTypes.Meta.ToString());
                                writer.WriteEndElement();

                                CnmtFileData = File.ReadAllBytes(Path);
                                var hash = SHA256.Create().ComputeHash(CnmtFileData);

                                CnmtFileName = hash.Take(16).ToArray().ToHexString() + ".cnmt.nca";
                                XmlFileName = hash.Take(16).ToArray().ToHexString() + ".cnmt.xml";

                                writer.WriteStartElement("Id");
                                writer.WriteString(hash.Take(16).ToArray().ToHexString());
                                writer.WriteEndElement();

                                writer.WriteStartElement("Size");
                                writer.WriteString(CnmtFileData.Length.ToString());
                                writer.WriteEndElement();

                                writer.WriteStartElement("Hash");
                                writer.WriteString(hash.ToHexString());
                                writer.WriteEndElement();

                                writer.WriteStartElement("KeyGeneration");
                                writer.WriteString(MKeyRev.ToString());
                                writer.WriteEndElement();
                            }
                            writer.WriteEndElement();

                            writer.WriteStartElement("Digest");
                            writer.WriteString(Digest.ToHexString());
                            writer.WriteEndElement();

                            writer.WriteStartElement("KeyGenerationMin");
                            writer.WriteString(MKeyRev.ToString());
                            writer.WriteEndElement();

                            writer.WriteStartElement("RequiredSystemVersion");
                            writer.WriteString(SystemVersion.ToString());
                            writer.WriteEndElement();

                            writer.WriteStartElement("PatchId");
                            {
                                var id = TitleID[6] << 8 | TitleID[7];
                                id &= 0x1FFF;
                                var patchID = "0x" + TitleID.ToHexString().Substring(0, 13) +
                                              (id == 0x800 ? "000" : "800");
                                
                                writer.WriteString(patchID);
                            }
                            writer.WriteEndElement();
                        }
                        writer.WriteEndElement();
                    }
                    writer.WriteEndDocument();
                }

                var output = Encoding.UTF8.GetString(stream.GetBuffer());
                var index = output.IndexOf("\0", StringComparison.Ordinal);
                if (index > 0) output = output.Substring(0, index);

                return Encoding.UTF8.GetBytes(output).Skip(3).ToArray();
            }
        }

        public CNMT(byte[] header, byte[] section0, string filename)
        {
            Path = filename;
            _header = header;
            _section0 = section0;
            Entries = Parse();
            XmlString = GenXML();
        }
    }
}