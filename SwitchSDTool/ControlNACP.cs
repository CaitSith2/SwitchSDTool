using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;
using libhac;
using SwitchSDTool.Properties;

namespace SwitchSDTool
{
    public class ControlNACP
    {
        public string Version;
        public string BaseTitleID;
        public string[] TitleNames;
        public string[] DeveloperNames;
        public Bitmap[] Icons;
        public List<Languages> Languages;

        public (string, string, string, string, Bitmap) GetTitleNameIcon(TreeView language)
        {
            for (var i = 0; i < language.Nodes.Count; i++)
            {
                if (language.Nodes[i].Tag is Languages index
                    && (int) index < TitleNames.Length
                    && !string.IsNullOrEmpty(TitleNames[(int) index]))
                {
                    var j = (int) index;
                    return (TitleNames[j], DeveloperNames[j], Version, BaseTitleID, Icons[(int) index]);
                }
            }

            return ($"Unknown", string.Empty, string.Empty, BaseTitleID, Resources.Ultra_microSDXC_UHS_I_A1_front);
        }

        public ControlNACP(Romfs romfs, string baseTitleID)
        {
            TitleNames = new string[15];
            DeveloperNames = new string[15];
            Icons = new Bitmap[15];
            Languages = new List<Languages>();
            BaseTitleID = baseTitleID;
            using (var control = new BinaryReader(romfs.OpenFile("/control.nacp")))
            {
                var versionBytes = new byte[16];
                control.BaseStream.Seek(0x3060, SeekOrigin.Begin);
                control.Read(versionBytes, 0, 0x10);

                var version = Encoding.UTF8.GetString(versionBytes);
                var index = version.IndexOf("\0", StringComparison.Ordinal);
                if (index == 0) version = string.Empty;
                if (index > 0) version = version.Substring(0, index);
                Version = version;

                for (var i = 0; i < 15; i++)
                {
                    var offset = i * 0x300;
                    control.BaseStream.Seek(offset, SeekOrigin.Begin);
                    var titlenameBytes = new byte[0x200];
                    var developernameBytes = new byte[0x100];
                    control.Read(titlenameBytes, 0, 0x200);
                    control.Read(developernameBytes, 0, 0x100);

                    var lname = ((Languages)i).ToString();
                    lname = $"/icon_{lname}.dat";
                    if (!romfs.FileExists(lname)) continue;
                    Bitmap icon;
                    using (var bm = new Bitmap(romfs.OpenFile(lname)))
                    {
                        icon = new Bitmap(bm);
                    }
                    Languages.Add((Languages)i);

                    var titlename = Encoding.UTF8.GetString(titlenameBytes);
                    index = titlename.IndexOf("\0", StringComparison.Ordinal);
                    if (index == 0) titlename = string.Empty;
                    if (index > 0) titlename = titlename.Substring(0, index);

                    var developername = Encoding.UTF8.GetString(developernameBytes);
                    index = developername.IndexOf("\0", StringComparison.Ordinal);
                    if (index == 0) developername = string.Empty;
                    if (index > 0) developername = developername.Substring(0, index);
                    

                    TitleNames[i] = titlename;
                    DeveloperNames[i] = developername;
                    Icons[i] = icon;
                }
            }
        }
    }
}