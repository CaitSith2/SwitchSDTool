using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;
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

        public ControlNACP(string ncadir, string baseTitleID)
        {
            TitleNames = new string[15];
            DeveloperNames = new string[15];
            Icons = new Bitmap[15];
            BaseTitleID = baseTitleID;
            using (var control = File.OpenRead(Path.Combine(ncadir, "control.nacp")))
            {
                var versionBytes = new byte[16];
                control.Seek(0x3060, SeekOrigin.Begin);
                control.Read(versionBytes, 0, 0x10);

                var version = Encoding.UTF8.GetString(versionBytes);
                var index = version.IndexOf("\0", StringComparison.Ordinal);
                if (index == 0) version = string.Empty;
                if (index > 0) version = version.Substring(0, index);
                Version = version;

                for (var i = 0; i < 15; i++)
                {
                    var offset = i * 0x300;
                    control.Seek(offset, SeekOrigin.Begin);
                    var titlenameBytes = new byte[0x200];
                    var developernameBytes = new byte[0x100];
                    control.Read(titlenameBytes, 0, 0x200);
                    control.Read(developernameBytes, 0, 0x100);

                    var titlename = Encoding.UTF8.GetString(titlenameBytes);
                    if (string.IsNullOrEmpty(titlename)) continue;
                    index = titlename.IndexOf("\0", StringComparison.Ordinal);
                    if (index == 0) continue;
                    if (index > 0) titlename = titlename.Substring(0, index);

                    var developername = Encoding.UTF8.GetString(developernameBytes);
                    if (string.IsNullOrEmpty(developername)) continue;
                    index = developername.IndexOf("\0", StringComparison.Ordinal);
                    if (index == 0) continue;
                    if (index > 0) developername = developername.Substring(0, index);

                    var lname = ((Languages)i).ToString();
                    lname = Path.Combine(ncadir, $"icon_{lname}.dat");
                    if (!File.Exists(lname)) continue;
                    Bitmap icon;
                    using (var bm = new Bitmap(lname))
                    {
                        icon = new Bitmap(bm);
                    }

                    TitleNames[i] = titlename;
                    DeveloperNames[i] = developername;
                    Icons[i] = icon;
                }
            }

            foreach (var ncadirfile in Directory.GetFiles(ncadir))
                File.Delete(ncadirfile);
        }
    }
}