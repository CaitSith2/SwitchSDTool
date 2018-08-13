using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace SwitchSDTool
{
    // ReSharper disable once UnusedMember.Global
    public static class Util
    {
        public static string[] PathSplit(this string path)
        {
            return path.Split(
                new[] {Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, Path.VolumeSeparatorChar},
                StringSplitOptions.None);
        }

        public static string ToHexString(this byte[] bytes)
        {
            return string.Join("", (bytes ?? new byte[0]).Select(x => $"{x:x2}"));
        }

        //https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static byte[] ToByte(this string hex)
        {
            if(string.IsNullOrEmpty(hex) || !hex.All(x => "0123456789abcdefABCDEF".Contains(x.ToString())) || hex.Length % 2 == 1)
                return null;
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static bool Compare(this byte[] data1, byte[] data2)
        {
            int len = Math.Min(data1.Length, data2.Length);
            for (int i = 0; i < len; i++)
            {
                if (data1[i] != data2[i]) return false;
            }

            return true;
        }

        public static string StripIllegalCharacters(this string input)
        {
            input = input.Replace("*", "+");
            input = input.Replace("<", "{").Replace(">", "}");
            input = input.Replace(":", ";");
            input = input.Replace("\"", "'");
            input = input.Replace("?", "!");
            return input.Replace("/", "").Replace("\\", "").Replace("|", "");
        }

        //https://stackoverflow.com/questions/2203975/move-node-in-tree-up-or-down
        public static void MoveUp(this TreeNode node)
        {
            TreeNode parent = node.Parent;
            TreeView view = node.TreeView;
            if (parent != null)
            {
                int index = parent.Nodes.IndexOf(node);
                if (index > 0)
                {
                    parent.Nodes.RemoveAt(index);
                    parent.Nodes.Insert(index - 1, node);
                }
            }
            else if (node.TreeView.Nodes.Contains(node)) //root node
            {
                int index = view.Nodes.IndexOf(node);
                if (index > 0)
                {
                    view.Nodes.RemoveAt(index);
                    view.Nodes.Insert(index - 1, node);
                }
            }
        }

        public static void MoveDown(this TreeNode node)
        {
            TreeNode parent = node.Parent;
            TreeView view = node.TreeView;
            if (parent != null)
            {
                int index = parent.Nodes.IndexOf(node);
                if (index < parent.Nodes.Count - 1)
                {
                    parent.Nodes.RemoveAt(index);
                    parent.Nodes.Insert(index + 1, node);
                }
            }
            else if (view != null && view.Nodes.Contains(node)) //root node
            {
                int index = view.Nodes.IndexOf(node);
                if (index < view.Nodes.Count - 1)
                {
                    view.Nodes.RemoveAt(index);
                    view.Nodes.Insert(index + 1, node);
                }
            }
        }

        public static string StringValueOf(this Enum value)
        {
            var fi = value.GetType().GetField(value.ToString());
            var attributes = (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);
            return attributes.Length > 0 
                ? attributes[0].Description 
                : value.ToString();
        }

        public static object EnumValueOf(this string value, Type enumType)
        {
            string[] names = Enum.GetNames(enumType);
            foreach (string name in names)
            {
                if (StringValueOf((Enum)Enum.Parse(enumType, name)).Equals(value))
                {
                    return Enum.Parse(enumType, name);
                }
            }

            throw new ArgumentException("The string is not a description or value of the specified enum.");
        }
    }
}