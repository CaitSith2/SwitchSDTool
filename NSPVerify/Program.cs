using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using libhac;

namespace NSPVerify
{
    class Program
    {
        static void Main(string[] args)
        {
            var path = args.Length >= 1 
                ? args[0] 
                : Environment.CurrentDirectory;

            var fs = new FileSystem(path);

            if (!File.Exists("keys.txt"))
            {
                Console.WriteLine("Cannot verify NSPs without keys.txt");
                Console.WriteLine();
                Console.WriteLine("Press any key to continue");
                Console.ReadKey();
                return;
            }

            var keyset = ExternalKeys.ReadKeyFile("keys.txt");
            var badlist = new List<string>();
            var exceptionlist = new List<string>();



            foreach (var file in fs.GetFileSystemEntries("", "*.nsp", SearchOption.AllDirectories))
            {
                var filename = Path.GetFileName(file);
                var progress = $"Checking {filename}: ";
                Console.Write(progress);
                try
                {
                    bool ok = true;
                    using (var nspfile = fs.OpenFile(file, FileMode.Open, FileAccess.Read))
                    {
                        
                        var nspdata = new Pfs(nspfile);
                        var cnmtfile = nspdata.Files.FirstOrDefault(x => x.Name.ToLowerInvariant().EndsWith(".cnmt.nca"));
                        if (cnmtfile == null)
                        {
                            Console.WriteLine($"\rChecking {filename}: No cnmt.nca file present");
                            badlist.Add(filename);
                            continue;
                        }

                        var cnmtdata = nspdata.OpenFile(cnmtfile);
                        Cnmt cnmt;
                        using (var sr = new BinaryReader(cnmtdata))
                        {
                            var cnmthash = SHA256.Create().ComputeHash(sr.ReadBytes((int) cnmtdata.Length));
                            if (!cnmtfile.Name.ToLowerInvariant().Contains(cnmthash.Take(16).ToArray().ToHexString()))
                            {
                                //Put failure here
                                Console.WriteLine($"\rChecking {filename}: cnmt.nca file is corrupted");
                                badlist.Add(filename);
                                cnmtdata.Dispose();
                                continue;
                            }

                            cnmtdata.Position = 0;
                            var cnmtnca = new Nca(keyset, cnmtdata, false);
                            var section = cnmtnca.OpenSection(0, false);
                            var sectionpfs = new Pfs(section);
                            cnmt = new Cnmt(sectionpfs.OpenFile(sectionpfs.Files[0]));
                        }
                        
                        foreach (var entry in cnmt.ContentEntries)
                        {
                            var entryfile = nspdata.Files.FirstOrDefault(x => x.Name.ToLowerInvariant().EndsWith(entry.NcaId.ToHexString() + ".nca"));
                            if (entryfile == null)
                            {
                                if (entry.Type != CnmtContentType.UpdatePatch)
                                {
                                    //Put failure here
                                    Console.WriteLine($"\rChecking {filename}: one of the entries required by the cnmt.nca is missing.");
                                    badlist.Add(filename);
                                    break;
                                }

                                continue;
                            }

                            using (var entrynca = nspdata.OpenFile(entryfile))
                            {
                                var hash = SHA256.Create();

                                using (var sr = new BinaryReader(entrynca))
                                {
                                    while (entrynca.Length != entrynca.Position)
                                    {
                                        var entryncadata = sr.ReadBytes(0x100000);
                                        hash.TransformBlock(entryncadata, 0, entryncadata.Length, entryncadata, 0);
                                        Console.Write($"\rChecking {filename}: {((entrynca.Position * 100.0) / entrynca.Length):0.0}%");
                                    }

                                    hash.TransformFinalBlock(new byte[0], 0, 0);
                                }

                                if (hash.Hash.ToHexString().Equals(entry.Hash.ToHexString()))
                                {
                                    Console.Write($"\rChecking {filename}: {100:0.0}%");
                                    continue;
                                }

                                //Put failure here
                                Console.WriteLine($"\rChecking {filename}: one of the entries required by the cnmt.nca is corrupted");
                                badlist.Add(filename);
                                ok = false;
                                break;
                            }
                        }

                        if(ok)
                            Console.WriteLine($"\rChecking {filename}: OK        ");
                        //Put Success here
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine(ex.StackTrace);
                    exceptionlist.Add($"{filename}{Environment.NewLine}Exception: {ex.Message}{Environment.NewLine}Stack Trace: {ex.StackTrace}{Environment.NewLine}");
                }
            }

            File.WriteAllText("Corrupted NSPs.txt", string.Join(Environment.NewLine, badlist));
            File.WriteAllText("Exception Log.txt", string.Join(Environment.NewLine, exceptionlist));

            Console.WriteLine();
            Console.WriteLine("Press any key to continue");
            Console.ReadKey();
        }
    }

    public static class Util
    {
        public static string ToHexString(this byte[] bytes)
        {
            return string.Join("", (bytes ?? new byte[0]).Select(x => $"{x:x2}"));
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
    }
}
