using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using LibHac;

namespace NSPVerify
{
    class Program
    {
        private static string _path;

        static void PressAnyKey()
        {
            if (!_path.Equals(Environment.CurrentDirectory)) return;
            Console.WriteLine();
            Console.WriteLine("Press any key to continue");
            Console.ReadKey();
        }

        
        static void Main(string[] args)
        {
            Console.WriteLine("Nintendo Switch NSP Verifier v1.00");
            Console.WriteLine("Copyright 2018 CaitSith2");
            Console.WriteLine("");

            _path = args.Length >= 1 
                ? string.Join(" ", args)
                : Environment.CurrentDirectory;

            if (new[] {"--help", "-h"}.Any(x => x.Equals(_path, StringComparison.InvariantCultureIgnoreCase)))
            {
                Console.WriteLine("Usage: NSPVerify [path to NSP directory]");
                Console.WriteLine("");
                Console.WriteLine("If the tool is run without specifying a path, it will look for NSPs in the current directory and ALL sub-directories of current directory");
                return;
            }

            

            if (!Directory.Exists(_path))
            {
                Console.WriteLine("ERROR: Specified directory does not exist.  specify --help for usage information.");
                return;
            }

            var fs = new FileSystem(_path);

            var keys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".switch", "prod.keys");
            if (File.Exists("keys.txt"))
                keys = "keys.txt";

            if (!File.Exists(keys))
            {
                Console.WriteLine($"Cannot verify NSPs without keys.txt. Either put it in the same directory as this tool,");
                Console.WriteLine($"or place it in \"{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".switch")}\" named as prod.keys");
                PressAnyKey();
                return;
            }

            var keyset = ExternalKeys.ReadKeyFile(keys);
            var badlist = new List<string>();
            var exceptionlist = new List<string>();

            var files = fs.GetFileSystemEntries("", "*.nsp", SearchOption.AllDirectories).ToList();
            files.AddRange(fs.GetFileSystemEntries("", "*.nsx", SearchOption.AllDirectories));

            if (files.Count == 0)
            {
                Console.WriteLine("Error: No NSP/NSX files in specified directory");
                PressAnyKey();
                return;
            }

            foreach (var file in files)
            {
                var filename = Path.GetFileName(file);
                var relativefilename = Util.GetRelativePath(file, Path.GetFullPath(_path));
                Console.Write($"Checking {filename}: ");
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
                            badlist.Add(relativefilename);
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
                                badlist.Add(relativefilename);
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
                                    badlist.Add(relativefilename);
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
                                badlist.Add(relativefilename);
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
                    exceptionlist.Add($"{relativefilename}{Environment.NewLine}Exception: \"{ex.GetType()}\" {ex.Message}{Environment.NewLine}Stack Trace: {ex.StackTrace}{Environment.NewLine}");
                }
            }

            badlist.Insert(0, badlist.Count == 0 
                ? "None of the files are corrupted. :)" 
                : "The following NSP/NSX files are corrupted:");

            exceptionlist.Insert(0, exceptionlist.Count == 0 
                ? "No exceptions to log. :)" 
                : "Exceptions caused while parsing the following NSP/NSX files:");

            try
            {
                File.WriteAllText("Corrupted NSPs.txt", string.Join(Environment.NewLine, badlist));
                File.WriteAllText("Exception Log.txt", string.Join(Environment.NewLine, exceptionlist));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not write the output files \"Corrupted NSPs.txt\" and \"Exception Log.txt\" due to the following exception.");
                Console.WriteLine($"Exception: \"{ex.GetType()}\" {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}{Environment.NewLine}");

                Console.WriteLine(string.Join(Environment.NewLine, badlist));
                Console.WriteLine();
                Console.WriteLine(string.Join(Environment.NewLine, exceptionlist));
                Console.WriteLine();
            }

            Console.WriteLine("Done.");
            PressAnyKey();
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

        // todo Maybe make less naive
        public static string GetRelativePath(string path, string basePath)
        {
            var directory = new DirectoryInfo(basePath);
            var file = new FileInfo(path);

            string fullDirectory = directory.FullName;
            string fullFile = file.FullName;

            if (!fullFile.StartsWith(fullDirectory))
            {
                throw new ArgumentException($"{nameof(path)} is not a subpath of {nameof(basePath)}");
            }

            return fullFile.Substring(fullDirectory.Length + 1);
        }
    }
}
