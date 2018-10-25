using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using LibHac;

namespace SwitchSDTool
{
    public class Ticket
    {
        private static BigInteger RsaD;
        private static BigInteger RsaN;
        private static BigInteger RsaE;

        private static RSAParameters _params;
        private static bool _rsaCracked = false;

        private static readonly Dictionary<string, RSAParameters> RsaParameters = new Dictionary<string, RSAParameters>();

        private static readonly MethodInfo RecoverRsaParametersMethod = typeof(Crypto).GetMethod("RecoverRsaParameters", BindingFlags.NonPublic | BindingFlags.Static);

        public static void UpdateRSAKey()
        {
            UpdateRSAKey(0, 0, 0);
        }

        public static void UpdateRSAKey(BigInteger D, BigInteger N, BigInteger E)
        {
            try
            {
                RsaE = E;
                RsaD = D;
                RsaN = N;

                if (RsaE != 0x10001)
                {
                    ValidRSAKey = false;
                    _rsaCracked = false;
                    return;
                }
                

                var key = $"{D.ToByteArray().ToHexString()}{N.ToByteArray().ToHexString()}";

                if (RsaParameters.TryGetValue(key, out _params))
                {
                    ValidRSAKey = true;
                    _rsaCracked = true;
                }
                else if (RecoverRsaParametersMethod != null)
                {
                    _params = (RSAParameters)RecoverRsaParametersMethod.Invoke(null, new object[] {N, E, D});
                    if (TestRsaKey())
                    {
                        RsaParameters[key] = _params;
                        _rsaCracked = true;
                        ValidRSAKey = true;
                    }
                    else
                    {
                        _rsaCracked = false;;
                        ValidRSAKey = TestPublicPrivateKeySet();
                    }
                }
                else
                {
                    _rsaCracked = false; ;
                    ValidRSAKey = TestPublicPrivateKeySet();
                }
            }
            catch
            {
                _rsaCracked = false; ;
                ValidRSAKey = TestPublicPrivateKeySet();
            }
        }

        private static bool TestRsaKey()
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(_params);

            var test = new byte[] { 12, 34, 56, 78 };
            byte[] testEnc = rsa.Encrypt(test, false);
            byte[] testDec = rsa.Decrypt(testEnc, false);

            return LibHac.Util.ArraysEqual(test, testDec);
        }

        private static bool TestPublicPrivateKeySet()
        {
            BigInteger test = 0xCAFEBABE;
            var encrypted = BigInteger.ModPow(test, RsaD, RsaN);
            var decrypted = BigInteger.ModPow(encrypted, RsaE, RsaN);
            return test == decrypted;
        }

        public static bool ValidRSAKey { get; private set; }

        private static readonly byte[] CommonData = 
            ("04000100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +            //000-03F
             "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +            //040-07F
             "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +            //080-0BF
             "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +            //0C0-0FF
             "FFFFFFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +            //100-13F
             "526F6F742D434130303030303030332D585330303030303032300000000000000000000000000000000000000000000000000000000000000000000000000000" +            //140-17F
             /*00000000000000000000000000000000*/"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +            //180-1BF
             "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +            //1C0-1FF
             "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +            //200-23F
             "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +            //240-27F
             "0200"+/*00000000*/"0000000000000000000000000000000000000000000000000000"+/*00000000000000000000000000000000*/"0000000000000000C002000000000000").ToByte();   //280-2BF

        public static readonly byte[] CA3 =
            ("00010003704138EFBBBDA16A987DD901326D1C9459484C88A2861B91A312587AE70EF6237EC50E1032DC39DDE89A96A8E859D76A98A6E7E36A0CFE352CA89305" +
             "8234FF833FCB3B03811E9F0DC0D9A52F8045B4B2F9411B67A51C44B5EF8CE77BD6D56BA75734A1856DE6D4BED6D3A242C7C8791B3422375E5C779ABF072F7695" +
             "EFA0F75BCB83789FC30E3FE4CC8392207840638949C7F688565F649B74D63D8D58FFADDA571E9554426B1318FC468983D4C8A5628B06B6FC5D507C13E7A18AC1" +
             "511EB6D62EA5448F83501447A9AFB3ECC2903C9DD52F922AC9ACDBEF58C6021848D96E208732D3D1D9D9EA440D91621C7A99DB8843C59C1F2E2C7D9B577D512C" +
             "166D6F7E1AAD4A774A37447E78FE2021E14A95D112A068ADA019F463C7A55685AABB6888B9246483D18B9C806F474918331782344A4B8531334B26303263D9D2" +
             "EB4F4BB99602B352F6AE4046C69A5E7E8E4A18EF9BC0A2DED61310417012FD824CC116CFB7C4C1F7EC7177A17446CBDE96F3EDD88FCD052F0B888A45FDAF2B63" +
             "1354F40D16E5FA9C2C4EDA98E798D15E6046DC5363F3096B2C607A9D8DD55B1502A6AC7D3CC8D8C575998E7D796910C804C495235057E91ECD2637C9C1845151" +
             "AC6B9A0490AE3EC6F47740A0DB0BA36D075956CEE7354EA3E9A4F2720B26550C7D394324BC0CB7E9317D8A8661F42191FF10B08256CE3FD25B745E5194906B4D" +
             "61CB4C2E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
             "526F6F74000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
             "00000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
             "000000007BE8EF6CB279C9E2EEE121C6EAF44FF639F88F078B4B77ED9F9560B0358281B50E55AB721115A177703C7A30FE3AE9EF1C60BC1D974676B23A68CC04" +
             "B198525BC968F11DE2DB50E4D9E7F071E562DAE2092233E9D363F61DD7C19FF3A4A91E8F6553D471DD7B84B9F1B8CE7335F0F5540563A1EAB83963E09BE90101" +
             "1F99546361287020E9CC0DAB487F140D6626A1836D27111F2068DE4772149151CF69C61BA60EF9D949A0F71F5499F2D39AD28C7005348293C431FFBD33F6BCA6" +
             "0DC7195EA2BCC56D200BAF6D06D09C41DB8DE9C720154CA4832B69C08C69CD3B073A0063602F462D338061A5EA6C915CD5623579C3EB64CE44EF586D14BAAA88" +
             "34019B3EEBEED3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").ToByte();

        public static readonly byte[] XS20 =
            ("00010004969FE8288DA6B9DD52C7BD63642A4A9AE5F053ECCB93613FDA37992087BD9199DA5E6797618D77098133FD5B05CD8288139E2E975CD2608003878CDA" +
             "F020F51A0E5B7692780845561B31C61808E8A47C3462224D94F736E9A14E56ACBF71B7F11BBDEE38DDB846D6BD8F0AB4E4948C5434EAF9BF26529B7EB83671D3" +
             "CE60A6D7A850DBE6801EC52A7B7A3E5A27BC675BA3C53377CFC372EBCE02062F59F37003AA23AE35D4880E0E4B69F982FB1BAC806C2F75BA29587F2815FD7783" +
             "998C354D52B19E3FAD9FBEF444C48579288DB0978116AFC82CE54DACB9ED7E1BFD50938F22F85EECF3A4F426AE5FEB15B72F022FB36ECCE9314DAD131429BFC9" +
             "675F58EE000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
             "526F6F742D4341303030303030303300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
             "00000001585330303030303032300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
             "0000000000000000D21D3CE67C1069DA049D5E5310E76B907E18EEC80B337C4723E339573F4C664907DB2F0832D03DF5EA5F160A4AF24100D71AFAC2E3AE75AF" +
             "A1228012A9A21616597DF71EAFCB65941470D1B40F5EF83A597E179FCB5B57C2EE17DA3BC3769864CB47856767229D67328141FC9AB1DF149E0C5C15AEB80BC5" +
             "8FC71BE18966642D68308B506934B8EF779F78E4DDF30A0DCF93FCAFBFA131A8839FD641949F47EE25CEECF814D55B0BE6E5677C1EFFEC6F29871EF29AA3ED91" +
             "97B0D83852E050908031EF1ABBB5AFC8B3DD937A076FF6761AB362405C3F7D86A3B17A6170A659C16008950F7F5E06A5DE3E5998895EFA7DEEA060BE9575668F" +
             "78AB1907B3BA1B7D0001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").ToByte();


        public static Dictionary<string, string> TitleKeyDatabase = new Dictionary<string, string>();



        public byte[] Data;
        public byte[] TitleKey => Data.Skip(0x180).Take(16).ToArray();
        public byte[] TitleID => Data.Skip(0x2A0).Take(8).ToArray();
        public byte[] RightsID => Data.Skip(0x2A0).Take(16).ToArray();
        public readonly bool Common;
        public string AnonymizeError = null;

        private byte[] sxor(byte[] a, byte[] b)
        {
            var x = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                x[i] = (byte)(a[i] ^ b[i]);
            return x;
        }

        private byte[] MGF1(byte[] seed, int mask_len)
        {
            var mask = new List<byte>();
            var i = 0;
            while (mask.Count < mask_len)
            {
                var seedlist = seed.ToList();
                seedlist.AddRange(BitConverter.GetBytes(i++).Reverse().ToArray());
                mask.AddRange(SHA256.Create().ComputeHash(seedlist.ToArray()));
            }

            return mask.ToArray();
        }

        public Ticket(byte[] data)
        {
            if(data == null || data.Length < 0x2C0) throw new Exception("Bad data");
            Data = data;

            var titlekey = new List<byte>() { 0 };
            titlekey.AddRange(Data.Skip(0x180).Take(0x100));
            Common = Enumerable.Range(0x10, 0xF0).All(x => titlekey[x + 1] == 0);
        }

        public Ticket(string rightsID, string titleKey)
        {
            var rightsIDBytes = rightsID.ToByte();
            var titleKeyBytes = titleKey.ToByte();

            if(rightsIDBytes.Length != 16) throw new InvalidDataException("Rights ID must by 32 hex characters long");
            if(titleKeyBytes.Length != 16) throw new InvalidDataException("tilekey must be 32 hex characters long");

            var pticket = new List<byte>(CommonData);
            pticket.InsertRange(0x180, titleKeyBytes);
            pticket.InsertRange(0x283, rightsIDBytes.Skip(12).Take(4));
            pticket.InsertRange(0x2A0, rightsIDBytes);
            Data = pticket.ToArray();

            if (Data.Length != 0x2C0) throw new Exception("Could not create a ticket with the supplied rightsID and titlekey");
            TitleKeyDatabase[rightsID] = titleKey;
            Common = true;
        }

        
        public bool Anonymize()
        {
            AnonymizeError = null;
            var titlekey = new List<byte>() { 0 };
            titlekey.AddRange(Data.Skip(0x180).Take(0x100));

            if (Enumerable.Range(0x10, 0xF0).All(x => titlekey[x + 1] == 0))
            {
                return true;
            }

            if (!ValidRSAKey)
            {
                AnonymizeError = "Cannot pack without RSA Key.";
                return false;
            }

            if (_rsaCracked)
            {
                try
                {
                    var pticket = new List<byte>(CommonData);
                    pticket.InsertRange(0x180, Crypto.DecryptTitleKey(Data.Skip(0x180).Take(0x100).ToArray(), _params).Take(16));
                    pticket.InsertRange(0x283, Data.Skip(0x2AC).Take(4));
                    pticket.InsertRange(0x2A0, Data.Skip(0x2A0).Take(16));

                    if (pticket.Count != 0x2C0)
                    {
                        AnonymizeError = "Error: Ticket not expected size";
                        return false;
                    }

                    Data = pticket.ToArray();
                    TitleKeyDatabase[RightsID.ToHexString()] = TitleKey.ToHexString();


                    return true;
                }
                catch (Exception ex)
                {
                    AnonymizeError = "ERROR: Extracted RSA Key is not for this ticket.";
                    //return false;
                }
            }

            titlekey.Reverse();
            var encrypted = new BigInteger(titlekey.ToArray());
            var decrypted = BigInteger.ModPow(encrypted, RsaD, RsaN).ToByteArray().Reverse().ToList();
            while (decrypted.Count < 0x100)
                decrypted.Insert(0, 0);
            var keyblob0 = decrypted.Skip(1).Take(0x20).ToArray();
            var keyblob1 = decrypted.Skip(1).Skip(0x20).ToArray();
            var seed = sxor(keyblob0, MGF1(keyblob1, 0x20));
            var sdata = sxor(keyblob1, MGF1(seed, 0xDF));
            if (!sdata.Compare("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".ToByte()))
            {
                AnonymizeError = "ERROR: Extracted RSA Key is not for this ticket.";
                return false;
            }
            for (int i = 0x20; i < sdata.Length - 17; i++)
            {
                if (sdata[i] != 0)
                {
                    AnonymizeError = "ERROR: Extracted RSA Key is not for this ticket.";
                    return false;
                }
                if (sdata[i + 1] == 0) continue;
                if (sdata[i + 1] != 1)
                {
                    AnonymizeError = "ERROR: Extracted RSA Key is not for this ticket.";
                    return false;
                }

                var pticket = new List<byte>(CommonData);
                pticket.InsertRange(0x180, sdata.Skip(i + 2).Take(16));
                pticket.InsertRange(0x283, Data.Skip(0x2AC).Take(4));
                pticket.InsertRange(0x2A0, Data.Skip(0x2A0).Take(16));
                Data = pticket.ToArray();
                TitleKeyDatabase[RightsID.ToHexString()] = TitleKey.ToHexString();
                return true;
            }

            AnonymizeError = "ERROR: Extracted RSA Key is not for this ticket.";
            return false;
        }

        public override string ToString()
        {
            return $@"{TitleID.ToHexString().ToUpperInvariant()}={TitleKey.ToHexString().ToUpperInvariant()}";
        }
    }
}