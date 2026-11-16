# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
Get-Item "$env:SystemRoot\System32\bcrypt.dll", "$env:SystemRoot\System32\bcryptprimitives.dll" |
    Select-Object Name, @{Name = 'Version'; Expression = { $_.VersionInfo.FileVersion }}

Add-Type -TypeDefinition @'
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

public static class NativePqcProbe
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr handle, string algorithm, string provider, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr handle, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateKeyPair(IntPtr algorithm, out IntPtr key, uint length, uint flags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr handle, string property, byte[] value, uint length, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptFinalizeKeyPair(IntPtr key, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr key);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptImportKeyPair(IntPtr algorithm, IntPtr importKey, string type, out IntPtr key, byte[] blob, uint length, uint flags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptExportKey(IntPtr key, IntPtr exportKey, string type, byte[] output, uint length, out uint written, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptSignHash(IntPtr key, IntPtr padding, byte[] input, uint inputLength, byte[] output, uint outputLength, out uint written, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptVerifySignature(IntPtr key, IntPtr padding, byte[] input, uint inputLength, byte[] signature, uint signatureLength, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptEncapsulate(IntPtr key, byte[] secret, uint secretLength, out uint secretWritten, byte[] ciphertext, uint ciphertextLength, out uint ciphertextWritten, uint flags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecapsulate(IntPtr key, byte[] ciphertext, uint ciphertextLength, byte[] secret, uint secretLength, out uint written, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct PaddingInfo
    {
        public IntPtr Context;
        public uint ContextLength;
        public IntPtr PrehashAlgorithm;
    }

    private sealed class Key : IDisposable
    {
        public IntPtr Handle;
        public Key(IntPtr handle) { Handle = handle; }
        public void Dispose()
        {
            if (Handle == IntPtr.Zero) return;
            var handle = Handle;
            Handle = IntPtr.Zero;
            Check(BCryptDestroyKey(handle), "BCryptDestroyKey");
        }
    }

    private static void Check(int status, string operation)
    {
        if (status < 0)
            throw new InvalidOperationException(operation + ": NTSTATUS 0x" + unchecked((uint)status).ToString("X8"));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static Key Generate(IntPtr algorithm, string parameter)
    {
        IntPtr handle;
        Check(BCryptGenerateKeyPair(algorithm, out handle, 0, 0), "BCryptGenerateKeyPair");
        var key = new Key(handle);
        try
        {
            byte[] name = Encoding.Unicode.GetBytes(parameter + "\0");
            Check(BCryptSetProperty(handle, "ParameterSetName", name, (uint)name.Length, 0), "BCryptSetProperty(ParameterSetName)");
            Check(BCryptFinalizeKeyPair(handle, 0), "BCryptFinalizeKeyPair");
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static Key Import(IntPtr algorithm, string type, byte[] blob)
    {
        IntPtr handle;
        Check(BCryptImportKeyPair(algorithm, IntPtr.Zero, type, out handle, blob, (uint)blob.Length, 0), "BCryptImportKeyPair(" + type + ")");
        return new Key(handle);
    }

    private static byte[] Export(Key key, string type)
    {
        uint length;
        Check(BCryptExportKey(key.Handle, IntPtr.Zero, type, null, 0, out length, 0), "BCryptExportKey size(" + type + ")");
        byte[] blob = new byte[length];
        try
        {
            uint written;
            Check(BCryptExportKey(key.Handle, IntPtr.Zero, type, blob, length, out written, 0), "BCryptExportKey(" + type + ")");
            Require(written == length, "Exported blob length changed");
            return blob;
        }
        catch
        {
            Array.Clear(blob, 0, blob.Length);
            throw;
        }
    }

    private static byte[] SeedBlob(string parameter, bool dsa)
    {
        byte[] name = Encoding.Unicode.GetBytes(parameter + "\0");
        byte[] seed = Enumerable.Range(1, dsa ? 32 : 64).Select(x => (byte)x).ToArray();
        byte[] blob = new byte[12 + name.Length + seed.Length];
        Buffer.BlockCopy(BitConverter.GetBytes(dsa ? 0x53535344u : 0x534B4C4Du), 0, blob, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes((uint)name.Length), 0, blob, 4, 4);
        Buffer.BlockCopy(BitConverter.GetBytes((uint)seed.Length), 0, blob, 8, 4);
        Buffer.BlockCopy(name, 0, blob, 12, name.Length);
        Buffer.BlockCopy(seed, 0, blob, 12 + name.Length, seed.Length);
        Array.Clear(seed, 0, seed.Length);
        return blob;
    }

    private static void BlobLength(byte[] blob, string parameter, uint magic, int rawLength)
    {
        byte[] name = Encoding.Unicode.GetBytes(parameter + "\0");
        Require(blob.Length == 12 + name.Length + rawLength, "Unexpected raw key blob length");
        Require(BitConverter.ToUInt32(blob, 0) == magic, "Unexpected key blob magic");
        Require(BitConverter.ToUInt32(blob, 4) == name.Length, "Unexpected key blob parameter length");
        Require(BitConverter.ToUInt32(blob, 8) == rawLength, "Unexpected raw key length");
        Require(blob.Skip(12).Take(name.Length).SequenceEqual(name), "Unexpected parameter name");
    }

    private static void SignVerify(Key privateKey, Key publicKey, bool externalMu)
    {
        byte[] input = externalMu ? new byte[64] : Encoding.UTF8.GetBytes("native CI PQC probe");
        byte[] context = externalMu ? new byte[0] : Encoding.UTF8.GetBytes("test-context");
        uint flags = externalMu ? 0x40u : 0x20u;
        IntPtr padding = IntPtr.Zero;
        GCHandle contextHandle = default(GCHandle);
        try
        {
            if (!externalMu)
            {
                contextHandle = GCHandle.Alloc(context, GCHandleType.Pinned);
                PaddingInfo info = new PaddingInfo {
                    Context = contextHandle.AddrOfPinnedObject(),
                    ContextLength = (uint)context.Length,
                    PrehashAlgorithm = IntPtr.Zero
                };
                padding = Marshal.AllocHGlobal(Marshal.SizeOf<PaddingInfo>());
                Marshal.StructureToPtr(info, padding, false);
            }
            uint size;
            Check(BCryptSignHash(privateKey.Handle, padding, input, (uint)input.Length, null, 0, out size, flags), "BCryptSignHash size");
            byte[] signature = new byte[size];
            uint written;
            Check(BCryptSignHash(privateKey.Handle, padding, input, (uint)input.Length, signature, size, out written, flags), "BCryptSignHash externalMu=" + externalMu);
            Require(written == size, "Unexpected signature length");
            Check(BCryptVerifySignature(publicKey.Handle, padding, input, (uint)input.Length, signature, written, flags), "BCryptVerifySignature externalMu=" + externalMu);
            signature[0] ^= 1;
            int invalid = BCryptVerifySignature(publicKey.Handle, padding, input, (uint)input.Length, signature, written, flags);
            Require(invalid == unchecked((int)0xC000A000), "Tampered signature did not return STATUS_INVALID_SIGNATURE: 0x" + unchecked((uint)invalid).ToString("X8"));
        }
        finally
        {
            if (padding != IntPtr.Zero) Marshal.FreeHGlobal(padding);
            if (contextHandle.IsAllocated) contextHandle.Free();
        }
    }

    private static void KemRoundTrip(Key privateKey, Key publicKey, int expectedCiphertextLength)
    {
        uint ssLength, ctLength;
        Check(BCryptEncapsulate(publicKey.Handle, null, 0, out ssLength, null, 0, out ctLength, 0), "BCryptEncapsulate size");
        Require(ssLength == 32 && ctLength == expectedCiphertextLength, "Unexpected KEM output sizes");
        byte[] ss = new byte[ssLength], recovered = new byte[ssLength], ct = new byte[ctLength];
        try
        {
            uint ssWritten, ctWritten, recoveredWritten;
            Check(BCryptEncapsulate(publicKey.Handle, ss, ssLength, out ssWritten, ct, ctLength, out ctWritten, 0), "BCryptEncapsulate");
            Require(ssWritten == ssLength && ctWritten == ctLength, "Unexpected KEM output lengths");
            Check(BCryptDecapsulate(privateKey.Handle, ct, ctLength, recovered, ssLength, out recoveredWritten, 0), "BCryptDecapsulate");
            Require(recoveredWritten == ssLength && ss.SequenceEqual(recovered), "KEM shared secrets differ");
            ct[0] ^= 1;
            Check(BCryptDecapsulate(privateKey.Handle, ct, ctLength, recovered, ssLength, out recoveredWritten, 0), "BCryptDecapsulate implicit rejection");
            Require(recoveredWritten == ssLength && !ss.SequenceEqual(recovered), "KEM implicit rejection failed");
        }
        finally
        {
            Array.Clear(ss, 0, ss.Length);
            Array.Clear(recovered, 0, recovered.Length);
        }
    }

    private static void Probe(string algorithm, string parameter, int publicLength, int privateLength, int ciphertextLength)
    {
        IntPtr provider;
        Check(BCryptOpenAlgorithmProvider(out provider, algorithm, "Microsoft Primitive Provider", 0), "BCryptOpenAlgorithmProvider(" + algorithm + ")");
        bool dsa = algorithm == "ML-DSA";
        string publicType = dsa ? "PQDSAPUBLICBLOB" : "MLKEMPUBLICBLOB";
        string privateType = dsa ? "PQDSAPRIVATEBLOB" : "MLKEMPRIVATEBLOB";
        string seedType = dsa ? "PQDSAPRIVATESEEDBLOB" : "MLKEMPRIVATESEEDBLOB";
        byte[] privateBlob = null, seedBlob = null, repeatedPrivate = null;
        try
        {
            using (Key generated = Generate(provider, parameter))
            {
                byte[] publicBlob = Export(generated, publicType);
                privateBlob = Export(generated, privateType);
                BlobLength(publicBlob, parameter, dsa ? 0x4B505344u : 0x504B4C4Du, publicLength);
                BlobLength(privateBlob, parameter, dsa ? 0x4B535344u : 0x524B4C4Du, privateLength);
                using (Key publicKey = Import(provider, publicType, publicBlob))
                using (Key privateKey = Import(provider, privateType, privateBlob))
                {
                    if (dsa)
                    {
                        SignVerify(privateKey, publicKey, false);
                        SignVerify(privateKey, publicKey, true);
                    }
                    else KemRoundTrip(privateKey, publicKey, ciphertextLength);
                }
                Console.WriteLine("PASS: " + algorithm + "-" + parameter + " keygen, raw import/export, " +
                    (dsa ? "context + external-mu sign/verify, tamper rejection" : "encapsulate/decapsulate, implicit rejection"));
            }
            seedBlob = SeedBlob(parameter, dsa);
            using (Key first = Import(provider, seedType, seedBlob))
            using (Key second = Import(provider, seedType, seedBlob))
            {
                byte[] firstPublic = Export(first, publicType);
                byte[] secondPublic = Export(second, publicType);
                Array.Clear(privateBlob, 0, privateBlob.Length);
                privateBlob = Export(first, privateType);
                repeatedPrivate = Export(second, privateType);
                Require(firstPublic.SequenceEqual(secondPublic) && privateBlob.SequenceEqual(repeatedPrivate), "Seed import did not reproduce the same keypair");
                BlobLength(privateBlob, parameter, dsa ? 0x4B535344u : 0x524B4C4Du, privateLength);
                Console.WriteLine("PASS: " + algorithm + "-" + parameter + " reproducible seed import / expanded-key export");
            }
        }
        finally
        {
            if (privateBlob != null) Array.Clear(privateBlob, 0, privateBlob.Length);
            if (repeatedPrivate != null) Array.Clear(repeatedPrivate, 0, repeatedPrivate.Length);
            if (seedBlob != null) Array.Clear(seedBlob, 0, seedBlob.Length);
            Check(BCryptCloseAlgorithmProvider(provider, 0), "BCryptCloseAlgorithmProvider");
        }
    }

    public static int Run()
    {
        int failures = 0;
        string[] dsa = { "44", "65", "87" };
        int[] dsaPublic = { 1312, 1952, 2592 }, dsaPrivate = { 2560, 4032, 4896 };
        string[] kem = { "512", "768", "1024" };
        int[] kemPublic = { 800, 1184, 1568 }, kemPrivate = { 1632, 2400, 3168 }, kemCt = { 768, 1088, 1568 };
        for (int i = 0; i < 3; ++i)
        {
            try { Probe("ML-DSA", dsa[i], dsaPublic[i], dsaPrivate[i], 0); }
            catch (Exception error) { Console.WriteLine("FAIL: ML-DSA-" + dsa[i] + ": " + error.Message); ++failures; }
            try { Probe("ML-KEM", kem[i], kemPublic[i], kemPrivate[i], kemCt[i]); }
            catch (Exception error) { Console.WriteLine("FAIL: ML-KEM-" + kem[i] + ": " + error.Message); ++failures; }
        }
        Console.WriteLine("NOT PROBED: deterministic ML-DSA signing and fixed-entropy signing/encapsulation; no documented CNG controls identified.");
        return failures;
    }
}
'@

$failures = [NativePqcProbe]::Run()
if ($failures -ne 0) {
    throw "$failures native CNG PQC parameter-set probes failed."
}
