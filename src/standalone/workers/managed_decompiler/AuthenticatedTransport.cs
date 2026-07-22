using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Aida.ManagedDecompiler;

internal sealed record WorkerStartupOptions(
    nint ReadHandle,
    nint WriteHandle,
    nint ModuleHandle,
    int ModuleSize,
    nint IdentityHandle,
    string RuntimeManifestHash)
{
    private const int MaximumModuleBytes = 256 * 1024 * 1024;

    internal static WorkerStartupOptions Parse(string[] arguments)
    {
        if (arguments.Length != 8 || !string.Equals(arguments[0], "--aida-managed-decompiler-worker", StringComparison.Ordinal))
            throw new InvalidDataException("managed worker activation is invalid");

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < arguments.Length; ++index)
        {
            var separator = arguments[index].IndexOf('=');
            if (separator <= 2 || separator == arguments[index].Length - 1)
                throw new InvalidDataException("managed worker argument is malformed");
            var name = arguments[index][..separator];
            var value = arguments[index][(separator + 1)..];
            if (!values.TryAdd(name, value))
                throw new InvalidDataException("managed worker argument is duplicated");
        }

        if (values.Count != 7 || !values.TryGetValue("--provider", out var provider) || provider != "2" ||
            !values.TryGetValue("--read-handle", out var readHandle) ||
            !values.TryGetValue("--write-handle", out var writeHandle) ||
            !values.TryGetValue("--module-handle", out var moduleHandle) ||
            !values.TryGetValue("--module-size", out var moduleSize) ||
            !values.TryGetValue("--identity-handle", out var identityHandle) ||
            !values.TryGetValue("--runtime-manifest-hash", out var runtimeManifestHash))
            throw new InvalidDataException("managed worker argument contract is incomplete");
        if (runtimeManifestHash.Length != 64 ||
            runtimeManifestHash.All(character => character == '0') ||
            runtimeManifestHash.Any(character =>
                (character < '0' || character > '9') &&
                (character < 'a' || character > 'f')))
            throw new InvalidDataException("managed worker runtime manifest identity is invalid");

        if (!int.TryParse(moduleSize, NumberStyles.None, CultureInfo.InvariantCulture,
                out var parsedModuleSize) || parsedModuleSize <= 0 ||
            parsedModuleSize > MaximumModuleBytes)
            throw new InvalidDataException("managed worker module size is invalid");

        var parsedReadHandle = ParseHandle(readHandle);
        var parsedWriteHandle = ParseHandle(writeHandle);
        var parsedModuleHandle = ParseHandle(moduleHandle);
        var parsedIdentityHandle = ParseHandle(identityHandle);
        if (new HashSet<nint> { parsedReadHandle, parsedWriteHandle,
                parsedModuleHandle, parsedIdentityHandle }.Count != 4)
            throw new InvalidDataException("managed worker handle capabilities overlap");

        return new WorkerStartupOptions(parsedReadHandle, parsedWriteHandle,
            parsedModuleHandle, parsedModuleSize, parsedIdentityHandle,
            runtimeManifestHash);
    }

    private static nint ParseHandle(string value)
    {
        if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture,
                out var parsed) || parsed == 0 || parsed > (ulong)nint.MaxValue)
            throw new InvalidDataException("managed worker handle is invalid");
        return (nint)parsed;
    }
}

internal sealed record WorkerSession(
    byte[] Key,
    byte[] NonceHash,
    byte[] ManifestHash);

internal sealed class AuthenticatedTransport : IDisposable
{
    internal const int MaximumPayloadBytes = 16 * 1024 * 1024;
    private const int MaximumModuleBytes = 256 * 1024 * 1024;
    private const uint BootstrapMagic = 0x42574e41;
    private const uint FrameMagic = 0x46574e41;
    private const ushort FrameVersion = 1;
    private const ushort ContractFrameKind = 1;
    private const int DigestBytes = 32;
    private const int BootstrapBytes = 104;
    private const int FrameAuthenticatedHeaderBytes = 52;
    private const int FrameHeaderBytes = 84;
    private const int MaximumStartupFailurePayloadBytes = 512;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly FileStream input;
    private readonly FileStream output;
    private readonly WorkerSession session;
    private bool disposed;

    private sealed class AuthenticatedFrame(byte[] header, byte[] payload) : IDisposable
    {
        internal byte[] Header { get; } = header;
        internal byte[] Payload { get; } = payload;
        private bool disposed;

        public void Dispose()
        {
            if (disposed)
                return;
            disposed = true;
            CryptographicOperations.ZeroMemory(Header);
            CryptographicOperations.ZeroMemory(Payload);
        }
    }

    private AuthenticatedTransport(FileStream input, FileStream output, WorkerSession session)
    {
        this.input = input;
        this.output = output;
        this.session = session;
    }

    internal WorkerSession Session => session;

    internal static AuthenticatedTransport Establish(WorkerStartupOptions options)
    {
        var readHandle = new SafeFileHandle(options.ReadHandle, ownsHandle: true);
        var writeHandle = new SafeFileHandle(options.WriteHandle, ownsHandle: true);
        if (readHandle.IsInvalid || writeHandle.IsInvalid)
        {
            readHandle.Dispose();
            writeHandle.Dispose();
            throw new InvalidDataException("managed worker transport handle is unavailable");
        }

        FileStream input;
        try
        {
            input = new FileStream(readHandle, FileAccess.Read, 4096, isAsync: false);
        }
        catch
        {
            readHandle.Dispose();
            writeHandle.Dispose();
            throw;
        }
        FileStream? output = null;
        try
        {
            output = new FileStream(writeHandle, FileAccess.Write, 4096, isAsync: false);
            var bootstrap = GC.AllocateUninitializedArray<byte>(BootstrapBytes);
            byte[] nonce;
            byte[] key;
            byte[] manifestHash;
            try
            {
                input.ReadExactly(bootstrap);
                if (BinaryPrimitives.ReadUInt32LittleEndian(bootstrap) != BootstrapMagic ||
                    BinaryPrimitives.ReadUInt16LittleEndian(bootstrap.AsSpan(4)) != FrameVersion ||
                    BinaryPrimitives.ReadUInt16LittleEndian(bootstrap.AsSpan(6)) != 0)
                    throw new InvalidDataException("managed worker bootstrap is malformed");
                nonce = bootstrap.AsSpan(8, DigestBytes).ToArray();
                key = bootstrap.AsSpan(8 + DigestBytes, DigestBytes).ToArray();
                manifestHash = bootstrap.AsSpan(8 + DigestBytes * 2, DigestBytes).ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bootstrap);
            }
            byte[]? nonceHash = null;
            try
            {
                try
                {
                    nonceHash = SHA256.HashData(nonce);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonce);
                }
                var verifiedNonceHash = nonceHash ?? throw new InvalidDataException("managed worker bootstrap nonce hash is unavailable");
                if (key.All(value => value == 0) || verifiedNonceHash.All(value => value == 0) || manifestHash.All(value => value == 0))
                    throw new InvalidDataException("managed worker bootstrap contains invalid session material");
                return new AuthenticatedTransport(input, output, new WorkerSession(key, verifiedNonceHash, manifestHash));
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(manifestHash);
                if (nonceHash is not null)
                    CryptographicOperations.ZeroMemory(nonceHash);
                throw;
            }
        }
        catch
        {
            output?.Dispose();
            input.Dispose();
            readHandle.Dispose();
            writeHandle.Dispose();
            throw;
        }
    }

    internal async Task<string> ReceivePayloadAsync(ulong expectedSequence, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (expectedSequence == 0)
            throw new InvalidDataException("managed worker receive sequence is invalid");

        var header = GC.AllocateUninitializedArray<byte>(FrameHeaderBytes);
        await input.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        if (BinaryPrimitives.ReadUInt32LittleEndian(header) != FrameMagic ||
            BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4)) != FrameVersion ||
            BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(6)) != ContractFrameKind ||
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8)) != expectedSequence ||
            !CryptographicOperations.FixedTimeEquals(header.AsSpan(20, DigestBytes), session.NonceHash))
        {
            CryptographicOperations.ZeroMemory(header);
            throw new InvalidDataException("managed worker frame header is invalid");
        }

        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(16));
        if (payloadLength == 0 || payloadLength > MaximumPayloadBytes)
        {
            CryptographicOperations.ZeroMemory(header);
            throw new InvalidDataException("managed worker frame size is invalid");
        }

        var payload = GC.AllocateUninitializedArray<byte>(checked((int)payloadLength));
        await input.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        var authenticated = GC.AllocateUninitializedArray<byte>(checked(FrameAuthenticatedHeaderBytes + payload.Length));
        header.AsSpan(0, FrameAuthenticatedHeaderBytes).CopyTo(authenticated);
        payload.CopyTo(authenticated.AsSpan(FrameAuthenticatedHeaderBytes));
        var expectedTag = HMACSHA256.HashData(session.Key, authenticated);
        var authenticatedFrame = CryptographicOperations.FixedTimeEquals(
            expectedTag, header.AsSpan(FrameAuthenticatedHeaderBytes, DigestBytes));
        CryptographicOperations.ZeroMemory(authenticated);
        CryptographicOperations.ZeroMemory(expectedTag);
        CryptographicOperations.ZeroMemory(header);
        if (!authenticatedFrame)
        {
            CryptographicOperations.ZeroMemory(payload);
            throw new InvalidDataException("managed worker frame authentication failed");
        }

        try
        {
            return StrictUtf8.GetString(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    internal async Task SendPayloadAsync(ulong sequence, string payload, CancellationToken cancellationToken)
    {
        using var frame = CreateAuthenticatedFrame(sequence, payload, MaximumPayloadBytes);
        await output.WriteAsync(frame.Header, cancellationToken).ConfigureAwait(false);
        await output.WriteAsync(frame.Payload, cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    internal void SendStartupFailurePayload(string payload)
    {
        using var frame = CreateAuthenticatedFrame(1, payload, MaximumStartupFailurePayloadBytes);
        output.Write(frame.Header, 0, frame.Header.Length);
        output.Write(frame.Payload, 0, frame.Payload.Length);
        output.Flush();
    }

    private AuthenticatedFrame CreateAuthenticatedFrame(ulong sequence, string payload, int maximumPayloadBytes)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (sequence == 0 || string.IsNullOrEmpty(payload) || maximumPayloadBytes <= 0 ||
            maximumPayloadBytes > MaximumPayloadBytes)
            throw new InvalidDataException("managed worker response frame is invalid");
        var payloadBytes = StrictUtf8.GetBytes(payload);
        var header = new byte[FrameHeaderBytes];
        byte[]? authenticated = null;
        byte[]? tag = null;
        try
        {
            if (payloadBytes.Length > maximumPayloadBytes)
                throw new InvalidDataException("managed worker response exceeds the frame limit");
            BinaryPrimitives.WriteUInt32LittleEndian(header, FrameMagic);
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(4), FrameVersion);
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(6), ContractFrameKind);
            BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(8), sequence);
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16), checked((uint)payloadBytes.Length));
            session.NonceHash.CopyTo(header.AsSpan(20));
            authenticated = GC.AllocateUninitializedArray<byte>(checked(FrameAuthenticatedHeaderBytes + payloadBytes.Length));
            header.AsSpan(0, FrameAuthenticatedHeaderBytes).CopyTo(authenticated);
            payloadBytes.CopyTo(authenticated.AsSpan(FrameAuthenticatedHeaderBytes));
            tag = HMACSHA256.HashData(session.Key, authenticated);
            tag.CopyTo(header.AsSpan(FrameAuthenticatedHeaderBytes));
            return new AuthenticatedFrame(header, payloadBytes);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(payloadBytes);
            throw;
        }
        finally
        {
            if (authenticated is not null)
                CryptographicOperations.ZeroMemory(authenticated);
            if (tag is not null)
                CryptographicOperations.ZeroMemory(tag);
        }
    }

    internal static string HashIdentityHandle(nint rawHandle)
    {
        using var identityHandle = new SafeFileHandle(rawHandle, ownsHandle: true);
        if (identityHandle.IsInvalid || identityHandle.IsClosed)
            throw new InvalidDataException("managed worker identity handle is unavailable");
        using var stream = new FileStream(identityHandle, FileAccess.Read, 1024 * 1024, isAsync: false);
        stream.Position = 0;
        var hash = SHA256.HashData(stream);
        try
        {
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    internal static byte[] ReadModuleMapping(nint rawHandle, int size)
    {
        if (rawHandle == 0 || size <= 0 || size > MaximumModuleBytes)
            throw new InvalidDataException("managed worker module mapping is invalid");
        using var mappingHandle = new SafeFileHandle(rawHandle, ownsHandle: true);
        if (mappingHandle.IsInvalid || mappingHandle.IsClosed)
            throw new InvalidDataException("managed worker module mapping handle is invalid");
        var view = MapViewOfFile(mappingHandle.DangerousGetHandle(), 0x0004, 0, 0, (nuint)size);
        if (view == 0)
            throw new InvalidDataException("managed worker module mapping cannot be opened");
        try
        {
            var bytes = GC.AllocateUninitializedArray<byte>(size);
            Marshal.Copy(view, bytes, 0, size);
            return bytes;
        }
        finally
        {
            if (!UnmapViewOfFile(view))
                Environment.FailFast("managed worker module mapping could not be released");
        }
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        input.Dispose();
        output.Dispose();
        CryptographicOperations.ZeroMemory(session.Key);
        CryptographicOperations.ZeroMemory(session.NonceHash);
        CryptographicOperations.ZeroMemory(session.ManifestHash);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint MapViewOfFile(nint fileMappingObject, uint desiredAccess, uint fileOffsetHigh, uint fileOffsetLow, nuint bytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnmapViewOfFile(nint baseAddress);
}
