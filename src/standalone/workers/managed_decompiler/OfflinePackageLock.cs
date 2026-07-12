using System.Security.Cryptography;

namespace Aida.ManagedDecompiler;

internal sealed record OfflinePackage(string Id, string Version, string FileName, string Sha256);

internal sealed class OfflineIntegrityException : Exception
{
    internal OfflineIntegrityException(string message) : base(message)
    {
    }
}

internal static class OfflinePackageLock
{
    internal const string DecompilerAssemblySha256 = "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345";

    internal static readonly IReadOnlyList<OfflinePackage> Packages = new[]
    {
        new OfflinePackage("ICSharpCode.Decompiler", "10.1.0.8386", "ICSharpCode.Decompiler.10.1.0.8386.nupkg", "a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af"),
        new OfflinePackage("System.Collections.Immutable", "9.0.0", "System.Collections.Immutable.9.0.0.nupkg", "fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7"),
        new OfflinePackage("System.Reflection.Metadata", "9.0.0", "System.Reflection.Metadata.9.0.0.nupkg", "6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634")
    };

    internal static string ManifestHashHex { get; } = ComputeManifestHash();
    private static readonly object StartupGate = new();
    private static string? verifiedPackageRoot;

    internal static void EstablishStartupGate(string packageRoot)
    {
        var normalizedRoot = ValidatePackageRoot(packageRoot, null, CancellationToken.None);
        ValidateLoadedDecompilerAssembly(null, CancellationToken.None);
        lock (StartupGate)
        {
            if (verifiedPackageRoot is not null && !string.Equals(verifiedPackageRoot, normalizedRoot, StringComparison.OrdinalIgnoreCase))
                throw new OfflineIntegrityException("offline package root changed after startup verification");
            verifiedPackageRoot = normalizedRoot;
        }
    }

    internal static void RequireRuntimeGate(
        string offlineLockHash,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        resourceBudget.Checkpoint(cancellationToken);
        string packageRoot;
        lock (StartupGate)
            packageRoot = verifiedPackageRoot ?? throw new OfflineIntegrityException("offline package startup gate is not established");
        if (!FixedTimeHexEquals(offlineLockHash, ManifestHashHex))
            throw new OfflineIntegrityException("offline package lock hash does not match the startup gate");
        var normalizedRoot = ValidatePackageRoot(packageRoot, resourceBudget, cancellationToken);
        if (!string.Equals(packageRoot, normalizedRoot, StringComparison.OrdinalIgnoreCase))
            throw new OfflineIntegrityException("offline package root identity changed after startup verification");
        ValidateLoadedDecompilerAssembly(resourceBudget, cancellationToken);
        resourceBudget.Checkpoint(cancellationToken);
    }

    private static string ValidatePackageRoot(
        string packageRoot,
        ResourceBudgetGuard? resourceBudget,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(packageRoot))
            throw new OfflineIntegrityException("offline package root is empty");
        string normalizedRoot;
        try
        {
            normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(packageRoot));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new OfflineIntegrityException("offline package root is invalid");
        }
        if (!Directory.Exists(normalizedRoot))
            throw new OfflineIntegrityException("offline package root is unavailable");

        foreach (var package in Packages)
        {
            var path = Path.Combine(normalizedRoot, package.FileName);
            if (!File.Exists(path))
                throw new OfflineIntegrityException($"offline package is unavailable: {package.Id}");
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
                var actual = HashStream(stream, resourceBudget, cancellationToken);
                if (!FixedTimeHexEquals(actual, package.Sha256))
                    throw new OfflineIntegrityException($"offline package hash mismatch: {package.Id}");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new OfflineIntegrityException($"offline package cannot be verified: {package.Id}");
            }
        }
        return normalizedRoot;
    }

    private static void ValidateLoadedDecompilerAssembly(
        ResourceBudgetGuard? resourceBudget,
        CancellationToken cancellationToken)
    {
        var path = typeof(ICSharpCode.Decompiler.CSharp.CSharpDecompiler).Assembly.Location;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            throw new OfflineIntegrityException("offline decompiler assembly is unavailable");
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
            var actual = HashStream(stream, resourceBudget, cancellationToken);
            if (!FixedTimeHexEquals(actual, DecompilerAssemblySha256))
                throw new OfflineIntegrityException("offline decompiler assembly hash mismatch");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new OfflineIntegrityException("offline decompiler assembly cannot be verified");
        }
    }

    private static string ComputeManifestHash()
    {
        var canonical = string.Join('\n', Packages.Select(package => $"{package.Id}|{package.Version}|{package.Sha256}"));
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static string HashStream(
        Stream stream,
        ResourceBudgetGuard? resourceBudget,
        CancellationToken cancellationToken)
    {
        const int BufferSize = 1024 * 1024;
        resourceBudget?.EnsureAllocationFits((ulong)BufferSize, cancellationToken);
        byte[] buffer;
        try
        {
            buffer = GC.AllocateUninitializedArray<byte>(BufferSize);
        }
        catch (OutOfMemoryException) when (resourceBudget is not null)
        {
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            resourceBudget?.Checkpoint(cancellationToken);
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
                break;
            hash.AppendData(buffer, 0, read);
        }
        resourceBudget?.Checkpoint(cancellationToken);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static bool FixedTimeHexEquals(string? left, string? right)
    {
        if (left is null || right is null || left.Length != 64 || right.Length != 64)
            return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
