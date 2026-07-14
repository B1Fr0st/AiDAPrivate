using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Aida.ManagedDecompiler;

internal sealed class RuntimeIntegrityException : Exception
{
    internal RuntimeIntegrityException(string message) : base(message)
    {
    }
}

internal static class RuntimeIdentity
{
    internal const string DecompilerAssemblySha256 = "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345";
    internal const string TargetFramework = ".NETCoreApp,Version=v10.0";
    internal const string RuntimeVersion = "10.0.9";
    private static readonly object Gate = new();
    private static FileStream[]? identityLocks;
    private static string? runtimeManifestHash;
    private static string? packageRoot;

    internal static string ManifestHashHex
    {
        get
        {
            lock (Gate)
                return runtimeManifestHash ?? throw new RuntimeIntegrityException("managed runtime identity is not established");
        }
    }

    internal static void Establish(string expectedRuntimeManifestHash)
    {
        if (!IsLowerHexDigest(expectedRuntimeManifestHash) ||
            expectedRuntimeManifestHash.All(character => character == '0'))
            throw new RuntimeIntegrityException("managed runtime manifest identity is invalid");
        ValidateEnvironment();
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
            throw new RuntimeIntegrityException("managed worker process path is unavailable");
        var executable = CanonicalFile(processPath);
        if (!string.Equals(Path.GetFileName(executable), "AiDA_ManagedDecompilerWorker.exe", StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker apphost identity is invalid");
        var depsRoot = Path.GetDirectoryName(executable) ?? throw new RuntimeIntegrityException("managed worker package path is invalid");
        var root = Path.GetDirectoryName(depsRoot) ?? throw new RuntimeIntegrityException("managed worker package root is invalid");
        if (PathComponents(root).Any(component => string.Equals(component, ".deps", StringComparison.OrdinalIgnoreCase)))
            throw new RuntimeIntegrityException("managed worker cannot execute from a repository dependency root");
        var expectedDotnetRoot = CanonicalDirectory(Path.Combine(depsRoot, "dotnet"));
        var configuredDotnetRoot = CanonicalDirectory(Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? string.Empty);
        if (!string.Equals(expectedDotnetRoot, configuredDotnetRoot, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker DOTNET_ROOT is not app-local");
        var manifestPath = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedRuntime.manifest.json"));
        var digestPath = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedRuntime.manifest.sha256"));
        using var pendingLocks = new PendingIdentityLocks();
        var manifestLock = pendingLocks.Open(manifestPath);
        var digestLock = pendingLocks.Open(digestPath);
        if (manifestLock.Length <= 0 || manifestLock.Length > 512 * 1024 || digestLock.Length != 65)
            throw new RuntimeIntegrityException("managed runtime manifest package size is invalid");
        var actualManifestHash = HashStream(manifestLock);
        if (!FixedTimeHexEquals(actualManifestHash, expectedRuntimeManifestHash))
            throw new RuntimeIntegrityException("managed runtime manifest hash does not match startup identity");
        digestLock.Position = 0;
        string digestText;
        using (var reader = new StreamReader(digestLock, System.Text.Encoding.ASCII, false, 128, true))
            digestText = reader.ReadToEnd();
        if (!string.Equals(digestText, expectedRuntimeManifestHash + "\n", StringComparison.Ordinal))
            throw new RuntimeIntegrityException("managed runtime manifest digest is invalid");
        var workerAssembly = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedDecompilerWorker.dll"));
        var depsJson = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedDecompilerWorker.deps.json"));
        var runtimeConfig = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedDecompilerWorker.runtimeconfig.json"));
        var immutable = CanonicalFile(Path.Combine(depsRoot, "System.Collections.Immutable.dll"));
        var metadata = CanonicalFile(Path.Combine(depsRoot, "System.Reflection.Metadata.dll"));
        var provider = CanonicalFile(Path.Combine(depsRoot, "ICSharpCode.Decompiler.dll"));
        var loadedWorker = CanonicalFile(typeof(RuntimeIdentity).Assembly.Location);
        var loadedProvider = CanonicalFile(typeof(ICSharpCode.Decompiler.CSharp.CSharpDecompiler).Assembly.Location);
        var loadedImmutable = CanonicalFile(typeof(System.Collections.Immutable.ImmutableArray).Assembly.Location);
        var loadedMetadata = CanonicalFile(typeof(System.Reflection.Metadata.MetadataReader).Assembly.Location);
        if (!string.Equals(workerAssembly, loadedWorker, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(provider, loadedProvider, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(immutable, loadedImmutable, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(metadata, loadedMetadata, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker loaded assembly paths are not app-local");
        var coreLibrary = CanonicalFile(typeof(object).Assembly.Location);
        var expectedCoreLibrary = CanonicalFile(Path.Combine(expectedDotnetRoot, "shared", "Microsoft.NETCore.App", RuntimeVersion, "System.Private.CoreLib.dll"));
        if (!string.Equals(coreLibrary, expectedCoreLibrary, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(AppContext.TargetFrameworkName, TargetFramework, StringComparison.Ordinal) ||
            Environment.Version.Major != 10 || Environment.Version.Minor != 0 || Environment.Version.Build != 9 ||
            !string.Equals(RuntimeInformation.RuntimeIdentifier, "win-x64", StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker framework identity is invalid");
        var providerLock = pendingLocks.Open(provider);
        if (!FixedTimeHexEquals(HashStream(providerLock), DecompilerAssemblySha256))
            throw new RuntimeIntegrityException("managed decompiler assembly hash mismatch");
        _ = pendingLocks.Open(executable);
        _ = pendingLocks.Open(workerAssembly);
        _ = pendingLocks.Open(depsJson);
        _ = pendingLocks.Open(runtimeConfig);
        _ = pendingLocks.Open(immutable);
        _ = pendingLocks.Open(metadata);
        _ = pendingLocks.Open(coreLibrary);
        _ = pendingLocks.Open(Path.Combine(expectedDotnetRoot, "host", "fxr", RuntimeVersion, "hostfxr.dll"));
        lock (Gate)
        {
            if (runtimeManifestHash is not null || identityLocks is not null)
                throw new RuntimeIntegrityException("managed runtime identity was already established");
            identityLocks = pendingLocks.Transfer();
            runtimeManifestHash = expectedRuntimeManifestHash;
            packageRoot = root;
        }
    }

    internal static void RequireRuntimeGate(string expectedRuntimeManifestHash, ResourceBudgetGuard resourceBudget, CancellationToken cancellationToken)
    {
        resourceBudget.Checkpoint(cancellationToken);
        string establishedHash;
        string establishedRoot;
        lock (Gate)
        {
            establishedHash = runtimeManifestHash ?? throw new RuntimeIntegrityException("managed runtime identity is unavailable");
            establishedRoot = packageRoot ?? throw new RuntimeIntegrityException("managed runtime package root is unavailable");
            if (identityLocks is not { Length: 11 })
                throw new RuntimeIntegrityException("managed runtime identity locks are unavailable");
        }
        if (!FixedTimeHexEquals(establishedHash, expectedRuntimeManifestHash))
            throw new RuntimeIntegrityException("managed runtime identity changed after startup");
        var processPath = Environment.ProcessPath ?? throw new RuntimeIntegrityException("managed worker process path is unavailable");
        var currentRoot = Path.GetDirectoryName(Path.GetDirectoryName(CanonicalFile(processPath)) ?? string.Empty) ?? string.Empty;
        if (!string.Equals(CanonicalDirectory(currentRoot), establishedRoot, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed runtime package root changed after startup");
        ValidateEnvironment();
        resourceBudget.Checkpoint(cancellationToken);
    }

    private static void ValidateEnvironment()
    {
        var required = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["COMPlus_EnableDiagnostics"] = "0",
            ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1",
            ["DOTNET_EnableDiagnostics"] = "0",
            ["DOTNET_MULTILEVEL_LOOKUP"] = "0",
            ["DOTNET_NOLOGO"] = "1",
            ["DOTNET_ROLL_FORWARD"] = "Disable",
            ["DOTNET_ROLL_FORWARD_TO_PRERELEASE"] = "0",
            ["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"
        };
        var allowed = new HashSet<string>(required.Keys, StringComparer.OrdinalIgnoreCase)
        {
            "DOTNET_ROOT", "PATH", "SystemRoot", "WINDIR"
        };
        foreach (var key in Environment.GetEnvironmentVariables().Keys)
        {
            if (key is not string name || !allowed.Contains(name))
                throw new RuntimeIntegrityException("managed worker environment exceeds its minimal allowlist");
        }
        foreach (var entry in required)
        {
            if (!string.Equals(Environment.GetEnvironmentVariable(entry.Key), entry.Value, StringComparison.Ordinal))
                throw new RuntimeIntegrityException("managed worker environment violates app-local runtime policy");
        }
        var systemRoot = CanonicalDirectory(Environment.GetEnvironmentVariable("SystemRoot") ?? string.Empty);
        var windowsDirectory = CanonicalDirectory(Environment.GetEnvironmentVariable("WINDIR") ?? string.Empty);
        var systemPath = CanonicalDirectory(Environment.GetEnvironmentVariable("PATH") ?? string.Empty);
        if (!string.Equals(systemRoot, windowsDirectory, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(systemPath, CanonicalDirectory(Path.Combine(systemRoot, "System32")), StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker Windows environment is not minimal");
        foreach (var forbidden in new[]
        {
            "COREHOST_TRACE", "COREHOST_TRACEFILE", "DOTNET_ADDITIONAL_DEPS", "DOTNET_HOST_PATH",
            "DOTNET_SHARED_STORE", "DOTNET_STARTUP_HOOKS", "CORECLR_ENABLE_PROFILING",
            "CORECLR_PROFILER", "CORECLR_PROFILER_PATH", "COR_ENABLE_PROFILING", "COR_PROFILER"
        })
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(forbidden)))
                throw new RuntimeIntegrityException("managed worker environment contains a forbidden host override");
        }
    }

    private static FileStream OpenIdentity(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);

    private sealed class PendingIdentityLocks : IDisposable
    {
        private readonly List<FileStream> locks = new();

        internal FileStream Open(string path)
        {
            var stream = OpenIdentity(path);
            locks.Add(stream);
            return stream;
        }

        internal FileStream[] Transfer()
        {
            var result = locks.ToArray();
            locks.Clear();
            return result;
        }

        public void Dispose()
        {
            foreach (var stream in locks)
                stream.Dispose();
            locks.Clear();
        }
    }

    private static string HashStream(FileStream stream)
    {
        stream.Position = 0;
        var hash = SHA256.HashData(stream);
        try
        {
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            stream.Position = 0;
        }
    }

    private static string CanonicalFile(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new RuntimeIntegrityException("managed runtime file is unavailable");
        RejectReparseComponents(full);
        return Path.TrimEndingDirectorySeparator(full);
    }

    private static string CanonicalDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new RuntimeIntegrityException("managed runtime directory is unavailable");
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full))
            throw new RuntimeIntegrityException("managed runtime directory is unavailable");
        RejectReparseComponents(full);
        return Path.TrimEndingDirectorySeparator(full);
    }

    private static void RejectReparseComponents(string path)
    {
        var current = Path.GetPathRoot(path) ?? throw new RuntimeIntegrityException("managed runtime path root is unavailable");
        foreach (var component in Path.GetRelativePath(current, path).Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new RuntimeIntegrityException("managed runtime path contains a reparse component");
        }
    }

    private static IEnumerable<string> PathComponents(string path) =>
        Path.GetRelativePath(Path.GetPathRoot(path) ?? string.Empty, path)
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);

    private static bool IsLowerHexDigest(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool FixedTimeHexEquals(string? left, string? right)
    {
        if (!IsLowerHexDigest(left) || !IsLowerHexDigest(right))
            return false;
        var leftBytes = Convert.FromHexString(left!);
        var rightBytes = Convert.FromHexString(right!);
        try
        {
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }
}
