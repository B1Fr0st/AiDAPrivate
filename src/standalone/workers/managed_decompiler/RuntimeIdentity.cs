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
    private const uint TokenQuery = 0x0008;
    private const int TokenAppContainerSid = 31;
    private const int ErrorInsufficientBuffer = 122;
    private const string AppContainerTokenOpenFailure = "managed worker AppContainer token cannot be opened";
    private const string AppContainerTokenSizeInvalid = "managed worker AppContainer token size is invalid";
    private const string AppContainerTokenQueryFailure = "managed worker AppContainer token query failed";
    private const string AppContainerSidInvalid = "managed worker AppContainer SID is invalid";
    private const string AppContainerProfileUnavailable = "managed worker AppContainer profile is unavailable";
    private const string AppContainerProfileInaccessible = "managed worker AppContainer profile cannot be accessed";
    private const string AppContainerLocalAppDataFailure = "managed worker AppContainer LOCALAPPDATA is not profile-bound";
    private const string AppContainerTempFailure = "managed worker AppContainer TEMP is not profile-bound";
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
        if (string.IsNullOrWhiteSpace(processPath) || !Path.IsPathFullyQualified(processPath))
            throw new RuntimeIntegrityException("managed worker process path is unavailable");
        var executablePath = Path.GetFullPath(processPath);
        var depsRootPath = Path.GetDirectoryName(executablePath) ?? throw new RuntimeIntegrityException("managed worker package path is invalid");
        var rootPath = Path.GetDirectoryName(depsRootPath) ?? throw new RuntimeIntegrityException("managed worker package root is invalid");
        var root = CanonicalRootDirectory(rootPath, "managed worker package root is invalid");
        var depsRoot = CanonicalDirectory(depsRootPath, root, "managed worker package path is invalid");
        var executable = CanonicalFile(executablePath, root);
        if (!string.Equals(Path.GetFileName(executable), "AiDA_ManagedDecompilerWorker.exe", StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker apphost identity is invalid");
        if (PathComponents(root).Any(component => string.Equals(component, ".deps", StringComparison.OrdinalIgnoreCase)))
            throw new RuntimeIntegrityException("managed worker cannot execute from a repository dependency root");
        var expectedDotnetRoot = CanonicalDirectory(Path.Combine(depsRoot, "dotnet"), root,
            "managed worker DOTNET_ROOT is not app-local");
        var configuredDotnetRoot = CanonicalDirectory(Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? string.Empty, root,
            "managed worker DOTNET_ROOT is not app-local");
        if (!string.Equals(expectedDotnetRoot, configuredDotnetRoot, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker DOTNET_ROOT is not app-local");
        var manifestPath = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedRuntime.manifest.json"), root);
        var digestPath = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedRuntime.manifest.sha256"), root);
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
        var workerAssembly = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedDecompilerWorker.dll"), root);
        var depsJson = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedDecompilerWorker.deps.json"), root);
        var runtimeConfig = CanonicalFile(Path.Combine(depsRoot, "AiDA_ManagedDecompilerWorker.runtimeconfig.json"), root);
        var packagedImmutable = CanonicalFile(Path.Combine(depsRoot, "System.Collections.Immutable.dll"), root);
        var packagedMetadata = CanonicalFile(Path.Combine(depsRoot, "System.Reflection.Metadata.dll"), root);
        var provider = CanonicalFile(Path.Combine(depsRoot, "ICSharpCode.Decompiler.dll"), root);
        var frameworkRoot = CanonicalDirectory(Path.Combine(expectedDotnetRoot, "shared", "Microsoft.NETCore.App", RuntimeVersion), root,
            "managed worker framework identity is invalid");
        var runtimeImmutable = CanonicalFile(Path.Combine(frameworkRoot, "System.Collections.Immutable.dll"), root);
        var runtimeMetadata = CanonicalFile(Path.Combine(frameworkRoot, "System.Reflection.Metadata.dll"), root);
        var loadedWorker = CanonicalFile(typeof(RuntimeIdentity).Assembly.Location, root);
        var loadedProvider = CanonicalFile(typeof(ICSharpCode.Decompiler.CSharp.CSharpDecompiler).Assembly.Location, root);
        var loadedImmutable = CanonicalFile(typeof(System.Collections.Immutable.ImmutableArray).Assembly.Location, root);
        var loadedMetadata = CanonicalFile(typeof(System.Reflection.Metadata.MetadataReader).Assembly.Location, root);
        if (!string.Equals(workerAssembly, loadedWorker, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(provider, loadedProvider, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(runtimeImmutable, loadedImmutable, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(runtimeMetadata, loadedMetadata, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker loaded assembly paths are not app-local");
        var coreLibrary = CanonicalFile(typeof(object).Assembly.Location, root);
        var expectedCoreLibrary = CanonicalFile(Path.Combine(expectedDotnetRoot, "shared", "Microsoft.NETCore.App", RuntimeVersion, "System.Private.CoreLib.dll"), root);
        var hostFxr = CanonicalFile(Path.Combine(expectedDotnetRoot, "host", "fxr", RuntimeVersion, "hostfxr.dll"), root);
        if (!string.Equals(coreLibrary, expectedCoreLibrary, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(AppContext.TargetFrameworkName, TargetFramework, StringComparison.Ordinal) ||
            Environment.Version.Major != 10 || Environment.Version.Minor != 0 || Environment.Version.Build != 9 ||
            !string.Equals(RuntimeInformation.RuntimeIdentifier, "win-x64", StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker framework identity is invalid");
        var providerLock = pendingLocks.Open(provider);
        if (!FixedTimeHexEquals(HashStream(providerLock), DecompilerAssemblySha256))
            throw new RuntimeIntegrityException("managed decompiler assembly hash mismatch");
        var packagedImmutableLock = pendingLocks.Open(packagedImmutable);
        var packagedMetadataLock = pendingLocks.Open(packagedMetadata);
        var runtimeImmutableLock = pendingLocks.Open(runtimeImmutable);
        var runtimeMetadataLock = pendingLocks.Open(runtimeMetadata);
        if (!FixedTimeHexEquals(HashStream(packagedImmutableLock), HashStream(runtimeImmutableLock)) ||
            !FixedTimeHexEquals(HashStream(packagedMetadataLock), HashStream(runtimeMetadataLock)))
            throw new RuntimeIntegrityException("managed framework dependency copies do not match the loaded runtime");
        _ = pendingLocks.Open(executable);
        _ = pendingLocks.Open(workerAssembly);
        _ = pendingLocks.Open(depsJson);
        _ = pendingLocks.Open(runtimeConfig);
        _ = pendingLocks.Open(coreLibrary);
        _ = pendingLocks.Open(hostFxr);
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
            if (identityLocks is not { Length: 13 })
                throw new RuntimeIntegrityException("managed runtime identity locks are unavailable");
        }
        if (!FixedTimeHexEquals(establishedHash, expectedRuntimeManifestHash))
            throw new RuntimeIntegrityException("managed runtime identity changed after startup");
        var processPath = Environment.ProcessPath ?? throw new RuntimeIntegrityException("managed worker process path is unavailable");
        var currentRoot = Path.GetDirectoryName(Path.GetDirectoryName(CanonicalFile(processPath, establishedRoot)) ?? string.Empty) ?? string.Empty;
        if (!string.Equals(CanonicalDirectory(currentRoot, establishedRoot,
                "managed runtime package root changed after startup"), establishedRoot, StringComparison.OrdinalIgnoreCase))
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
            "DOTNET_ROOT", "LOCALAPPDATA", "PATH", "SystemRoot", "TEMP", "TMP", "WINDIR"
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
        var systemRoot = CanonicalRootDirectory(Environment.GetEnvironmentVariable("SystemRoot") ?? string.Empty,
            "managed worker Windows environment is not minimal");
        var windowsDirectory = CanonicalDirectory(Environment.GetEnvironmentVariable("WINDIR") ?? string.Empty, systemRoot,
            "managed worker Windows environment is not minimal");
        var systemPath = CanonicalDirectory(Environment.GetEnvironmentVariable("PATH") ?? string.Empty, systemRoot,
            "managed worker Windows environment is not minimal");
        if (!string.Equals(systemRoot, windowsDirectory, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(systemPath, CanonicalDirectory(Path.Combine(systemRoot, "System32"), systemRoot,
                "managed worker Windows environment is not minimal"), StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed worker Windows environment is not minimal");
        var profileLocalAppData = CurrentAppContainerLocalAppData();
        var configuredLocalAppData = CanonicalDirectory(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? string.Empty,
            profileLocalAppData, AppContainerLocalAppDataFailure);
        if (!string.Equals(configuredLocalAppData, profileLocalAppData, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException(AppContainerLocalAppDataFailure);
        var expectedTemp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(profileLocalAppData, "Temp")));
        var configuredTemp = CanonicalProspectiveDirectory(Environment.GetEnvironmentVariable("TEMP") ?? string.Empty,
            profileLocalAppData, AppContainerTempFailure);
        var configuredTmp = CanonicalProspectiveDirectory(Environment.GetEnvironmentVariable("TMP") ?? string.Empty,
            profileLocalAppData, AppContainerTempFailure);
        if (!string.Equals(configuredTemp, expectedTemp, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuredTmp, expectedTemp, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException(AppContainerTempFailure);
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

    private static string CanonicalFile(string path, string trustedRoot)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new RuntimeIntegrityException("managed runtime file is unavailable");
        RejectReparseComponents(full, trustedRoot);
        return Path.TrimEndingDirectorySeparator(full);
    }

    private static string CanonicalDirectory(string path, string trustedRoot, string unavailableMessage)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new RuntimeIntegrityException(unavailableMessage);
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full))
            throw new RuntimeIntegrityException(unavailableMessage);
        RejectReparseComponents(full, trustedRoot);
        return Path.TrimEndingDirectorySeparator(full);
    }

    private static string CanonicalProspectiveDirectory(string path, string trustedRoot, string unavailableMessage)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new RuntimeIntegrityException(unavailableMessage);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        try
        {
            var attributes = File.GetAttributes(full);
            if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
                throw new RuntimeIntegrityException("managed runtime directory identity is invalid");
            RejectReparseComponents(full, trustedRoot);
        }
        catch (FileNotFoundException)
        {
            var parent = Path.GetDirectoryName(full) ?? throw new RuntimeIntegrityException(unavailableMessage);
            _ = CanonicalDirectory(parent, trustedRoot, unavailableMessage);
        }
        catch (DirectoryNotFoundException)
        {
            throw new RuntimeIntegrityException(unavailableMessage);
        }
        return full;
    }

    private static string CanonicalRootDirectory(string path, string unavailableMessage)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new RuntimeIntegrityException(unavailableMessage);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!Directory.Exists(full))
            throw new RuntimeIntegrityException(unavailableMessage);
        var attributes = File.GetAttributes(full);
        if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimeIntegrityException("managed runtime root directory identity is invalid");
        return full;
    }

    private static string CurrentAppContainerLocalAppData()
    {
        nint token = 0;
        nint tokenInformation = 0;
        nint sidText = 0;
        nint folderPath = 0;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token) || token == 0)
                throw new RuntimeIntegrityException(AppContainerTokenOpenFailure);
            if (GetTokenInformation(token, TokenAppContainerSid, 0, 0, out var informationSize) ||
                Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer ||
                informationSize < (uint)IntPtr.Size || informationSize > 4096)
                throw new RuntimeIntegrityException(AppContainerTokenSizeInvalid);
            tokenInformation = Marshal.AllocHGlobal(checked((int)informationSize));
            if (!GetTokenInformation(token, TokenAppContainerSid, tokenInformation,
                    informationSize, out var returnedSize) ||
                returnedSize < (uint)IntPtr.Size || returnedSize > informationSize)
                throw new RuntimeIntegrityException(AppContainerTokenQueryFailure);
            var appContainerSid = Marshal.ReadIntPtr(tokenInformation);
            if (appContainerSid == 0 || !IsValidSid(appContainerSid) ||
                !ConvertSidToStringSidW(appContainerSid, out sidText) || sidText == 0)
                throw new RuntimeIntegrityException(AppContainerSidInvalid);
            var sid = Marshal.PtrToStringUni(sidText);
            if (string.IsNullOrWhiteSpace(sid))
                throw new RuntimeIntegrityException(AppContainerSidInvalid);
            if (GetAppContainerFolderPath(sid, out folderPath) < 0 || folderPath == 0)
                throw new RuntimeIntegrityException(AppContainerProfileUnavailable);
            var path = Marshal.PtrToStringUni(folderPath);
            if (string.IsNullOrWhiteSpace(path))
                throw new RuntimeIntegrityException(AppContainerProfileUnavailable);
            return CanonicalAppContainerProfileRoot(path);
        }
        finally
        {
            if (folderPath != 0)
                Marshal.FreeCoTaskMem(folderPath);
            if (sidText != 0)
                _ = LocalFree(sidText);
            if (tokenInformation != 0)
                Marshal.FreeHGlobal(tokenInformation);
            if (token != 0)
                _ = CloseHandle(token);
        }
    }

    private static string CanonicalAppContainerProfileRoot(string path)
    {
        string full;
        FileAttributes attributes;
        try
        {
            full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            attributes = File.GetAttributes(full);
        }
        catch (FileNotFoundException)
        {
            throw new RuntimeIntegrityException(AppContainerProfileUnavailable);
        }
        catch (DirectoryNotFoundException)
        {
            throw new RuntimeIntegrityException(AppContainerProfileUnavailable);
        }
        catch (UnauthorizedAccessException)
        {
            throw new RuntimeIntegrityException(AppContainerProfileInaccessible);
        }
        catch (IOException)
        {
            throw new RuntimeIntegrityException(AppContainerProfileInaccessible);
        }
        catch (ArgumentException)
        {
            throw new RuntimeIntegrityException(AppContainerProfileInaccessible);
        }
        catch (NotSupportedException)
        {
            throw new RuntimeIntegrityException(AppContainerProfileInaccessible);
        }
        if ((attributes & FileAttributes.Directory) == 0 ||
            (attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimeIntegrityException(AppContainerProfileInaccessible);
        return full;
    }

    private static void RejectReparseComponents(string path, string trustedRoot)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trustedRoot));
        var target = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(target, root, StringComparison.OrdinalIgnoreCase) &&
            !target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new RuntimeIntegrityException("managed runtime path escapes its trusted root");
        var current = root;
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            throw new RuntimeIntegrityException("managed runtime path contains a reparse component");
        foreach (var component in Path.GetRelativePath(root, target).Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
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

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern nint GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(nint processHandle, uint desiredAccess, out nint tokenHandle);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(nint tokenHandle, int tokenInformationClass,
        nint tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(nint sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSidW(nint sid, out nint stringSid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetAppContainerFolderPath(string appContainerSid, out nint path);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern nint LocalFree(nint memory);
}
