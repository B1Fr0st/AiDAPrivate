using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aida.ManagedDecompiler;

namespace Aida.C03.ManagedCliHarness;

internal static class Program
{
    private const string FixtureAssemblyFileName = "ManagedCliFixtures.dll";
    private const string FixtureManifestRelativePath = "src/standalone/tests/c03/managed_cli/fixture_manifest.json";
    private const string OfflinePackageRelativePath = ".deps/nuget-offline";
    private static readonly WorkerBudget StandardBudget = new("balanced", 30_000, 30_000, 1UL << 30, 1_000_000);
    private static readonly WorkerProviderExpectation ProviderExpectation = new(
        "10.1.0.8386",
        OfflinePackageLock.DecompilerAssemblySha256,
        "managed-cli-worker-harness",
        HashText("managed-cli-worker-harness"));

    private static async Task<int> Main()
    {
        try
        {
            var repositoryRoot = FindRepositoryRoot();
            var manifest = LoadManifest(Path.Combine(repositoryRoot, FixtureManifestRelativePath));
            var fixturePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, FixtureAssemblyFileName));
            Require(File.Exists(fixturePath), "managed CLI fixture assembly is unavailable");
            var moduleHash = HashFile(fixturePath);
            var inventory = ReadMethodInventory(fixturePath);
            ValidateManifestInventory(manifest, inventory);

            var firstCase = manifest.Methods[0];
            var firstMethod = inventory.Methods[firstCase.Symbol];
            var firstRequest = CreateRequest(1, fixturePath, moduleHash, firstMethod, StandardBudget);
            await ValidateMandatoryOfflineGateAsync(firstRequest).ConfigureAwait(false);

            OfflinePackageLock.EstablishStartupGate(Path.Combine(repositoryRoot, OfflinePackageRelativePath));
            await ValidateManifestMethodsAsync(manifest, inventory, fixturePath, moduleHash).ConfigureAwait(false);
            await ValidateCancellationAsync(firstRequest).ConfigureAwait(false);
            await ValidateResourceLimitsAsync().ConfigureAwait(false);
            await ValidateSnapshotBindingAsync(firstRequest, fixturePath).ConfigureAwait(false);
            await ValidateMalformedCasesAsync(manifest, firstMethod, fixturePath).ConfigureAwait(false);
            Console.Out.WriteLine("managed CLI worker harness satisfied");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    private static async Task ValidateMandatoryOfflineGateAsync(WorkerRequest request)
    {
        await using var guard = new ResourceBudgetGuard(request.Budget);
        try
        {
            _ = MetadataAnalysis.Analyze(request, guard, CancellationToken.None);
            throw new InvalidOperationException("managed CLI analysis bypassed the offline startup gate");
        }
        catch (OfflineIntegrityException)
        {
        }
    }

    private static async Task ValidateManifestMethodsAsync(
        FixtureManifest manifest,
        MethodInventory inventory,
        string fixturePath,
        string moduleHash)
    {
        ulong sequence = 10;
        foreach (var fixtureCase in manifest.Methods)
        {
            var method = inventory.Methods[fixtureCase.Symbol];
            var request = CreateRequest(sequence++, fixturePath, moduleHash, method, StandardBudget);
            string? baseline = null;
            for (var run = 0; run < manifest.Validation.DeterministicRuns; run++)
            {
                var result = await AnalyzeAsync(request, CancellationToken.None).ConfigureAwait(false);
                ValidateMethodResult(fixtureCase, method, request, result);
                var serialized = WorkerProtocol.Serialize(result);
                if (baseline is not null)
                    Require(string.Equals(baseline, serialized, StringComparison.Ordinal), $"managed CLI output is nondeterministic for {fixtureCase.Symbol}");
                baseline = serialized;
            }
        }
    }

    private static async Task<WorkerResult> AnalyzeAsync(WorkerRequest request, CancellationToken cancellationToken)
    {
        await using var guard = new ResourceBudgetGuard(request.Budget);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(request.Budget.MaxWallClockMs));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, guard.LimitToken);
        var result = await Task.Run(() => MetadataAnalysis.Analyze(request, guard, linked.Token), linked.Token).ConfigureAwait(false);
        await guard.CompleteAsync().ConfigureAwait(false);
        return result;
    }

    private static void ValidateMethodResult(FixtureCase fixtureCase, MethodDescriptor method, WorkerRequest request, WorkerResult result)
    {
        Require(string.Equals(result.ModuleHash, request.ModuleHash, StringComparison.Ordinal), $"module hash drifted for {fixtureCase.Symbol}");
        Require(result.MetadataToken == method.Token && result.Identity.GenericArity == fixtureCase.MethodGenericArity,
            $"metadata identity drifted for {fixtureCase.Symbol}");
        Require(string.Equals(result.Identity.DeclaringType + "." + result.Identity.MethodName, fixtureCase.Symbol, StringComparison.Ordinal),
            $"symbol identity drifted for {fixtureCase.Symbol}");
        Require(string.Equals(result.Identity.MethodSignature, method.Signature, StringComparison.Ordinal),
            $"method signature drifted for {fixtureCase.Symbol}");
        Require(FixedTimeHexEquals(result.Source.Sha256, HashText(result.Source.Text)), $"source hash drifted for {fixtureCase.Symbol}");
        foreach (var fragment in fixtureCase.ExpectedSourceFragments)
            Require(result.Source.Text.Contains(fragment, StringComparison.Ordinal), $"source fragment {fragment} is absent for {fixtureCase.Symbol}");

        var token = result.TokenMap.Single(entry => entry.Token == method.Token);
        Require(!string.IsNullOrWhiteSpace(token.StableIdentity), $"stable token identity is absent for {fixtureCase.Symbol}");
        if (fixtureCase.Coverage.Contains("generic", StringComparer.Ordinal))
            Require(method.GenericArity != 0 || method.DeclaringType.Contains('`'), $"generic coverage is not represented for {fixtureCase.Symbol}");
        if (fixtureCase.Coverage.Contains("async", StringComparer.Ordinal))
            Require(token.IsAsync, $"async token classification is absent for {fixtureCase.Symbol}");
        if (fixtureCase.Coverage.Contains("iterator", StringComparer.Ordinal) || fixtureCase.Coverage.Contains("async_iterator", StringComparer.Ordinal))
            Require(token.IsIterator, $"iterator token classification is absent for {fixtureCase.Symbol}");
        if (fixtureCase.Coverage.Contains("exceptions", StringComparer.Ordinal))
            Require(token.HasExceptionRegions, $"exception-region classification is absent for {fixtureCase.Symbol}");

        var valueIds = result.Ir.Blocks.SelectMany(block => block.Values).Select(value => value.Id).ToHashSet();
        Require(valueIds.Count != 0 && result.Ir.Blocks.SelectMany(block => block.Values).SelectMany(value => value.OperandIds).All(valueIds.Contains),
            $"provider IR operand graph is not closed for {fixtureCase.Symbol}");
        Require(result.TokenMap.Zip(result.TokenMap.Skip(1), (left, right) => left.Token < right.Token).All(value => value),
            $"token map ordering drifted for {fixtureCase.Symbol}");
    }

    private static async Task ValidateCancellationAsync(WorkerRequest request)
    {
        Require(request.Budget.MaxWallClockMs != 0, "cancellation fixture budget is invalid");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try
        {
            _ = await AnalyzeAsync(request, cancellation.Token).ConfigureAwait(false);
            throw new InvalidOperationException("managed CLI analysis ignored cancellation");
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static async Task ValidateResourceLimitsAsync()
    {
        await using (var memoryGuard = new ResourceBudgetGuard(new WorkerBudget("balanced", 5_000, 5_000, 1, 1_000)))
        {
            try
            {
                memoryGuard.Checkpoint(CancellationToken.None);
                throw new InvalidOperationException("managed CLI memory limit was not enforced");
            }
            catch (ResourceLimitException exception)
            {
                Require(exception.Kind == ResourceLimitKind.Memory, "managed CLI memory limit reported the wrong resource");
            }
        }

        await using var cpuGuard = new ResourceBudgetGuard(new WorkerBudget("balanced", 5_000, 1, 8UL << 30, 1_000));
        var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed < TimeSpan.FromSeconds(5))
        {
            Thread.SpinWait(50_000);
            try
            {
                cpuGuard.Checkpoint(CancellationToken.None);
            }
            catch (ResourceLimitException exception)
            {
                Require(exception.Kind == ResourceLimitKind.Cpu, "managed CLI CPU limit reported the wrong resource");
                return;
            }
        }
        throw new InvalidOperationException("managed CLI CPU limit was not enforced");
    }

    private static async Task ValidateSnapshotBindingAsync(WorkerRequest request, string fixturePath)
    {
        var temporaryPath = Path.Combine(Path.GetTempPath(), $"aida-managed-cli-snapshot-{Guid.NewGuid():N}.dll");
        try
        {
            File.Copy(fixturePath, temporaryPath, overwrite: false);
            var bound = request with { ModulePath = temporaryPath, ModuleHash = HashFile(temporaryPath), Sequence = request.Sequence + 10_000 };
            var bytes = File.ReadAllBytes(temporaryPath);
            bytes[^1] ^= 0x5a;
            File.WriteAllBytes(temporaryPath, bytes);
            try
            {
                _ = await AnalyzeAsync(bound, CancellationToken.None).ConfigureAwait(false);
                throw new InvalidOperationException("managed CLI accepted a module changed after hash binding");
            }
            catch (InvalidDataException)
            {
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static async Task ValidateMalformedCasesAsync(FixtureManifest manifest, MethodDescriptor method, string fixturePath)
    {
        var original = File.ReadAllBytes(fixturePath);
        var metadataOffset = FindSequence(original, Encoding.ASCII.GetBytes("BSJB"));
        Require(metadataOffset >= 0, "managed CLI fixture metadata signature is absent");
        for (var malformedIndex = 0; malformedIndex < manifest.Malformed.Count; malformedIndex++)
        {
            var malformed = manifest.Malformed[malformedIndex];
            Require(string.Equals(malformed.ExpectedCode, "malformed_metadata", StringComparison.Ordinal) &&
                string.Equals(malformed.ExpectedKey, "managed_cli.malformed_metadata", StringComparison.Ordinal),
                $"malformed fixture expectation drifted for {malformed.Id}");
            var temporaryPath = Path.Combine(Path.GetTempPath(), $"aida-managed-cli-malformed-{malformed.Id}-{Guid.NewGuid():N}.dll");
            try
            {
                var token = method.Token;
                byte[] bytes;
                switch (malformed.Mutation)
                {
                    case "corrupt_metadata_signature":
                        bytes = original.ToArray();
                        bytes[metadataOffset] ^= 0xff;
                        break;
                    case "truncate_metadata_root":
                        bytes = original[..Math.Min(original.Length, metadataOffset + 8)];
                        break;
                    case "non_method_token":
                        bytes = original.ToArray();
                        token = 0x02000001;
                        break;
                    default:
                        throw new InvalidDataException($"unsupported malformed fixture mutation: {malformed.Mutation}");
                }
                File.WriteAllBytes(temporaryPath, bytes);
                var request = CreateRequest(20_000 + checked((ulong)malformedIndex), temporaryPath, HashBytes(bytes), method, StandardBudget) with
                {
                    MetadataToken = token
                };
                try
                {
                    _ = await AnalyzeAsync(request, CancellationToken.None).ConfigureAwait(false);
                    throw new InvalidOperationException($"managed CLI accepted malformed fixture {malformed.Id}");
                }
                catch (Exception exception) when (exception is BadImageFormatException or InvalidDataException)
                {
                }
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }
        }
    }

    private static WorkerRequest CreateRequest(
        ulong sequence,
        string modulePath,
        string moduleHash,
        MethodDescriptor method,
        WorkerBudget budget)
    {
        return new WorkerRequest(
            WorkerProtocol.Schema,
            WorkerProtocol.Version,
            "decompile",
            sequence,
            $"managed-cli-fixture-{sequence}",
            Path.GetFullPath(modulePath),
            moduleHash,
            method.Token,
            1,
            OfflinePackageLock.ManifestHashHex,
            budget,
            ProviderExpectation);
    }

    private static MethodInventory ReadMethodInventory(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var peReader = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
        Require(peReader.HasMetadata, "managed CLI fixture has no metadata");
        var reader = peReader.GetMetadataReader();
        var provider = new StableSignatureTypeProvider();
        var methods = new Dictionary<string, MethodDescriptor>(StringComparer.Ordinal);
        var typeNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var typeName = MetadataAnalysis.GetTypeDefinitionName(reader, typeHandle);
            typeNames.Add(typeName);
            var type = reader.GetTypeDefinition(typeHandle);
            foreach (var methodHandle in type.GetMethods())
            {
                var method = reader.GetMethodDefinition(methodHandle);
                var methodName = reader.GetString(method.Name);
                var signature = method.DecodeSignature(provider, new GenericContext(typeName, methodName));
                var descriptor = new MethodDescriptor(
                    unchecked((uint)MetadataTokens.GetToken(methodHandle)),
                    typeName,
                    methodName,
                    $"{signature.ReturnType}({string.Join(',', signature.ParameterTypes)})",
                    checked((uint)method.GetGenericParameters().Count));
                var symbol = typeName + "." + methodName;
                Require(methods.TryAdd(symbol, descriptor), $"managed CLI fixture symbol is ambiguous: {symbol}");
            }
        }
        return new MethodInventory(methods, typeNames);
    }

    private static void ValidateManifestInventory(FixtureManifest manifest, MethodInventory inventory)
    {
        Require(string.Equals(manifest.Schema, "aida.c03.managed-cli-fixtures", StringComparison.Ordinal) && manifest.SchemaVersion == 1,
            "managed CLI fixture manifest schema is invalid");
        Require(string.Equals(manifest.Assembly, "ManagedCliFixtures", StringComparison.Ordinal) && manifest.Methods.Count >= 6,
            "managed CLI fixture manifest inventory is incomplete");
        Require(manifest.Validation.DeterministicRuns >= 2 && manifest.Validation.Cancellation && manifest.Validation.OfflineStartupGate &&
            manifest.Validation.SnapshotBinding && manifest.Validation.ResourceLimits.OrderBy(value => value, StringComparer.Ordinal)
                .SequenceEqual(new[] { "maxCpuMs", "maxMemoryBytes" }.OrderBy(value => value, StringComparer.Ordinal), StringComparer.Ordinal),
            "managed CLI fixture validation contract is incomplete");
        foreach (var fixtureCase in manifest.Methods)
        {
            Require(inventory.Methods.TryGetValue(fixtureCase.Symbol, out var method), $"managed CLI fixture symbol is absent: {fixtureCase.Symbol}");
            Require(method.GenericArity == fixtureCase.MethodGenericArity, $"managed CLI fixture generic arity drifted: {fixtureCase.Symbol}");
            Require(fixtureCase.Coverage.Count != 0 && fixtureCase.ExpectedSourceFragments.Count != 0,
                $"managed CLI fixture coverage is empty: {fixtureCase.Symbol}");
        }
        foreach (var malformed in manifest.Malformed)
            Require(inventory.Types.Contains(malformed.SourceContract), $"managed CLI malformed source contract is absent: {malformed.SourceContract}");
    }

    private static FixtureManifest LoadManifest(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
        var root = document.RootElement;
        var methods = root.GetProperty("methods").EnumerateArray().Select(value => new FixtureCase(
            value.GetProperty("symbol").GetString() ?? throw new InvalidDataException("fixture symbol is empty"),
            value.GetProperty("method_generic_arity").GetUInt32(),
            value.GetProperty("coverage").EnumerateArray().Select(item => item.GetString() ?? throw new InvalidDataException("fixture coverage is empty")).ToArray(),
            value.GetProperty("expected_source_fragments").EnumerateArray().Select(item => item.GetString() ?? throw new InvalidDataException("fixture source fragment is empty")).ToArray())).ToList();
        var malformed = root.GetProperty("malformed").EnumerateArray().Select(value => new MalformedCase(
            value.GetProperty("id").GetString() ?? throw new InvalidDataException("malformed fixture ID is empty"),
            value.GetProperty("source_contract").GetString() ?? throw new InvalidDataException("malformed source contract is empty"),
            value.GetProperty("mutation").GetString() ?? throw new InvalidDataException("malformed mutation is empty"),
            value.GetProperty("expected_code").GetString() ?? throw new InvalidDataException("malformed code is empty"),
            value.GetProperty("expected_key").GetString() ?? throw new InvalidDataException("malformed key is empty"))).ToList();
        var validationValue = root.GetProperty("validation");
        var validation = new ValidationContract(
            validationValue.GetProperty("deterministic_runs").GetInt32(),
            validationValue.GetProperty("cancellation").GetBoolean(),
            validationValue.GetProperty("resource_limits").EnumerateArray().Select(value => value.GetString() ?? throw new InvalidDataException("resource limit is empty")).ToArray(),
            validationValue.GetProperty("offline_startup_gate").GetBoolean(),
            validationValue.GetProperty("snapshot_binding").GetBoolean());
        return new FixtureManifest(
            root.GetProperty("schema").GetString() ?? throw new InvalidDataException("fixture schema is empty"),
            root.GetProperty("schema_version").GetInt32(),
            root.GetProperty("assembly").GetString() ?? throw new InvalidDataException("fixture assembly is empty"),
            methods,
            malformed,
            validation);
    }

    private static string FindRepositoryRoot()
    {
        foreach (var seed in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
        {
            var current = new DirectoryInfo(Path.GetFullPath(seed));
            while (current is not null)
            {
                if (File.Exists(Path.Combine(current.FullName, "AGENTS.md")) && Directory.Exists(Path.Combine(current.FullName, ".deps")))
                    return current.FullName;
                current = current.Parent;
            }
        }
        throw new DirectoryNotFoundException("AiDA repository root is unavailable");
    }

    private static int FindSequence(byte[] bytes, byte[] sequence)
    {
        for (var offset = 0; offset <= bytes.Length - sequence.Length; offset++)
        {
            if (bytes.AsSpan(offset, sequence.Length).SequenceEqual(sequence))
                return offset;
        }
        return -1;
    }

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string HashBytes(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static string HashText(string value) => HashBytes(Encoding.UTF8.GetBytes(value));

    private static bool FixedTimeHexEquals(string left, string right)
    {
        if (left.Length != 64 || right.Length != 64)
            return false;
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed record FixtureManifest(
        string Schema,
        int SchemaVersion,
        string Assembly,
        IReadOnlyList<FixtureCase> Methods,
        IReadOnlyList<MalformedCase> Malformed,
        ValidationContract Validation);

    private sealed record FixtureCase(
        string Symbol,
        uint MethodGenericArity,
        IReadOnlyList<string> Coverage,
        IReadOnlyList<string> ExpectedSourceFragments);

    private sealed record MalformedCase(
        string Id,
        string SourceContract,
        string Mutation,
        string ExpectedCode,
        string ExpectedKey);

    private sealed record ValidationContract(
        int DeterministicRuns,
        bool Cancellation,
        IReadOnlyList<string> ResourceLimits,
        bool OfflineStartupGate,
        bool SnapshotBinding);

    private sealed record MethodDescriptor(
        uint Token,
        string DeclaringType,
        string MethodName,
        string Signature,
        uint GenericArity);

    private sealed record MethodInventory(
        IReadOnlyDictionary<string, MethodDescriptor> Methods,
        IReadOnlySet<string> Types);
}
