using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aida.ManagedDecompiler;
using Microsoft.Win32.SafeHandles;

namespace Aida.C03.ManagedCliHarness;

internal static class Program
{
    private const string FixtureAssemblyFileName = "ManagedCliFixtures.dll";
    private const string FixtureManifestRelativePath = "src/standalone/tests/c03/managed_cli/fixture_manifest.json";
    private const string ManagedContractHash = "4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6";
    private const string ManagedWorkerBuildMaterial = "aida-managed-decompiler-worker-build-v3|snapshot-bound-contract=4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6|tfm=net10.0|runtime=Microsoft.NETCore.App/10.0.9";
    private const string GeneratedParameterTypeName = "Aida.C03.GeneratedParameterFixture";
    private const int MaximumWireSignatureBytes = 8 * 1024;
    private static string runtimeManifestHash = string.Empty;
    private static readonly WorkerBudget StandardBudget = new(
        "balanced", 30_000, 30_000, 1UL << 30, 1_000_000,
        1_000_000, 1_000_000, 0, false);
    private static readonly WorkerProviderExpectation ProviderExpectation = new(
        "10.1.0.8386",
        RuntimeIdentity.DecompilerAssemblySha256,
        "aida-managed-decompiler-worker-v3",
        HashText(ManagedWorkerBuildMaterial));

    private static async Task<int> Main()
    {
        byte[]? moduleBytes = null;
        try
        {
            var repositoryRoot = FindRepositoryRoot();
            var packageRoot = ResolveManagedPackageRoot();
            runtimeManifestHash = ReadRuntimeManifestHash(packageRoot);
            ValidateStartupArgumentContract();
            var manifest = LoadManifest(Path.Combine(repositoryRoot, FixtureManifestRelativePath));
            var fixturePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, FixtureAssemblyFileName));
            Require(File.Exists(fixturePath), "managed CLI fixture assembly is unavailable");
            moduleBytes = File.ReadAllBytes(fixturePath);
            Require(moduleBytes.Length != 0, "managed CLI fixture assembly is empty");
            var moduleHash = HashBytes(moduleBytes);
            var inventory = ReadMethodInventory(fixturePath);
            ValidateManifestInventory(manifest, inventory);

            var firstCase = manifest.Methods[0];
            var firstMethod = inventory.Methods[firstCase.Symbol];
            var firstRequest = CreateRequest(1, "regular_file", fixturePath,
                moduleHash, checked((ulong)moduleBytes.LongLength), firstMethod,
                StandardBudget, 1, 1);
            await ValidateMandatoryRuntimeGateAsync(firstRequest).ConfigureAwait(false);
            await ValidateManifestMethodsAsync(manifest, inventory,
                fixturePath, moduleHash, checked((ulong)moduleBytes.LongLength)).ConfigureAwait(false);
            await ValidateParameterMetadataAsync().ConfigureAwait(false);
            await ValidateResourceLimitsAsync().ConfigureAwait(false);
            await ValidateResourceBudgetBoundsAsync(firstRequest).ConfigureAwait(false);
            await ValidateSnapshotBindingAsync(firstRequest,
                fixturePath, moduleBytes).ConfigureAwait(false);
            await ValidateMalformedCasesAsync(manifest, firstMethod,
                fixturePath).ConfigureAwait(false);
            await ValidateConcurrentWorkspaceIsolationAsync(fixturePath,
                moduleHash, checked((ulong)moduleBytes.LongLength), firstMethod).ConfigureAwait(false);
            Console.Out.WriteLine("managed CLI worker harness satisfied");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
        finally
        {
            if (moduleBytes is not null)
                CryptographicOperations.ZeroMemory(moduleBytes);
        }
    }

    private static async Task ValidateMandatoryRuntimeGateAsync(WorkerRequest request)
    {
        await using var guard = new ResourceBudgetGuard(request.Budget);
        try
        {
            _ = MetadataAnalysis.Analyze(request, guard, CancellationToken.None);
            throw new InvalidOperationException("managed CLI analysis bypassed the app-local runtime gate");
        }
        catch (RuntimeIntegrityException)
        {
        }
    }

    private static void ValidateStartupArgumentContract()
    {
        var valid = new[]
        {
            "--aida-managed-decompiler-worker",
            "--provider=2",
            "--read-handle=1",
            "--write-handle=2",
            "--module-handle=3",
            "--module-size=1",
            "--identity-handle=4",
            "--runtime-manifest-hash=" + runtimeManifestHash
        };
        var parsed = WorkerStartupOptions.Parse(valid);
        Require(parsed.ModuleSize == 1 && parsed.ReadHandle != parsed.WriteHandle &&
            parsed.ModuleHandle != parsed.IdentityHandle,
            "managed CLI worker startup contract rejected its exact handle allowlist");

        void RequireRejected(string[] arguments, string message)
        {
            try
            {
                _ = WorkerStartupOptions.Parse(arguments);
                throw new InvalidOperationException(message);
            }
            catch (InvalidDataException)
            {
            }
        }

        var oversized = valid.ToArray();
        oversized[5] = "--module-size=268435457";
        RequireRejected(oversized, "managed CLI worker accepted an oversized module mapping");
        var duplicate = valid.ToArray();
        duplicate[4] = "--module-handle=2";
        RequireRejected(duplicate, "managed CLI worker accepted overlapping handle capabilities");
        var nonCanonical = valid.ToArray();
        nonCanonical[2] = "--read-handle=+1";
        RequireRejected(nonCanonical, "managed CLI worker accepted a non-canonical handle value");
        var missingRuntime = valid[..^1];
        RequireRejected(missingRuntime, "managed CLI worker accepted a missing runtime identity");
        var uppercaseRuntime = valid.ToArray();
        uppercaseRuntime[^1] = "--runtime-manifest-hash=A" + runtimeManifestHash[1..];
        RequireRejected(uppercaseRuntime, "managed CLI worker accepted a non-canonical runtime identity");
        var emptyRuntimeIdentity = valid.ToArray();
        emptyRuntimeIdentity[^1] = "--runtime-manifest-hash=" + new string('0', 64);
        RequireRejected(emptyRuntimeIdentity, "managed CLI worker accepted an empty runtime identity");
        var repositoryRuntime = valid.Append("--package-root=.deps").ToArray();
        RequireRejected(repositoryRuntime, "managed CLI worker accepted a repository package override");
    }

    private static async Task ValidateManifestMethodsAsync(
        FixtureManifest manifest,
        MethodInventory inventory,
        string fixturePath,
        string moduleHash,
        ulong moduleSize)
    {
        ulong sequence = 10;
        foreach (var fixtureCase in manifest.Methods)
        {
            var method = inventory.Methods[fixtureCase.Symbol];
            var request = CreateRequest(sequence++, "regular_file", fixturePath,
                moduleHash, moduleSize, method, StandardBudget, 7, 9);
            string? baseline = null;
            for (var run = 0; run < manifest.Validation.DeterministicRuns; run++)
            {
                await using var worker = await ManagedWorkerProcess.StartAsync(fixturePath).ConfigureAwait(false);
                var result = await worker.DecompileAsync(request).ConfigureAwait(false);
                ValidateMethodResult(manifest.Assembly, fixtureCase, method, request, result);
                var serialized = WorkerProtocol.Serialize(result);
                if (baseline is not null)
                    Require(string.Equals(baseline, serialized, StringComparison.Ordinal), $"managed CLI output is nondeterministic for {fixtureCase.Symbol}");
                baseline = serialized;
            }
        }
        var firstMethod = inventory.Methods[manifest.Methods[0].Symbol];
        var cancellationRequest = CreateRequest(sequence++, "regular_file", fixturePath,
            moduleHash, moduleSize, firstMethod, StandardBudget, 7, 9);
        await using var cancellationWorker = await ManagedWorkerProcess.StartAsync(fixturePath).ConfigureAwait(false);
        var cancelled = await cancellationWorker.DecompileAndCancelAsync(cancellationRequest).ConfigureAwait(false);
        Require(cancelled.Diagnostics.Count == 1 && string.Equals(cancelled.Diagnostics[0].Code, "cancelled", StringComparison.Ordinal),
            "managed CLI worker cancellation response is invalid");
        var memoryRequest = CreateRequest(sequence++, "regular_file", fixturePath,
            moduleHash, moduleSize, firstMethod,
            new WorkerBudget("balanced", 5_000, 5_000, moduleSize * 2, 1_000_000,
                1_000_000, 1_000_000, 0, false), 7, 9);
        await using var memoryWorker = await ManagedWorkerProcess.StartAsync(fixturePath).ConfigureAwait(false);
        var limited = await memoryWorker.DecompileFailureAsync(memoryRequest).ConfigureAwait(false);
        Require(limited.Diagnostics.Count == 1 && string.Equals(limited.Diagnostics[0].Code, "resource_limit", StringComparison.Ordinal),
            "managed CLI worker resource response is invalid");

        var deadlineRequest = CreateRequest(sequence, "regular_file", fixturePath,
            moduleHash, moduleSize, firstMethod,
            new WorkerBudget("balanced", 1, 30_000, 1UL << 30, 1_000_000,
                1_000_000, 1_000_000, 0, false), 7, 9);
        await using var deadlineWorker = await ManagedWorkerProcess.StartAsync(
            fixturePath).ConfigureAwait(false);
        var deadline = await deadlineWorker.DecompileFailureAsync(deadlineRequest).ConfigureAwait(false);
        Require(deadline.Diagnostics.Count == 1 &&
            string.Equals(deadline.Diagnostics[0].Code, "deadline_exceeded", StringComparison.Ordinal),
            "managed CLI worker deadline response is invalid");
    }

    private static async Task ValidateParameterMetadataAsync()
    {
        var fixture = CreateParameterMetadataFixture(ParameterFixtureKind.Valid);
        var repeatedFixture = CreateParameterMetadataFixture(ParameterFixtureKind.Valid);
        try
        {
            Require(fixture.Bytes.AsSpan().SequenceEqual(repeatedFixture.Bytes),
                "managed CLI generated parameter fixture is nondeterministic");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(repeatedFixture.Bytes);
        }
        var temporaryPath = Path.Combine(Path.GetTempPath(), $"aida-managed-cli-parameter-rows-{Guid.NewGuid():N}.dll");
        try
        {
            File.WriteAllBytes(temporaryPath, fixture.Bytes);
            ValidateParameterFixtureEncoding(temporaryPath, fixture);
            var inventory = ReadMethodInventory(temporaryPath);
            Require(fixture.Methods.All(entry => inventory.Methods.TryGetValue(entry.Key, out var method) && method == entry.Value),
                "managed CLI generated parameter fixture inventory drifted");
            var expectations = new[]
            {
                new ParameterIdentityExpectation("StaticNamed", new[] { "left", "right" },
                    new[] { "left", "right" }, Array.Empty<string>()),
                new ParameterIdentityExpectation("InstanceNamed", new[] { "this", "value", "delta" },
                    new[] { "value", "delta" }, Array.Empty<string>()),
                new ParameterIdentityExpectation("StoreForms", new[] { "arg_0", "shortNamed", "longNamed", "storeOnly" },
                    new[] { "shortNamed", "longNamed", "storeOnly" },
                    new[] { "arg_0", "shortNamed", "longNamed", "storeOnly" }),
                new ParameterIdentityExpectation("Reordered", new[] { "first", "second" },
                    new[] { "first", "second" }, Array.Empty<string>())
            };
            ulong sequence = 40_000;
            foreach (var expectation in expectations)
            {
                var symbol = GeneratedParameterTypeName + "." + expectation.MethodName;
                var method = fixture.Methods[symbol];
                var request = CreateRequest(sequence++, "regular_file", temporaryPath, HashBytes(fixture.Bytes),
                    checked((ulong)fixture.Bytes.LongLength), method, StandardBudget, 301, 43);
                string? baseline = null;
                for (var run = 0; run < 2; run++)
                {
                    await using var worker = await ManagedWorkerProcess.StartAsync(temporaryPath).ConfigureAwait(false);
                    var result = await worker.DecompileAsync(request).ConfigureAwait(false);
                    ValidateParameterIdentityResult(expectation, method, request, result);
                    var serialized = WorkerProtocol.Serialize(result);
                    if (baseline is not null)
                        Require(string.Equals(baseline, serialized, StringComparison.Ordinal),
                            $"managed CLI parameter identities are nondeterministic for {expectation.MethodName}");
                    baseline = serialized;
                }
            }

            var cancellationMethod = fixture.Methods[GeneratedParameterTypeName + ".StoreForms"];
            var cancellationRequest = CreateRequest(sequence++, "regular_file", temporaryPath, HashBytes(fixture.Bytes),
                checked((ulong)fixture.Bytes.LongLength), cancellationMethod, StandardBudget, 302, 47);
            await using (var cancellationWorker = await ManagedWorkerProcess.StartAsync(temporaryPath).ConfigureAwait(false))
            {
                var cancellation = await cancellationWorker.DecompileAndCancelAsync(cancellationRequest).ConfigureAwait(false);
                Require(cancellation.Diagnostics.Count == 1 &&
                    string.Equals(cancellation.Diagnostics[0].Code, "cancelled", StringComparison.Ordinal),
                    "managed CLI parameter metadata cancellation response is invalid");
            }

            var budgetRequest = CreateRequest(sequence, "regular_file", temporaryPath, HashBytes(fixture.Bytes),
                checked((ulong)fixture.Bytes.LongLength), cancellationMethod,
                new WorkerBudget("balanced", 5_000, 5_000, 1UL << 30,
                    1, 1_000_000, 1_000_000, 0, false), 303, 53);
            await using var budgetWorker = await ManagedWorkerProcess.StartAsync(temporaryPath).ConfigureAwait(false);
            var budgetFailure = await budgetWorker.DecompileFailureAsync(budgetRequest).ConfigureAwait(false);
            Require(budgetFailure.Diagnostics.Count == 1 &&
                string.Equals(budgetFailure.Diagnostics[0].Code, "resource_limit", StringComparison.Ordinal),
                "managed CLI parameter metadata resource budget was not enforced");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fixture.Bytes);
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }

        foreach (var malformed in new[]
                 {
                     ParameterFixtureKind.DuplicateSequence,
                     ParameterFixtureKind.OutOfRangeSequence,
                     ParameterFixtureKind.DuplicateReturnSequence,
                     ParameterFixtureKind.ExcessRows
                 })
            await ValidateMalformedParameterMetadataAsync(malformed).ConfigureAwait(false);
    }

    private static void ValidateParameterIdentityResult(
        ParameterIdentityExpectation expectation,
        MethodDescriptor method,
        WorkerRequest request,
        WorkerResult result)
    {
        ValidateTerminalBinding(request, result.ModuleSource, result.EntityHash,
            result.MetadataToken, result.WorkspaceGeneration, result.TypeGraphRevision,
            result.Budget, result.RuntimeManifestHash, result.ContractHash,
            result.CacheIdentity, result.RequestBindingHash, result.Provider);
        Require(result.MetadataToken == method.Token &&
            string.Equals(result.Identity.AssemblyIdentity, "ManagedParameterRows", StringComparison.Ordinal) &&
            string.Equals(result.Identity.ModuleName, "ManagedParameterRows.dll", StringComparison.Ordinal) &&
            string.Equals(result.Identity.DeclaringType, GeneratedParameterTypeName, StringComparison.Ordinal) &&
            string.Equals(result.Identity.MethodName, expectation.MethodName, StringComparison.Ordinal) &&
            string.Equals(result.Identity.MethodSignature, method.Signature, StringComparison.Ordinal),
            $"managed CLI parameter metadata identity drifted for {expectation.MethodName}");
        Require(FixedTimeHexEquals(result.Source.Sha256, HashText(result.Source.Text)),
            $"managed CLI parameter metadata source hash drifted for {expectation.MethodName}");
        foreach (var sourceName in expectation.SourceNames)
            Require(result.Source.Text.Contains(sourceName, StringComparison.Ordinal),
                $"managed CLI metadata parameter name {sourceName} was not preserved for {expectation.MethodName}");

        ValidateProviderOperands(GeneratedParameterTypeName + "." + expectation.MethodName, result);
        var values = result.Ir.Blocks.SelectMany(block => block.Values).ToArray();
        var parameterSymbols = values.Where(value => string.Equals(value.Opcode, "parameter", StringComparison.Ordinal))
            .Select(value => value.StableSymbol).ToHashSet(StringComparer.Ordinal);
        Require(parameterSymbols.SetEquals(expectation.StableSymbols),
            $"managed CLI canonical parameter identities drifted for {expectation.MethodName}");
        Require(!parameterSymbols.Contains("returnValue") && !parameterSymbols.Contains("instanceReturn") &&
            !parameterSymbols.Contains("storeReturn") && !parameterSymbols.Contains("reorderedReturn"),
            $"managed CLI return Param row leaked into argument identities for {expectation.MethodName}");

        if (expectation.StoreDestinations.Count != 0)
        {
            var byId = values.ToDictionary(value => value.Id);
            var destinations = values.Where(value => string.Equals(value.Opcode, "store", StringComparison.Ordinal))
                .Select(value => value.OperandIds.Count == 2 && byId.TryGetValue(value.OperandIds[0], out var destination) &&
                    string.Equals(destination.Opcode, "parameter", StringComparison.Ordinal)
                        ? destination.StableSymbol
                        : string.Empty)
                .ToArray();
            Require(destinations.SequenceEqual(expectation.StoreDestinations, StringComparer.Ordinal),
                $"managed CLI parameter store destinations drifted for {expectation.MethodName}");
        }
    }

    private static async Task ValidateMalformedParameterMetadataAsync(ParameterFixtureKind kind)
    {
        var fixture = CreateParameterMetadataFixture(kind);
        var temporaryPath = Path.Combine(Path.GetTempPath(), $"aida-managed-cli-parameter-{kind}-{Guid.NewGuid():N}.dll");
        try
        {
            File.WriteAllBytes(temporaryPath, fixture.Bytes);
            var method = fixture.Methods[GeneratedParameterTypeName + ".Malformed"];
            var request = CreateRequest(41_000 + checked((ulong)kind), "regular_file", temporaryPath,
                HashBytes(fixture.Bytes), checked((ulong)fixture.Bytes.LongLength), method,
                StandardBudget, 401 + checked((ulong)kind), 61);
            await using var worker = await ManagedWorkerProcess.StartAsync(temporaryPath).ConfigureAwait(false);
            var failure = await worker.DecompileFailureAsync(request).ConfigureAwait(false);
            var expectedMessage = kind switch
            {
                ParameterFixtureKind.DuplicateSequence or ParameterFixtureKind.DuplicateReturnSequence =>
                    "method parameter sequence is duplicated",
                ParameterFixtureKind.OutOfRangeSequence =>
                    "method parameter sequence exceeds its signature bounds",
                ParameterFixtureKind.ExcessRows =>
                    "method parameter table exceeds its signature bounds",
                _ => throw new InvalidDataException("parameter fixture malformed case is invalid")
            };
            Require(failure.Diagnostics.Count == 1 &&
                string.Equals(failure.Diagnostics[0].Code, "malformed_metadata", StringComparison.Ordinal) &&
                string.Equals(failure.Diagnostics[0].Key, "managed_cli.malformed_metadata", StringComparison.Ordinal) &&
                failure.Diagnostics[0].Args.Count == 2 &&
                string.Equals(failure.Diagnostics[0].Args[0], "bad_image", StringComparison.Ordinal) &&
                string.Equals(failure.Diagnostics[0].Args[1], expectedMessage, StringComparison.Ordinal),
                $"managed CLI malformed parameter metadata did not fail closed for {kind}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fixture.Bytes);
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static void ValidateMethodResult(string assemblyIdentity, FixtureCase fixtureCase, MethodDescriptor method, WorkerRequest request, WorkerResult result)
    {
        ValidateTerminalBinding(request, result.ModuleSource, result.EntityHash,
            result.MetadataToken, result.WorkspaceGeneration, result.TypeGraphRevision,
            result.Budget, result.RuntimeManifestHash, result.ContractHash,
            result.CacheIdentity, result.RequestBindingHash, result.Provider);
        Require(result.MetadataToken == method.Token && result.Identity.GenericArity == fixtureCase.MethodGenericArity,
            $"metadata identity drifted for {fixtureCase.Symbol}");
        Require(string.Equals(result.Identity.AssemblyIdentity, assemblyIdentity, StringComparison.Ordinal),
            $"assembly identity drifted for {fixtureCase.Symbol}");
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
        ValidateProviderOperands(fixtureCase.Symbol, result);
        Require(result.TokenMap.Zip(result.TokenMap.Skip(1), (left, right) => left.Token < right.Token).All(value => value),
            $"token map ordering drifted for {fixtureCase.Symbol}");
    }

    private static void ValidateProviderOperands(string symbol, WorkerResult result)
    {
        var values = result.Ir.Blocks.SelectMany(block => block.Values).ToArray();
        var returnType = result.TypeGraph.Nodes.Single(node => node.Id == result.ReturnTypeId);
        var binaryOperators = new HashSet<string>(new[]
        {
            "*", "/", "%", "+", "-", "<<", ">>", "<", "<=", ">", ">=", "==", "!=", "&", "^", "|", "&&", "||"
        }, StringComparer.Ordinal);
        foreach (var value in values)
        {
            switch (value.Opcode)
            {
                case "parameter":
                case "local":
                    Require(value.OperandIds.Count == 0 && !string.IsNullOrWhiteSpace(value.StableSymbol),
                        $"provider IR variable payload is invalid for {symbol}");
                    break;
                case "constant":
                case "unknown":
                    Require(value.OperandIds.Count == 0 && !string.IsNullOrWhiteSpace(value.StableImmediate),
                        $"provider IR leaf payload is invalid for {symbol}");
                    break;
                case "unary":
                case "cast":
                case "load":
                    Require(value.OperandIds.Count == 1,
                        $"provider IR unary operand arity is invalid for {symbol}");
                    break;
                case "binary":
                    Require(value.OperandIds.Count == 2 && binaryOperators.Contains(value.StableImmediate),
                        $"provider IR binary payload is invalid for {symbol}");
                    break;
                case "store":
                case "field_store":
                    Require(value.OperandIds.Count == 2,
                        $"provider IR store operand arity is invalid for {symbol}");
                    break;
                case "array_load":
                    Require(value.OperandIds.Count == 2,
                        $"provider IR array-load operand arity is invalid for {symbol}");
                    break;
                case "array_store":
                    Require(value.OperandIds.Count == 3,
                        $"provider IR array-store operand arity is invalid for {symbol}");
                    break;
                case "branch":
                    Require(value.OperandIds.Count == 0,
                        $"provider IR branch operand arity is invalid for {symbol}");
                    break;
                case "conditional_branch":
                    Require(value.OperandIds.Count == 1 && value.StableImmediate.StartsWith("condition.true=", StringComparison.Ordinal) &&
                        value.StableImmediate.Contains(";negated=", StringComparison.Ordinal),
                        $"provider IR conditional payload is invalid for {symbol}");
                    break;
                case "switch_branch":
                    Require(value.OperandIds.Count == 1,
                        $"provider IR switch operand arity is invalid for {symbol}");
                    break;
                case "return_value":
                    Require(value.OperandIds.Count == (returnType.Kind == "void" ? 0 : 1),
                        $"provider IR return operand arity is invalid for {symbol}");
                    break;
                case "throw_value":
                    Require(value.OperandIds.Count == 1,
                        $"provider IR throw operand arity is invalid for {symbol}");
                    break;
            }
        }
    }

    private static void ValidateTerminalBinding(
        WorkerRequest request,
        WorkerModuleSource moduleSource,
        string entityHash,
        uint metadataToken,
        ulong workspaceGeneration,
        ulong typeGraphRevision,
        WorkerBudget budget,
        string responseRuntimeManifestHash,
        string contractHash,
        string cacheIdentity,
        string requestBindingHash,
        WorkerProviderExpectation provider)
    {
        Require(string.Equals(moduleSource.Kind, request.ModuleSource.Kind, StringComparison.Ordinal) &&
            string.Equals(moduleSource.LogicalIdentity, request.ModuleSource.LogicalIdentity, StringComparison.Ordinal) &&
            FixedTimeHexEquals(moduleSource.ModuleHash, request.ModuleSource.ModuleHash) &&
            moduleSource.ModuleSize == request.ModuleSource.ModuleSize &&
            FixedTimeHexEquals(entityHash, request.EntityHash) && metadataToken == request.MetadataToken &&
            workspaceGeneration == request.WorkspaceGeneration && typeGraphRevision == request.TypeGraphRevision &&
            budget == request.Budget && FixedTimeHexEquals(responseRuntimeManifestHash, request.RuntimeManifestHash) &&
            FixedTimeHexEquals(contractHash, request.ContractHash) &&
            FixedTimeHexEquals(cacheIdentity, request.CacheIdentity) &&
            FixedTimeHexEquals(requestBindingHash, request.RequestBindingHash) &&
            provider == request.Provider,
            "managed CLI terminal response is not exactly bound to its request");
    }

    private static void ValidateFailureBinding(WorkerRequest request, WorkerFailure failure)
    {
        ValidateTerminalBinding(request, failure.ModuleSource, failure.EntityHash,
            failure.MetadataToken, failure.WorkspaceGeneration, failure.TypeGraphRevision,
            failure.Budget, failure.RuntimeManifestHash, failure.ContractHash,
            failure.CacheIdentity, failure.RequestBindingHash, failure.Provider);
    }

    private static async Task ValidateResourceLimitsAsync()
    {
        await using (var memoryGuard = new ResourceBudgetGuard(new WorkerBudget(
            "balanced", 5_000, 5_000, 1, 1_000, 1_000, 1_000, 0, false)))
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

        await using var cpuGuard = new ResourceBudgetGuard(new WorkerBudget(
            "balanced", 5_000, 1, WorkerBudgetLimits.MaximumMemoryBytes,
            1_000, 1_000, 1_000, 0, false));
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

    private static async Task ValidateResourceBudgetBoundsAsync(WorkerRequest request)
    {
        var tiny = new WorkerBudget("balanced", 1, 1,
            request.ModuleSource.ModuleSize * 2, 1, 1, 1, 0, false);
        MetadataAnalysis.ValidateRequest(RebindRequest(request with { Budget = tiny }));

        await RequireBudgetRejectedAsync(request, new WorkerBudget(
                "balanced", 1, ulong.MaxValue, 1, 1, 1, 1, 0, false),
            "managed CLI accepted UINT64_MAX CPU budget").ConfigureAwait(false);
        await RequireBudgetRejectedAsync(request, new WorkerBudget(
                "balanced", 1, WorkerBudgetLimits.MaximumCpuMs + 1, 1, 1, 1, 1, 0, false),
            "managed CLI accepted oversized CPU budget").ConfigureAwait(false);
        await RequireBudgetRejectedAsync(request, new WorkerBudget(
                "balanced", 1, 1, ulong.MaxValue, 1, 1, 1, 0, false),
            "managed CLI accepted UINT64_MAX memory budget").ConfigureAwait(false);
        await RequireBudgetRejectedAsync(request, new WorkerBudget(
                "balanced", 1, 1, WorkerBudgetLimits.MaximumMemoryBytes + 1,
                1, 1, 1, 0, false),
            "managed CLI accepted oversized memory budget").ConfigureAwait(false);
        await RequireBudgetRejectedAsync(request, new WorkerBudget(
                "balanced", 1, 1, request.ModuleSource.ModuleSize * 2,
                1, 1, 1, 1, false),
            "managed CLI accepted semantic queries in the balanced profile").ConfigureAwait(false);
    }

    private static async Task RequireBudgetRejectedAsync(WorkerRequest request, WorkerBudget budget, string message)
    {
        try
        {
            MetadataAnalysis.ValidateRequest(request with { Budget = budget });
            throw new InvalidOperationException(message);
        }
        catch (InvalidDataException)
        {
        }

        try
        {
            await using var guard = new ResourceBudgetGuard(budget);
            throw new InvalidOperationException(message);
        }
        catch (InvalidDataException)
        {
        }
    }

    private static async Task ValidateSnapshotBindingAsync(
        WorkerRequest request,
        string fixturePath,
        byte[] fixtureBytes)
    {
        var temporaryPath = Path.Combine(Path.GetTempPath(), $"aida-managed-cli-snapshot-{Guid.NewGuid():N}.dll");
        try
        {
            File.WriteAllBytes(temporaryPath, fixtureBytes);
            var source = new WorkerModuleSource("embedded_member",
                Path.GetFullPath(fixturePath) + "#member:nested/ManagedCliFixtures.dll",
                HashBytes(fixtureBytes), checked((ulong)fixtureBytes.LongLength));
            var bound = RebindRequest(request with
            {
                RequestId = request.RequestId + "-snapshot",
                ModuleSource = source,
                EntityHash = HashText(request.EntityHash + "|" + source.ModuleHash),
                WorkspaceGeneration = request.WorkspaceGeneration + 1
            });
            await using var worker = await ManagedWorkerProcess.StartAsync(temporaryPath).ConfigureAwait(false);
            var bytes = File.ReadAllBytes(temporaryPath);
            bytes[^1] ^= 0x5a;
            File.WriteAllBytes(temporaryPath, bytes);
            var result = await worker.DecompileAsync(bound).ConfigureAwait(false);
            ValidateTerminalBinding(bound, result.ModuleSource, result.EntityHash,
                result.MetadataToken, result.WorkspaceGeneration, result.TypeGraphRevision,
                result.Budget, result.RuntimeManifestHash, result.ContractHash,
                result.CacheIdentity, result.RequestBindingHash, result.Provider);
            Require(FixedTimeHexEquals(result.ModuleSource.ModuleHash,
                    bound.ModuleSource.ModuleHash),
                "managed CLI immutable module snapshot changed after launch binding");

            await using var staleWorker = await ManagedWorkerProcess.StartAsync(
                temporaryPath).ConfigureAwait(false);
            var stale = await staleWorker.DecompileFailureAsync(bound).ConfigureAwait(false);
            Require(stale.Diagnostics.Count == 1 &&
                string.Equals(stale.Diagnostics[0].Code, "malformed_metadata", StringComparison.Ordinal),
                "managed CLI stale snapshot binding was not rejected");

            try
            {
                MetadataAnalysis.ValidateRequest(RebindRequest(bound with
                {
                    ModuleSource = source with { LogicalIdentity = fixturePath }
                }));
                throw new InvalidOperationException("managed CLI embedded source without member identity was accepted");
            }
            catch (InvalidDataException)
            {
            }
            CryptographicOperations.ZeroMemory(bytes);
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
                var request = CreateRequest(20_000 + checked((ulong)malformedIndex),
                    "regular_file", temporaryPath, HashBytes(bytes),
                    checked((ulong)bytes.LongLength), method, StandardBudget, 41, 17);
                request = RebindRequest(request with { MetadataToken = token });
                if (string.Equals(malformed.Mutation, "non_method_token", StringComparison.Ordinal))
                {
                    try
                    {
                        MetadataAnalysis.ValidateRequest(request);
                        throw new InvalidOperationException(
                            "managed CLI non-method token request was accepted");
                    }
                    catch (InvalidDataException)
                    {
                    }
                    CryptographicOperations.ZeroMemory(bytes);
                    continue;
                }
                await using var worker = await ManagedWorkerProcess.StartAsync(temporaryPath).ConfigureAwait(false);
                var failure = await worker.DecompileFailureAsync(request).ConfigureAwait(false);
                Require(failure.Diagnostics.Count == 1 &&
                    string.Equals(failure.Diagnostics[0].Code, malformed.ExpectedCode, StringComparison.Ordinal) &&
                    string.Equals(failure.Diagnostics[0].Key, malformed.ExpectedKey, StringComparison.Ordinal),
                    $"managed CLI malformed fixture diagnostic drifted for {malformed.Id}");
                CryptographicOperations.ZeroMemory(bytes);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }
        }
    }

    private static GeneratedParameterFixture CreateParameterMetadataFixture(ParameterFixtureKind kind)
    {
        var metadata = new MetadataBuilder();
        var ilStream = new BlobBuilder();
        var moduleId = new Guid("6628540c-5acf-48a6-974d-6ec4361a7932");
        metadata.AddModule(0, metadata.GetOrAddString("ManagedParameterRows.dll"),
            metadata.GetOrAddGuid(moduleId), default, default);
        metadata.AddAssembly(metadata.GetOrAddString("ManagedParameterRows"), new Version(1, 0, 0, 0),
            default, default, default, AssemblyHashAlgorithm.None);
        var systemRuntime = metadata.AddAssemblyReference(metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0), default, default, default, default);
        var objectType = metadata.AddTypeReference(systemRuntime, metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var methodBodyStream = new MethodBodyStreamEncoder(ilStream);
        var methods = new Dictionary<string, MethodDescriptor>(StringComparer.Ordinal);
        var specifications = ParameterMethodSpecifications(kind);
        MethodDefinitionHandle firstMethod = default;
        foreach (var spec in specifications)
        {
            var code = new BlobBuilder();
            code.WriteBytes(spec.IlBytes);
            var bodyOffset = methodBodyStream.AddMethodBody(new InstructionEncoder(code), maxStack: 2);
            var signature = MethodSignatureBytes(spec.IsInstance, spec.ParameterCount);
            var firstParameter = spec.ParameterRows.Count == 0
                ? default
                : MetadataTokens.ParameterHandle(metadata.GetRowCount(TableIndex.Param) + 1);
            foreach (var row in spec.ParameterRows)
            {
                var name = row.Name is null ? default : metadata.GetOrAddString(row.Name);
                metadata.AddParameter(ParameterAttributes.None, name, row.Sequence);
            }
            var attributes = MethodAttributes.Public | MethodAttributes.HideBySig;
            if (!spec.IsInstance)
                attributes |= MethodAttributes.Static;
            var method = metadata.AddMethodDefinition(attributes, MethodImplAttributes.IL,
                metadata.GetOrAddString(spec.Name), metadata.GetOrAddBlob(signature), bodyOffset, firstParameter);
            if (firstMethod.IsNil)
                firstMethod = method;
            var descriptor = new MethodDescriptor(unchecked((uint)MetadataTokens.GetToken(method)),
                GeneratedParameterTypeName, spec.Name, Convert.ToHexString(signature), 0);
            methods.Add(GeneratedParameterTypeName + "." + spec.Name, descriptor);
        }
        if (firstMethod.IsNil)
            throw new InvalidDataException("generated parameter fixture has no methods");
        metadata.AddTypeDefinition(default, default, metadata.GetOrAddString("<Module>"), default,
            MetadataTokens.FieldDefinitionHandle(1), firstMethod);
        metadata.AddTypeDefinition(TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.AutoLayout |
            TypeAttributes.BeforeFieldInit, metadata.GetOrAddString("Aida.C03"),
            metadata.GetOrAddString("GeneratedParameterFixture"), objectType,
            MetadataTokens.FieldDefinitionHandle(1), firstMethod);
        var peBuilder = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata), ilStream, strongNameSignatureSize: 0,
            flags: CorFlags.ILOnly,
            deterministicIdProvider: _ => new BlobContentId(moduleId, 0x724f5753U + checked((uint)kind)));
        var peImage = new BlobBuilder();
        _ = peBuilder.Serialize(peImage);
        return new GeneratedParameterFixture(peImage.ToArray(), methods, specifications);
    }

    private static IReadOnlyList<GeneratedParameterMethod> ParameterMethodSpecifications(ParameterFixtureKind kind)
    {
        if (kind == ParameterFixtureKind.Valid)
        {
            return new[]
            {
                new GeneratedParameterMethod("StaticNamed", false, 2,
                    new[]
                    {
                        new GeneratedParameterRow(0, "returnValue"),
                        new GeneratedParameterRow(1, "left"),
                        new GeneratedParameterRow(2, "right")
                    },
                    new byte[] { 0x02, 0x03, 0x58, 0x2a }),
                new GeneratedParameterMethod("InstanceNamed", true, 2,
                    new[]
                    {
                        new GeneratedParameterRow(0, "instanceReturn"),
                        new GeneratedParameterRow(1, "value"),
                        new GeneratedParameterRow(2, "delta")
                    },
                    new byte[] { 0x02, 0x26, 0x03, 0x04, 0x58, 0x2a }),
                new GeneratedParameterMethod("StoreForms", false, 4,
                    new[]
                    {
                        new GeneratedParameterRow(0, "storeReturn"),
                        new GeneratedParameterRow(1, null),
                        new GeneratedParameterRow(2, "shortNamed"),
                        new GeneratedParameterRow(3, "longNamed"),
                        new GeneratedParameterRow(4, "storeOnly")
                    },
                    new byte[]
                    {
                        0x16, 0x10, 0x00,
                        0x17, 0x10, 0x01,
                        0x18, 0xfe, 0x0b, 0x02, 0x00,
                        0x19, 0x10, 0x03,
                        0x0e, 0x01, 0x26,
                        0xfe, 0x09, 0x02, 0x00, 0x2a
                    }),
                new GeneratedParameterMethod("Reordered", false, 2,
                    new[]
                    {
                        new GeneratedParameterRow(2, "second"),
                        new GeneratedParameterRow(0, "reorderedReturn"),
                        new GeneratedParameterRow(1, "first")
                    },
                    new byte[] { 0x02, 0x03, 0x58, 0x2a })
            };
        }

        var rows = kind switch
        {
            ParameterFixtureKind.DuplicateSequence => new[]
            {
                new GeneratedParameterRow(0, "malformedReturn"),
                new GeneratedParameterRow(1, "first"),
                new GeneratedParameterRow(1, "duplicate")
            },
            ParameterFixtureKind.OutOfRangeSequence => new[]
            {
                new GeneratedParameterRow(0, "malformedReturn"),
                new GeneratedParameterRow(1, "first"),
                new GeneratedParameterRow(3, "outside")
            },
            ParameterFixtureKind.DuplicateReturnSequence => new[]
            {
                new GeneratedParameterRow(0, "malformedReturn"),
                new GeneratedParameterRow(0, "duplicateReturn"),
                new GeneratedParameterRow(1, "first")
            },
            ParameterFixtureKind.ExcessRows => new[]
            {
                new GeneratedParameterRow(0, "malformedReturn"),
                new GeneratedParameterRow(1, "first"),
                new GeneratedParameterRow(2, "second"),
                new GeneratedParameterRow(2, "excess")
            },
            _ => throw new InvalidDataException("parameter fixture kind is invalid")
        };
        return new[]
        {
            new GeneratedParameterMethod("Malformed", false, 2, rows,
                new byte[] { 0x02, 0x03, 0x58, 0x2a })
        };
    }

    private static byte[] MethodSignatureBytes(bool isInstance, int parameterCount)
    {
        if (parameterCount < 0 || parameterCount > 0x7f)
            throw new InvalidDataException("generated parameter signature arity is invalid");
        var signature = new byte[checked(parameterCount + 3)];
        signature[0] = isInstance ? (byte)0x20 : (byte)0x00;
        signature[1] = checked((byte)parameterCount);
        signature[2] = 0x08;
        Array.Fill(signature, (byte)0x08, 3, parameterCount);
        return signature;
    }

    private static void ValidateParameterFixtureEncoding(string path, GeneratedParameterFixture fixture)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var peReader = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
        Require(peReader.HasMetadata, "generated parameter fixture has no CLI metadata");
        var reader = peReader.GetMetadataReader();
        var methods = reader.MethodDefinitions.ToDictionary(
            handle => reader.GetString(reader.GetMethodDefinition(handle).Name),
            handle => reader.GetMethodDefinition(handle), StringComparer.Ordinal);
        foreach (var spec in fixture.Specifications)
        {
            Require(methods.TryGetValue(spec.Name, out var method),
                $"generated parameter fixture method is absent: {spec.Name}");
            var signature = method.DecodeSignature(new StableSignatureTypeProvider(),
                new GenericContext(GeneratedParameterTypeName, spec.Name));
            Require(signature.Header.IsInstance == spec.IsInstance &&
                ((method.Attributes & MethodAttributes.Static) != 0) != spec.IsInstance &&
                signature.ParameterTypes.Length == spec.ParameterCount,
                $"generated parameter fixture signature drifted: {spec.Name}");
            var rows = method.GetParameters().Select(handle =>
            {
                var parameter = reader.GetParameter(handle);
                return new GeneratedParameterRow(parameter.SequenceNumber,
                    parameter.Name.IsNil ? null : reader.GetString(parameter.Name));
            }).ToArray();
            Require(rows.SequenceEqual(spec.ParameterRows),
                $"generated parameter fixture Param rows drifted: {spec.Name}");
            var body = peReader.GetMethodBody(method.RelativeVirtualAddress);
            Require((body.GetILBytes() ?? Array.Empty<byte>()).SequenceEqual(spec.IlBytes),
                $"generated parameter fixture IL encoding drifted: {spec.Name}");
        }
    }

    private static async Task ValidateConcurrentWorkspaceIsolationAsync(
        string fixturePath,
        string moduleHash,
        ulong moduleSize,
        MethodDescriptor method)
    {
        var leftRequest = CreateRequest(30_001, "regular_file", fixturePath,
            moduleHash, moduleSize, method, StandardBudget, 101, 23);
        var rightRequest = CreateRequest(30_002, "regular_file", fixturePath,
            moduleHash, moduleSize, method, StandardBudget, 202, 29);
        Require(!FixedTimeHexEquals(leftRequest.CacheIdentity, rightRequest.CacheIdentity) &&
            !FixedTimeHexEquals(leftRequest.RequestBindingHash, rightRequest.RequestBindingHash),
            "managed CLI cross-workspace request identities collided");
        await using var leftWorker = await ManagedWorkerProcess.StartAsync(
            fixturePath).ConfigureAwait(false);
        await using var rightWorker = await ManagedWorkerProcess.StartAsync(
            fixturePath).ConfigureAwait(false);
        var results = await Task.WhenAll(
            leftWorker.DecompileAsync(leftRequest),
            rightWorker.DecompileAsync(rightRequest)).ConfigureAwait(false);
        Require(results[0].WorkspaceGeneration == leftRequest.WorkspaceGeneration &&
            results[1].WorkspaceGeneration == rightRequest.WorkspaceGeneration &&
            results[0].WorkspaceGeneration != results[1].WorkspaceGeneration &&
            FixedTimeHexEquals(results[0].ModuleSource.ModuleHash,
                results[1].ModuleSource.ModuleHash),
            "managed CLI concurrent workspace responses crossed request boundaries");
    }

    private static WorkerRequest CreateRequest(
        ulong sequence,
        string sourceKind,
        string logicalIdentity,
        string moduleHash,
        ulong moduleSize,
        MethodDescriptor method,
        WorkerBudget budget,
        ulong workspaceGeneration,
        ulong typeGraphRevision)
    {
        var source = new WorkerModuleSource(sourceKind,
            string.Equals(sourceKind, "regular_file", StringComparison.Ordinal)
                ? Path.GetFullPath(logicalIdentity) : logicalIdentity,
            moduleHash, moduleSize);
        var entityHash = HashText(WorkerProtocol.Serialize(new
        {
            Source = source,
            method.Token,
            method.DeclaringType,
            method.Name,
            method.Signature,
            method.GenericArity
        }));
        var request = new WorkerRequest(
            WorkerProtocol.Schema,
            WorkerProtocol.Version,
            "decompile",
            1,
            $"managed-cli-fixture-{sequence}",
            source,
            entityHash,
            method.Token,
            workspaceGeneration,
            typeGraphRevision,
            runtimeManifestHash,
            ManagedContractHash,
            string.Empty,
            string.Empty,
            budget,
            ProviderExpectation);
        return RebindRequest(request);
    }

    private static WorkerRequest RebindRequest(WorkerRequest request)
    {
        var cacheIdentity = HashText(WorkerProtocol.Serialize(new
        {
            request.ContractHash,
            request.EntityHash,
            request.ModuleSource,
            request.WorkspaceGeneration,
            request.TypeGraphRevision,
            request.Budget,
            request.RuntimeManifestHash,
            request.Provider
        }));
        var requestBindingHash = HashText(WorkerProtocol.Serialize(new
        {
            request.Schema,
            request.SchemaVersion,
            request.Sequence,
            request.RequestId,
            CacheIdentity = cacheIdentity
        }));
        return request with
        {
            CacheIdentity = cacheIdentity,
            RequestBindingHash = requestBindingHash
        };
    }

    private static MethodInventory ReadMethodInventory(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var peReader = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
        Require(peReader.HasMetadata, "managed CLI fixture has no metadata");
        var reader = peReader.GetMetadataReader();
        var methods = new Dictionary<string, MethodDescriptor>(StringComparer.Ordinal);
        var typeNames = new HashSet<string>(StringComparer.Ordinal);
        var fieldNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var typeName = MetadataAnalysis.GetTypeDefinitionName(reader, typeHandle);
            typeNames.Add(typeName);
            var type = reader.GetTypeDefinition(typeHandle);
            foreach (var fieldHandle in type.GetFields())
                fieldNames.Add(typeName + "." + reader.GetString(reader.GetFieldDefinition(fieldHandle).Name));
            foreach (var methodHandle in type.GetMethods())
            {
                var method = reader.GetMethodDefinition(methodHandle);
                var methodName = reader.GetString(method.Name);
                var descriptor = new MethodDescriptor(
                    unchecked((uint)MetadataTokens.GetToken(methodHandle)),
                    typeName,
                    methodName,
                    MethodSignatureIdentity(reader, method),
                    checked((uint)method.GetGenericParameters().Count));
                var symbol = typeName + "." + methodName;
                Require(methods.TryAdd(symbol, descriptor), $"managed CLI fixture symbol is ambiguous: {symbol}");
            }
        }
        return new MethodInventory(methods, typeNames, fieldNames);
    }

    private static string MethodSignatureIdentity(MetadataReader reader, MethodDefinition method)
    {
        var signature = reader.GetBlobBytes(method.Signature);
        Require(signature.Length != 0 && signature.Length <= MaximumWireSignatureBytes,
            "managed CLI fixture method signature exceeds the wire contract");
        return Convert.ToHexString(signature);
    }

    private static void ValidateManifestInventory(FixtureManifest manifest, MethodInventory inventory)
    {
        Require(string.Equals(manifest.Schema, "aida.c03.managed-cli-fixtures", StringComparison.Ordinal) && manifest.SchemaVersion == 1,
            "managed CLI fixture manifest schema is invalid");
        Require(string.Equals(manifest.Assembly, "ManagedCliFixtures", StringComparison.Ordinal) && manifest.Methods.Count >= 6,
            "managed CLI fixture manifest inventory is incomplete");
        Require(manifest.Validation.DeterministicRuns >= 2 && manifest.Validation.Cancellation && manifest.Validation.RuntimeGate &&
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
        foreach (var field in new[] { "ExpectedFailureCode", "ExpectedFailureKey", "MetadataSignature", "CorruptSignatureMutation", "TruncateRootMutation", "NonMethodToken" })
            Require(inventory.Fields.Contains("Aida.C03.ManagedCliFixtures.MalformedMetadataContract." + field),
                $"managed CLI malformed source field is absent: {field}");
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
            validationValue.GetProperty("runtime_identity_gate").GetBoolean(),
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

    private static string ResolveManagedPackageRoot()
    {
        var configured = Environment.GetEnvironmentVariable("AIDA_C03_MANAGED_PACKAGE_ROOT");
        if (string.IsNullOrWhiteSpace(configured))
            throw new DirectoryNotFoundException("managed CLI app-local package root is not configured");
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configured));
        if (!Directory.Exists(root) || root.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries)
                .Any(component => string.Equals(component, ".deps", StringComparison.OrdinalIgnoreCase)))
            throw new DirectoryNotFoundException("managed CLI app-local package root is invalid");
        return root;
    }

    private static string ReadRuntimeManifestHash(string packageRoot)
    {
        var manifest = Path.Combine(packageRoot, "deps", "AiDA_ManagedRuntime.manifest.json");
        var digest = Path.Combine(packageRoot, "deps", "AiDA_ManagedRuntime.manifest.sha256");
        Require(File.Exists(manifest) && File.Exists(digest), "managed CLI runtime manifest package is unavailable");
        var actual = HashFile(manifest);
        var text = File.ReadAllText(digest, Encoding.ASCII);
        Require(string.Equals(text, actual + "\n", StringComparison.Ordinal), "managed CLI runtime manifest digest is invalid");
        return actual;
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
        byte[]? leftBytes = null;
        byte[]? rightBytes = null;
        try
        {
            leftBytes = Convert.FromHexString(left);
            rightBytes = Convert.FromHexString(right);
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        catch (FormatException)
        {
            return false;
        }
        finally
        {
            if (leftBytes is not null)
                CryptographicOperations.ZeroMemory(leftBytes);
            if (rightBytes is not null)
                CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class ManagedWorkerProcess : IAsyncDisposable
    {
        private readonly SafeFileHandle process;
        private readonly HarnessTransport transport;
        private bool requestSent;
        private bool terminalReceived;

        private ManagedWorkerProcess(SafeFileHandle process, HarnessTransport transport)
        {
            this.process = process;
            this.transport = transport;
        }

        internal static async Task<ManagedWorkerProcess> StartAsync(string modulePath)
        {
            var launch = WorkerLaunch.Start(modulePath);
            HarnessTransport? transport = null;
            try
            {
                transport = await HarnessTransport.EstablishAsync(launch.RequestStream, launch.ResponseStream).ConfigureAwait(false);
                var helloPayload = await transport.ReceivePayloadAsync(1).ConfigureAwait(false);
                var hello = WorkerProtocol.Deserialize<WorkerTransportHello>(helloPayload);
                Require(string.Equals(hello.Schema, "aida.c03.managed-cli.transport", StringComparison.Ordinal) &&
                    hello.SchemaVersion == 3 && string.Equals(hello.Kind, "hello", StringComparison.Ordinal) && hello.Sequence == 1 &&
                    FixedTimeHexEquals(hello.SessionNonceHash, transport.SessionNonceHash) &&
                    FixedTimeHexEquals(hello.ManifestHash, transport.ManifestHash) &&
                    FixedTimeHexEquals(hello.RuntimeManifestHash, runtimeManifestHash) &&
                    FixedTimeHexEquals(hello.WorkerBinaryHash, launch.WorkerHash) &&
                    FixedTimeHexEquals(hello.ProviderBinaryHash, RuntimeIdentity.DecompilerAssemblySha256) &&
                    string.Equals(hello.WorkerBuildId, ProviderExpectation.WorkerBuildId, StringComparison.Ordinal) &&
                    FixedTimeHexEquals(hello.WorkerBuildHash, ProviderExpectation.WorkerBuildHash),
                    "managed CLI worker authenticated hello is invalid");
                launch.TransferOwnership();
                return new ManagedWorkerProcess(launch.Process, transport);
            }
            catch
            {
                transport?.Dispose();
                launch.Abort();
                throw;
            }
        }

        internal async Task<WorkerResult> DecompileAsync(WorkerRequest request)
        {
            await SendRequestAsync(request).ConfigureAwait(false);
            var line = await ReadResponseAsync().ConfigureAwait(false);
            using var document = JsonDocument.Parse(line);
            var kind = document.RootElement.GetProperty("kind").GetString();
            if (!string.Equals(kind, "result", StringComparison.Ordinal))
                throw new InvalidOperationException("managed CLI worker rejected a fixture: " + line);
            var result = WorkerProtocol.Deserialize<WorkerResult>(line);
            ValidateTerminalBinding(request, result.ModuleSource, result.EntityHash,
                result.MetadataToken, result.WorkspaceGeneration, result.TypeGraphRevision,
                result.Budget, result.RuntimeManifestHash, result.ContractHash,
                result.CacheIdentity, result.RequestBindingHash, result.Provider);
            return result;
        }

        internal async Task<WorkerFailure> DecompileAndCancelAsync(WorkerRequest request)
        {
            await SendRequestAsync(request).ConfigureAwait(false);
            var cancellation = new WorkerCancellation(
                WorkerProtocol.Schema,
                WorkerProtocol.Version,
                "cancel",
                request.Sequence + 1,
                request.RequestId,
                request.RequestBindingHash,
                "managed_cli_fixture_cancel");
            await transport.SendPayloadAsync(2, WorkerProtocol.Serialize(cancellation)).ConfigureAwait(false);
            var failure = WorkerProtocol.Deserialize<WorkerFailure>(
                await ReadFailureResponseAsync().ConfigureAwait(false));
            ValidateFailureBinding(request, failure);
            return failure;
        }

        internal async Task<WorkerFailure> DecompileFailureAsync(WorkerRequest request)
        {
            await SendRequestAsync(request).ConfigureAwait(false);
            var failure = WorkerProtocol.Deserialize<WorkerFailure>(
                await ReadFailureResponseAsync().ConfigureAwait(false));
            ValidateFailureBinding(request, failure);
            return failure;
        }

        private async Task SendRequestAsync(WorkerRequest request)
        {
            Require(!requestSent && !terminalReceived && request.Sequence == 1,
                "managed CLI harness request lifecycle is invalid");
            requestSent = true;
            await transport.SendPayloadAsync(1, WorkerProtocol.Serialize(request)).ConfigureAwait(false);
        }

        private async Task<string> ReadFailureResponseAsync()
        {
            var line = await ReadResponseAsync().ConfigureAwait(false);
            using var document = JsonDocument.Parse(line);
            if (!string.Equals(document.RootElement.GetProperty("kind").GetString(), "failure", StringComparison.Ordinal))
                throw new InvalidOperationException("managed CLI worker returned a result where failure was required: " + line);
            return line;
        }

        private async Task<string> ReadResponseAsync()
        {
            Require(requestSent && !terminalReceived, "managed CLI harness response lifecycle is invalid");
            var payload = await transport.ReceivePayloadAsync(2).ConfigureAwait(false);
            terminalReceived = true;
            return payload;
        }

        public ValueTask DisposeAsync()
        {
            var forced = false;
            uint exitCode = uint.MaxValue;
            try
            {
                var wait = WaitForSingleObject(process, terminalReceived ? 10_000U : 0U);
                if (wait != WaitObject0)
                {
                    forced = true;
                    TerminateProcess(process, 1);
                    WaitForSingleObject(process, 10_000U);
                }
                GetExitCodeProcess(process, out exitCode);
            }
            finally
            {
                transport.Dispose();
                process.Dispose();
            }
            Require(terminalReceived && !forced && exitCode == 0, "managed CLI worker did not shut down cleanly");
            return ValueTask.CompletedTask;
        }

        private sealed class WorkerLaunch
        {
            private bool transferred;

            private WorkerLaunch(SafeFileHandle process, FileStream requestStream, FileStream responseStream, string workerHash)
            {
                Process = process;
                RequestStream = requestStream;
                ResponseStream = responseStream;
                WorkerHash = workerHash;
            }

            internal SafeFileHandle Process { get; }
            internal FileStream RequestStream { get; }
            internal FileStream ResponseStream { get; }
            internal string WorkerHash { get; }

            internal static WorkerLaunch Start(string modulePath)
            {
                var packageRoot = ResolveManagedPackageRoot();
                var workerPath = Path.GetFullPath(Path.Combine(packageRoot, "deps", "AiDA_ManagedDecompilerWorker.exe"));
                var dotnetRoot = Path.GetFullPath(Path.Combine(packageRoot, "deps", "dotnet"));
                modulePath = Path.GetFullPath(modulePath);
                Require(File.Exists(workerPath), "managed CLI app-local worker apphost is unavailable");
                Require(File.Exists(Path.Combine(dotnetRoot, "host", "fxr", "10.0.9", "hostfxr.dll")),
                    "managed CLI app-local hostfxr is unavailable");
                Require(FixedTimeHexEquals(ReadRuntimeManifestHash(packageRoot), runtimeManifestHash),
                    "managed CLI runtime manifest changed before worker launch");
                var moduleBytes = File.ReadAllBytes(modulePath);
                Require(moduleBytes.Length != 0, "managed CLI module snapshot is empty");

                SafeFileHandle? childRead = null;
                SafeFileHandle? parentWrite = null;
                SafeFileHandle? parentRead = null;
                SafeFileHandle? childWrite = null;
                SafeFileHandle? mapping = null;
                SafeFileHandle? childMapping = null;
                SafeFileHandle? identity = null;
                SafeFileHandle? childIdentity = null;
                SafeFileHandle? process = null;
                FileStream? requestStream = null;
                FileStream? responseStream = null;
                nint attributeList = 0;
                nint handleList = 0;
                nint environmentBlock = 0;
                try
                {
                    var security = new SecurityAttributes
                    {
                        Length = checked((uint)Marshal.SizeOf<SecurityAttributes>()),
                        InheritHandle = 1
                    };
                    Require(CreatePipe(out childRead, out parentWrite, ref security, 0) &&
                        CreatePipe(out parentRead, out childWrite, ref security, 0),
                        "managed CLI harness pipes could not be created");
                    Require(SetHandleInformation(parentWrite!, HandleFlagInherit, 0) &&
                        SetHandleInformation(parentRead!, HandleFlagInherit, 0),
                        "managed CLI harness parent pipe inheritance could not be removed");

                    mapping = CreateFileMapping(new nint(-1), 0, PageReadWrite, 0, checked((uint)moduleBytes.Length), null);
                    Require(!mapping.IsInvalid, "managed CLI harness module mapping could not be created");
                    var view = MapViewOfFile(mapping!, FileMapWrite, 0, 0, checked((nuint)moduleBytes.Length));
                    Require(view != 0, "managed CLI harness module mapping could not be opened");
                    try
                    {
                        Marshal.Copy(moduleBytes, 0, view, moduleBytes.Length);
                    }
                    finally
                    {
                        Require(UnmapViewOfFile(view), "managed CLI harness module mapping could not be released");
                        CryptographicOperations.ZeroMemory(moduleBytes);
                    }
                    var currentProcess = GetCurrentProcess();
                    Require(DuplicateHandle(currentProcess, mapping!, currentProcess, out childMapping,
                        FileMapRead, true, 0), "managed CLI harness read-only module handle could not be created");
                    identity = File.OpenHandle(workerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    Require(DuplicateHandle(currentProcess, identity, currentProcess, out childIdentity,
                        0, true, DuplicateSameAccess), "managed CLI harness identity handle could not be created");

                    nuint attributeBytes = 0;
                    InitializeProcThreadAttributeList(0, 1, 0, ref attributeBytes);
                    Require(attributeBytes != 0, "managed CLI harness attribute size is invalid");
                    attributeList = Marshal.AllocHGlobal(checked((nint)attributeBytes));
                    Require(InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeBytes),
                        "managed CLI harness attribute list could not be initialized");
                    var inherited = new[]
                    {
                        childRead!.DangerousGetHandle(),
                        childWrite!.DangerousGetHandle(),
                        childMapping!.DangerousGetHandle(),
                        childIdentity!.DangerousGetHandle()
                    };
                    handleList = Marshal.AllocHGlobal(checked(inherited.Length * IntPtr.Size));
                    for (var index = 0; index < inherited.Length; index++)
                        Marshal.WriteIntPtr(handleList, index * IntPtr.Size, inherited[index]);
                    Require(UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeHandleList,
                        handleList, checked((nuint)(inherited.Length * IntPtr.Size)), 0, 0),
                        "managed CLI harness inherited handle whitelist could not be installed");

                    var startup = new StartupInfoEx();
                    startup.StartupInfo.Size = checked((uint)Marshal.SizeOf<StartupInfoEx>());
                    startup.AttributeList = attributeList;
                    var commandLine = new StringBuilder();
                    commandLine.Append(QuoteArgument(workerPath));
                    commandLine.Append(" --aida-managed-decompiler-worker --provider=2");
                    commandLine.Append(" --read-handle=").Append(childRead!.DangerousGetHandle().ToInt64());
                    commandLine.Append(" --write-handle=").Append(childWrite!.DangerousGetHandle().ToInt64());
                    commandLine.Append(" --module-handle=").Append(childMapping!.DangerousGetHandle().ToInt64());
                    commandLine.Append(" --module-size=").Append(moduleBytes.Length);
                    commandLine.Append(" --identity-handle=").Append(childIdentity!.DangerousGetHandle().ToInt64());
                    commandLine.Append(" --runtime-manifest-hash=").Append(runtimeManifestHash);
                    environmentBlock = CreateWorkerEnvironment(dotnetRoot);
                    Require(CreateProcess(workerPath, commandLine, 0, 0, true,
                        ExtendedStartupInfoPresent | CreateNoWindow | CreateUnicodeEnvironment,
                        environmentBlock, packageRoot,
                        ref startup, out var processInformation),
                        "managed CLI worker process could not start");
                    using var thread = new SafeFileHandle(processInformation.Thread, ownsHandle: true);
                    process = new SafeFileHandle(processInformation.Process, ownsHandle: true);
                    requestStream = new FileStream(parentWrite!, FileAccess.Write, 4096, isAsync: false);
                    parentWrite = null;
                    responseStream = new FileStream(parentRead!, FileAccess.Read, 4096, isAsync: false);
                    parentRead = null;
                    var result = new WorkerLaunch(process, requestStream, responseStream, HashFile(workerPath));
                    process = null;
                    requestStream = null;
                    responseStream = null;
                    return result;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(moduleBytes);
                    if (attributeList != 0)
                    {
                        DeleteProcThreadAttributeList(attributeList);
                        Marshal.FreeHGlobal(attributeList);
                    }
                    if (handleList != 0)
                        Marshal.FreeHGlobal(handleList);
                    if (environmentBlock != 0)
                        Marshal.FreeHGlobal(environmentBlock);
                    requestStream?.Dispose();
                    responseStream?.Dispose();
                    process?.Dispose();
                    childRead?.Dispose();
                    parentWrite?.Dispose();
                    parentRead?.Dispose();
                    childWrite?.Dispose();
                    mapping?.Dispose();
                    childMapping?.Dispose();
                    identity?.Dispose();
                    childIdentity?.Dispose();
                }
            }

            private static nint CreateWorkerEnvironment(string dotnetRoot)
            {
                var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                Require(!string.IsNullOrWhiteSpace(systemRoot), "managed CLI harness SystemRoot is unavailable");
                var entries = new[]
                {
                    "COMPlus_EnableDiagnostics=0",
                    "DOTNET_CLI_TELEMETRY_OPTOUT=1",
                    "DOTNET_EnableDiagnostics=0",
                    "DOTNET_MULTILEVEL_LOOKUP=0",
                    "DOTNET_NOLOGO=1",
                    "DOTNET_ROLL_FORWARD=Disable",
                    "DOTNET_ROLL_FORWARD_TO_PRERELEASE=0",
                    "DOTNET_ROOT=" + dotnetRoot,
                    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
                    "PATH=" + Path.Combine(systemRoot!, "System32"),
                    "SystemRoot=" + systemRoot,
                    "WINDIR=" + systemRoot
                }.OrderBy(value => value, StringComparer.OrdinalIgnoreCase);
                return Marshal.StringToHGlobalUni(string.Join('\0', entries) + "\0\0");
            }

            internal void TransferOwnership()
            {
                transferred = true;
            }

            internal void Abort()
            {
                if (transferred)
                    return;
                TerminateProcess(Process, 1);
                WaitForSingleObject(Process, 10_000U);
                RequestStream.Dispose();
                ResponseStream.Dispose();
                Process.Dispose();
            }
        }

        private sealed class HarnessTransport : IDisposable
        {
            private const int MaximumPayloadBytes = 16 * 1024 * 1024;
            private const uint BootstrapMagic = 0x42574e41;
            private const uint FrameMagic = 0x46574e41;
            private const ushort Version = 1;
            private const ushort ContractKind = 1;
            private const int DigestBytes = 32;
            private const int BootstrapBytes = 104;
            private const int AuthenticatedHeaderBytes = 52;
            private const int HeaderBytes = 84;
            private static readonly UTF8Encoding StrictUtf8 = new(false, true);
            private readonly FileStream requestStream;
            private readonly FileStream responseStream;
            private readonly byte[] key;
            private readonly byte[] nonceHash;
            private readonly byte[] manifestHash;
            private bool disposed;

            private HarnessTransport(FileStream requestStream, FileStream responseStream,
                byte[] key, byte[] nonceHash, byte[] manifestHash)
            {
                this.requestStream = requestStream;
                this.responseStream = responseStream;
                this.key = key;
                this.nonceHash = nonceHash;
                this.manifestHash = manifestHash;
            }

            internal string SessionNonceHash => Convert.ToHexString(nonceHash).ToLowerInvariant();
            internal string ManifestHash => Convert.ToHexString(manifestHash).ToLowerInvariant();

            internal static async Task<HarnessTransport> EstablishAsync(FileStream requestStream, FileStream responseStream)
            {
                var nonce = RandomNumberGenerator.GetBytes(DigestBytes);
                var key = RandomNumberGenerator.GetBytes(DigestBytes);
                var nonceHash = SHA256.HashData(nonce);
                var manifestHash = SHA256.HashData(Encoding.UTF8.GetBytes("aida.c03.managed-cli.harness-manifest-v2"));
                var bootstrap = new byte[BootstrapBytes];
                BinaryPrimitives.WriteUInt32LittleEndian(bootstrap, BootstrapMagic);
                BinaryPrimitives.WriteUInt16LittleEndian(bootstrap.AsSpan(4), Version);
                nonce.CopyTo(bootstrap.AsSpan(8));
                key.CopyTo(bootstrap.AsSpan(8 + DigestBytes));
                manifestHash.CopyTo(bootstrap.AsSpan(8 + DigestBytes * 2));
                CryptographicOperations.ZeroMemory(nonce);
                try
                {
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                    await requestStream.WriteAsync(bootstrap, deadline.Token).ConfigureAwait(false);
                    await requestStream.FlushAsync(deadline.Token).ConfigureAwait(false);
                    return new HarnessTransport(requestStream, responseStream, key, nonceHash, manifestHash);
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(key);
                    CryptographicOperations.ZeroMemory(nonceHash);
                    CryptographicOperations.ZeroMemory(manifestHash);
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bootstrap);
                }
            }

            internal async Task SendPayloadAsync(ulong sequence, string payload)
            {
                Require(!disposed && sequence != 0 && !string.IsNullOrEmpty(payload),
                    "managed CLI harness frame is invalid");
                var payloadBytes = StrictUtf8.GetBytes(payload);
                Require(payloadBytes.Length <= MaximumPayloadBytes, "managed CLI harness payload is oversized");
                var header = new byte[HeaderBytes];
                BinaryPrimitives.WriteUInt32LittleEndian(header, FrameMagic);
                BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(4), Version);
                BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(6), ContractKind);
                BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(8), sequence);
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16), checked((uint)payloadBytes.Length));
                nonceHash.CopyTo(header.AsSpan(20));
                var authenticated = new byte[AuthenticatedHeaderBytes + payloadBytes.Length];
                header.AsSpan(0, AuthenticatedHeaderBytes).CopyTo(authenticated);
                payloadBytes.CopyTo(authenticated.AsSpan(AuthenticatedHeaderBytes));
                var tag = HMACSHA256.HashData(key, authenticated);
                tag.CopyTo(header.AsSpan(AuthenticatedHeaderBytes));
                CryptographicOperations.ZeroMemory(authenticated);
                CryptographicOperations.ZeroMemory(tag);
                try
                {
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                    await requestStream.WriteAsync(header, deadline.Token).ConfigureAwait(false);
                    await requestStream.WriteAsync(payloadBytes, deadline.Token).ConfigureAwait(false);
                    await requestStream.FlushAsync(deadline.Token).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(header);
                    CryptographicOperations.ZeroMemory(payloadBytes);
                }
            }

            internal async Task<string> ReceivePayloadAsync(ulong expectedSequence)
            {
                Require(!disposed && expectedSequence != 0, "managed CLI harness receive sequence is invalid");
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                var header = new byte[HeaderBytes];
                await responseStream.ReadExactlyAsync(header, deadline.Token).ConfigureAwait(false);
                Require(BinaryPrimitives.ReadUInt32LittleEndian(header) == FrameMagic &&
                    BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4)) == Version &&
                    BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(6)) == ContractKind &&
                    BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8)) == expectedSequence &&
                    CryptographicOperations.FixedTimeEquals(header.AsSpan(20, DigestBytes), nonceHash),
                    "managed CLI harness response header is invalid");
                var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(16));
                Require(payloadLength != 0 && payloadLength <= MaximumPayloadBytes,
                    "managed CLI harness response size is invalid");
                var payload = new byte[checked((int)payloadLength)];
                await responseStream.ReadExactlyAsync(payload, deadline.Token).ConfigureAwait(false);
                var authenticated = new byte[AuthenticatedHeaderBytes + payload.Length];
                header.AsSpan(0, AuthenticatedHeaderBytes).CopyTo(authenticated);
                payload.CopyTo(authenticated.AsSpan(AuthenticatedHeaderBytes));
                var tag = HMACSHA256.HashData(key, authenticated);
                var valid = CryptographicOperations.FixedTimeEquals(tag, header.AsSpan(AuthenticatedHeaderBytes, DigestBytes));
                CryptographicOperations.ZeroMemory(authenticated);
                CryptographicOperations.ZeroMemory(tag);
                CryptographicOperations.ZeroMemory(header);
                Require(valid, "managed CLI harness response authentication failed");
                try
                {
                    return StrictUtf8.GetString(payload);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(payload);
                }
            }

            public void Dispose()
            {
                if (disposed)
                    return;
                disposed = true;
                requestStream.Dispose();
                responseStream.Dispose();
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(nonceHash);
                CryptographicOperations.ZeroMemory(manifestHash);
            }
        }

        private static string QuoteArgument(string value)
        {
            Require(!value.Contains('\0'), "managed CLI harness argument contains NUL");
            if (value.Length != 0 && value.All(character => !char.IsWhiteSpace(character) && character != '"'))
                return value;
            var result = new StringBuilder(value.Length + 2);
            result.Append('"');
            var slashes = 0;
            foreach (var character in value)
            {
                if (character == '\\')
                {
                    slashes++;
                    continue;
                }
                if (character == '"')
                {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('"');
                    slashes = 0;
                    continue;
                }
                result.Append('\\', slashes);
                slashes = 0;
                result.Append(character);
            }
            result.Append('\\', slashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private const uint HandleFlagInherit = 1;
        private const uint PageReadWrite = 0x04;
        private const uint FileMapWrite = 0x0002;
        private const uint FileMapRead = 0x0004;
        private const uint DuplicateSameAccess = 0x00000002;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateNoWindow = 0x08000000;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private static readonly nuint ProcThreadAttributeHandleList = 0x00020002;
        private const uint WaitObject0 = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            internal uint Length;
            internal nint SecurityDescriptor;
            internal int InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            internal uint Size;
            internal nint Reserved;
            internal nint Desktop;
            internal nint Title;
            internal uint X;
            internal uint Y;
            internal uint XSize;
            internal uint YSize;
            internal uint XCountChars;
            internal uint YCountChars;
            internal uint FillAttribute;
            internal uint Flags;
            internal ushort ShowWindow;
            internal ushort ReservedBytes;
            internal nint ReservedPointer;
            internal nint StandardInput;
            internal nint StandardOutput;
            internal nint StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            internal StartupInfo StartupInfo;
            internal nint AttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            internal nint Process;
            internal nint Thread;
            internal uint ProcessId;
            internal uint ThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(out SafeFileHandle readPipe, out SafeFileHandle writePipe,
            ref SecurityAttributes pipeAttributes, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileMappingW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileMapping(nint file, nint attributes, uint protection,
            uint maximumSizeHigh, uint maximumSizeLow, string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint MapViewOfFile(SafeFileHandle mapping, uint access,
            uint offsetHigh, uint offsetLow, nuint bytesToMap);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnmapViewOfFile(nint baseAddress);

        [DllImport("kernel32.dll")]
        private static extern nint GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateHandle(nint sourceProcess, SafeFileHandle sourceHandle,
            nint targetProcess, out SafeFileHandle targetHandle, uint access,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(nint attributeList,
            int attributeCount, uint flags, ref nuint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(nint attributeList, uint flags,
            nuint attribute, nint value, nuint size, nint previousValue, nint returnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(nint attributeList);

        [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(string applicationName, StringBuilder commandLine,
            nint processAttributes, nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags, nint environment, string currentDirectory,
            ref StartupInfoEx startupInfo, out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
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
        bool RuntimeGate,
        bool SnapshotBinding);

    private enum ParameterFixtureKind
    {
        Valid,
        DuplicateSequence,
        OutOfRangeSequence,
        DuplicateReturnSequence,
        ExcessRows
    }

    private sealed record GeneratedParameterRow(int Sequence, string? Name);

    private sealed record GeneratedParameterMethod(
        string Name,
        bool IsInstance,
        int ParameterCount,
        IReadOnlyList<GeneratedParameterRow> ParameterRows,
        byte[] IlBytes);

    private sealed record GeneratedParameterFixture(
        byte[] Bytes,
        IReadOnlyDictionary<string, MethodDescriptor> Methods,
        IReadOnlyList<GeneratedParameterMethod> Specifications);

    private sealed record ParameterIdentityExpectation(
        string MethodName,
        IReadOnlyList<string> StableSymbols,
        IReadOnlyList<string> SourceNames,
        IReadOnlyList<string> StoreDestinations);

    private sealed record MethodDescriptor(
        uint Token,
        string DeclaringType,
        string MethodName,
        string Signature,
        uint GenericArity);

    private sealed record MethodInventory(
        IReadOnlyDictionary<string, MethodDescriptor> Methods,
        IReadOnlySet<string> Types,
        IReadOnlySet<string> Fields);
}
