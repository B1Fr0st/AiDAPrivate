using System.Collections.Immutable;
using System.Globalization;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

namespace Aida.ManagedDecompiler;

internal sealed class ParseOnlyAssemblyResolver : IAssemblyResolver
{
    public MetadataFile? Resolve(IAssemblyReference reference) => null;

    public MetadataFile? ResolveModule(MetadataFile mainModule, string moduleName) => null;

    public Task<MetadataFile?> ResolveAsync(IAssemblyReference reference) => Task.FromResult<MetadataFile?>(null);

    public Task<MetadataFile?> ResolveModuleAsync(MetadataFile mainModule, string moduleName) => Task.FromResult<MetadataFile?>(null);
}

internal sealed record ParsedMethod(
    WorkerIdentity Identity,
    IReadOnlyList<WorkerTokenMap> TokenMap,
    WorkerTypeGraph TypeGraph,
    ulong ReturnTypeId,
    WorkerIr Ir,
    IReadOnlyList<WorkerUnknown> Unknowns,
    IReadOnlyList<WorkerDiagnostic> Diagnostics);

internal sealed record ModuleSnapshot(byte[] Bytes, string Sha256);

internal static class MetadataAnalysis
{
    private const long MaximumModuleBytes = 256L * 1024L * 1024L;
    private const int MaximumSourceBytes = 8 * 1024 * 1024;
    private const int MaximumMetadataEntries = 1_048_576;
    private const int MaximumWireIdentityBytes = 4 * 1024;
    private const int MaximumWireSignatureBytes = 8 * 1024;
    private const int MaximumRendererIdentifierBytes = 8 * 1024;
    private const byte MetadataTypeConfidence = 100;
    private const byte OpcodeTypeConfidence = 100;
    private const byte ConservativeFallbackTypeConfidence = 50;
    private const string ManagedContractHash = "4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6";
    private const string ManagedWorkerBuildId = "aida-managed-decompiler-worker-v3";
    private const string ManagedWorkerBuildHash = "4dd8c0d095629437387a4b631fd9ac3c3cb8e840f6b7af277ccc2ad49d4bc3b7";
    private static readonly object ModuleSnapshotGate = new();
    private static ModuleSnapshot? moduleSnapshot;

    internal static void EstablishModuleSnapshot(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length == 0 || bytes.LongLength > MaximumModuleBytes)
            throw new InvalidDataException("module snapshot length is invalid");
        var hash = SHA256.HashData(bytes);
        var snapshot = new ModuleSnapshot(bytes, Convert.ToHexString(hash).ToLowerInvariant());
        CryptographicOperations.ZeroMemory(hash);
        lock (ModuleSnapshotGate)
        {
            if (moduleSnapshot is not null)
                throw new InvalidDataException("module snapshot was already established");
            moduleSnapshot = snapshot;
        }
    }

    internal static void ReleaseModuleSnapshot()
    {
        ModuleSnapshot? snapshot;
        lock (ModuleSnapshotGate)
        {
            snapshot = moduleSnapshot;
            moduleSnapshot = null;
        }
        if (snapshot is not null)
            CryptographicOperations.ZeroMemory(snapshot.Bytes);
    }

    internal static WorkerResult Analyze(WorkerRequest request, ResourceBudgetGuard resourceBudget, CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        RuntimeIdentity.RequireRuntimeGate(request.RuntimeManifestHash, resourceBudget, cancellationToken);
        resourceBudget.Checkpoint(cancellationToken);

        var snapshot = ReadVerifiedSnapshot(request, resourceBudget, cancellationToken);
        using var stream = new MemoryStream(snapshot.Bytes, writable: false);
        using var module = new PEFile(request.ModuleSource.LogicalIdentity, stream,
            PEStreamOptions.LeaveOpen, MetadataReaderOptions.None);
        var peReader = module.Reader;
        if (!peReader.HasMetadata)
            throw new BadImageFormatException("target does not contain CLI metadata");

        var reader = module.Metadata;
        if (reader.TypeDefinitions.Count > MaximumMetadataEntries || reader.MethodDefinitions.Count > MaximumMetadataEntries)
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        var methodHandle = RequireMethodHandle(request.MetadataToken, reader);
        var declaringTypes = BuildDeclaringTypeMap(reader, resourceBudget, cancellationToken);
        var parsed = ParseMethod(reader, peReader, methodHandle, declaringTypes, request, resourceBudget, cancellationToken);
        var source = DecompileMethod(module, request.MetadataToken, cancellationToken);
        resourceBudget.Checkpoint(cancellationToken);
        var sourceByteCount = Encoding.UTF8.GetByteCount(source);
        if (sourceByteCount > MaximumSourceBytes)
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        resourceBudget.EnsureAllocationFits(checked((ulong)sourceByteCount), cancellationToken);
        var sourceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source))).ToLowerInvariant();
        RevalidateSnapshot(snapshot, request, resourceBudget, cancellationToken);

        return new WorkerResult(
            WorkerProtocol.Schema,
            WorkerProtocol.Version,
            "result",
            request.Sequence,
            request.RequestId,
            request.ModuleSource,
            request.EntityHash,
            request.MetadataToken,
            request.WorkspaceGeneration,
            request.TypeGraphRevision,
            request.Budget,
            RuntimeIdentity.ManifestHashHex,
            request.ContractHash,
            request.CacheIdentity,
            request.RequestBindingHash,
            request.Provider,
            parsed.Identity,
            new WorkerSource(source, sourceHash),
            parsed.TokenMap,
            parsed.TypeGraph,
            parsed.ReturnTypeId,
            parsed.Ir,
            parsed.Unknowns,
            parsed.Diagnostics);
    }

    internal static void ValidateRequest(WorkerRequest request)
    {
        if (!string.Equals(request.Schema, WorkerProtocol.Schema, StringComparison.Ordinal) || request.SchemaVersion != WorkerProtocol.Version ||
            !string.Equals(request.Kind, "decompile", StringComparison.Ordinal) || request.Sequence == 0 || string.IsNullOrWhiteSpace(request.RequestId) ||
            request.RequestId.Length > 128 || request.RequestId.Contains('\0') || request.ModuleSource is null ||
            !ValidModuleSource(request.ModuleSource) || request.WorkspaceGeneration == 0 ||
            (request.MetadataToken >> 24) != 0x06 || (request.MetadataToken & 0x00ffffffU) == 0 ||
            request.TypeGraphRevision == 0 || request.Budget is null || request.Provider is null ||
            !IsLowerHexDigest(request.EntityHash) || request.EntityHash.All(character => character == '0') ||
            !FixedTimeHexEquals(request.RuntimeManifestHash, RuntimeIdentity.ManifestHashHex) ||
            !FixedTimeHexEquals(request.ContractHash, ManagedContractHash) ||
            !IsLowerHexDigest(request.CacheIdentity) || request.CacheIdentity.All(character => character == '0') ||
            !IsLowerHexDigest(request.RequestBindingHash) || request.RequestBindingHash.All(character => character == '0') ||
            request.Budget.MaxWallClockMs == 0 || !WorkerBudgetLimits.IsSane(request.Budget) ||
            request.ModuleSource.ModuleSize > request.Budget.MaxMemoryBytes / 2 ||
            request.Budget.MaxProviderIrNodes == 0 || request.Budget.Profile is not ("fast" or "balanced" or "thorough") ||
            !string.Equals(request.Provider.Version, "10.1.0.8386", StringComparison.Ordinal) ||
            !FixedTimeHexEquals(request.Provider.DecompilerAssemblyHash, RuntimeIdentity.DecompilerAssemblySha256) ||
            !string.Equals(request.Provider.WorkerBuildId, ManagedWorkerBuildId, StringComparison.Ordinal) ||
            !FixedTimeHexEquals(request.Provider.WorkerBuildHash, ManagedWorkerBuildHash))
            throw new InvalidDataException("managed decompiler request violates the app-local runtime contract");

    }

    private static ModuleSnapshot ReadVerifiedSnapshot(
        WorkerRequest request,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        ModuleSnapshot snapshot;
        lock (ModuleSnapshotGate)
            snapshot = moduleSnapshot ?? throw new InvalidDataException("module snapshot is unavailable");
        var length = snapshot.Bytes.LongLength;
        if (length <= 0 || length > MaximumModuleBytes)
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        resourceBudget.EnsureAllocationFits(checked((ulong)length), cancellationToken);
        if ((ulong)length != request.ModuleSource.ModuleSize ||
            !FixedTimeHexEquals(snapshot.Sha256, request.ModuleSource.ModuleHash))
            throw new InvalidDataException("module hash does not match the verified snapshot");
        resourceBudget.Checkpoint(cancellationToken);
        return snapshot;
    }

    private static void RevalidateSnapshot(
        ModuleSnapshot snapshot,
        WorkerRequest request,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        resourceBudget.Checkpoint(cancellationToken);
        var hash = SHA256.HashData(snapshot.Bytes);
        try
        {
            var actual = Convert.ToHexString(hash).ToLowerInvariant();
            if (!FixedTimeHexEquals(actual, snapshot.Sha256) ||
                !FixedTimeHexEquals(actual, request.ModuleSource.ModuleHash))
                throw new InvalidDataException("module snapshot changed during managed analysis");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
        resourceBudget.Checkpoint(cancellationToken);
    }

    private static bool ValidModuleSource(WorkerModuleSource source)
    {
        if (source.ModuleSize == 0 || source.ModuleSize > (ulong)MaximumModuleBytes ||
            !IsLowerHexDigest(source.ModuleHash) || source.ModuleHash.All(character => character == '0') ||
            string.IsNullOrWhiteSpace(source.LogicalIdentity) ||
            source.LogicalIdentity.Length > 32768 || source.LogicalIdentity.Contains('\0') ||
            source.LogicalIdentity.Any(character => character < 0x20 || character == 0x7f))
            return false;
        if (string.Equals(source.Kind, "regular_file", StringComparison.Ordinal))
            return Path.IsPathFullyQualified(source.LogicalIdentity);
        if (!string.Equals(source.Kind, "embedded_member", StringComparison.Ordinal))
            return false;
        var marker = source.LogicalIdentity.IndexOf("#member:", StringComparison.Ordinal);
        if (marker <= 0 || marker + 8 >= source.LogicalIdentity.Length)
            return false;
        var member = source.LogicalIdentity[(marker + 8)..].Replace('\\', '/');
        if (member.StartsWith("/", StringComparison.Ordinal) ||
            member.EndsWith("/", StringComparison.Ordinal))
            return false;
        return member.Split('/', StringSplitOptions.None)
            .All(component => component.Length != 0 && component is not "." and not "..");
    }

    private static MethodDefinitionHandle RequireMethodHandle(uint token, MetadataReader reader)
    {
        if ((token >> 24) != 0x06 || (token & 0x00ffffffU) == 0 || (token & 0x00ffffffU) > reader.MethodDefinitions.Count)
            throw new BadImageFormatException("metadata token is not a method definition");
        return MetadataTokens.MethodDefinitionHandle(unchecked((int)token));
    }

    private static Dictionary<MethodDefinitionHandle, string> BuildDeclaringTypeMap(
        MetadataReader reader,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<MethodDefinitionHandle, string>();
        foreach (var handle in reader.TypeDefinitions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var name = GetTypeDefinitionName(reader, handle);
            foreach (var method in reader.GetTypeDefinition(handle).GetMethods())
            {
                resourceBudget.Checkpoint(cancellationToken);
                result.Add(method, name);
            }
        }
        return result;
    }

    private static ParsedMethod ParseMethod(
        MetadataReader reader,
        PEReader peReader,
        MethodDefinitionHandle methodHandle,
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes,
        WorkerRequest request,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var provider = new StableSignatureTypeProvider();
        var tokenMap = BuildTokenMap(reader, peReader, declaringTypes, resourceBudget, cancellationToken);
        var method = reader.GetMethodDefinition(methodHandle);
        var identity = BuildIdentity(reader, methodHandle, declaringTypes);
        var signature = method.DecodeSignature(provider, new GenericContext(identity.DeclaringType, identity.MethodName));
        var parameterIdentities = BuildParameterIdentities(reader, method, signature, resourceBudget, cancellationToken);
        var instructions = DecodeInstructions(peReader, method.RelativeVirtualAddress, resourceBudget, cancellationToken);
        var unknowns = new List<WorkerUnknown>();
        var diagnostics = new List<WorkerDiagnostic>();
        var typeEvidence = new Dictionary<string, byte>(StringComparer.Ordinal);
        AddTypeEvidence(typeEvidence, new TypeEvidence("System.Object", ConservativeFallbackTypeConfidence));
        AddTypeEvidence(typeEvidence, new TypeEvidence(signature.ReturnType, MetadataTypeConfidence));
        foreach (var parameter in signature.ParameterTypes)
            AddTypeEvidence(typeEvidence, new TypeEvidence(parameter, MetadataTypeConfidence));
        foreach (var instruction in instructions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            AddTypeEvidence(typeEvidence, InstructionTypeEvidence(instruction.Opcode));
            if (instruction.Opcode == 0xffff)
                unknowns.Add(new WorkerUnknown("malformed_input", $"il.invalid_opcode.{instruction.Offset:x4}", instruction.Offset, 0, 0, "loader_metadata"));
            else if (ToProviderOpcode(instruction.Opcode) == "unknown")
                unknowns.Add(new WorkerUnknown("unsupported_instruction", $"il.unsupported.{instruction.Opcode:x4}", instruction.Offset, instruction.MetadataToken, 40, "provider_semantics"));
        }

        if (checked((ulong)instructions.Count) > request.Budget.MaxProviderIrNodes)
            throw new ResourceLimitException(ResourceLimitKind.ProviderIrNodes);

        var typeGraph = BuildTypeGraph(typeEvidence, request.TypeGraphRevision);
        var typeIds = typeGraph.Nodes.ToDictionary(node => node.CanonicalName, node => node.Id, StringComparer.Ordinal);
        var blocks = BuildBlocks(reader, provider, new GenericContext(identity.DeclaringType, identity.MethodName),
            parameterIdentities, instructions, peReader, method.RelativeVirtualAddress, typeIds, signature.ReturnType, unknowns,
            request.Budget.MaxProviderIrNodes, resourceBudget, cancellationToken);
        if (blocks.Count == 0)
        {
            blocks = new List<WorkerIrBlock>
            {
                new WorkerIrBlock(1, Array.Empty<ulong>(), Array.Empty<ulong>(), Array.Empty<ulong>(), new[]
                {
                    new WorkerIrValue(1, "unknown", typeIds["System.Object"], Array.Empty<ulong>(), "method-body-absent", "", -1, 0, 0, "loader_metadata")
                }, -1)
            };
            unknowns.Add(new WorkerUnknown("unsupported_metadata", "cli.method.no_body", -1, 0, 0, "loader_metadata"));
            diagnostics.Add(new WorkerDiagnostic("warning", "unresolved_reference", "managed_cli.method_body_absent", Array.Empty<string>(), null, 0, false, 1));
        }

        return new ParsedMethod(identity, tokenMap, typeGraph, typeIds[signature.ReturnType],
            new WorkerIr(blocks[0].Id, blocks), unknowns, diagnostics);
    }

    private static MethodParameterIdentities BuildParameterIdentities(
        MetadataReader reader,
        MethodDefinition method,
        MethodSignature<string> signature,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        resourceBudget.Checkpoint(cancellationToken);
        var parameterCount = signature.ParameterTypes.Length;
        if (parameterCount > MaximumMetadataEntries)
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        var isStatic = (method.Attributes & System.Reflection.MethodAttributes.Static) != 0;
        if (isStatic == signature.Header.IsInstance)
            throw new BadImageFormatException("method static attribute conflicts with its signature instance flag");
        resourceBudget.EnsureAllocationFits(checked((ulong)(parameterCount + 1) * 64UL), cancellationToken);
        var names = new string[parameterCount];
        var instanceOffset = signature.Header.IsInstance ? 1 : 0;
        for (var index = 0; index < names.Length; index++)
        {
            resourceBudget.Checkpoint(cancellationToken);
            names[index] = $"arg_{checked(index + instanceOffset)}";
        }

        var seenSequences = new bool[checked(parameterCount + 1)];
        var rowCount = 0;
        foreach (var handle in method.GetParameters())
        {
            resourceBudget.Checkpoint(cancellationToken);
            rowCount = checked(rowCount + 1);
            if (rowCount > parameterCount + 1 || rowCount > MaximumMetadataEntries)
                throw new BadImageFormatException("method parameter table exceeds its signature bounds");
            var parameter = reader.GetParameter(handle);
            var sequence = parameter.SequenceNumber;
            if (sequence < 0 || sequence > parameterCount)
                throw new BadImageFormatException("method parameter sequence exceeds its signature bounds");
            if (seenSequences[sequence])
                throw new BadImageFormatException("method parameter sequence is duplicated");
            seenSequences[sequence] = true;
            if (sequence == 0 || parameter.Name.IsNil)
                continue;
            var name = reader.GetString(parameter.Name);
            if (string.IsNullOrEmpty(name))
                continue;
            names[sequence - 1] = RenderIdentifierComponent(RequireWireIdentity(name, "parameter name"));
        }
        return new MethodParameterIdentities(signature.Header.IsInstance, names);
    }

    private static WorkerIdentity BuildIdentity(
        MetadataReader reader,
        MethodDefinitionHandle handle,
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes)
    {
        var method = reader.GetMethodDefinition(handle);
        var methodName = RequireWireIdentity(reader.GetString(method.Name), "method name");
        if (!declaringTypes.TryGetValue(handle, out var resolved))
            throw new InvalidDataException("method declaring type identity is unavailable");
        var declaringType = RequireWireIdentity(resolved, "method declaring type");
        var genericArity = checked((uint)method.GetGenericParameters().Count);
        var assemblyIdentity = GetAssemblyIdentity(reader);
        var moduleName = RequireWireIdentity(reader.GetString(reader.GetModuleDefinition().Name), "module name");
        var methodSignature = GetMethodSignatureIdentity(reader, method);
        return new WorkerIdentity(assemblyIdentity, moduleName, declaringType, methodName, methodSignature, genericArity);
    }

    private static IReadOnlyList<WorkerTokenMap> BuildTokenMap(
        MetadataReader reader,
        PEReader peReader,
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var result = new List<WorkerTokenMap>();
        foreach (var handle in reader.MethodDefinitions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var identity = BuildIdentity(reader, handle, declaringTypes);
            var method = reader.GetMethodDefinition(handle);
            var token = unchecked((uint)MetadataTokens.GetToken(handle));
            var attributes = GetAttributeTypeNames(reader, method.GetCustomAttributes(), declaringTypes, resourceBudget, cancellationToken);
            var isAsync = attributes.Contains("System.Runtime.CompilerServices.AsyncStateMachineAttribute", StringComparer.Ordinal) ||
                attributes.Contains("System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute", StringComparer.Ordinal);
            var isIterator = attributes.Contains("System.Runtime.CompilerServices.IteratorStateMachineAttribute", StringComparer.Ordinal) ||
                attributes.Contains("System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute", StringComparer.Ordinal);
            var hasExceptionRegions = method.RelativeVirtualAddress != 0 && peReader.GetMethodBody(method.RelativeVirtualAddress).ExceptionRegions.Length != 0;
            var stableIdentity = $"0x{token:x8}|{identity.DeclaringType}|{identity.MethodName}|{identity.MethodSignature}|{identity.GenericArity}";
            result.Add(new WorkerTokenMap(token, stableIdentity, identity.DeclaringType, identity.MethodName, identity.MethodSignature,
                identity.GenericArity, isAsync, isIterator, hasExceptionRegions));
        }
        return result;
    }

    private static IReadOnlyList<string> GetAttributeTypeNames(
        MetadataReader reader,
        CustomAttributeHandleCollection attributes,
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var names = new List<string>();
        foreach (var handle in attributes)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var attribute = reader.GetCustomAttribute(handle);
            var constructor = attribute.Constructor;
            string? name = constructor.Kind switch
            {
                HandleKind.MemberReference => GetMemberReferenceDeclaringType(reader, (MemberReferenceHandle)constructor),
                HandleKind.MethodDefinition when declaringTypes.TryGetValue((MethodDefinitionHandle)constructor, out var typeName) => typeName,
                _ => null
            };
            if (!string.IsNullOrWhiteSpace(name))
                names.Add(name);
        }
        return names;
    }

    private static string? GetMemberReferenceDeclaringType(MetadataReader reader, MemberReferenceHandle handle)
    {
        var parent = reader.GetMemberReference(handle).Parent;
        return parent.Kind switch
        {
            HandleKind.TypeDefinition => GetTypeDefinitionName(reader, (TypeDefinitionHandle)parent),
            HandleKind.TypeReference => GetTypeReferenceName(reader, (TypeReferenceHandle)parent),
            _ => null
        };
    }

    private static void AddTypeEvidence(IDictionary<string, byte> evidence, TypeEvidence candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate.Name) || candidate.Confidence is 0 or > 100)
            throw new InvalidDataException("managed type evidence is invalid");
        if (!evidence.TryGetValue(candidate.Name, out var existing) || existing < candidate.Confidence)
            evidence[candidate.Name] = candidate.Confidence;
    }

    private static WorkerTypeGraph BuildTypeGraph(IReadOnlyDictionary<string, byte> evidence, ulong revision)
    {
        var ordered = evidence
            .OrderBy(entry => entry.Key == "System.Object" ? 0 : 1)
            .ThenBy(entry => entry.Key, StringComparer.Ordinal)
            .ToList();
        var nodes = new List<WorkerTypeNode>(ordered.Count);
        for (var index = 0; index < ordered.Count; index++)
        {
            var name = ordered[index].Key;
            nodes.Add(new WorkerTypeNode((ulong)index + 1, TypeKind(name), name, name, PrimitiveByteSize(name), 0,
                IsSignedInteger(name), ordered[index].Value));
        }
        return new WorkerTypeGraph(revision, nodes, Array.Empty<WorkerTypeEdge>());
    }

    private static List<WorkerIrBlock> BuildBlocks(
        MetadataReader reader,
        StableSignatureTypeProvider signatureProvider,
        GenericContext genericContext,
        MethodParameterIdentities parameterIdentities,
        IReadOnlyList<IlInstruction> instructions,
        PEReader peReader,
        int rva,
        IReadOnlyDictionary<string, ulong> typeIds,
        string returnType,
        List<WorkerUnknown> unknowns,
        ulong maximumNodes,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        if (instructions.Count == 0)
            return new List<WorkerIrBlock>();

        var body = peReader.GetMethodBody(rva);
        var ilBytes = body.GetILBytes() ?? throw new BadImageFormatException("method body has no IL byte stream");
        var ilLength = ilBytes.Length;
        var starts = new HashSet<int> { instructions[0].Offset };
        var instructionOffsets = instructions.Select(instruction => instruction.Offset).ToHashSet();
        foreach (var instruction in instructions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            foreach (var target in instruction.BranchTargets)
            {
                if (!instructionOffsets.Contains(target))
                    throw new BadImageFormatException("branch target does not start an IL instruction");
                starts.Add(target);
            }
            if (TerminatesBlock(instruction.Opcode) && instruction.NextOffset < ilLength)
                starts.Add(instruction.NextOffset);
        }

        foreach (var region in body.ExceptionRegions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            if (!instructionOffsets.Contains(region.TryOffset) || !instructionOffsets.Contains(region.HandlerOffset))
                throw new BadImageFormatException("exception region does not align with IL instructions");
            starts.Add(region.TryOffset);
            starts.Add(region.HandlerOffset);
            if (region.Kind == ExceptionRegionKind.Filter)
            {
                if (!instructionOffsets.Contains(region.FilterOffset))
                    throw new BadImageFormatException("exception filter does not align with an IL instruction");
                starts.Add(region.FilterOffset);
            }
        }

        var orderedStarts = starts.OrderBy(offset => offset).ToArray();
        var blocks = new List<BlockBuilder>(orderedStarts.Length);
        for (var index = 0; index < orderedStarts.Length; index++)
        {
            var start = orderedStarts[index];
            var end = index + 1 < orderedStarts.Length ? orderedStarts[index + 1] : ilLength;
            var bodyInstructions = instructions.Where(instruction => instruction.Offset >= start && instruction.Offset < end).ToList();
            if (bodyInstructions.Count == 0)
                throw new BadImageFormatException("basic block has no IL instructions");
            blocks.Add(new BlockBuilder((ulong)index + 1, start, end, bodyInstructions));
        }

        var blockByOffset = blocks.ToDictionary(block => block.Start, block => block.Id);
        foreach (var block in blocks)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var terminal = block.Instructions[^1];
            foreach (var target in terminal.BranchTargets)
                block.Successors.Add(blockByOffset[target]);
            if ((IsConditionalBranch(terminal.Opcode) || terminal.Opcode == 0x0045) && terminal.NextOffset < ilLength)
                block.Successors.Add(BlockForOffset(blocks, terminal.NextOffset));
            else if (!TerminatesBlock(terminal.Opcode) && terminal.NextOffset < ilLength)
                block.Successors.Add(BlockForOffset(blocks, terminal.NextOffset));
        }

        foreach (var region in body.ExceptionRegions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var handlerId = blockByOffset[region.HandlerOffset];
            var filterId = region.Kind == ExceptionRegionKind.Filter ? blockByOffset[region.FilterOffset] : 0;
            foreach (var block in blocks.Where(block => block.Start >= region.TryOffset && block.Start < region.TryOffset + region.TryLength))
            {
                block.ExceptionSuccessors.Add(handlerId);
                if (filterId != 0)
                    block.ExceptionSuccessors.Add(filterId);
            }
        }

        foreach (var block in blocks)
        {
            resourceBudget.Checkpoint(cancellationToken);
            foreach (var successor in block.Successors.Concat(block.ExceptionSuccessors))
                blocks[(int)successor - 1].Predecessors.Add(block.Id);
        }

        var instructionIds = instructions.Select((instruction, index) => (instruction.Offset, Id: checked((ulong)index + 1)))
            .ToDictionary(entry => entry.Offset, entry => entry.Id);
        var argumentIds = BuildCanonicalSlotIds(instructions, instructionIds, true, parameterIdentities,
            resourceBudget, cancellationToken);
        var localIds = BuildCanonicalSlotIds(instructions, instructionIds, false, parameterIdentities,
            resourceBudget, cancellationToken);
        ulong valueId = checked((ulong)instructions.Count + 1);
        var result = new List<WorkerIrBlock>(blocks.Count);
        foreach (var block in blocks)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var values = new List<WorkerIrValue>(block.Instructions.Count + 4);
            var stack = new List<ulong>();
            foreach (var instruction in block.Instructions)
            {
                resourceBudget.Checkpoint(cancellationToken);
                var opcode = ToProviderOpcode(instruction.Opcode);
                var typeName = opcode == "return_value" ? returnType : InstructionTypeEvidence(instruction.Opcode).Name;
                if (!typeIds.TryGetValue(typeName, out var typeId))
                    typeId = typeIds["System.Object"];
                var shape = StackShape(reader, signatureProvider, genericContext, instruction, returnType);
                var operands = PopOperands(stack, shape.PopCount, block.Id, instruction, typeIds["System.Object"],
                    values, unknowns, ref valueId, maximumNodes, resourceBudget, cancellationToken);
                IReadOnlyList<ulong> semanticOperands = opcode == "unknown" ? Array.Empty<ulong>() : operands;
                var stableImmediate = StableImmediate(reader, instruction, opcode);
                var stableSymbol = StableSymbol(reader, parameterIdentities, instruction, opcode);

                if (IsSlotStore(instruction.Opcode))
                {
                    var slot = SlotIndex(instruction);
                    var slots = IsArgumentInstruction(instruction.Opcode) ? argumentIds : localIds;
                    if (!slots.TryGetValue(slot, out var destination))
                    {
                        destination = valueId++;
                        slots.Add(slot, destination);
                        RequireNodeBudget(valueId - 1, maximumNodes);
                        values.Add(new WorkerIrValue(destination,
                            IsArgumentInstruction(instruction.Opcode) ? "parameter" : "local",
                            typeIds["System.Object"], Array.Empty<ulong>(), string.Empty,
                            IsArgumentInstruction(instruction.Opcode) ? parameterIdentities.ResolveSlot(slot) : $"local_{slot}",
                            instruction.Offset, 0, 60, "provider_semantics"));
                    }
                    semanticOperands = new[] { destination, operands[0] };
                }

                if (IsRelationalBranch(instruction.Opcode))
                {
                    var comparisonId = valueId++;
                    RequireNodeBudget(comparisonId, maximumNodes);
                    values.Add(new WorkerIrValue(comparisonId, "binary", typeIds["System.Object"], operands,
                        RelationalOperator(instruction.Opcode), string.Empty, instruction.Offset, 0, 100, "provider_semantics"));
                    semanticOperands = new[] { comparisonId };
                }

                if (opcode == "conditional_branch")
                {
                    var target = instruction.BranchTargets.Count == 1
                        ? blockByOffset[instruction.BranchTargets[0]]
                        : throw new BadImageFormatException("conditional branch target is invalid");
                    stableImmediate = $"condition.true={target};negated={(IsFalseBranch(instruction.Opcode) ? 1 : 0)}";
                }

                var currentId = instructionIds[instruction.Offset];
                values.Add(new WorkerIrValue(currentId, opcode, typeId, semanticOperands, stableImmediate,
                    stableSymbol, instruction.Offset, instruction.MetadataToken, opcode == "unknown" ? (byte)40 : (byte)100,
                    opcode == "unknown" ? "provider_semantics" : "loader_metadata"));

                if (shape.ClearStack)
                    stack.Clear();
                else if (instruction.Opcode == 0x0025)
                {
                    stack.Add(currentId);
                    stack.Add(currentId);
                }
                else if (shape.PushCount != 0)
                    stack.Add(currentId);
            }
            result.Add(new WorkerIrBlock(block.Id,
                block.Predecessors.OrderBy(id => id).ToArray(),
                block.Successors.OrderBy(id => id).ToArray(),
                block.ExceptionSuccessors.OrderBy(id => id).ToArray(),
                values,
                block.Start));
        }
        RequireNodeBudget(valueId - 1, maximumNodes);
        return CanonicalizeValueIds(result, maximumNodes, resourceBudget, cancellationToken);
    }

    private static List<WorkerIrBlock> CanonicalizeValueIds(
        IReadOnlyList<WorkerIrBlock> blocks,
        ulong maximumNodes,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var remap = new Dictionary<ulong, ulong>();
        foreach (var block in blocks)
        {
            resourceBudget.Checkpoint(cancellationToken);
            foreach (var value in block.Values)
            {
                resourceBudget.Checkpoint(cancellationToken);
                if (value.Id == 0)
                    throw new InvalidDataException("managed provider IR value identity is invalid");
                var canonicalId = checked((ulong)remap.Count + 1);
                RequireNodeBudget(canonicalId, maximumNodes);
                if (!remap.TryAdd(value.Id, canonicalId))
                    throw new InvalidDataException("managed provider IR value identity is duplicated");
            }
        }

        var result = new List<WorkerIrBlock>(blocks.Count);
        foreach (var block in blocks)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var values = new List<WorkerIrValue>(block.Values.Count);
            foreach (var value in block.Values)
            {
                resourceBudget.Checkpoint(cancellationToken);
                var operandIds = new ulong[value.OperandIds.Count];
                for (var index = 0; index < operandIds.Length; index++)
                {
                    if (!remap.TryGetValue(value.OperandIds[index], out var operandId))
                        throw new InvalidDataException("managed provider IR operand identity is unavailable");
                    operandIds[index] = operandId;
                }
                values.Add(new WorkerIrValue(
                    remap[value.Id],
                    value.Opcode,
                    value.TypeId,
                    operandIds,
                    value.StableImmediate,
                    value.StableSymbol,
                    value.IlOffset,
                    value.MetadataToken,
                    value.Confidence,
                    value.Provenance));
            }
            result.Add(new WorkerIrBlock(
                block.Id,
                block.PredecessorIds,
                block.SuccessorIds,
                block.ExceptionSuccessorIds,
                values,
                block.StartOffset));
        }
        return result;
    }

    private static Dictionary<int, ulong> BuildCanonicalSlotIds(
        IReadOnlyList<IlInstruction> instructions,
        IReadOnlyDictionary<int, ulong> instructionIds,
        bool arguments,
        MethodParameterIdentities parameterIdentities,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<int, ulong>();
        foreach (var instruction in instructions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            if (IsSlotLoad(instruction.Opcode) && IsArgumentInstruction(instruction.Opcode) == arguments)
            {
                var slot = SlotIndex(instruction);
                if (arguments)
                    _ = parameterIdentities.ResolveSlot(slot);
                result.TryAdd(slot, instructionIds[instruction.Offset]);
            }
        }
        return result;
    }

    private static StackTransition StackShape(
        MetadataReader reader,
        StableSignatureTypeProvider provider,
        GenericContext genericContext,
        IlInstruction instruction,
        string returnType)
    {
        var opcode = instruction.Opcode;
        if (IsSlotLoad(opcode) || opcode is 0x0014 or >= 0x0015 and <= 0x0023 or 0x0072 or 0x00d0 or 0xfe06 or 0xfe1c)
            return new StackTransition(0, 1, false);
        if (IsSlotStore(opcode) || opcode == 0x0026)
            return new StackTransition(1, 0, false);
        if (opcode == 0x0025)
            return new StackTransition(1, 2, false);
        if (opcode is 0x0065 or 0x0066 or >= 0x0067 and <= 0x006e or 0x0074 or 0x0075 or 0x0076 or 0x0079 or 0x008c or 0x00a5)
            return new StackTransition(1, 1, false);
        if (opcode is >= 0x0058 and <= 0x0064)
            return new StackTransition(2, 1, false);
        if (opcode is >= 0x0046 and <= 0x0050)
            return new StackTransition(1, 1, false);
        if (opcode is >= 0x0051 and <= 0x0057 or 0x00df)
            return new StackTransition(2, 0, false);
        if (opcode is >= 0x0090 and <= 0x009a or 0x00a3 or 0x008f)
            return new StackTransition(2, 1, false);
        if (opcode is >= 0x009b and <= 0x00a4)
            return new StackTransition(3, 0, false);
        if (opcode is 0x007b or 0x007c)
            return new StackTransition(1, 1, false);
        if (opcode is 0x007e or 0x007f)
            return new StackTransition(0, 1, false);
        if (opcode == 0x007d)
            return new StackTransition(2, 0, false);
        if (opcode == 0x0080)
            return new StackTransition(1, 0, false);
        if (opcode is 0x0028 or 0x0029 or 0x006f or 0x0073)
            return CallStackShape(reader, provider, genericContext, instruction);
        if (opcode == 0xfe07)
            return new StackTransition(1, 1, false);
        if (opcode is 0x002b or 0x0038)
            return new StackTransition(0, 0, false);
        if (opcode is 0x002c or 0x002d or 0x0039 or 0x003a or 0x0045)
            return new StackTransition(1, 0, false);
        if (IsRelationalBranch(opcode))
            return new StackTransition(2, 0, false);
        if (opcode is 0x00dd or 0x00de)
            return new StackTransition(0, 0, true);
        if (opcode == 0x002a)
            return new StackTransition(returnType == "System.Void" ? 0 : 1, 0, false);
        if (opcode == 0x007a)
            return new StackTransition(1, 0, false);
        if (opcode is 0xfe1a or 0x00dc or 0xfe11 or 0x0027)
            return new StackTransition(opcode == 0xfe11 ? 1 : 0, 0, false);
        return new StackTransition(0, 0, false);
    }

    private static StackTransition CallStackShape(
        MetadataReader reader,
        StableSignatureTypeProvider provider,
        GenericContext genericContext,
        IlInstruction instruction)
    {
        var handle = MetadataTokens.EntityHandle(unchecked((int)instruction.MetadataToken));
        MethodSignature<string> signature;
        if (instruction.Opcode == 0x0029)
        {
            if (handle.Kind != HandleKind.StandaloneSignature)
                throw new BadImageFormatException("calli does not reference a standalone signature");
            signature = reader.GetStandaloneSignature((StandaloneSignatureHandle)handle).DecodeMethodSignature(provider, genericContext);
            return new StackTransition(checked(signature.ParameterTypes.Length + (signature.Header.IsInstance ? 1 : 0) + 1),
                signature.ReturnType == "System.Void" ? 0 : 1, false);
        }
        while (handle.Kind == HandleKind.MethodSpecification)
            handle = reader.GetMethodSpecification((MethodSpecificationHandle)handle).Method;
        signature = handle.Kind switch
        {
            HandleKind.MethodDefinition => reader.GetMethodDefinition((MethodDefinitionHandle)handle).DecodeSignature(provider, genericContext),
            HandleKind.MemberReference => reader.GetMemberReference((MemberReferenceHandle)handle).DecodeMethodSignature(provider, genericContext),
            _ => throw new BadImageFormatException("call target does not reference a method signature")
        };
        var receiver = instruction.Opcode == 0x0073 ? 0 : signature.Header.IsInstance ? 1 : 0;
        return new StackTransition(checked(signature.ParameterTypes.Length + receiver),
            instruction.Opcode == 0x0073 || signature.ReturnType != "System.Void" ? 1 : 0, false);
    }

    private static IReadOnlyList<ulong> PopOperands(
        List<ulong> stack,
        int count,
        ulong blockId,
        IlInstruction instruction,
        ulong unknownTypeId,
        List<WorkerIrValue> values,
        List<WorkerUnknown> unknowns,
        ref ulong nextValueId,
        ulong maximumNodes,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var reverse = new List<ulong>(count);
        for (var index = 0; index < count; index++)
        {
            resourceBudget.Checkpoint(cancellationToken);
            if (stack.Count != 0)
            {
                var last = stack.Count - 1;
                reverse.Add(stack[last]);
                stack.RemoveAt(last);
                continue;
            }
            var id = nextValueId++;
            RequireNodeBudget(id, maximumNodes);
            var token = $"cli.stack_input.block_{blockId}.IL_{instruction.Offset:x4}.{count - index - 1}";
            values.Add(new WorkerIrValue(id, "unknown", unknownTypeId, Array.Empty<ulong>(), token,
                string.Empty, instruction.Offset, 0, 0, "provider_semantics"));
            unknowns.Add(new WorkerUnknown("opaque_control_flow", token, instruction.Offset,
                instruction.MetadataToken, 0, "provider_semantics"));
            reverse.Add(id);
        }
        reverse.Reverse();
        return reverse;
    }

    private static void RequireNodeBudget(ulong id, ulong maximumNodes)
    {
        if (id == 0 || id > maximumNodes)
            throw new ResourceLimitException(ResourceLimitKind.ProviderIrNodes);
    }

    private static bool IsArgumentInstruction(ushort opcode) =>
        opcode is >= 0x0002 and <= 0x0005 or 0x000e or 0x000f or 0x0010 or >= 0xfe09 and <= 0xfe0b;

    private static bool IsSlotLoad(ushort opcode) =>
        opcode is >= 0x0002 and <= 0x0009 or 0x000e or 0x000f or 0x0011 or 0x0012 or
            0xfe09 or 0xfe0a or 0xfe0c or 0xfe0d;

    private static bool IsSlotStore(ushort opcode) =>
        opcode is >= 0x000a and <= 0x000d or 0x0010 or 0x0013 or 0xfe0b or 0xfe0e;

    private static int SlotIndex(IlInstruction instruction)
    {
        var opcode = instruction.Opcode;
        if (opcode is >= 0x0002 and <= 0x0005)
            return opcode - 0x0002;
        if (opcode is >= 0x0006 and <= 0x0009)
            return opcode - 0x0006;
        if (opcode is >= 0x000a and <= 0x000d)
            return opcode - 0x000a;
        var separator = instruction.OperandText.IndexOf(':');
        if (separator < 0 || !int.TryParse(instruction.OperandText[(separator + 1)..], NumberStyles.None,
                CultureInfo.InvariantCulture, out var slot) || slot < 0)
            throw new BadImageFormatException("CLI variable slot operand is invalid");
        return slot;
    }

    private static bool IsRelationalBranch(ushort opcode) =>
        opcode is >= 0x002e and <= 0x0037 or >= 0x003b and <= 0x0044;

    private static bool IsFalseBranch(ushort opcode) => opcode is 0x002c or 0x0039;

    private static string RelationalOperator(ushort opcode) => opcode switch
    {
        0x002e or 0x003b => "==",
        0x0033 or 0x0040 => "!=",
        0x002f or 0x0034 or 0x003c or 0x0041 => ">=",
        0x0030 or 0x0035 or 0x003d or 0x0042 => ">",
        0x0031 or 0x0036 or 0x003e or 0x0043 => "<=",
        0x0032 or 0x0037 or 0x003f or 0x0044 => "<",
        _ => throw new BadImageFormatException("CLI relational branch opcode is invalid")
    };

    private static string StableImmediate(MetadataReader reader, IlInstruction instruction, string opcode)
    {
        if (opcode is "parameter" or "local" or "return_value" or "throw_value" or "call")
            return string.Empty;
        if (opcode == "binary")
            return BinaryOperator(instruction.Opcode);
        if (opcode == "unary")
            return instruction.Opcode == 0x0065 ? "-" : "~";
        if (instruction.Opcode == 0x0025)
            return "copy";
        if (opcode == "constant")
            return ConstantText(reader, instruction);
        if (opcode == "cast")
            return "cast";
        if (opcode == "store")
            return "=";
        if (opcode == "load")
            return "*";
        if (opcode == "branch")
            return instruction.Symbol;
        if (opcode == "switch_branch")
            return instruction.Symbol;
        if (opcode == "unknown")
            return $"unknown_IL_{instruction.Offset:x4}_{instruction.Opcode:x4}";
        return string.Empty;
    }

    private static string StableSymbol(
        MetadataReader reader,
        MethodParameterIdentities parameterIdentities,
        IlInstruction instruction,
        string opcode)
    {
        if (opcode == "parameter")
            return parameterIdentities.ResolveSlot(SlotIndex(instruction));
        if (opcode == "local")
            return $"local_{SlotIndex(instruction)}";
        if (opcode == "call")
            return ResolveCallableSymbol(reader, instruction);
        if (opcode is "field_load" or "field_store")
            return ResolveFieldSymbol(reader, instruction);
        return string.Empty;
    }

    private static string ResolveCallableSymbol(MetadataReader reader, IlInstruction instruction)
    {
        var handle = RequireMetadataEntityHandle(instruction.MetadataToken, "call target");
        if (instruction.Opcode == 0x0029)
        {
            if (handle.Kind != HandleKind.StandaloneSignature)
                throw new BadImageFormatException("calli target is not a standalone signature");
            var signature = reader.GetBlobBytes(reader.GetStandaloneSignature((StandaloneSignatureHandle)handle).Signature);
            RequireMetadataSignature(signature, "calli signature");
            return "indirect_call";
        }
        if (handle.Kind == HandleKind.MethodSpecification)
        {
            var specification = reader.GetMethodSpecification((MethodSpecificationHandle)handle);
            RequireMetadataSignature(reader.GetBlobBytes(specification.Signature), "method specification signature");
            _ = specification.DecodeSignature(new StableSignatureTypeProvider(), new GenericContext(string.Empty, string.Empty));
            handle = specification.Method;
        }
        return handle.Kind switch
        {
            HandleKind.MethodDefinition => ResolveMethodDefinitionSymbol(reader, (MethodDefinitionHandle)handle),
            HandleKind.MemberReference => ResolveMethodReferenceSymbol(reader, (MemberReferenceHandle)handle),
            _ => throw new BadImageFormatException("call target does not reference a CLI method")
        };
    }

    private static string ResolveFieldSymbol(MetadataReader reader, IlInstruction instruction)
    {
        var handle = RequireMetadataEntityHandle(instruction.MetadataToken, "field target");
        return handle.Kind switch
        {
            HandleKind.FieldDefinition => ResolveFieldDefinitionSymbol(reader, (FieldDefinitionHandle)handle),
            HandleKind.MemberReference => ResolveFieldReferenceSymbol(reader, (MemberReferenceHandle)handle),
            _ => throw new BadImageFormatException("field target does not reference a CLI field")
        };
    }

    private static string ResolveMethodDefinitionSymbol(MetadataReader reader, MethodDefinitionHandle handle)
    {
        var definition = reader.GetMethodDefinition(handle);
        RequireMetadataSignature(reader.GetBlobBytes(definition.Signature), "method definition signature");
        _ = definition.DecodeSignature(new StableSignatureTypeProvider(), new GenericContext(string.Empty, string.Empty));
        return AppendRendererMember(RenderTypeDefinitionIdentifier(reader, definition.GetDeclaringType()),
            RequireWireIdentity(reader.GetString(definition.Name), "method symbol"));
    }

    private static string ResolveMethodReferenceSymbol(MetadataReader reader, MemberReferenceHandle handle)
    {
        var reference = reader.GetMemberReference(handle);
        if (reference.GetKind() != MemberReferenceKind.Method)
            throw new BadImageFormatException("call target member reference is not a method");
        RequireMetadataSignature(reader.GetBlobBytes(reference.Signature), "method reference signature");
        _ = reference.DecodeMethodSignature(new StableSignatureTypeProvider(), new GenericContext(string.Empty, string.Empty));
        return AppendRendererMember(RenderMemberReferenceOwner(reader, reference.Parent),
            RequireWireIdentity(reader.GetString(reference.Name), "method reference symbol"));
    }

    private static string ResolveFieldDefinitionSymbol(MetadataReader reader, FieldDefinitionHandle handle)
    {
        var definition = reader.GetFieldDefinition(handle);
        RequireMetadataSignature(reader.GetBlobBytes(definition.Signature), "field definition signature");
        _ = definition.DecodeSignature(new StableSignatureTypeProvider(), new GenericContext(string.Empty, string.Empty));
        return AppendRendererMember(RenderTypeDefinitionIdentifier(reader, definition.GetDeclaringType()),
            RequireWireIdentity(reader.GetString(definition.Name), "field symbol"));
    }

    private static string ResolveFieldReferenceSymbol(MetadataReader reader, MemberReferenceHandle handle)
    {
        var reference = reader.GetMemberReference(handle);
        if (reference.GetKind() != MemberReferenceKind.Field)
            throw new BadImageFormatException("field target member reference is not a field");
        RequireMetadataSignature(reader.GetBlobBytes(reference.Signature), "field reference signature");
        _ = reference.DecodeFieldSignature(new StableSignatureTypeProvider(), new GenericContext(string.Empty, string.Empty));
        return AppendRendererMember(RenderMemberReferenceOwner(reader, reference.Parent),
            RequireWireIdentity(reader.GetString(reference.Name), "field reference symbol"));
    }

    private static string RenderMemberReferenceOwner(MetadataReader reader, EntityHandle parent)
    {
        return parent.Kind switch
        {
            HandleKind.TypeDefinition => RenderTypeDefinitionIdentifier(reader, (TypeDefinitionHandle)parent),
            HandleKind.TypeReference => RenderTypeReferenceIdentifier(reader, (TypeReferenceHandle)parent),
            HandleKind.TypeSpecification => RenderTypeSpecificationIdentifier(reader, (TypeSpecificationHandle)parent),
            HandleKind.MethodDefinition => RenderTypeDefinitionIdentifier(reader,
                reader.GetMethodDefinition((MethodDefinitionHandle)parent).GetDeclaringType()),
            HandleKind.ModuleReference => RenderIdentifierComponent(RequireWireIdentity(
                reader.GetString(reader.GetModuleReference((ModuleReferenceHandle)parent).Name), "module reference symbol")),
            _ => throw new BadImageFormatException("member reference has an unsupported declaring scope")
        };
    }

    private static string RenderTypeDefinitionIdentifier(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var names = new List<string>();
        var visited = new HashSet<int>();
        string @namespace;
        while (true)
        {
            if (handle.IsNil || !visited.Add(MetadataTokens.GetRowNumber(handle)) || visited.Count > reader.TypeDefinitions.Count)
                throw new BadImageFormatException("type definition declaring scope is invalid");
            var definition = reader.GetTypeDefinition(handle);
            names.Add(RequireWireIdentity(reader.GetString(definition.Name), "type definition symbol"));
            var declaringType = definition.GetDeclaringType();
            if (declaringType.IsNil)
            {
                @namespace = reader.GetString(definition.Namespace);
                break;
            }
            handle = declaringType;
        }
        names.Reverse();
        return RenderQualifiedTypeIdentifier(@namespace, names);
    }

    private static string RenderTypeReferenceIdentifier(MetadataReader reader, TypeReferenceHandle handle)
    {
        var names = new List<string>();
        var visited = new HashSet<int>();
        string @namespace;
        while (true)
        {
            if (handle.IsNil || !visited.Add(MetadataTokens.GetRowNumber(handle)) || visited.Count > reader.TypeReferences.Count)
                throw new BadImageFormatException("type reference resolution scope is invalid");
            var reference = reader.GetTypeReference(handle);
            names.Add(RequireWireIdentity(reader.GetString(reference.Name), "type reference symbol"));
            if (reference.ResolutionScope.Kind == HandleKind.TypeReference)
            {
                handle = (TypeReferenceHandle)reference.ResolutionScope;
                continue;
            }
            if (reference.ResolutionScope.IsNil)
                throw new BadImageFormatException("type reference resolution scope is absent");
            @namespace = reader.GetString(reference.Namespace);
            break;
        }
        names.Reverse();
        return RenderQualifiedTypeIdentifier(@namespace, names);
    }

    private static string RenderTypeSpecificationIdentifier(MetadataReader reader, TypeSpecificationHandle handle)
    {
        var specification = reader.GetTypeSpecification(handle);
        var signature = reader.GetBlobBytes(specification.Signature);
        RequireMetadataSignature(signature, "type specification signature");
        var identity = specification.DecodeSignature(new StableSignatureTypeProvider(), new GenericContext(string.Empty, string.Empty));
        return RenderIdentifierComponent(RequireWireIdentity(identity, "type specification symbol"));
    }

    private static string RenderQualifiedTypeIdentifier(string @namespace, IReadOnlyList<string> names)
    {
        if (names.Count == 0)
            throw new BadImageFormatException("type symbol has no name");
        var components = new List<string>();
        if (!string.IsNullOrEmpty(@namespace))
        {
            foreach (var component in @namespace.Split('.', StringSplitOptions.None))
            {
                if (component.Length == 0)
                    throw new BadImageFormatException("type namespace contains an empty component");
                components.Add(RenderIdentifierComponent(RequireWireIdentity(component, "namespace symbol")));
            }
        }
        foreach (var name in names)
            components.Add(RenderIdentifierComponent(name));
        return RequireRendererIdentifier(string.Join("::", components));
    }

    private static string AppendRendererMember(string owner, string member)
    {
        if (string.IsNullOrEmpty(owner))
            throw new BadImageFormatException("member symbol has no declaring type");
        return RequireRendererIdentifier($"{owner}::{RenderIdentifierComponent(member)}");
    }

    private static string RenderIdentifierComponent(string value)
    {
        if (value == ".ctor")
            return "$ctor";
        if (value == ".cctor")
            return "$cctor";
        var valid = value.Length != 0 && !value.Contains("$cli$", StringComparison.Ordinal) &&
            IsRendererIdentifierStart(value[0]);
        for (var index = 1; valid && index < value.Length; index++)
            valid = IsRendererIdentifierContinuation(value[index]);
        if (valid)
            return RequireRendererIdentifier(value);
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length == 0 || bytes.Length > MaximumWireIdentityBytes)
            throw new InvalidDataException("metadata identifier component exceeds the renderer contract");
        return RequireRendererIdentifier("$cli$" + Convert.ToHexString(bytes));
    }

    private static bool IsRendererIdentifierStart(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or '_' or '$';

    private static bool IsRendererIdentifierContinuation(char value) =>
        IsRendererIdentifierStart(value) || value is >= '0' and <= '9';

    private static string RequireRendererIdentifier(string value)
    {
        if (string.IsNullOrEmpty(value) || Encoding.UTF8.GetByteCount(value) > MaximumRendererIdentifierBytes)
            throw new InvalidDataException("metadata identifier exceeds the renderer contract");
        return value;
    }

    private static EntityHandle RequireMetadataEntityHandle(uint token, string field)
    {
        if (token == 0)
            throw new BadImageFormatException($"{field} metadata token is absent");
        try
        {
            var handle = MetadataTokens.EntityHandle(unchecked((int)token));
            if (handle.IsNil)
                throw new BadImageFormatException($"{field} metadata token is nil");
            return handle;
        }
        catch (ArgumentException exception)
        {
            throw new BadImageFormatException($"{field} metadata token is invalid", exception);
        }
    }

    private static void RequireMetadataSignature(byte[] signature, string field)
    {
        if (signature.Length == 0 || signature.Length > MaximumWireSignatureBytes)
            throw new BadImageFormatException($"{field} is invalid");
    }

    private static string BinaryOperator(ushort opcode) => opcode switch
    {
        0x0058 => "+", 0x0059 => "-", 0x005a => "*", 0x005b or 0x005c => "/",
        0x005d or 0x005e => "%", 0x005f => "&", 0x0060 => "|", 0x0061 => "^",
        0x0062 => "<<", 0x0063 or 0x0064 => ">>",
        _ => throw new BadImageFormatException("CLI binary opcode is invalid")
    };

    private static string ConstantText(MetadataReader reader, IlInstruction instruction) => instruction.Opcode switch
    {
        0x0014 => "null",
        0x0015 => "-1",
        >= 0x0016 and <= 0x001e => (instruction.Opcode - 0x0016).ToString(CultureInfo.InvariantCulture),
        0x0072 when instruction.MetadataToken != 0 => System.Text.Json.JsonSerializer.Serialize(
            reader.GetUserString(MetadataTokens.UserStringHandle(unchecked((int)(instruction.MetadataToken & 0x00ffffffU))))),
        _ => instruction.OperandText.Contains(':')
            ? instruction.OperandText[(instruction.OperandText.IndexOf(':') + 1)..]
            : instruction.Symbol.Length != 0 ? instruction.Symbol : $"IL_{instruction.Offset:x4}"
    };

    private static ulong BlockForOffset(IReadOnlyList<BlockBuilder> blocks, int offset)
    {
        foreach (var block in blocks)
        {
            if (offset >= block.Start && offset < block.End)
                return block.Id;
        }
        throw new BadImageFormatException("fall-through address is not in an IL block");
    }

    private static string DecompileMethod(PEFile module, uint metadataToken, CancellationToken cancellationToken)
    {
        var settings = new DecompilerSettings
        {
            AsyncAwait = true,
            AsyncEnumerator = true,
            YieldReturn = true,
            AlwaysUseBraces = true,
            UseDebugSymbols = false,
            ShowXmlDocumentation = false,
            DecompileMemberBodies = true
        };
        var decompiler = new CSharpDecompiler(module, new ParseOnlyAssemblyResolver(), settings)
        {
            CancellationToken = cancellationToken
        };
        return decompiler.DecompileAsString(new[] { MetadataTokens.EntityHandle(unchecked((int)metadataToken)) });
    }

    private static IReadOnlyList<IlInstruction> DecodeInstructions(
        PEReader peReader,
        int rva,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        if (rva == 0)
            return Array.Empty<IlInstruction>();
        var body = peReader.GetMethodBody(rva);
        var bytes = body.GetILBytes() ?? throw new BadImageFormatException("method body has no IL byte stream");
        var result = new List<IlInstruction>();
        var offset = 0;
        while (offset < bytes.Length)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var start = offset;
            var first = ReadByte(bytes, ref offset);
            ushort opcode = first;
            if (first == 0xfe)
                opcode = (ushort)(0xfe00 | ReadByte(bytes, ref offset));
            var kind = OperandKindFor(opcode);
            var operand = ReadOperand(bytes, ref offset, start, kind, out var targets, out var metadataToken, out var symbol);
            result.Add(new IlInstruction(start, offset, opcode, OpcodeName(opcode), operand, symbol, metadataToken, targets));
        }
        return result;
    }

    private static string ReadOperand(
        ReadOnlySpan<byte> bytes,
        ref int offset,
        int instructionOffset,
        IlOperandKind kind,
        out IReadOnlyList<int> targets,
        out uint metadataToken,
        out string symbol)
    {
        targets = Array.Empty<int>();
        metadataToken = 0;
        symbol = string.Empty;
        switch (kind)
        {
            case IlOperandKind.None:
                return string.Empty;
            case IlOperandKind.Byte:
                return $"u1:{ReadByte(bytes, ref offset)}";
            case IlOperandKind.SByte:
                return $"i1:{unchecked((sbyte)ReadByte(bytes, ref offset))}";
            case IlOperandKind.UInt16:
                return $"u2:{ReadUInt16(bytes, ref offset)}";
            case IlOperandKind.Int32:
                return $"i4:{ReadInt32(bytes, ref offset)}";
            case IlOperandKind.Int64:
                return $"i8:{ReadInt64(bytes, ref offset)}";
            case IlOperandKind.Single:
                return $"r4:{BitConverter.Int32BitsToSingle(ReadInt32(bytes, ref offset)).ToString("R", CultureInfo.InvariantCulture)}";
            case IlOperandKind.Double:
                return $"r8:{BitConverter.Int64BitsToDouble(ReadInt64(bytes, ref offset)).ToString("R", CultureInfo.InvariantCulture)}";
            case IlOperandKind.ShortBranch:
            {
                var delta = unchecked((sbyte)ReadByte(bytes, ref offset));
                var target = ResolveRelativeTarget(offset, delta, bytes.Length);
                targets = new[] { target };
                symbol = $"IL_{target:x4}";
                return $"branch:{symbol}";
            }
            case IlOperandKind.Branch:
            {
                var delta = ReadInt32(bytes, ref offset);
                var target = ResolveRelativeTarget(offset, delta, bytes.Length);
                targets = new[] { target };
                symbol = $"IL_{target:x4}";
                return $"branch:{symbol}";
            }
            case IlOperandKind.Switch:
            {
                var count = ReadInt32(bytes, ref offset);
                if (count < 0 || count > 1_048_576)
                    throw new BadImageFormatException("switch target count exceeds the bounded metadata limit");
                var deltas = new int[count];
                for (var index = 0; index < deltas.Length; index++)
                    deltas[index] = ReadInt32(bytes, ref offset);
                var baseOffset = offset;
                var resolved = new int[count];
                for (var index = 0; index < deltas.Length; index++)
                    resolved[index] = ResolveRelativeTarget(baseOffset, deltas[index], bytes.Length);
                targets = resolved;
                symbol = string.Join(",", resolved.Select(target => $"IL_{target:x4}"));
                return $"switch:{symbol}";
            }
            case IlOperandKind.Token:
                metadataToken = unchecked((uint)ReadInt32(bytes, ref offset));
                symbol = $"token:0x{metadataToken:x8}";
                return symbol;
            default:
                throw new BadImageFormatException($"unsupported IL operand at {instructionOffset:x4}");
        }
    }

    private static int ResolveRelativeTarget(int baseOffset, int delta, int ilLength)
    {
        var target = checked((long)baseOffset + delta);
        if (target < 0 || target >= ilLength)
            throw new BadImageFormatException("branch target lies outside the IL byte stream");
        return checked((int)target);
    }

    private static byte ReadByte(ReadOnlySpan<byte> bytes, ref int offset)
    {
        if ((uint)offset >= (uint)bytes.Length)
            throw new BadImageFormatException("truncated IL instruction");
        return bytes[offset++];
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, ref int offset)
    {
        var first = ReadByte(bytes, ref offset);
        var second = ReadByte(bytes, ref offset);
        return (ushort)(first | (second << 8));
    }

    private static int ReadInt32(ReadOnlySpan<byte> bytes, ref int offset)
    {
        var first = ReadByte(bytes, ref offset);
        var second = ReadByte(bytes, ref offset);
        var third = ReadByte(bytes, ref offset);
        var fourth = ReadByte(bytes, ref offset);
        return first | (second << 8) | (third << 16) | (fourth << 24);
    }

    private static long ReadInt64(ReadOnlySpan<byte> bytes, ref int offset)
    {
        var low = unchecked((uint)ReadInt32(bytes, ref offset));
        var high = ReadInt32(bytes, ref offset);
        return ((long)high << 32) | low;
    }

    private static IlOperandKind OperandKindFor(ushort opcode)
    {
        return opcode switch
        {
            >= 0x000e and <= 0x0013 => IlOperandKind.Byte,
            0x001f => IlOperandKind.SByte,
            0x0020 => IlOperandKind.Int32,
            0x0021 => IlOperandKind.Int64,
            0x0022 => IlOperandKind.Single,
            0x0023 => IlOperandKind.Double,
            >= 0x002b and <= 0x0037 => IlOperandKind.ShortBranch,
            >= 0x0038 and <= 0x0044 => IlOperandKind.Branch,
            0x0045 => IlOperandKind.Switch,
            0x00dd => IlOperandKind.Branch,
            0x00de => IlOperandKind.ShortBranch,
            0x0027 or 0x0028 or 0x0029 or 0x006f or >= 0x0070 and <= 0x0075 or 0x0079 or
                >= 0x007b and <= 0x0081 or 0x008c or 0x008d or 0x008f or >= 0x00a3 and <= 0x00a5 or
                0x00c2 or 0x00c6 or 0x00d0 => IlOperandKind.Token,
            >= 0xfe06 and <= 0xfe07 => IlOperandKind.Token,
            >= 0xfe09 and <= 0xfe0e => IlOperandKind.UInt16,
            0xfe12 or 0xfe19 => IlOperandKind.Byte,
            0xfe15 or 0xfe16 or 0xfe1c => IlOperandKind.Token,
            _ => IlOperandKind.None
        };
    }

    private static bool TerminatesBlock(ushort opcode) => IsBranch(opcode) || TerminatesControlFlow(opcode);

    private static bool TerminatesControlFlow(ushort opcode) => opcode is 0x002a or 0x007a or 0x00dc or 0xfe11 or 0xfe1a or 0x0027;

    private static bool IsBranch(ushort opcode) => opcode is >= 0x002b and <= 0x0045 or 0x00dd or 0x00de;

    private static bool IsConditionalBranch(ushort opcode) => opcode is >= 0x002c and <= 0x0037 or >= 0x003a and <= 0x0044;

    private static string OpcodeName(ushort opcode) => opcode switch
    {
        0x000e or 0x000f or 0xfe09 or 0xfe0a => "ldarg",
        0x0010 or 0xfe0b => "starg",
        >= 0x0011 and <= 0x0013 or >= 0xfe0c and <= 0xfe0e => "ldloc-stloc",
        0x0025 => "dup",
        0x0026 => "pop",
        0x0027 => "jmp",
        0x0028 => "call",
        0x0029 => "calli",
        0x002a => "ret",
        >= 0x002b and <= 0x0045 => "branch",
        >= 0x0046 and <= 0x0050 or 0x009a or 0x00a3 => "ldelem",
        >= 0x0051 and <= 0x005d => "stind",
        >= 0x005e and <= 0x0066 => "binary",
        >= 0x0067 and <= 0x006e or 0x0074 or 0x0075 or 0x0076 or 0x0079 or 0x008c => "cast",
        0x006f => "callvirt",
        0x0070 => "cpobj",
        0x0071 => "ldobj",
        0x0072 => "ldstr",
        0x0073 => "newobj",
        >= 0x007b and <= 0x0080 => "field",
        0x008d => "newarr",
        0x008f => "ldelema",
        >= 0x009b and <= 0x00a4 => "stelem",
        0x00a5 => "unbox.any",
        0x00d0 => "ldtoken",
        0x00dd or 0x00de => "leave",
        0xfe06 => "ldftn",
        0xfe07 => "ldvirtftn",
        0xfe11 => "endfilter",
        0xfe15 => "initobj",
        0xfe16 => "constrained",
        0xfe1a => "rethrow",
        0xfe1c => "sizeof",
        _ => $"op_{opcode:x4}"
    };

    private static string ToProviderOpcode(ushort opcode) => opcode switch
    {
        >= 0x0002 and <= 0x0005 or 0x000e or 0x000f or >= 0xfe09 and <= 0xfe0a => "parameter",
        >= 0x0006 and <= 0x0009 or >= 0x0011 and <= 0x0012 or >= 0xfe0c and <= 0xfe0d => "local",
        >= 0x000a and <= 0x000d or 0x0010 or 0x0013 or 0xfe0b or 0xfe0e => "store",
        0x0014 or >= 0x0015 and <= 0x0023 or 0x0072 or 0x00d0 => "constant",
        0x0025 => "cast",
        0x0065 or 0x0066 => "unary",
        >= 0x0058 and <= 0x0064 => "binary",
        >= 0x0067 and <= 0x006e or 0x0074 or 0x0075 or 0x0076 or 0x0079 or 0x008c or 0x00a5 => "cast",
        >= 0x0046 and <= 0x0050 => "load",
        >= 0x0090 and <= 0x009a or 0x00a3 => "array_load",
        >= 0x009b and <= 0x00a4 => "array_store",
        >= 0x007b and <= 0x007c or 0x007e or 0x007f => "field_load",
        0x007d or 0x0080 => "field_store",
        0x0027 or 0x0028 or 0x0029 or 0x006f or 0x0073 or 0xfe06 or 0xfe07 => "call",
        0x002b or 0x0038 or 0x00dd or 0x00de => "branch",
        >= 0x002c and <= 0x0044 => "conditional_branch",
        0x0045 => "switch_branch",
        0x002a => "return_value",
        0x007a or 0xfe1a => "throw_value",
        _ => "unknown"
    };

    private static TypeEvidence InstructionTypeEvidence(ushort opcode) => opcode switch
    {
        0x0015 or 0x0016 or 0x0017 or 0x0018 or 0x0019 or 0x001a or 0x001b or 0x001c or 0x001d or 0x001e or 0x001f or 0x0020 =>
            new TypeEvidence("System.Int32", OpcodeTypeConfidence),
        0x0021 => new TypeEvidence("System.Int64", OpcodeTypeConfidence),
        0x0022 => new TypeEvidence("System.Single", OpcodeTypeConfidence),
        0x0023 => new TypeEvidence("System.Double", OpcodeTypeConfidence),
        0x0014 => new TypeEvidence("System.Object", OpcodeTypeConfidence),
        0x0072 => new TypeEvidence("System.String", OpcodeTypeConfidence),
        _ => new TypeEvidence("System.Object", ConservativeFallbackTypeConfidence)
    };

    private static string TypeKind(string name) => name switch
    {
        "System.Void" => "void",
        "System.Boolean" => "boolean",
        "System.SByte" or "System.Int16" or "System.Int32" or "System.Int64" or "System.IntPtr" => "signed_integer",
        "System.Byte" or "System.UInt16" or "System.UInt32" or "System.UInt64" or "System.UIntPtr" or "System.Char" => "unsigned_integer",
        "System.Single" or "System.Double" => "floating_point",
        _ when name.EndsWith("&", StringComparison.Ordinal) => "managed_by_reference",
        _ when name.EndsWith("*", StringComparison.Ordinal) => "pointer",
        _ when name.EndsWith("[]", StringComparison.Ordinal) => "array",
        _ when name.StartsWith("!", StringComparison.Ordinal) => "generic_parameter",
        _ => "reference"
    };

    private static ulong? PrimitiveByteSize(string name) => name switch
    {
        "System.Boolean" or "System.SByte" or "System.Byte" => 1,
        "System.Int16" or "System.UInt16" or "System.Char" => 2,
        "System.Int32" or "System.UInt32" or "System.Single" => 4,
        "System.Int64" or "System.UInt64" or "System.Double" => 8,
        _ => null
    };

    private static bool IsSignedInteger(string name) => name is "System.SByte" or "System.Int16" or "System.Int32" or "System.Int64" or "System.IntPtr";

    private static string GetAssemblyIdentity(MetadataReader reader)
    {
        if (!reader.IsAssembly)
            return RequireWireIdentity(reader.GetString(reader.GetModuleDefinition().Name), "assembly identity");
        return RequireWireIdentity(reader.GetString(reader.GetAssemblyDefinition().Name), "assembly identity");
    }

    private static string GetMethodSignatureIdentity(MetadataReader reader, MethodDefinition method)
    {
        var signature = reader.GetBlobBytes(method.Signature);
        if (signature.Length == 0 || signature.Length > MaximumWireSignatureBytes)
            throw new InvalidDataException("method signature identity exceeds the wire contract");
        return Convert.ToHexString(signature);
    }

    private static string RequireWireIdentity(string value, string field)
    {
        if (string.IsNullOrEmpty(value) || Encoding.UTF8.GetByteCount(value) > MaximumWireIdentityBytes || value.Contains('\0'))
            throw new InvalidDataException($"{field} exceeds the wire contract");
        return value;
    }

    internal static string GetTypeDefinitionName(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var definition = reader.GetTypeDefinition(handle);
        var name = reader.GetString(definition.Name);
        var @namespace = reader.GetString(definition.Namespace);
        return string.IsNullOrEmpty(@namespace) ? name : $"{@namespace}.{name}";
    }

    internal static string GetTypeReferenceName(MetadataReader reader, TypeReferenceHandle handle)
    {
        var reference = reader.GetTypeReference(handle);
        var name = reader.GetString(reference.Name);
        var @namespace = reader.GetString(reference.Namespace);
        return string.IsNullOrEmpty(@namespace) ? name : $"{@namespace}.{name}";
    }

    private static bool IsLowerHexDigest(string? value)
    {
        if (value is null || value.Length != 64)
            return false;
        foreach (var character in value)
        {
            if (!(character is >= '0' and <= '9' or >= 'a' and <= 'f'))
                return false;
        }
        return true;
    }

    private static bool FixedTimeHexEquals(string? left, string? right)
    {
        if (left is null || right is null || !IsLowerHexDigest(left) || !IsLowerHexDigest(right))
            return false;
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
    }

    private readonly record struct TypeEvidence(string Name, byte Confidence);

    private readonly record struct StackTransition(int PopCount, int PushCount, bool ClearStack);

    private sealed class MethodParameterIdentities
    {
        private readonly bool isInstance;
        private readonly IReadOnlyList<string> explicitNames;

        internal MethodParameterIdentities(bool isInstance, IReadOnlyList<string> explicitNames)
        {
            this.isInstance = isInstance;
            this.explicitNames = explicitNames;
        }

        internal string ResolveSlot(int slot)
        {
            if (slot < 0)
                throw new BadImageFormatException("CLI argument slot is invalid");
            if (isInstance && slot == 0)
                return "this";
            var parameterIndex = slot - (isInstance ? 1 : 0);
            if ((uint)parameterIndex >= (uint)explicitNames.Count)
                throw new BadImageFormatException("CLI argument slot exceeds the method signature");
            return explicitNames[parameterIndex];
        }
    }

    private sealed class BlockBuilder
    {
        internal BlockBuilder(ulong id, int start, int end, IReadOnlyList<IlInstruction> instructions)
        {
            Id = id;
            Start = start;
            End = end;
            Instructions = instructions;
        }

        internal ulong Id { get; }
        internal int Start { get; }
        internal int End { get; }
        internal IReadOnlyList<IlInstruction> Instructions { get; }
        internal HashSet<ulong> Predecessors { get; } = new();
        internal HashSet<ulong> Successors { get; } = new();
        internal HashSet<ulong> ExceptionSuccessors { get; } = new();
    }

    private sealed record IlInstruction(int Offset, int NextOffset, ushort Opcode, string Name, string OperandText, string Symbol, uint MetadataToken, IReadOnlyList<int> BranchTargets);

    private enum IlOperandKind
    {
        None,
        Byte,
        SByte,
        UInt16,
        Int32,
        Int64,
        Single,
        Double,
        ShortBranch,
        Branch,
        Switch,
        Token
    }
}

internal readonly record struct GenericContext(string DeclaringType, string MethodName);

internal sealed class StableSignatureTypeProvider : ISignatureTypeProvider<string, GenericContext>
{
    public string GetArrayType(string elementType, ArrayShape shape) => $"{elementType}[{new string(',', Math.Max(0, shape.Rank - 1))}]";

    public string GetByReferenceType(string elementType) => $"{elementType}&";

    public string GetFunctionPointerType(MethodSignature<string> signature) => $"methodptr({signature.ReturnType}({string.Join(",", signature.ParameterTypes)}))";

    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => $"{genericType}<{string.Join(",", typeArguments)}>";

    public string GetGenericMethodParameter(GenericContext genericContext, int index) => $"!!{index}";

    public string GetGenericTypeParameter(GenericContext genericContext, int index) => $"!{index}";

    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => $"{unmodifiedType} {(isRequired ? "modreq" : "modopt")}({modifier})";

    public string GetPinnedType(string elementType) => $"pinned({elementType})";

    public string GetPointerType(string elementType) => $"{elementType}*";

    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Void => "System.Void",
        PrimitiveTypeCode.Boolean => "System.Boolean",
        PrimitiveTypeCode.Char => "System.Char",
        PrimitiveTypeCode.SByte => "System.SByte",
        PrimitiveTypeCode.Byte => "System.Byte",
        PrimitiveTypeCode.Int16 => "System.Int16",
        PrimitiveTypeCode.UInt16 => "System.UInt16",
        PrimitiveTypeCode.Int32 => "System.Int32",
        PrimitiveTypeCode.UInt32 => "System.UInt32",
        PrimitiveTypeCode.Int64 => "System.Int64",
        PrimitiveTypeCode.UInt64 => "System.UInt64",
        PrimitiveTypeCode.Single => "System.Single",
        PrimitiveTypeCode.Double => "System.Double",
        PrimitiveTypeCode.String => "System.String",
        PrimitiveTypeCode.IntPtr => "System.IntPtr",
        PrimitiveTypeCode.UIntPtr => "System.UIntPtr",
        PrimitiveTypeCode.Object => "System.Object",
        PrimitiveTypeCode.TypedReference => "System.TypedReference",
        _ => throw new BadImageFormatException("CLI primitive type code is unsupported")
    };

    public string GetSZArrayType(string elementType) => $"{elementType}[]";

    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => MetadataAnalysis.GetTypeDefinitionName(reader, handle);

    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => MetadataAnalysis.GetTypeReferenceName(reader, handle);

    public string GetTypeFromSpecification(MetadataReader reader, GenericContext genericContext, TypeSpecificationHandle handle, byte rawTypeKind) =>
        reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
}
