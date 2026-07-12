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
    WorkerIr Ir,
    IReadOnlyList<WorkerUnknown> Unknowns,
    IReadOnlyList<WorkerDiagnostic> Diagnostics);

internal sealed record ModuleSnapshot(byte[] Bytes, string Sha256);

internal static class MetadataAnalysis
{
    private const long MaximumModuleBytes = int.MaxValue;
    private const int MaximumSourceBytes = 8 * 1024 * 1024;

    internal static WorkerResult Analyze(WorkerRequest request, ResourceBudgetGuard resourceBudget, CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        OfflinePackageLock.RequireRuntimeGate(request.OfflineLockHash, resourceBudget, cancellationToken);
        resourceBudget.Checkpoint(cancellationToken);

        var snapshot = ReadVerifiedSnapshot(request, resourceBudget, cancellationToken);
        using var stream = new MemoryStream(snapshot.Bytes, writable: false);
        using var module = new PEFile(request.ModulePath, stream, PEStreamOptions.LeaveOpen, MetadataReaderOptions.None);
        var peReader = module.Reader;
        if (!peReader.HasMetadata)
            throw new BadImageFormatException("target does not contain CLI metadata");

        var reader = module.Metadata;
        var methodHandle = RequireMethodHandle(request.MetadataToken, reader);
        var declaringTypes = BuildDeclaringTypeMap(reader);
        var parsed = ParseMethod(reader, peReader, methodHandle, declaringTypes, request, resourceBudget, cancellationToken);
        var source = DecompileMethod(module, request.MetadataToken, cancellationToken);
        resourceBudget.Checkpoint(cancellationToken);
        var sourceByteCount = Encoding.UTF8.GetByteCount(source);
        if (sourceByteCount > MaximumSourceBytes)
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        resourceBudget.EnsureAllocationFits(checked((ulong)sourceByteCount), cancellationToken);
        var sourceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source))).ToLowerInvariant();

        return new WorkerResult(
            WorkerProtocol.Schema,
            WorkerProtocol.Version,
            "result",
            request.Sequence,
            request.RequestId,
            snapshot.Sha256,
            request.MetadataToken,
            OfflinePackageLock.ManifestHashHex,
            new WorkerProvider(request.Provider.Version, OfflinePackageLock.DecompilerAssemblySha256),
            parsed.Identity,
            new WorkerSource(source, sourceHash),
            parsed.TokenMap,
            parsed.TypeGraph,
            parsed.Ir,
            parsed.Unknowns,
            parsed.Diagnostics);
    }

    internal static void ValidateRequest(WorkerRequest request)
    {
        if (!string.Equals(request.Schema, WorkerProtocol.Schema, StringComparison.Ordinal) || request.SchemaVersion != WorkerProtocol.Version ||
            !string.Equals(request.Kind, "decompile", StringComparison.Ordinal) || request.Sequence == 0 || string.IsNullOrWhiteSpace(request.RequestId) ||
            request.RequestId.Length > 128 || string.IsNullOrWhiteSpace(request.ModulePath) || request.ModulePath.Length > 32768 ||
            !Path.IsPathFullyQualified(request.ModulePath) || request.WorkspaceGeneration == 0 || request.MetadataToken == 0 ||
            request.Budget is null || request.Provider is null || !IsLowerHexDigest(request.ModuleHash) ||
            !FixedTimeHexEquals(request.OfflineLockHash, OfflinePackageLock.ManifestHashHex) ||
            request.Budget.MaxWallClockMs == 0 || request.Budget.MaxCpuMs == 0 || request.Budget.MaxMemoryBytes == 0 ||
            request.Budget.MaxProviderIrNodes == 0 || request.Budget.Profile is not ("fast" or "balanced" or "thorough") ||
            !string.Equals(request.Provider.Version, "10.1.0.8386", StringComparison.Ordinal) ||
            !FixedTimeHexEquals(request.Provider.DecompilerAssemblyHash, OfflinePackageLock.DecompilerAssemblySha256) ||
            string.IsNullOrWhiteSpace(request.Provider.WorkerBuildId) || request.Provider.WorkerBuildId.Length > 256 ||
            !IsLowerHexDigest(request.Provider.WorkerBuildHash) ||
            request.Provider.WorkerBuildHash.All(character => character == '0'))
            throw new InvalidDataException("managed decompiler request violates the offline contract");

    }

    private static ModuleSnapshot ReadVerifiedSnapshot(
        WorkerRequest request,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        using var stream = new FileStream(request.ModulePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
        var length = stream.Length;
        if (length <= 0 || length > MaximumModuleBytes)
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        resourceBudget.EnsureAllocationFits(checked((ulong)length), cancellationToken);
        byte[] bytes;
        try
        {
            bytes = GC.AllocateUninitializedArray<byte>(checked((int)length));
        }
        catch (OutOfMemoryException)
        {
            throw new ResourceLimitException(ResourceLimitKind.Memory);
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var offset = 0;
        while (offset < bytes.Length)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var read = stream.Read(bytes, offset, Math.Min(1024 * 1024, bytes.Length - offset));
            if (read == 0)
                throw new InvalidDataException("module changed while creating the verified snapshot");
            hash.AppendData(bytes, offset, read);
            offset += read;
        }
        if (stream.ReadByte() != -1 || stream.Length != length)
            throw new InvalidDataException("module changed while creating the verified snapshot");
        var actualHash = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        if (!FixedTimeHexEquals(actualHash, request.ModuleHash))
            throw new InvalidDataException("module hash does not match the verified snapshot");
        resourceBudget.Checkpoint(cancellationToken);
        return new ModuleSnapshot(bytes, actualHash);
    }

    private static MethodDefinitionHandle RequireMethodHandle(uint token, MetadataReader reader)
    {
        if ((token >> 24) != 0x06 || (token & 0x00ffffffU) == 0 || (token & 0x00ffffffU) > reader.MethodDefinitions.Count)
            throw new BadImageFormatException("metadata token is not a method definition");
        return MetadataTokens.MethodDefinitionHandle(unchecked((int)token));
    }

    private static Dictionary<MethodDefinitionHandle, string> BuildDeclaringTypeMap(MetadataReader reader)
    {
        var result = new Dictionary<MethodDefinitionHandle, string>();
        foreach (var handle in reader.TypeDefinitions)
        {
            var name = GetTypeDefinitionName(reader, handle);
            foreach (var method in reader.GetTypeDefinition(handle).GetMethods())
                result.Add(method, name);
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
        var tokenMap = BuildTokenMap(reader, peReader, declaringTypes, provider, resourceBudget, cancellationToken);
        var method = reader.GetMethodDefinition(methodHandle);
        var identity = BuildIdentity(reader, methodHandle, declaringTypes, provider);
        var signature = method.DecodeSignature(provider, new GenericContext(identity.DeclaringType, identity.MethodName));
        var instructions = DecodeInstructions(peReader, method.RelativeVirtualAddress, resourceBudget, cancellationToken);
        var unknowns = new List<WorkerUnknown>();
        var diagnostics = new List<WorkerDiagnostic>();
        var typeNames = new SortedSet<string>(StringComparer.Ordinal) { "System.Object", signature.ReturnType };
        foreach (var parameter in signature.ParameterTypes)
            typeNames.Add(parameter);
        foreach (var instruction in instructions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            typeNames.Add(InstructionTypeName(instruction.Opcode));
            if (instruction.Opcode == 0xffff)
                unknowns.Add(new WorkerUnknown("malformed_input", $"il.invalid_opcode.{instruction.Offset:x4}", instruction.Offset, 0, 0, "loader_metadata"));
            else if (ToProviderOpcode(instruction.Opcode) == "unknown")
                unknowns.Add(new WorkerUnknown("unsupported_instruction", $"il.unsupported.{instruction.Opcode:x4}", instruction.Offset, instruction.MetadataToken, 40, "provider_semantics"));
        }

        if (instructions.Count > request.Budget.MaxProviderIrNodes)
            throw new ResourceLimitException(ResourceLimitKind.ProviderIrNodes);

        var typeGraph = BuildTypeGraph(typeNames);
        var typeIds = typeGraph.Nodes.ToDictionary(node => node.CanonicalName, node => node.Id, StringComparer.Ordinal);
        var blocks = BuildBlocks(instructions, peReader, method.RelativeVirtualAddress, typeIds, signature.ReturnType, unknowns, resourceBudget, cancellationToken);
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

        return new ParsedMethod(identity, tokenMap, typeGraph, new WorkerIr(blocks[0].Id, blocks), unknowns, diagnostics);
    }

    private static WorkerIdentity BuildIdentity(
        MetadataReader reader,
        MethodDefinitionHandle handle,
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes,
        StableSignatureTypeProvider provider)
    {
        var method = reader.GetMethodDefinition(handle);
        var methodName = reader.GetString(method.Name);
        var declaringType = declaringTypes.TryGetValue(handle, out var resolved) ? resolved : "<unknown>";
        var signature = method.DecodeSignature(provider, new GenericContext(declaringType, methodName));
        var parameters = string.Join(",", signature.ParameterTypes);
        var genericArity = checked((uint)method.GetGenericParameters().Count);
        var assemblyIdentity = GetAssemblyIdentity(reader);
        var moduleName = reader.GetString(reader.GetModuleDefinition().Name);
        return new WorkerIdentity(assemblyIdentity, moduleName, declaringType, methodName, $"{signature.ReturnType}({parameters})", genericArity);
    }

    private static IReadOnlyList<WorkerTokenMap> BuildTokenMap(
        MetadataReader reader,
        PEReader peReader,
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes,
        StableSignatureTypeProvider provider,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        var result = new List<WorkerTokenMap>();
        foreach (var handle in reader.MethodDefinitions)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var identity = BuildIdentity(reader, handle, declaringTypes, provider);
            var method = reader.GetMethodDefinition(handle);
            var token = unchecked((uint)MetadataTokens.GetToken(handle));
            var attributes = GetAttributeTypeNames(reader, method.GetCustomAttributes(), declaringTypes);
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
        IReadOnlyDictionary<MethodDefinitionHandle, string> declaringTypes)
    {
        var names = new List<string>();
        foreach (var handle in attributes)
        {
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

    private static WorkerTypeGraph BuildTypeGraph(IEnumerable<string> names)
    {
        var ordered = names.Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name == "System.Object" ? 0 : 1)
            .ThenBy(name => name, StringComparer.Ordinal)
            .ToList();
        var nodes = new List<WorkerTypeNode>(ordered.Count);
        for (var index = 0; index < ordered.Count; index++)
        {
            var name = ordered[index];
            nodes.Add(new WorkerTypeNode((ulong)index + 1, TypeKind(name), name, name, PrimitiveByteSize(name), 0,
                IsSignedInteger(name), name == "System.Object" ? (byte)0 : (byte)100));
        }
        return new WorkerTypeGraph(1, nodes, Array.Empty<WorkerTypeEdge>());
    }

    private static List<WorkerIrBlock> BuildBlocks(
        IReadOnlyList<IlInstruction> instructions,
        PEReader peReader,
        int rva,
        IReadOnlyDictionary<string, ulong> typeIds,
        string returnType,
        List<WorkerUnknown> unknowns,
        ResourceBudgetGuard resourceBudget,
        CancellationToken cancellationToken)
    {
        if (instructions.Count == 0)
            return new List<WorkerIrBlock>();

        var body = peReader.GetMethodBody(rva);
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
            if (TerminatesBlock(instruction.Opcode) && instruction.NextOffset < body.GetILBytes().Length)
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
            var end = index + 1 < orderedStarts.Length ? orderedStarts[index + 1] : body.GetILBytes().Length;
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
            if ((IsConditionalBranch(terminal.Opcode) || terminal.Opcode == 0x0045) && terminal.NextOffset < body.GetILBytes().Length)
                block.Successors.Add(BlockForOffset(blocks, terminal.NextOffset));
            else if (!TerminatesControlFlow(terminal.Opcode) && terminal.NextOffset < body.GetILBytes().Length)
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

        ulong valueId = 1;
        var result = new List<WorkerIrBlock>(blocks.Count);
        foreach (var block in blocks)
        {
            resourceBudget.Checkpoint(cancellationToken);
            var values = new List<WorkerIrValue>(block.Instructions.Count);
            foreach (var instruction in block.Instructions)
            {
                resourceBudget.Checkpoint(cancellationToken);
                var opcode = ToProviderOpcode(instruction.Opcode);
                var typeName = opcode == "return_value" ? returnType : InstructionTypeName(instruction.Opcode);
                if (!typeIds.TryGetValue(typeName, out var typeId))
                    typeId = typeIds["System.Object"];
                var stableImmediate = $"IL_{instruction.Offset:x4}|{instruction.Name}|{instruction.OperandText}";
                values.Add(new WorkerIrValue(valueId++, opcode, typeId, Array.Empty<ulong>(), stableImmediate,
                    instruction.Symbol, instruction.Offset, instruction.MetadataToken, opcode == "unknown" ? (byte)40 : (byte)100,
                    opcode == "unknown" ? "provider_semantics" : "loader_metadata"));
            }
            result.Add(new WorkerIrBlock(block.Id,
                block.Predecessors.OrderBy(id => id).ToArray(),
                block.Successors.OrderBy(id => id).ToArray(),
                block.ExceptionSuccessors.OrderBy(id => id).ToArray(),
                values,
                block.Start));
        }
        return result;
    }

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
        var bytes = body.GetILBytes();
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
        ImmutableArray<byte> bytes,
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
                var target = checked(offset + delta);
                targets = new[] { target };
                symbol = $"IL_{target:x4}";
                return $"branch:{symbol}";
            }
            case IlOperandKind.Branch:
            {
                var delta = ReadInt32(bytes, ref offset);
                var target = checked(offset + delta);
                targets = new[] { target };
                symbol = $"IL_{target:x4}";
                return $"branch:{symbol}";
            }
            case IlOperandKind.Switch:
            {
                var count = ReadInt32(bytes, ref offset);
                if (count < 0 || count > 1_048_576)
                    throw new BadImageFormatException("switch target count exceeds the offline limit");
                var deltas = new int[count];
                for (var index = 0; index < deltas.Length; index++)
                    deltas[index] = ReadInt32(bytes, ref offset);
                var baseOffset = offset;
                var resolved = new int[count];
                for (var index = 0; index < deltas.Length; index++)
                    resolved[index] = checked(baseOffset + deltas[index]);
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

    private static byte ReadByte(ImmutableArray<byte> bytes, ref int offset)
    {
        if ((uint)offset >= (uint)bytes.Length)
            throw new BadImageFormatException("truncated IL instruction");
        return bytes[offset++];
    }

    private static ushort ReadUInt16(ImmutableArray<byte> bytes, ref int offset)
    {
        var first = ReadByte(bytes, ref offset);
        var second = ReadByte(bytes, ref offset);
        return (ushort)(first | (second << 8));
    }

    private static int ReadInt32(ImmutableArray<byte> bytes, ref int offset)
    {
        var first = ReadByte(bytes, ref offset);
        var second = ReadByte(bytes, ref offset);
        var third = ReadByte(bytes, ref offset);
        var fourth = ReadByte(bytes, ref offset);
        return first | (second << 8) | (third << 16) | (fourth << 24);
    }

    private static long ReadInt64(ImmutableArray<byte> bytes, ref int offset)
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
            0x0027 or 0x0028 or 0x0029 or 0x006f or 0x0072 or 0x0073 or >= 0x0074 and <= 0x0080 or 0x008c or 0x008d or 0x008f or 0x00a3 or 0x00a4 or 0x00a5 or 0x00c2 or 0x00c6 or 0x00d0 => IlOperandKind.Token,
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
        >= 0x0067 and <= 0x0076 or 0x008c or 0x0079 => "cast",
        0x006f => "callvirt",
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
        >= 0x0006 and <= 0x000d or >= 0x0011 and <= 0x0012 or >= 0xfe0c and <= 0xfe0d => "local",
        0x0010 or 0x0013 or 0xfe0b or 0xfe0e => "store",
        0x0014 or >= 0x0015 and <= 0x0023 or 0x0072 or 0x00d0 => "constant",
        0x0025 => "copy",
        0x0065 or 0x0066 => "unary",
        >= 0x0058 and <= 0x0064 => "binary",
        >= 0x0067 and <= 0x0076 or 0x0074 or 0x0075 or 0x0079 or 0x008c or 0x00a5 => "cast",
        >= 0x0046 and <= 0x0050 or 0x009a or 0x00a3 => "array_load",
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

    private static string InstructionTypeName(ushort opcode) => opcode switch
    {
        0x0015 or 0x0016 or 0x0017 or 0x0018 or 0x0019 or 0x001a or 0x001b or 0x001c or 0x001d or 0x001e or 0x001f or 0x0020 => "System.Int32",
        0x0021 => "System.Int64",
        0x0022 => "System.Single",
        0x0023 => "System.Double",
        0x0014 => "System.Object",
        0x0072 => "System.String",
        _ => "System.Object"
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
            return reader.GetString(reader.GetModuleDefinition().Name);
        var definition = reader.GetAssemblyDefinition();
        var name = reader.GetString(definition.Name);
        return $"{name}, Version={definition.Version}";
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
        _ => "System.Object"
    };

    public string GetSZArrayType(string elementType) => $"{elementType}[]";

    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => MetadataAnalysis.GetTypeDefinitionName(reader, handle);

    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => MetadataAnalysis.GetTypeReferenceName(reader, handle);

    public string GetTypeFromSpecification(MetadataReader reader, GenericContext genericContext, TypeSpecificationHandle handle, byte rawTypeKind) =>
        reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
}
