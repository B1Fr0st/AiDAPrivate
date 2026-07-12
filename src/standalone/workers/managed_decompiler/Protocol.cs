using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aida.ManagedDecompiler;

internal static class WorkerProtocol
{
    internal const string Schema = "aida.c03.managed-cli.worker";
    internal const int Version = 1;
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 64
    };

    internal static T Deserialize<T>(string line)
    {
        var value = JsonSerializer.Deserialize<T>(line, JsonOptions);
        return value ?? throw new InvalidOperationException("worker message is empty");
    }

    internal static string Serialize<T>(T value) => JsonSerializer.Serialize(value, JsonOptions);
}

internal sealed record WorkerRequest(
    string Schema,
    int SchemaVersion,
    string Kind,
    ulong Sequence,
    string RequestId,
    string ModulePath,
    string ModuleHash,
    uint MetadataToken,
    ulong WorkspaceGeneration,
    string OfflineLockHash,
    WorkerBudget Budget,
    WorkerProviderExpectation Provider);

internal sealed record WorkerCancellation(
    string Schema,
    int SchemaVersion,
    string Kind,
    ulong Sequence,
    string RequestId,
    string StableReason);

internal sealed record WorkerBudget(
    string Profile,
    ulong MaxWallClockMs,
    ulong MaxCpuMs,
    ulong MaxMemoryBytes,
    ulong MaxProviderIrNodes);

internal sealed record WorkerProviderExpectation(
    string Version,
    string DecompilerAssemblyHash,
    string WorkerBuildId,
    string WorkerBuildHash);

internal sealed record WorkerIdentity(
    string AssemblyIdentity,
    string ModuleName,
    string DeclaringType,
    string MethodName,
    string MethodSignature,
    uint GenericArity);

internal sealed record WorkerSource(string Text, string Sha256);

internal sealed record WorkerTypeNode(
    ulong Id,
    string Kind,
    string CanonicalName,
    string DisplayName,
    ulong? ByteSize,
    uint Alignment,
    bool Signed,
    byte Confidence);

internal sealed record WorkerTypeEdge(
    ulong SourceTypeId,
    ulong TargetTypeId,
    string Kind,
    string StableName,
    ulong? ByteOffset,
    uint Ordinal,
    byte Confidence);

internal sealed record WorkerTypeGraph(ulong Revision, IReadOnlyList<WorkerTypeNode> Nodes, IReadOnlyList<WorkerTypeEdge> Edges);

internal sealed record WorkerIrValue(
    ulong Id,
    string Opcode,
    ulong TypeId,
    IReadOnlyList<ulong> OperandIds,
    string StableImmediate,
    string StableSymbol,
    int IlOffset,
    uint MetadataToken,
    byte Confidence,
    string Provenance);

internal sealed record WorkerIrBlock(
    ulong Id,
    IReadOnlyList<ulong> PredecessorIds,
    IReadOnlyList<ulong> SuccessorIds,
    IReadOnlyList<ulong> ExceptionSuccessorIds,
    IReadOnlyList<WorkerIrValue> Values,
    int StartOffset);

internal sealed record WorkerIr(ulong EntryBlockId, IReadOnlyList<WorkerIrBlock> Blocks);

internal sealed record WorkerUnknown(string Reason, string StableToken, int IlOffset, uint MetadataToken, byte Confidence, string Provenance);

internal sealed record WorkerDiagnostic(string Severity, string Code, string Key, IReadOnlyList<string> Args, int? IlOffset, byte Confidence, bool Retryable, uint Ordinal);

internal sealed record WorkerProvider(string Version, string DecompilerAssemblyHash);

internal sealed record WorkerTokenMap(
    uint Token,
    string StableIdentity,
    string DeclaringType,
    string MethodName,
    string MethodSignature,
    uint GenericArity,
    bool IsAsync,
    bool IsIterator,
    bool HasExceptionRegions);

internal sealed record WorkerResult(
    string Schema,
    int SchemaVersion,
    string Kind,
    ulong Sequence,
    string RequestId,
    string ModuleHash,
    uint MetadataToken,
    string OfflineLockHash,
    WorkerProvider Provider,
    WorkerIdentity Identity,
    WorkerSource Source,
    IReadOnlyList<WorkerTokenMap> TokenMap,
    WorkerTypeGraph TypeGraph,
    WorkerIr Ir,
    IReadOnlyList<WorkerUnknown> Unknowns,
    IReadOnlyList<WorkerDiagnostic> Diagnostics);

internal sealed record WorkerFailure(
    string Schema,
    int SchemaVersion,
    string Kind,
    ulong Sequence,
    string RequestId,
    string ModuleHash,
    uint MetadataToken,
    string OfflineLockHash,
    IReadOnlyList<WorkerDiagnostic> Diagnostics);
