using System.Security.Cryptography;
using System.Text;

namespace Aida.ManagedDecompiler;

internal static class Program
{
    private const string TransportSchema = "aida.c03.managed-cli.transport";
    private const string WorkerBuildId = "aida-managed-decompiler-worker-v3";
    private const string WorkerBuildHashMaterial = "aida-managed-decompiler-worker-build-v3|snapshot-bound-contract=4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6|tfm=net10.0|runtime=Microsoft.NETCore.App/10.0.9";

    private static async Task<int> Main(string[] arguments)
    {
        ActiveJob? activeJob = null;
        try
        {
            var options = WorkerStartupOptions.Parse(arguments);
            RuntimeIdentity.Establish(options.RuntimeManifestHash);
            var moduleBytes = AuthenticatedTransport.ReadModuleMapping(options.ModuleHandle, options.ModuleSize);
            MetadataAnalysis.EstablishModuleSnapshot(moduleBytes);
            var workerBinaryHash = AuthenticatedTransport.HashIdentityHandle(options.IdentityHandle);
            using var transport = AuthenticatedTransport.Establish(options);
            await SendHelloAsync(transport, workerBinaryHash).ConfigureAwait(false);

            var requestPayload = await transport.ReceivePayloadAsync(1, CancellationToken.None).ConfigureAwait(false);
            if (Encoding.UTF8.GetByteCount(requestPayload) > AuthenticatedTransport.MaximumPayloadBytes)
                throw new InvalidDataException("managed worker request exceeds the frame limit");
            var request = WorkerProtocol.Deserialize<WorkerRequest>(requestPayload);
            MetadataAnalysis.ValidateRequest(request);
            if (request.Sequence != 1)
                throw new InvalidDataException("managed worker request sequence does not match its authenticated frame");

            activeJob = new ActiveJob(request);
            var execution = RunJobAsync(activeJob);
            var cancellation = ReceiveCancellationAsync(transport, activeJob);
            var completed = await Task.WhenAny(execution, cancellation).ConfigureAwait(false);
            if (ReferenceEquals(completed, cancellation))
                await cancellation.ConfigureAwait(false);
            var responsePayload = await execution.ConfigureAwait(false);
            await transport.SendPayloadAsync(2, responsePayload, CancellationToken.None).ConfigureAwait(false);
            return 0;
        }
        catch
        {
            activeJob?.Cancellation.Cancel();
            return 1;
        }
        finally
        {
            activeJob?.Cancellation.Dispose();
            MetadataAnalysis.ReleaseModuleSnapshot();
        }
    }

    private static async Task SendHelloAsync(AuthenticatedTransport transport, string workerBinaryHash)
    {
        var buildHashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(WorkerBuildHashMaterial));
        string buildHash;
        try
        {
            buildHash = Convert.ToHexString(buildHashBytes).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buildHashBytes);
        }
        var hello = new WorkerTransportHello(
            TransportSchema,
            3,
            "hello",
            1,
            Convert.ToHexString(transport.Session.NonceHash).ToLowerInvariant(),
            Convert.ToHexString(transport.Session.ManifestHash).ToLowerInvariant(),
            RuntimeIdentity.ManifestHashHex,
            workerBinaryHash,
            RuntimeIdentity.DecompilerAssemblySha256,
            WorkerBuildId,
            buildHash);
        await transport.SendPayloadAsync(1, WorkerProtocol.Serialize(hello), CancellationToken.None).ConfigureAwait(false);
    }

    private static async Task ReceiveCancellationAsync(AuthenticatedTransport transport, ActiveJob job)
    {
        var payload = await transport.ReceivePayloadAsync(2, CancellationToken.None).ConfigureAwait(false);
        var cancellation = WorkerProtocol.Deserialize<WorkerCancellation>(payload);
        ValidateCancellation(cancellation, job.Request);
        job.Cancellation.Cancel();
    }

    private static async Task<string> RunJobAsync(ActiveJob job)
    {
        WorkerFailure? failure = null;
        string? payload = null;
        ResourceBudgetGuard? resources = null;
        using var deadline = new CancellationTokenSource();
        var deadlineMs = Math.Min(job.Request.Budget.MaxWallClockMs, (ulong)int.MaxValue);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(deadlineMs));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(job.Cancellation.Token, deadline.Token);
        try
        {
            resources = new ResourceBudgetGuard(job.Request.Budget);
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(linked.Token, resources.LimitToken);
            var candidate = await Task.Run(() => MetadataAnalysis.Analyze(job.Request, resources, bounded.Token), bounded.Token).ConfigureAwait(false);
            var candidatePayload = WorkerProtocol.Serialize(candidate);
            if (Encoding.UTF8.GetByteCount(candidatePayload) > AuthenticatedTransport.MaximumPayloadBytes)
                throw new ResourceLimitException(ResourceLimitKind.Memory);
            resources.Checkpoint(bounded.Token);
            await resources.CompleteAsync().ConfigureAwait(false);
            payload = candidatePayload;
        }
        catch (OperationCanceledException)
        {
            if (resources?.LimitExceeded == true)
            {
                failure = Failure(job.Request, "resource_limit", "managed_cli.resource_limit", false);
            }
            else
            {
                var deadlineExceeded = deadline.IsCancellationRequested && !job.Cancellation.IsCancellationRequested;
                failure = Failure(job.Request,
                    deadlineExceeded ? "deadline_exceeded" : "cancelled",
                    deadlineExceeded ? "managed_cli.deadline_exceeded" : "managed_cli.cancelled", false);
            }
        }
        catch (ResourceLimitException)
        {
            failure = Failure(job.Request, "resource_limit", "managed_cli.resource_limit", false);
        }
        catch (OutOfMemoryException)
        {
            failure = Failure(job.Request, "resource_limit", "managed_cli.resource_limit", false);
        }
        catch (RuntimeIntegrityException)
        {
            failure = Failure(job.Request, "worker_integrity_failure", "managed_cli.runtime_integrity", false);
        }
        catch (BadImageFormatException)
        {
            failure = Failure(job.Request, "malformed_metadata", "managed_cli.malformed_metadata", false);
        }
        catch (InvalidDataException)
        {
            failure = Failure(job.Request, "malformed_metadata", "managed_cli.malformed_metadata", false);
        }
        catch (FileNotFoundException)
        {
            failure = Failure(job.Request, "unresolved_reference", "managed_cli.unresolved_reference", false);
        }
        catch (UnauthorizedAccessException)
        {
            failure = Failure(job.Request, "provider_failure", "managed_cli.access_denied", false);
        }
        catch (IOException)
        {
            failure = Failure(job.Request, "provider_failure", "managed_cli.io_failure", true);
        }
        catch
        {
            failure = Failure(job.Request, "provider_failure", "managed_cli.provider_failure", false);
        }
        finally
        {
            if (resources is not null)
                await resources.DisposeAsync().ConfigureAwait(false);
        }

        return payload ?? WorkerProtocol.Serialize(failure!);
    }

    private static void ValidateCancellation(WorkerCancellation cancellation, WorkerRequest request)
    {
        if (!string.Equals(cancellation.Schema, WorkerProtocol.Schema, StringComparison.Ordinal) || cancellation.SchemaVersion != WorkerProtocol.Version ||
            !string.Equals(cancellation.Kind, "cancel", StringComparison.Ordinal) || cancellation.Sequence != request.Sequence + 1 ||
            !string.Equals(cancellation.RequestId, request.RequestId, StringComparison.Ordinal) ||
            !string.Equals(cancellation.RequestBindingHash, request.RequestBindingHash, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(cancellation.StableReason) || cancellation.StableReason.Length > 256 || cancellation.StableReason.Contains('\0'))
            throw new InvalidDataException("managed worker cancellation violates the authenticated request contract");
    }

    private static WorkerFailure Failure(WorkerRequest request, string code, string key, bool retryable)
    {
        return new WorkerFailure(
            WorkerProtocol.Schema,
            WorkerProtocol.Version,
            "failure",
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
            new[] { new WorkerDiagnostic("error", code, key, Array.Empty<string>(), null, 100, retryable, 1) });
    }

    private sealed class ActiveJob
    {
        internal ActiveJob(WorkerRequest request)
        {
            Request = request;
        }

        internal WorkerRequest Request { get; }
        internal CancellationTokenSource Cancellation { get; } = new();
    }
}
