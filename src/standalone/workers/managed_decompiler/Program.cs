using System.Text;
using System.Text.Json;

namespace Aida.ManagedDecompiler;

internal static class Program
{
    private const int MaximumWireBytes = 16 * 1024 * 1024;
    private static readonly object ActiveGate = new();
    private static readonly SemaphoreSlim OutputGate = new(1, 1);
    private static ActiveJob? activeJob;

    private static async Task<int> Main(string[] arguments)
    {
        if (arguments.Length != 4 || !string.Equals(arguments[0], "--offline-package-root", StringComparison.Ordinal) ||
            !string.Equals(arguments[2], "--module-handle", StringComparison.Ordinal))
            return 2;
        try
        {
            OfflinePackageLock.EstablishStartupGate(arguments[1]);
            MetadataAnalysis.EstablishModuleHandle(arguments[3]);
        }
        catch (Exception)
        {
            return 1;
        }

        var jobs = new List<Task>();
        string? line;
        while ((line = await Console.In.ReadLineAsync().ConfigureAwait(false)) is not null)
        {
            if (line.Length == 0 || Encoding.UTF8.GetByteCount(line) > MaximumWireBytes)
            {
                await WriteLineAsync(WorkerProtocol.Serialize(Failure(0, string.Empty, string.Empty, 0, "invalid_contract", "managed_cli.message_size", 100, false))).ConfigureAwait(false);
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(line);
                if (!document.RootElement.TryGetProperty("kind", out var kindElement) || kindElement.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("worker message kind is absent");
                var kind = kindElement.GetString();
                if (string.Equals(kind, "decompile", StringComparison.Ordinal))
                {
                    var request = WorkerProtocol.Deserialize<WorkerRequest>(line);
                    MetadataAnalysis.ValidateRequest(request);
                    var job = new ActiveJob(request);
                    lock (ActiveGate)
                    {
                        if (activeJob is not null)
                            throw new InvalidOperationException("managed decompiler worker accepts one active job");
                        activeJob = job;
                    }
                    jobs.Add(RunJobAsync(job));
                }
                else if (string.Equals(kind, "cancel", StringComparison.Ordinal))
                {
                    var cancellation = WorkerProtocol.Deserialize<WorkerCancellation>(line);
                    ValidateCancellation(cancellation);
                    ActiveJob? job;
                    lock (ActiveGate)
                        job = activeJob;
                    if (job is not null && string.Equals(job.Request.RequestId, cancellation.RequestId, StringComparison.Ordinal))
                        job.Cancellation.Cancel();
                }
                else
                {
                    throw new InvalidDataException("worker message kind is unsupported");
                }
            }
            catch (Exception)
            {
                await WriteLineAsync(WorkerProtocol.Serialize(Failure(0, string.Empty, string.Empty, 0, "invalid_contract", "managed_cli.request_rejected", 100, false))).ConfigureAwait(false);
            }
        }

        await Task.WhenAll(jobs).ConfigureAwait(false);
        return 0;
    }

    private static async Task RunJobAsync(ActiveJob job)
    {
        WorkerResult? result = null;
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
            if (Encoding.UTF8.GetByteCount(candidatePayload) > MaximumWireBytes)
                throw new ResourceLimitException(ResourceLimitKind.Memory);
            resources.Checkpoint(bounded.Token);
            await resources.CompleteAsync().ConfigureAwait(false);
            result = candidate;
            payload = candidatePayload;
        }
        catch (OperationCanceledException)
        {
            if (resources?.LimitExceeded == true)
            {
                failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                    "resource_limit", "managed_cli.resource_limit", 100, false);
            }
            else
            {
                var deadlineExceeded = deadline.IsCancellationRequested && !job.Cancellation.IsCancellationRequested;
                failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                    deadlineExceeded ? "deadline_exceeded" : "cancelled",
                    deadlineExceeded ? "managed_cli.deadline_exceeded" : "managed_cli.cancelled", 100, false);
            }
        }
        catch (ResourceLimitException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "resource_limit", "managed_cli.resource_limit", 100, false);
        }
        catch (OutOfMemoryException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "resource_limit", "managed_cli.resource_limit", 100, false);
        }
        catch (OfflineIntegrityException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "worker_integrity_failure", "managed_cli.offline_integrity", 100, false);
        }
        catch (BadImageFormatException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "malformed_metadata", "managed_cli.malformed_metadata", 100, false);
        }
        catch (InvalidDataException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "malformed_metadata", "managed_cli.malformed_metadata", 100, false);
        }
        catch (FileNotFoundException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "unresolved_reference", "managed_cli.unresolved_reference", 100, false);
        }
        catch (UnauthorizedAccessException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "provider_failure", "managed_cli.access_denied", 100, false);
        }
        catch (IOException)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "provider_failure", "managed_cli.io_failure", 100, true);
        }
        catch (Exception)
        {
            failure = Failure(job.Request.Sequence, job.Request.RequestId, job.Request.ModuleHash, job.Request.MetadataToken,
                "provider_failure", "managed_cli.provider_failure", 100, false);
        }
        finally
        {
            if (resources is not null)
                await resources.DisposeAsync().ConfigureAwait(false);
            lock (ActiveGate)
            {
                if (ReferenceEquals(activeJob, job))
                    activeJob = null;
            }
        }

        await WriteLineAsync(payload ?? WorkerProtocol.Serialize(result ?? failure!)).ConfigureAwait(false);
    }

    private static void ValidateCancellation(WorkerCancellation cancellation)
    {
        if (!string.Equals(cancellation.Schema, WorkerProtocol.Schema, StringComparison.Ordinal) || cancellation.SchemaVersion != WorkerProtocol.Version ||
            !string.Equals(cancellation.Kind, "cancel", StringComparison.Ordinal) || cancellation.Sequence == 0 ||
            string.IsNullOrWhiteSpace(cancellation.RequestId) || cancellation.RequestId.Length > 128 || cancellation.RequestId.Contains('\0') ||
            string.IsNullOrWhiteSpace(cancellation.StableReason) || cancellation.StableReason.Length > 256 || cancellation.StableReason.Contains('\0'))
            throw new InvalidDataException("worker cancellation violates the offline contract");
    }

    private static WorkerFailure Failure(
        ulong sequence,
        string requestId,
        string moduleHash,
        uint metadataToken,
        string code,
        string key,
        byte confidence,
        bool retryable)
    {
        return new WorkerFailure(
            WorkerProtocol.Schema,
            WorkerProtocol.Version,
            "failure",
            sequence,
            requestId,
            moduleHash,
            metadataToken,
            OfflinePackageLock.ManifestHashHex,
            new[] { new WorkerDiagnostic("error", code, key, Array.Empty<string>(), null, confidence, retryable, 1) });
    }

    private static async Task WriteLineAsync(string value)
    {
        await OutputGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await Console.Out.WriteLineAsync(value).ConfigureAwait(false);
            await Console.Out.FlushAsync().ConfigureAwait(false);
        }
        finally
        {
            OutputGate.Release();
        }
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
