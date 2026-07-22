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
        AuthenticatedTransport? transport = null;
        var startupStage = "options";
        var helloStarted = false;
        try
        {
            var options = WorkerStartupOptions.Parse(arguments);
            startupStage = "transport";
            transport = AuthenticatedTransport.Establish(options);
            startupStage = "runtime_identity";
            RuntimeIdentity.Establish(options.RuntimeManifestHash);
            startupStage = "module_mapping";
            var moduleBytes = AuthenticatedTransport.ReadModuleMapping(options.ModuleHandle, options.ModuleSize);
            startupStage = "module_snapshot";
            MetadataAnalysis.EstablishModuleSnapshot(moduleBytes);
            startupStage = "worker_identity";
            var workerBinaryHash = AuthenticatedTransport.HashIdentityHandle(options.IdentityHandle);
            startupStage = "hello";
            helloStarted = true;
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
        catch (Exception exception)
        {
            activeJob?.Cancellation.Cancel();
            if (transport is not null && !helloStarted)
            {
                try
                {
                    SendStartupFailure(transport, startupStage, exception);
                }
                catch
                {
                }
            }
            return 1;
        }
        finally
        {
            transport?.Dispose();
            activeJob?.Cancellation.Dispose();
            MetadataAnalysis.ReleaseModuleSnapshot();
        }
    }

    private static void SendStartupFailure(AuthenticatedTransport transport, string stage,
        Exception exception)
    {
        var failure = new WorkerTransportStartupFailure(
            TransportSchema,
            3,
            "startup_failure",
            1,
            Convert.ToHexString(transport.Session.NonceHash).ToLowerInvariant(),
            stage,
            StartupFailureCode(exception),
            exception is IOException);
        transport.SendStartupFailurePayload(WorkerProtocol.Serialize(failure));
    }

    private static string StartupFailureCode(Exception exception) => exception switch
    {
        RuntimeIntegrityException integrity => integrity.Message switch
        {
            "managed runtime identity is not established" => "identity_not_established",
            "managed runtime manifest identity is invalid" => "runtime_manifest_identity",
            "managed worker process path is unavailable" => "process_path_unavailable",
            "managed worker package path is invalid" => "package_path_invalid",
            "managed worker package root is invalid" => "package_root_invalid",
            "managed worker apphost identity is invalid" => "apphost_identity",
            "managed worker cannot execute from a repository dependency root" => "repository_dependency_root",
            "managed worker DOTNET_ROOT is not app-local" => "dotnet_root",
            "managed runtime manifest package size is invalid" => "runtime_manifest_size",
            "managed worker loaded assembly paths are not app-local" => "loaded_assembly_path",
            "managed framework dependency copies do not match the loaded runtime" => "framework_dependency_hash",
            "managed worker framework identity is invalid" => "framework_identity",
            "managed worker AppContainer token cannot be opened" => "appcontainer_token_open",
            "managed worker AppContainer token size is invalid" => "appcontainer_token_size",
            "managed worker AppContainer token query failed" => "appcontainer_token_query",
            "managed worker AppContainer SID is invalid" => "appcontainer_sid",
            "managed worker AppContainer profile is unavailable" => "appcontainer_profile",
            "managed worker AppContainer profile cannot be accessed" => "appcontainer_profile_access",
            "managed worker AppContainer LOCALAPPDATA is not profile-bound" => "appcontainer_localappdata",
            "managed worker AppContainer TEMP is not profile-bound" => "appcontainer_temp",
            "managed worker AppContainer environment is not profile-bound" => "appcontainer_environment",
            "managed worker environment exceeds its minimal allowlist" => "environment_allowlist",
            "managed worker environment violates app-local runtime policy" => "environment_policy",
            "managed worker Windows environment is not minimal" => "windows_environment",
            "managed worker environment contains a forbidden host override" => "forbidden_host_override",
            "managed runtime manifest hash does not match startup identity" => "runtime_manifest_hash",
            "managed runtime manifest digest is invalid" => "runtime_manifest_digest",
            "managed decompiler assembly hash mismatch" => "provider_hash",
            "managed runtime identity was already established" => "identity_reentry",
            "managed runtime identity is unavailable" => "identity_unavailable",
            "managed runtime package root is unavailable" => "package_root_unavailable",
            "managed runtime identity locks are unavailable" => "identity_locks",
            "managed runtime identity changed after startup" => "identity_changed",
            "managed runtime package root changed after startup" => "package_root_changed",
            "managed runtime file is unavailable" => "runtime_file_unavailable",
            "managed runtime directory is unavailable" => "runtime_directory_unavailable",
            "managed runtime root directory identity is invalid" => "runtime_root_identity",
            "managed runtime path escapes its trusted root" => "path_escape",
            "managed runtime path contains a reparse component" => "reparse_path",
            _ => "runtime_integrity"
        },
        InvalidDataException => "invalid_data",
        BadImageFormatException => "bad_image",
        UnauthorizedAccessException => "access_denied",
        IOException => "io_failure",
        OutOfMemoryException => "resource_limit",
        _ => "unexpected"
    };

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
        catch (BadImageFormatException exception)
        {
            failure = Failure(job.Request, "malformed_metadata", "managed_cli.malformed_metadata", false,
                MalformedMetadataArguments("bad_image", exception.Message));
        }
        catch (InvalidDataException exception)
        {
            failure = Failure(job.Request, "malformed_metadata", "managed_cli.malformed_metadata", false,
                MalformedMetadataArguments("invalid_data", exception.Message));
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

    private static IReadOnlyList<string> MalformedMetadataArguments(string category, string message)
    {
        const int maximumMessageLength = 1024;
        var bounded = message.Replace("\0", string.Empty, StringComparison.Ordinal);
        if (bounded.Length > maximumMessageLength)
        {
            bounded = bounded[..maximumMessageLength];
            if (char.IsHighSurrogate(bounded[^1]))
                bounded = bounded[..^1];
        }
        return new[] { category, bounded };
    }

    private static WorkerFailure Failure(WorkerRequest request, string code, string key, bool retryable,
        IReadOnlyList<string>? arguments = null)
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
            new[] { new WorkerDiagnostic("error", code, key, arguments ?? Array.Empty<string>(), null, 100, retryable, 1) });
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

    private sealed record WorkerTransportStartupFailure(
        string Schema,
        int SchemaVersion,
        string Kind,
        ulong Sequence,
        string SessionNonceHash,
        string Stage,
        string Code,
        bool Retryable);
}
