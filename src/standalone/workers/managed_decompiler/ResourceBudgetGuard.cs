using System.Diagnostics;

namespace Aida.ManagedDecompiler;

internal enum ResourceLimitKind
{
    None,
    Cpu,
    Memory,
    ProviderIrNodes,
    MonitorFailure
}

internal sealed class ResourceLimitException : Exception
{
    internal ResourceLimitException(ResourceLimitKind kind)
        : base($"managed decompiler resource limit exceeded: {kind}")
    {
        Kind = kind;
    }

    internal ResourceLimitKind Kind { get; }
}

internal sealed class ResourceBudgetGuard : IAsyncDisposable
{
    private static readonly TimeSpan MonitorInterval = TimeSpan.FromMilliseconds(5);
    private readonly Process process;
    private readonly object sampleGate = new();
    private readonly long baselineCpuTicks;
    private readonly long maximumCpuTicks;
    private readonly ulong maximumMemoryBytes;
    private readonly CancellationTokenSource limitCancellation = new();
    private readonly CancellationTokenSource monitorCancellation = new();
    private readonly Task monitorTask;
    private int limitKind;
    private int checkpointCount;
    private int monitorStopped;
    private int disposed;

    internal ResourceBudgetGuard(WorkerBudget budget)
    {
        if (budget.MaxCpuMs == 0 || budget.MaxMemoryBytes == 0)
            throw new InvalidDataException("managed decompiler resource budget is invalid");
        maximumCpuTicks = budget.MaxCpuMs > (ulong)long.MaxValue / (ulong)TimeSpan.TicksPerMillisecond
            ? long.MaxValue
            : checked((long)budget.MaxCpuMs * TimeSpan.TicksPerMillisecond);
        maximumMemoryBytes = budget.MaxMemoryBytes;
        process = Process.GetCurrentProcess();
        process.Refresh();
        baselineCpuTicks = process.TotalProcessorTime.Ticks;
        monitorTask = MonitorAsync();
    }

    internal CancellationToken LimitToken => limitCancellation.Token;

    internal bool LimitExceeded => Volatile.Read(ref limitKind) != (int)ResourceLimitKind.None;

    internal ResourceLimitKind LimitKind => (ResourceLimitKind)Volatile.Read(ref limitKind);

    internal void Checkpoint(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if ((Interlocked.Increment(ref checkpointCount) & 63) == 1)
            SampleAndSignal();
        ThrowIfExceeded();
        cancellationToken.ThrowIfCancellationRequested();
    }

    internal void EnsureAllocationFits(ulong allocationBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var usage = CaptureUsage();
        if (usage.CpuTicks > maximumCpuTicks)
            Signal(ResourceLimitKind.Cpu);
        if (usage.MemoryBytes > maximumMemoryBytes || allocationBytes > maximumMemoryBytes ||
            usage.MemoryBytes > maximumMemoryBytes - allocationBytes)
            Signal(ResourceLimitKind.Memory);
        ThrowIfExceeded();
        cancellationToken.ThrowIfCancellationRequested();
    }

    internal async ValueTask CompleteAsync()
    {
        await StopMonitorAsync().ConfigureAwait(false);
        SampleAndSignal();
        ThrowIfExceeded();
    }

    internal void ThrowIfExceeded()
    {
        var kind = LimitKind;
        if (kind != ResourceLimitKind.None)
            throw new ResourceLimitException(kind);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        await StopMonitorAsync().ConfigureAwait(false);
        monitorCancellation.Dispose();
        limitCancellation.Dispose();
        process.Dispose();
    }

    private async Task MonitorAsync()
    {
        try
        {
            using var timer = new PeriodicTimer(MonitorInterval);
            while (await timer.WaitForNextTickAsync(monitorCancellation.Token).ConfigureAwait(false))
            {
                SampleAndSignal();
                if (LimitExceeded)
                    return;
            }
        }
        catch (OperationCanceledException) when (monitorCancellation.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            Signal(ResourceLimitKind.MonitorFailure);
        }
    }

    private async ValueTask StopMonitorAsync()
    {
        if (Interlocked.Exchange(ref monitorStopped, 1) == 0)
            monitorCancellation.Cancel();
        await monitorTask.ConfigureAwait(false);
    }

    private void SampleAndSignal()
    {
        try
        {
            var usage = CaptureUsage();
            if (usage.CpuTicks > maximumCpuTicks)
                Signal(ResourceLimitKind.Cpu);
            if (usage.MemoryBytes > maximumMemoryBytes)
                Signal(ResourceLimitKind.Memory);
        }
        catch (Exception)
        {
            Signal(ResourceLimitKind.MonitorFailure);
        }
    }

    private (long CpuTicks, ulong MemoryBytes) CaptureUsage()
    {
        lock (sampleGate)
        {
            process.Refresh();
            var elapsedTicks = Math.Max(0, process.TotalProcessorTime.Ticks - baselineCpuTicks);
            var privateBytes = ToUnsigned(process.PrivateMemorySize64);
            var workingSetBytes = ToUnsigned(process.WorkingSet64);
            var managedBytes = ToUnsigned(GC.GetTotalMemory(false));
            return (elapsedTicks, Math.Max(privateBytes, Math.Max(workingSetBytes, managedBytes)));
        }
    }

    private void Signal(ResourceLimitKind kind)
    {
        if (kind == ResourceLimitKind.None ||
            Interlocked.CompareExchange(ref limitKind, (int)kind, (int)ResourceLimitKind.None) != (int)ResourceLimitKind.None)
            return;
        limitCancellation.Cancel();
    }

    private static ulong ToUnsigned(long value) => value <= 0 ? 0 : checked((ulong)value);
}
