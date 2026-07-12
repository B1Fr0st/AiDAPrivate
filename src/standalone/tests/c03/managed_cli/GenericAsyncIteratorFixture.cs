using System.Runtime.CompilerServices;

namespace Aida.C03.ManagedCliFixtures;

public interface IProjection<in TInput, out TOutput>
{
    TOutput Project(TInput input);
}

public sealed class GenericAsyncIteratorFixture<TValue> where TValue : notnull
{
    private readonly IProjection<TValue, string> projection;

    public GenericAsyncIteratorFixture(IProjection<TValue, string> projection)
    {
        this.projection = projection;
    }

    public async Task<string> ComposeAsync<TPrefix>(TPrefix prefix, TValue value, CancellationToken cancellationToken)
        where TPrefix : IFormattable
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        return $"{prefix}:{projection.Project(value)}";
    }

    public async IAsyncEnumerable<string> StreamAsync(
        IEnumerable<TValue> values,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var value in values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return projection.Project(value);
        }
    }

    public IEnumerable<string> Stream(IEnumerable<TValue> values)
    {
        foreach (var value in values)
            yield return projection.Project(value);
    }
}
