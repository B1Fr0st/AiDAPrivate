namespace Aida.C03.ManagedCliFixtures;

public static class ExceptionAndTokenFixture
{
    public static int Filtered(int value)
    {
        try
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));
            return checked(100 / value);
        }
        catch (DivideByZeroException)
        {
            return 0;
        }
        catch (ArgumentOutOfRangeException exception) when (exception.ParamName == nameof(value))
        {
            return -1;
        }
        finally
        {
            GC.KeepAlive(value);
        }
    }

    public static T Echo<T>(T value) where T : class => value;

    public static int SwitchAndThrow(int value)
    {
        return value switch
        {
            0 => 0,
            1 => 1,
            _ when value > 8 => throw new InvalidOperationException(value.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            _ => -1
        };
    }
}
