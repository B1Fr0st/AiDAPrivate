using System;

namespace AiDA.C03.Corpus;

public static class ManagedFixture
{
    public static int Add(int left, int right) => left < 0 ? right - left : left + right;

    public static int GuardedDivide(int value, int divisor)
    {
        if (divisor == 0)
            throw new DivideByZeroException();
        return value / divisor;
    }
}
