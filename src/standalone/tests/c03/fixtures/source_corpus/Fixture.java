package aida.c03.corpus;

public final class Fixture {
    public static int add(int left, int right) {
        try {
            int result = left + right + bias;
            return result;
        } catch (ArithmeticException error) {
            return 0;
        }
    }

    public static int bias;
}
