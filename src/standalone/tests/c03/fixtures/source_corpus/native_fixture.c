#include <stdint.h>

int32_t fixture_add(int32_t left, int32_t right)
{
    if (left < 0)
        return right - left;
    return left + right;
}

int32_t fixture_dispatch(int32_t selector)
{
    switch (selector) {
    case 0: return fixture_add(1, 2);
    case 1: return fixture_add(-1, 2);
    default: return 0;
    }
}
