#include <stdio.h>
#include <time.h>

unsigned int gcd(unsigned int a, unsigned int b)
{
    while (b != 0)
    {
        unsigned int r = a % b;
        a = b;
        b = r;
    }
    return a;
}

int main()
{
    unsigned int a, b;
    printf("Enter the values of a: ");
    scanf("%u", &a);
    printf("Enter the values of b: ");
    scanf("%u",&b);

    clock_t start = clock();

    unsigned int g = gcd(a, b);

    clock_t end = clock();

    printf("GCD = %u\n", g);
    printf("Time = %f seconds\n",
           (double)(end - start) / CLOCKS_PER_SEC);

    return 0;
}
