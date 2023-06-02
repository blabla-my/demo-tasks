#include <stdio.h>

int fac(int x)
{
    int tmp;
    unsigned long next;
    static void *jumpTab[4] = {&&lab1, &&lab2, &&lab3, &&lab4};
    next = 4;
    goto *(jumpTab[next - 1]);
lab4:
    if (x == 1)
    {
        next = 3;
    }
    else
    {
        next = 2;
    }
    goto *(jumpTab[next - 1]);
lab3:
    return (1);
    goto *(jumpTab[next - 1]);
lab2:
    tmp = fac(x - 1);
    next = 1;
    goto *(jumpTab[next - 1]);
lab1:
    return (x * tmp);
    goto *(jumpTab[next - 1]);
}

int main() {
    int x = 0;
    scanf("Please input the argument: %d", &x);
    int y = fac(y);
    printf("The result is: %d", y);
    return 0;
}