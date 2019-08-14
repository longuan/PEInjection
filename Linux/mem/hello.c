#include <stdio.h>
#include <stdlib.h>

char *message = "Hello World!";

int main()
{
    while(getchar() != EOF)
    {
        printf("%s", message);
    }

    return 0;
}
