#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    char buf[8];
    strcpy(buf, "this string is too long");  /* 缓冲区溢出：25字节 > 8字节 */

    int *p = malloc(sizeof(int));
    free(p);
    *p = 42;                                 /* 释放后使用（UAF） */

    printf("%s %d\n", buf, *p);
    return 0;
}