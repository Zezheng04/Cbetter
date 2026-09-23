/* tests/smoke.c —— 每个函数一条确定触发的告警 */
#include <stdlib.h>
#include <string.h>

int null_deref(void) {
    int *p = 0;
    return *p;                                  /* 期望 CWE-476 */
}

int div_zero(int a) {
    int b = 0;
    return a / b;                               /* 期望 CWE-369 */
}

void oob_write(void) {
    char buf[16];
    memcpy(buf, "0123456789ABCDEFGHIJKLMN", 25); /* 期望缓冲区越界族 */
}

void double_free(void) {
    char *p = malloc(16);
    free(p);
    free(p);                                     /* 期望 CWE-415 */
}