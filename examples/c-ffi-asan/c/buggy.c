/* Planted memory-safety bugs, compiled with -fsanitize=address. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Heap-buffer-overflow: write 1 byte past the end of a caller-sized alloc.
 * The caller supplies `len`; we allocate exactly that many bytes and then
 * write at index `len`, which is 1 past the right redzone boundary. */
void buggy_parse_hbo(const uint8_t *input, size_t len) {
    if (len == 0) return;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) return;
    memcpy(buf, input, len);
    buf[len] = 0x41;  /* one byte past end — right redzone */
    free(buf);
}

/* Use-after-free: free, then read. */
uint8_t buggy_parse_uaf(const uint8_t *input, size_t len) {
    if (len < 4) return 0;
    uint8_t *buf = (uint8_t *)malloc(16);
    if (!buf) return 0;
    memcpy(buf, input, 4);
    free(buf);
    return buf[0];  /* dereference after free */
}

/* Double-free. */
void buggy_parse_df(const uint8_t *input, size_t len) {
    (void)input;
    (void)len;
    void *p = malloc(32);
    if (!p) return;
    free(p);
    free(p);  /* double free */
}
