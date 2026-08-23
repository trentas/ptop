// Fixture for DWARF line resolution. The line numbers below are asserted by
// dwarf_test.go — adding lines above a marked function will break the test,
// which is the point: it proves the line came from the debug info and not from
// a coincidence.
#include <stdlib.h>

void *alloc_small(void) {
    return malloc(128); /* LINE:alloc_small_body */
}

void *alloc_big(void) {
    return malloc(256 * 1024); /* LINE:alloc_big_body */
}

int main(void) {
    void *a = alloc_small();
    void *b = alloc_big();
    free(a);
    free(b);
    return 0;
}
