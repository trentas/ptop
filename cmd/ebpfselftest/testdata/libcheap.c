// libcheap.c is the planted workload of the selftest's libc heap case (#155).
//
// The selftest is a static Go binary, and a Go program allocates through the Go
// allocator, so it has no libc for the heap lane to probe. This program is the
// target instead. heap_libc.go compiles it at run time and passes every planted
// quantity as a -D define, so the numbers the grader expects have one source.
//
// It is driven over its standard streams:
//
//	stdout "ready\n"             libc is mapped: attach now
//	stdin  one byte              start
//	churn: CHURN_PER_TICK malloc+free pairs every 10ms, for CHURN_MS
//	stdout "churned <n> <ns>\n"  pairs made, and how long that took
//	retain: blocks held at known call sites
//	stdout "retained\n"
//	stdin  EOF                   exit, still holding every block
//
// Nothing here goes through stdio. printf allocates its buffer on first use,
// and a planted heap must have no allocation the grader did not plant.
//
// Every call site is its own non-inlined function, called from a loop in
// another function. A heap lane that names the CALLER of the function that
// called malloc then names the loop, not the site, and the grade says which.

#define _GNU_SOURCE
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#if !defined(CHURN_PER_TICK) || !defined(CHURN_MS) || !defined(CHURN_SIZE) ||       \
    !defined(RETAIN_MALLOC_N) || !defined(RETAIN_MALLOC_SIZE) ||                    \
    !defined(RETAIN_CALLOC_N) || !defined(RETAIN_CALLOC_NMEMB) ||                   \
    !defined(RETAIN_CALLOC_SIZE) || !defined(GROW_FROM) || !defined(GROW_TO) ||     \
    !defined(SPREAD_N) || !defined(SPREAD_SIZE)
#error "heap_libc.go passes every planted quantity as a -D define"
#endif

#define NOINLINE __attribute__((noinline))
#define TICK_NS  10000000L

void *kept_malloc[RETAIN_MALLOC_N];
void *kept_calloc[RETAIN_CALLOC_N];
void *grown;
void *kept_spread[12][SPREAD_N];

// The churn's block goes through a volatile, so the compiler cannot prove the
// malloc+free pair dead and drop it.
static void *volatile sink;

NOINLINE void churn_site(void) {
    sink = malloc(CHURN_SIZE);
    free(sink);
}

NOINLINE void retain_malloc(int i) { kept_malloc[i] = malloc(RETAIN_MALLOC_SIZE); }

NOINLINE void retain_calloc(int i) {
    kept_calloc[i] = calloc(RETAIN_CALLOC_NMEMB, RETAIN_CALLOC_SIZE);
}

// The first call is realloc(NULL, n), the idiom for "allocate or grow", and the
// block crosses glibc's mmap threshold on the way up: both paths run inside
// realloc without going through the realloc the caller sees.
NOINLINE void grow_realloc(void) {
    for (size_t n = GROW_FROM; n <= GROW_TO; n <<= 1)
        grown = realloc(grown, n);
}

// Twelve more sites than the named three, each holding the same amount, so the
// top list is cut and what it leaves out has to be accounted for.
#define SPREAD(k)                                                                    \
    NOINLINE void spread_##k(void) {                                                 \
        for (int i = 0; i < SPREAD_N; i++)                                           \
            kept_spread[k][i] = malloc(SPREAD_SIZE);                                 \
    }
SPREAD(0) SPREAD(1) SPREAD(2) SPREAD(3) SPREAD(4) SPREAD(5)
SPREAD(6) SPREAD(7) SPREAD(8) SPREAD(9) SPREAD(10) SPREAD(11)

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

// churn makes CHURN_PER_TICK pairs every tick, sleeping to an absolute deadline
// so a late tick does not push every later one.
NOINLINE static long churn(long long *took) {
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    long long start = now_ns(), end = start + CHURN_MS * 1000000LL;
    long n = 0;
    while (now_ns() < end) {
        for (int i = 0; i < CHURN_PER_TICK; i++) {
            churn_site();
            n++;
        }
        next.tv_nsec += TICK_NS;
        if (next.tv_nsec >= 1000000000L) {
            next.tv_sec++;
            next.tv_nsec -= 1000000000L;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }
    *took = now_ns() - start;
    return n;
}

NOINLINE static void retain(void) {
    for (int i = 0; i < RETAIN_MALLOC_N; i++)
        retain_malloc(i);
    for (int i = 0; i < RETAIN_CALLOC_N; i++)
        retain_calloc(i);
    grow_realloc();
    spread_0(); spread_1(); spread_2(); spread_3(); spread_4(); spread_5();
    spread_6(); spread_7(); spread_8(); spread_9(); spread_10(); spread_11();
}

static void say(const char *s) {
    size_t n = 0;
    while (s[n])
        n++;
    (void)!write(1, s, n);
}

// put appends v in decimal to buf at *at.
static void put(char *buf, size_t *at, long long v) {
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v > 0);
    while (n > 0)
        buf[(*at)++] = tmp[--n];
}

int main(void) {
    char c;
    say("ready\n");
    if (read(0, &c, 1) != 1)
        _exit(1);

    long long took = 0;
    long n = churn(&took);
    char line[64] = "churned ";
    size_t at = 8;
    put(line, &at, n);
    line[at++] = ' ';
    put(line, &at, took);
    line[at++] = '\n';
    line[at] = 0;
    say(line);

    retain();
    say("retained\n");

    while (read(0, &c, 1) > 0) {
    }
    _exit(0);
}
