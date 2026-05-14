/* Regression test for the heap-buffer-overflow in make_sorted_dirlist().
 *
 * darkhttpd.c sizes its filename buffer as
 *
 *     xmalloc(strlen(path) + MAXNAMLEN + 1)
 *
 * and then sprintf()s "%s%s" of path and ent->d_name into it, guarded only by
 * an assert(strlen(ent->d_name) <= MAXNAMLEN). In release builds NDEBUG is
 * defined (see darkhttpd.c near line 30), so the assert is stripped, and on
 * filesystems whose runtime _PC_NAME_MAX exceeds the compile-time MAXNAMLEN
 * readdir() can hand back a longer name and the sprintf overruns the heap
 * allocation.
 *
 * We stub opendir/readdir/closedir before pulling in darkhttpd.c and hand the
 * code a single entry whose d_name is wider than MAXNAMLEN. To detect the
 * overflow without relying on AddressSanitizer (which is not always
 * available), we ship our own malloc/realloc/free shims via the linker's
 * --wrap mechanism: each allocation is over-sized by CANARY_LEN bytes filled
 * with a known pattern, and at free time we check that the tail of the user
 * region is still untouched. When sprintf writes past the requested
 * allocation, the canary gets stamped with the synthetic filename and the
 * test reports FAIL.
 *
 * The wrapper allocates CANARY_LEN extra bytes past the requested size so the
 * overflow stays inside the actual malloc chunk and does not corrupt
 * glibc's allocator metadata; CANARY_LEN is chosen comfortably larger than
 * the expected overflow size.
 *
 * Compile with:
 *   $CC -g -O2 test_dirlist_overflow.c \
 *     -Wl,--wrap=malloc,--wrap=realloc,--wrap=free \
 *     -o test_dirlist_overflow
 *
 * Without the fix: prints "FAIL: heap-buffer-overflow ..." and exits 1.
 * With the fix:    prints "PASS: ..." and exits 0.
 */

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* ---- malloc canary tracker ---- */

#define CANARY_LEN  1024u
#define CANARY_BYTE 0xA5u

extern void *__real_malloc(size_t);
extern void *__real_realloc(void *, size_t);
extern void  __real_free(void *);

struct slot {
    void *p;
    size_t sz;
};

#define MAX_ALLOCS 256
static struct slot allocs[MAX_ALLOCS];
static size_t alloc_count = 0;
static int overflow_seen = 0;

static void track(void *p, size_t sz) {
    if (p == NULL) return;
    memset((unsigned char *)p + sz, (int)CANARY_BYTE, CANARY_LEN);
    if (alloc_count < MAX_ALLOCS) {
        allocs[alloc_count].p = p;
        allocs[alloc_count].sz = sz;
        alloc_count++;
    }
}

/* Returns 1 if untouched (or untracked), 0 if the canary tripped. */
static int check_and_remove(void *p) {
    size_t i;
    if (p == NULL) return 1;
    for (i = 0; i < alloc_count; i++) {
        if (allocs[i].p == p) {
            unsigned char *c = (unsigned char *)p + allocs[i].sz;
            size_t j;
            for (j = 0; j < CANARY_LEN; j++) {
                if (c[j] != (unsigned char)CANARY_BYTE) {
                    overflow_seen = 1;
                    fprintf(stderr,
                        "heap-buffer-overflow: alloc size=%zu, "
                        "canary[%zu]=0x%02x (expected 0x%02x)\n",
                        allocs[i].sz, j, c[j],
                        (unsigned)CANARY_BYTE);
                    /* Keep going to count further damage? No — one is enough.
                     * Still, remove the slot so __real_free runs cleanly. */
                    break;
                }
            }
            allocs[i] = allocs[--alloc_count];
            return overflow_seen ? 0 : 1;
        }
    }
    return 1; /* untracked allocation, pass through */
}

void *__wrap_malloc(size_t sz) {
    void *p = __real_malloc(sz + CANARY_LEN);
    track(p, sz);
    return p;
}

void *__wrap_realloc(void *p, size_t sz) {
    if (p != NULL) (void)check_and_remove(p);
    void *q = __real_realloc(p, sz + CANARY_LEN);
    track(q, sz);
    return q;
}

void __wrap_free(void *p) {
    (void)check_and_remove(p);
    __real_free(p);
}

/* ---- redirect darkhttpd's opendir/readdir/closedir to our mocks ---- */

static DIR          *mock_opendir(const char *path);
static struct dirent *mock_readdir(DIR *dir);
static int           mock_closedir(DIR *dir);

#define opendir(p)  mock_opendir(p)
#define readdir(d)  mock_readdir(d)
#define closedir(d) mock_closedir(d)

#define main _main_disabled_
#include "../darkhttpd.c"
#undef main

#undef opendir
#undef readdir
#undef closedir

/* ---- synthetic dirent with d_name longer than MAXNAMLEN ----
 *
 * struct dirent declares d_name as char[256], but on Linux the storage
 * backing each readdir() entry is variable-length; glibc returns pointers
 * into a per-DIR buffer whose effective size is governed by d_reclen. We
 * mirror that by stashing the entry in a union whose tail extends past the
 * declared d_name field, so strlen(ent->d_name) returns more than MAXNAMLEN.
 */
static union {
    struct dirent ent;
    char raw[sizeof(struct dirent) + 4096];
} fake;

/* MAXNAMLEN + 256 is well past the documented bound but stays comfortably
 * inside CANARY_LEN of our over-allocation, so the overflow stamps the
 * canary without smashing the malloc chunk. */
#define LONG_NAME_LEN ((size_t)(MAXNAMLEN + 256))

static int readdir_calls;

static DIR *mock_opendir(const char *path) {
    (void)path;
    readdir_calls = 0;
    /* Any non-NULL sentinel; mock_readdir doesn't dereference it. */
    return (DIR *)(uintptr_t)1;
}

static struct dirent *mock_readdir(DIR *dir) {
    char *name;
    (void)dir;
    if (readdir_calls++ > 0)
        return NULL;
    memset(fake.raw, 0, sizeof(fake.raw));
    name = fake.raw + offsetof(struct dirent, d_name);
    memset(name, 'a', LONG_NAME_LEN);
    name[LONG_NAME_LEN] = '\0';
    return &fake.ent;
}

static int mock_closedir(DIR *dir) { (void)dir; return 0; }

int main(void) {
    struct dlent **list = NULL;
    /* Trailing slash matches how darkhttpd builds the path before the
     * "%s%s" sprintf. The exact path doesn't matter for the overflow; we
     * use /tmp/ to keep currname's prefix short and predictable. */
    ssize_t n = make_sorted_dirlist("/tmp/", &list);

    /* stat() of the fake path failed, so entries==0 is expected on the
     * fixed code path. We do not inspect n; we only care whether any
     * tracked allocation's canary was disturbed. */
    cleanup_sorted_dirlist(list, n);
    free(list);

    if (overflow_seen) {
        printf("FAIL: heap-buffer-overflow in make_sorted_dirlist "
               "(sprintf past xmalloc bound)\n");
        return 1;
    }
    printf("PASS: no heap-buffer-overflow detected (entries=%zd)\n", n);
    return 0;
}
/* vim:set tabstop=4 shiftwidth=4 expandtab tw=78: */
