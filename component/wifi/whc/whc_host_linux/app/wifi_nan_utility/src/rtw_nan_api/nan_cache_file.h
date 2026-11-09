#ifndef NAN_CACHE_FILE_H
#define NAN_CACHE_FILE_H

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* PASN reads this file in another process while discovery updates it.
 * Never truncate the live identity cache: publish a complete 0600 snapshot.
 */
static int nan_cache_write_atomic(const char *path, const void *data, size_t len)
{
    char tmp[PATH_MAX];
    const unsigned char *p = data;
    int fd, ok = 1;
    int n = snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
    if (n < 0 || n >= (int)sizeof(tmp)) return -1;
    fd = mkstemp(tmp);
    if (fd < 0) return -1;
    while (len) {
        ssize_t count = write(fd, p, len);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = 0; break; }
        p += count;
        len -= (size_t)count;
    }
    if (ok && fsync(fd)) ok = 0;
    if (close(fd)) ok = 0;
    if (ok && rename(tmp, path)) ok = 0;
    if (!ok) unlink(tmp);
    return ok ? 0 : -1;
}

#endif
