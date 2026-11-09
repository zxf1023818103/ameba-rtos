/* A PASN reader must see a complete old or new snapshot during replacement. */
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "../whc_host_linux/app/wifi_nan_utility/src/rtw_nan_api/nan_cache_file.h"

int main(void)
{
    char dir[] = "/tmp/nan-cache-test-XXXXXX", path[128];
    unsigned char record[500], readback[501];
    int status;
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/nik_cache", dir);
    memset(record, 1, sizeof(record));
    assert(!nan_cache_write_atomic(path, record, sizeof(record)));
    FILE *old = fopen(path, "rb");
    assert(old);
    memset(record, 2, sizeof(record));
    assert(!nan_cache_write_atomic(path, record, sizeof(record)));
    assert(fread(readback, 1, sizeof(readback), old) == sizeof(record));
    for (size_t i = 0; i < sizeof(record); ++i) assert(readback[i] == 1);
    fclose(old);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        for (unsigned i = 0; i < 300; ++i) {
            memset(record, (i % 253) + 1, sizeof(record));
            assert(!nan_cache_write_atomic(path, record, sizeof(record)));
        }
        _exit(0);
    }
    unsigned snapshots = 0;
    do {
        FILE *f = fopen(path, "rb");
        struct stat st;
        assert(f && !fstat(fileno(f), &st));
        assert((st.st_mode & 0777) == 0600);
        assert(fread(readback, 1, sizeof(readback), f) == sizeof(record));
        fclose(f);
        for (size_t i = 1; i < sizeof(record); ++i) assert(readback[i] == readback[0]);
        ++snapshots;
    } while (!waitpid(child, &status, WNOHANG));
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    unlink(path);
    rmdir(dir);
    printf("NIK cache: %u complete concurrent snapshots; retained reader unchanged; mode 0600\n", snapshots);
    return 0;
}
