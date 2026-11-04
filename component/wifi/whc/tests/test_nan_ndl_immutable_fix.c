#include <assert.h>
#include <stdint.h>
#include <string.h>

uint8_t *__wrap_rtw_nan_ndl_attri_construct(
    uint8_t *, void *, uint8_t, uint8_t, uint32_t *);

/* Captured frame 1085's NDL body. The mocked native constructor supplies the
 * complete attribute, as the actual constructor does before the next TLV.
 */
static const uint8_t captured[] = {
    20,28,0, 0x3a,0x11,0,0x0e,
    0,0x20,0,8, 0xfc,0,0,0,0,0,0,0,
    0,0x20,0,8, 0,0,0,0,0xfc,0,0,0
};
static uint8_t native[128];
static unsigned native_size, calls;
static int wrong_cursor;

uint8_t *__real_rtw_nan_ndl_attri_construct(
    uint8_t *out, void *peer, uint8_t type, uint8_t status, uint32_t *length)
{
    (void)peer; (void)type; (void)status;
    ++calls;
    memcpy(out, native, native_size);
    *length += native_size;
    return out + native_size - wrong_cursor;
}

static void reset(void)
{
    memcpy(native, captured, sizeof(captured));
    native_size = sizeof(captured);
    wrong_cursor = 0;
}

static void unchanged(unsigned type, unsigned status)
{
    uint8_t buffer[256];
    uint32_t length = 37;
    memset(buffer, 0x5a, sizeof(buffer));
    uint8_t *end = __wrap_rtw_nan_ndl_attri_construct(
        buffer + 37, NULL, type, status, &length);
    assert(end == buffer + 37 + native_size - wrong_cursor);
    assert(length == 37 + native_size);
    assert(!memcmp(buffer + 37, native, native_size));
}

int main(void)
{
    uint8_t buffer[256];
    uint32_t length;
    uint8_t *end;
    /* Reproduce the captured response, then append the next real TLV. */
    reset(); memset(buffer, 0xa5, sizeof(buffer)); length = 37;
    end = __wrap_rtw_nan_ndl_attri_construct(buffer + 37, NULL, 1, 1, &length);
    assert(calls == 1 && end == buffer + 44 && length == 44);
    assert(!memcmp(buffer + 37, (uint8_t[]){20,4,0,0x3a,0x11,0,0x0c}, 7));
    memcpy(end, (uint8_t[]){21,3,0,0,0xff,0xff}, 6); length += 6;
    assert(buffer[37+3+buffer[38]] == 21 && length == 50);
    for (unsigned i=0; i<37; ++i) assert(buffer[i] == 0xa5);
    /* Other negotiation outcomes/types must keep native immutable entries. */
    for (unsigned type=0; type<4; ++type)
        for (unsigned status=0; status<3; ++status)
            if (type != 1 || status != 1) unchanged(type, status);
    /* Preserve optional fields before the schedule list. */
    for (unsigned flags=0; flags<4; ++flags) {
        reset(); unsigned n = (flags&1 ? 1:0) + (flags&2 ? 2:0);
        memmove(native+7+n, native+7, native_size-7);
        memset(native+7, 0x6b, n); native_size += n; native[1] += n;
        native[6] |= (flags&1 ? 1:0) | (flags&2 ? 16:0);
        length=0;
        end=__wrap_rtw_nan_ndl_attri_construct(buffer,NULL,1,1,&length);
        assert(length==7+n && end==buffer+length && buffer[1]==4+n);
        assert(buffer[6]==(native[6]&~2));
        for (unsigned i=0;i<n;++i) assert(buffer[7+i]==0x6b);
    }
    /* Fail closed on unexpected native layouts, never walk past an entry. */
    reset(); native[1]--; unchanged(1,1);
    reset(); native[0]=19; unchanged(1,1);
    reset(); native[4]=0x01; unchanged(1,1);
    reset(); native[6]&=~2; unchanged(1,1);
    reset(); native[10]=255; unchanged(1,1);
    reset(); wrong_cursor=1; unchanged(1,1);
    for (unsigned n=0;n<sizeof(captured);++n) {
        reset(); native_size=n; unchanged(1,1);
    }
    return 0;
}
