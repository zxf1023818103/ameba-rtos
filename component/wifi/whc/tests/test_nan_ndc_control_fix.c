#include <assert.h>
#include <stdint.h>
#include <string.h>

uint8_t *__wrap_rtw_nan_ndc_attri_contruct(
    uint8_t *, void *, uint8_t, uint8_t, uint32_t *);

static uint8_t attribute[] = {
    19,15,0, 0,7,2,0xc1,0xd9,0xc0,0x5b, 0,0x18,0,4,2,0,0,0
};
static unsigned native_size = sizeof(attribute);
uint8_t *__real_rtw_nan_ndc_attri_contruct(
    uint8_t *out, void *peer, uint8_t type, uint8_t status, uint32_t *length)
{
    (void)peer; (void)type; (void)status;
    memcpy(out,attribute,native_size);
    *length += native_size;
    return out+native_size;
}

int main(void)
{
    uint8_t buffer[64];
    uint8_t expected[sizeof(attribute)];
    uint32_t length;
    uint8_t *end;
    /* Only the reserved bits may change, including when Selected is zero. */
    const unsigned controls[] = {0x5b,0,1,0xff,0xfe,0x80,0x81};
    for (unsigned i=0;i<sizeof(controls)/sizeof(controls[0]);++i) {
        attribute[9]=controls[i];
        memcpy(expected,attribute,sizeof(expected));expected[9]&=1;
        memset(buffer,0xa5,sizeof(buffer));length=11;
        end=__wrap_rtw_nan_ndc_attri_contruct(buffer+11,NULL,1,1,&length);
        assert(end==buffer+11+sizeof(attribute) && length==11+sizeof(attribute));
        assert(!memcmp(buffer+11,expected,sizeof(expected)));
        for(unsigned j=0;j<11;++j)assert(buffer[j]==0xa5);
        for(unsigned j=length;j<sizeof(buffer);++j)assert(buffer[j]==0xa5);
    }
    /* No attribute / truncated native output must remain untouched. */
    attribute[9]=0x5b;
    for(native_size=0;native_size<sizeof(attribute);++native_size) {
        length=0;
        end=__wrap_rtw_nan_ndc_attri_contruct(buffer,NULL,0,2,&length);
        assert(end==buffer+native_size && length==native_size);
        assert(!memcmp(buffer,attribute,native_size));
    }
    attribute[0]=18;length=0;
    end=__wrap_rtw_nan_ndc_attri_contruct(buffer,NULL,1,1,&length);
    assert(end==buffer+native_size && !memcmp(buffer,attribute,native_size));
    return 0;
}
