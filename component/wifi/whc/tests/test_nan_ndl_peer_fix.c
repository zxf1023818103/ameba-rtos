#include <assert.h>
#include <stdint.h>
#include <string.h>
int green2_nan_ndl_keep_peer(const uint8_t *,const uint8_t *,size_t,unsigned);
const uint8_t *green2_nan_ndp_request_attr(const uint8_t *,size_t);
int green2_nan_ndp_confirm_pending(const uint8_t *,const uint8_t *);

static void test_duplicate_request(void) {
    uint8_t frame[64]={0},entry[436]={0};
    const uint8_t *a;
    frame[31]=16;frame[32]=11;frame[34]=7;frame[43]=1;
    memcpy(frame+37,"abcdef",6);
    a=green2_nan_ndp_request_attr(frame,45);
    assert(a==frame+31);
    entry[428]=4;entry[11]=7;entry[20]=1;memcpy(entry+14,"abcdef",6);
    assert(green2_nan_ndp_confirm_pending(entry,a));
    entry[428]=0;assert(!green2_nan_ndp_confirm_pending(entry,a));entry[428]=4;
    entry[11]++;assert(!green2_nan_ndp_confirm_pending(entry,a));entry[11]--;
    entry[20]++;assert(!green2_nan_ndp_confirm_pending(entry,a));entry[20]--;
    entry[14]^=1;assert(!green2_nan_ndp_confirm_pending(entry,a));entry[14]^=1;
    assert(!green2_nan_ndp_confirm_pending(NULL,a));
    assert(!green2_nan_ndp_confirm_pending(entry,NULL));
    for(size_t n=0;n<45;n++)assert(!green2_nan_ndp_request_attr(frame,n));
    memcpy(frame+45,frame+31,14);frame[45]=41;
    assert(green2_nan_ndp_request_attr(frame,59)==frame+45);
    frame[57]++;assert(!green2_nan_ndp_request_attr(frame,59));frame[57]--;
    frame[45]=16;assert(!green2_nan_ndp_request_attr(frame,59));frame[45]=41;
    frame[35]=1;assert(!green2_nan_ndp_request_attr(frame,59));frame[35]=0;
    frame[32]=10;assert(!green2_nan_ndp_request_attr(frame,45));frame[32]=11;
    frame[43]=0;assert(!green2_nan_ndp_request_attr(frame,45));frame[43]=1;
    frame[59]=18;frame[60]=20;assert(!green2_nan_ndp_request_attr(frame,64));
    assert(!green2_nan_ndp_request_attr(NULL,45));
}
int main(void) {
    uint8_t peer[544]={0},frame[40]={0};
    const uint8_t header[]={9,9,0x50,0x6f,0x9a,0x18,5};
    const uint8_t mac[]={0x86,0x6d,0x49,0xaa,0xc9,0x54};
    frame[0]=0xd0;frame[1]=0x40;frame[4]=0;memcpy(frame+10,mac,6);
    memcpy(frame+24,header,7);memcpy(peer+67,mac,6);
    peer[177]=0x40;peer[388]=1;
    assert(green2_nan_ndl_keep_peer(peer,frame,31,5));
    for(size_t n=0;n<31;n++)assert(!green2_nan_ndl_keep_peer(peer,frame,n,5));
    frame[1]=0;assert(!green2_nan_ndl_keep_peer(peer,frame,31,5));frame[1]=0x40;
    frame[10]^=2;assert(!green2_nan_ndl_keep_peer(peer,frame,31,5));frame[10]^=2;
    peer[388]=0;assert(!green2_nan_ndl_keep_peer(peer,frame,31,5));peer[388]=1;
    peer[177]=0;assert(!green2_nan_ndl_keep_peer(peer,frame,31,5));peer[177]=0x40;
    frame[4]=1;assert(!green2_nan_ndl_keep_peer(peer,frame,31,5));frame[4]=0;
    frame[30]=6;assert(!green2_nan_ndl_keep_peer(peer,frame,31,5));
    assert(green2_nan_ndl_keep_peer(0,0,0,6)); /* original non-request branch */
    assert(!green2_nan_ndl_keep_peer(0,frame,31,5));
    assert(!green2_nan_ndl_keep_peer(peer,0,31,5));
    test_duplicate_request();
    return 0;
}
