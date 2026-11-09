// Real libsrt loopback test: a new viewer must replace a still-connected peer
// without waiting for its three-second idle timeout or draining queued video.
#define main camera_program_main
#include "../nan_test/ubuntu-core/camera-srt.cpp"
#undef main
#include <cassert>
int main() {
    assert(srt_startup() == 0);
    SRTSOCKET server = srt_create_socket();
    option(server, SRTO_TRANSTYPE, SRTT_LIVE);
    option(server, SRTO_SENDER, true);
    option(server, SRTO_PEERLATENCY, 150);
    option(server, SRTO_RCVSYN, false);
    option(server, SRTO_LINGER, linger{0, 0});
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(srt_bind(server, (sockaddr *)&a, sizeof(a)) == 0);
    int length = sizeof(a);
    assert(srt_getsockname(server, (sockaddr *)&a, &length) == 0);
    assert(srt_listen(server, 2) == 0);
    int poller = srt_epoll_create(), events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
    assert(srt_epoll_add_usock(poller, server, &events) == 0);
    SRTSOCKET one = srt_create_socket();
    option(one, SRTO_TRANSTYPE, SRTT_LIVE);
    option(one, SRTO_TSBPDMODE, true);
    option(one, SRTO_RCVLATENCY, 150);
    assert(srt_connect(one, (sockaddr *)&a, sizeof(a)) == 0);
    SRTSOCKET peer = SRT_INVALID_SOCK;
    assert(accept_latest(poller, server, peer, 1000));
    auto old = peer;
    assert(srt_getsockstate(old) == SRTS_CONNECTED);
    assert(!accept_latest(poller, server, peer, 0));
    assert(peer == old);
    SRTSOCKET two = srt_create_socket();
    option(two, SRTO_TRANSTYPE, SRTT_LIVE);
    option(two, SRTO_TSBPDMODE, true);
    option(two, SRTO_RCVLATENCY, 150);
    assert(srt_connect(two, (sockaddr *)&a, sizeof(a)) == 0);
    auto began = now_us(CLOCK_MONOTONIC);
    assert(accept_latest(poller, server, peer, 1000));
    assert(peer != old && srt_getsockstate(peer) == SRTS_CONNECTED);
    assert(now_us(CLOCK_MONOTONIC) - began < 500000);
    char data[1316] = "new viewer frame";
    // Live SRT transports a burst of messages, as does multipart MJPEG.
    for (int i = 0; i < 8; ++i) assert(srt_sendmsg(peer, data, sizeof(data), -1, 0) == sizeof(data));
    char reply[2048]; option(two, SRTO_RCVTIMEO, 200);
    int received = 0;
    auto deadline = now_us(CLOCK_MONOTONIC) + 2000000;
    do {
        received = srt_recvmsg(two, reply, sizeof(reply));
        if (received == int(sizeof(data))) break;
    } while (now_us(CLOCK_MONOTONIC) < deadline);
    if (received != sizeof(data)) fprintf(stderr, "handover receive=%d error=%s peer=%d caller=%d\n",
        received, srt_getlasterror_str(), srt_getsockstate(peer), srt_getsockstate(two));
    assert(received == sizeof(data));
    assert(memcmp(data, reply, sizeof(data)) == 0);
    srt_close(peer); srt_close(one); srt_close(two); srt_close(server);
    srt_epoll_release(poller); srt_cleanup();
}
