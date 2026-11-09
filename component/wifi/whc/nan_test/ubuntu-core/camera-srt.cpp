// Native V4L2 JPEG -> SRT multipart. No decoder or encoder is involved.
// Capture never waits for the network: four driver buffers, one latest frame.
#include <srt/srt.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>
#include <utility>
#include <atomic>

static_assert(std::atomic_bool::is_always_lock_free, "Signal flag must be lock-free");
static std::atomic_bool stopping{false};
static void stop(int) { stopping.store(true, std::memory_order_relaxed); }
static int64_t now_us(clockid_t clock) {
    timespec t{}; clock_gettime(clock, &t);
    return int64_t(t.tv_sec) * 1000000 + t.tv_nsec / 1000;
}
static void die(const char *what) { perror(what); exit(1); }
static int xioctl(int fd, unsigned long op, void *arg) {
    int r; do { r = ioctl(fd, op, arg); } while (r < 0 && errno == EINTR && !stopping);
    return r;
}
struct Frame {
    std::vector<char> jpeg;
    int64_t mono = 0, epoch = 0;
    uint32_t seq = 0;
};
static std::mutex mutex;
static std::condition_variable ready;
static Frame latest;
static uint64_t replaced = 0;
static bool send_part(SRTSOCKET sock, const char *data, size_t size) {
    while (size && !stopping) {
        int n = int(size > 1316 ? 1316 : size);
        if (srt_sendmsg(sock, data, n, -1, 0) != n) return false;
        data += n; size -= n;
    }
    return !stopping;
}
template<typename T> static void option(SRTSOCKET s, SRT_SOCKOPT opt, T value) {
    if (srt_setsockflag(s, opt, &value, sizeof(value)) == SRT_ERROR) {
        fprintf(stderr, "SRT option %d: %s\n", opt, srt_getlasterror_str()); exit(1);
    }
}
// This camera has one viewer. Poll the listener even while a previous viewer
// is streaming: after an App kill, its SRT peer can remain CONNECTED until the
// idle timer expires although a replacement has already finished handshaking.
static bool accept_latest(int poller, SRTSOCKET server, SRTSOCKET &peer, int timeout_ms) {
    SRT_EPOLL_EVENT event{};
    if (srt_epoll_uwait(poller, &event, 1, timeout_ms) <= 0) return false;
    SRTSOCKET incoming = srt_accept(server, nullptr, nullptr);
    if (incoming == SRT_INVALID_SOCK) return false;
    bool replacing = peer != SRT_INVALID_SOCK;
    if (replacing) srt_close(peer); // LINGER disabled: stale video is discarded.
    peer = incoming;
    fprintf(stderr, "SRT client connected replacing=%d\n", replacing);
    return true;
}
static void transmit(const char *address) {
    srt_startup();
    SRTSOCKET server = srt_create_socket();
    option(server, SRTO_TRANSTYPE, SRTT_LIVE);
    option(server, SRTO_SENDER, true);
    option(server, SRTO_TLPKTDROP, true);
    option(server, SRTO_PEERLATENCY, 150);
    option(server, SRTO_SNDDROPDELAY, 0);
    option(server, SRTO_SNDBUF, 262144);
    option(server, SRTO_SNDTIMEO, 100);
    option(server, SRTO_PEERIDLETIMEO, 3000);
    option(server, SRTO_LINGER, linger{0, 0});
    // Pace packet bursts before they reach the shared USB/Wi-Fi skb pool.
    // Capture continues independently and replaces stale, unsent JPEGs.
    option(server, SRTO_MAXBW, int64_t{1500000}); // bytes/s, including SRT retransmissions
    option(server, SRTO_RCVSYN, false); // nonblocking accept, permits clean shutdown
    sockaddr_in6 bind_address{};
    bind_address.sin6_family = AF_INET6;
    bind_address.sin6_port = htons(9000);
    bind_address.sin6_scope_id = if_nametoindex("nan0");
    if (!bind_address.sin6_scope_id || inet_pton(AF_INET6, address, &bind_address.sin6_addr) != 1 ||
        !IN6_IS_ADDR_LINKLOCAL(&bind_address.sin6_addr)) {
        fprintf(stderr, "Expected NAN link-local IPv6 address\n"); exit(1);
    }
    if (srt_bind(server, (sockaddr *)&bind_address, sizeof(bind_address)) || srt_listen(server, 1)) {
        fprintf(stderr, "SRT listen: %s\n", srt_getlasterror_str()); exit(1);
    }
    int poller = srt_epoll_create();
    int events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
    if (poller < 0 || srt_epoll_add_usock(poller, server, &events) < 0) {
        fprintf(stderr, "SRT poll: %s\n", srt_getlasterror_str()); exit(1);
    }
    while (!stopping) {
        SRTSOCKET peer = SRT_INVALID_SOCK;
        if (!accept_latest(poller, server, peer, 200)) continue;
        uint64_t sent = 0, dropped = 0;
        int64_t last_log = now_us(CLOCK_MONOTONIC);
        while (!stopping && srt_getsockstate(peer) == SRTS_CONNECTED) {
            if (accept_latest(poller, server, peer, 0)) {
                sent = 0; dropped = 0; last_log = now_us(CLOCK_MONOTONIC);
            }
            Frame frame;
            uint64_t replacement_count;
            {
                std::unique_lock<std::mutex> lock(mutex);
                ready.wait_for(lock, std::chrono::milliseconds(100), [] { return stopping || !latest.jpeg.empty(); });
                frame = std::move(latest); latest = Frame{};
                replacement_count = replaced;
            }
            if (frame.jpeg.empty()) continue;
            int64_t age = now_us(CLOCK_MONOTONIC) - frame.mono;
            if (age > 200000) { dropped++; continue; }
            char header[256];
            int n = snprintf(header, sizeof(header),
                "--ffmpeg\r\nContent-type: image/jpeg\r\nContent-length: %zu\r\n"
                "X-Capture-Unix-Us: %lld\r\nX-Sequence: %u\r\n\r\n",
                frame.jpeg.size(), (long long)frame.epoch, frame.seq);
            bool ok = send_part(peer, header, n) && send_part(peer, frame.jpeg.data(), frame.jpeg.size()) &&
                      send_part(peer, "\r\n", 2);
            if (ok) sent++; else dropped++; // next boundary resynchronizes an incomplete frame
            if (now_us(CLOCK_MONOTONIC) - last_log >= 5000000) {
                SRT_TRACEBSTATS stats{}; srt_bstats(peer, &stats, 0);
                fprintf(stderr, "camera sent=%llu replaced=%llu dropped=%llu seq=%u captureAgeMs=%.1f srtSendBufferMs=%d\n",
                    (unsigned long long)sent, (unsigned long long)replacement_count,
                    (unsigned long long)dropped, frame.seq, age / 1000.0, stats.msSndBuf);
                last_log = now_us(CLOCK_MONOTONIC);
            }
        }
        srt_close(peer);
        fprintf(stderr, "SRT client disconnected\n");
    }
    srt_epoll_release(poller); srt_close(server); srt_cleanup();
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: camera-srt /dev/videoN NAN_IPV6\n"); return 2; }
    signal(SIGINT, stop); signal(SIGTERM, stop);
    int fd = open(argv[1], O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) die("camera open");
    v4l2_format fmt{}; fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 1280; fmt.fmt.pix.height = 720;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0) die("camera format");
    if (fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_MJPEG || fmt.fmt.pix.width != 1280 || fmt.fmt.pix.height != 720) {
        fprintf(stderr, "Camera did not accept native MJPEG 1280x720\n"); return 1;
    }
    v4l2_streamparm parm{}; parm.type = fmt.type;
    parm.parm.capture.timeperframe.numerator = 1; parm.parm.capture.timeperframe.denominator = 30;
    if (xioctl(fd, VIDIOC_S_PARM, &parm) < 0) die("camera frame rate");
    v4l2_requestbuffers req{}; req.count = 4; req.type = fmt.type; req.memory = V4L2_MEMORY_MMAP;
    if (xioctl(fd, VIDIOC_REQBUFS, &req) < 0 || req.count < 2 || req.count > 16) die("camera buffers");
    std::vector<std::pair<void *, size_t>> maps;
    for (uint32_t i = 0; i < req.count; i++) {
        v4l2_buffer b{}; b.type = fmt.type; b.memory = req.memory; b.index = i;
        if (xioctl(fd, VIDIOC_QUERYBUF, &b) < 0) die("query buffer");
        void *p = mmap(nullptr, b.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, b.m.offset);
        if (p == MAP_FAILED) die("mmap");
        maps.emplace_back(p, b.length);
        if (xioctl(fd, VIDIOC_QBUF, &b) < 0) die("queue buffer");
    }
    if (xioctl(fd, VIDIOC_STREAMON, &fmt.type) < 0) die("camera stream on");
    fprintf(stderr, "Native MJPEG 1280x720 capture buffers=%u; latest-frame SRT port=9000\n", req.count);
    std::thread sender(transmit, argv[2]);
    int result = 0;
    while (!stopping) {
        pollfd p{fd, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0) continue;
        v4l2_buffer b{}; b.type = fmt.type; b.memory = req.memory;
        if (xioctl(fd, VIDIOC_DQBUF, &b) < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            perror("dequeue"); result = 1; break;
        }
        if (b.index >= maps.size()) { fprintf(stderr, "Invalid camera buffer index\n"); result = 1; break; }
        const auto *bytes = static_cast<const unsigned char *>(maps[b.index].first);
        if (!(b.flags & V4L2_BUF_FLAG_ERROR) && b.bytesused >= 4 && b.bytesused <= maps[b.index].second &&
            bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[b.bytesused - 2] == 0xff && bytes[b.bytesused - 1] == 0xd9) {
            Frame frame;
            frame.mono = now_us(CLOCK_MONOTONIC);
            int64_t wall = now_us(CLOCK_REALTIME);
            if ((b.flags & V4L2_BUF_FLAG_TIMESTAMP_MASK) == V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC)
                frame.mono = int64_t(b.timestamp.tv_sec) * 1000000 + b.timestamp.tv_usec;
            frame.epoch = wall - (now_us(CLOCK_MONOTONIC) - frame.mono);
            frame.seq = b.sequence;
            frame.jpeg.assign((const char *)bytes, (const char *)bytes + b.bytesused);
            { std::lock_guard<std::mutex> lock(mutex);
              if (!latest.jpeg.empty()) replaced++;
              latest = std::move(frame); }
            ready.notify_one();
        }
        if (xioctl(fd, VIDIOC_QBUF, &b) < 0) { perror("requeue"); result = 1; break; }
    }
    stopping = 1; ready.notify_all(); sender.join();
    xioctl(fd, VIDIOC_STREAMOFF, &fmt.type);
    for (auto &m : maps) munmap(m.first, m.second);
    close(fd);
    return result;
}
