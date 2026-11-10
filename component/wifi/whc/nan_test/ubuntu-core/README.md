# Ubuntu Core 26 / VMware：Green2 USB NAN + BLE

amd64 Ubuntu Core 26 中，WHC USB 提供 Wi-Fi NAN，`btusb` 提供 BLE HCI。
服务随 snap 开机启动。使用 Canonical `dangerous` model、自定义 kernel /
gadget 和 `devmode` 应用，供开发测试；生产签名、严格权限和 OTA 尚未验证。

## 已验证环境

2026-11-09，Windows VMware Workstation 26.0.0，4 vCPU、4 GB RAM、
EFI、Secure Boot 关闭、SATA 稀疏磁盘、NAT 管理网络。

| 项目 | 版本/配置 |
| --- | --- |
| model | ubuntu-core-26-amd64-dangerous，revision 2 |
| core26 | revision 468，cloud-init/stable |
| kernel | pc-kernel revision 3755，7.0.0-38.38r1，重打包为 green2.2 |
| gadget | pc revision 227，26-0.1，加入 NoCloud 初始化 |
| snapd / BlueZ | revision 28332 / 410，2.78 / 5.85-4 |
| 构建环境 | Ubuntu 26.04、GCC 15、Python 3.14、iw 6.17 |
| hostap | zephyrproject-rtos/hostap `1ce844ea5a9d8860d8690a125925fcc7274461df` |
| USB | `0bda:f851`，序列号 `00E04C000001` |
| Wi-Fi / NAN / BLE MAC | `94:c9:60:59:06:fc` / `94:cb:60:59:06:fc` / `94:c9:60:59:06:fd` |
| NAN | 2.4 GHz，`_flashstudio._tcp`，TCP 8000，Green2 Core26 |
| BLE | Green2 Core26 BLE，服务 `7b183224-9168-443e-a927-7aeea07e0001` |

复用已烧录的 NAN + BT USB flash-boot 固件，本轮未烧录模组。
固件先初始化 WHC 队列、Wi-Fi、BT controller，再启动 USB；使用
`../rpi/patches/0001-btusb-green2-flash-boot.patch` 避免重复下载 BT patch。
本板固件 SHA256：

```text
boot.bin  f25111408ab301aca60445af8790a6a7649bef8100e797e878561c02f2255a22
app       f0b1c3d5b27164cf8ff552df0294d375647d905f2d12eabd46265856b2d24127
```

## 构建

宿主需要 Docker、snapd、ubuntu-image、squashfs-tools、qemu-utils 和
Python 3 / PyYAML。修改下列路径，使用新的独立工作目录。保留下载的
assertion 和日志；更换内核版本时必须重新核对 kernel/header/source ABI。

```sh
repo=/home/zxf/ameba-rtos
work=/path/to/new-core26-work
mkdir -m700 "$work"
cd "$work"
snap download pc --revision=227
snap download pc-kernel --revision=3755
snap download core26 --revision=468
snap download snapd --revision=28332
snap download bluez --revision=410
curl -fL https://raw.githubusercontent.com/canonical/models/main/ubuntu-core-26-amd64-dangerous.model \
  -o ubuntu-core-26-amd64-dangerous.model
unsquashfs -d pc-tree pc_227.snap
unsquashfs -d pc-kernel-tree pc-kernel_3755.snap
make -C "$repo/component/wifi/whc/whc_host_linux" prepare
cp -a "$repo/component/wifi/whc/whc_host_linux" "$work/whc_host_linux"
git clone https://github.com/zephyrproject-rtos/hostap.git "$work/hostap"
git -C "$work/hostap" checkout 1ce844ea5a9d8860d8690a125925fcc7274461df
cp "$repo/component/wifi/whc/nan_test/rpi/hostap-pasn.config" \
  "$work/hostap/wpa_supplicant/.config"
docker build -t green2-core26-builder "$repo/component/wifi/whc/nan_test/ubuntu-core"
docker run --rm -v "$repo:/repo:ro" -v "$work:/work" green2-core26-builder
sudo bash "$repo/component/wifi/whc/nan_test/ubuntu-core/build-image.sh" \
  "$work" "$HOME/.ssh/id_rsa.pub" "$work/image-work"
qemu-img convert -f raw -O vmdk -o subformat=monolithicSparse \
  "$work/image/pc.img" "$work/green2-core26.vmdk"
```

保留 model 原始字节；额外空行会破坏 assertion 解码。
构建脚本只构建 `libpasn.so`，不构建完整 wpa_supplicant。
内核模块放在 kernel snap 的 `modules/$kver/kernel/`；Core 生成的驱动
树不会映射本包顶层 `updates/`，放错位置会使索引存在但模块文件不可用。

`build-image.sh` 将公钥、用户 `zxf`、主机名和 BlueZ 配置写入 gadget 的
NoCloud 数据源，再生成约 16 GiB raw 镜像。账户可无密码 sudo，SSH
密码登录关闭。私钥和 NAN 配对缓存不写入镜像。自动刷新设为 hold，
避免测试时官方 kernel 覆盖本地模块，更新需先验证对应模块。
在线 apt / Snap Store 依赖不保证跨时间逐字节可重现；应用内保留
`runtime-packages.txt` 精确版本清单。

BlueZ 配置先写入 `/var/lib/cloud/green2-bluez-main.conf`，首次启动的
`runcmd` 在 snap seeding 完成后再安装到 `/var/snap/bluez/410/etc/main.conf`。
镜像固定 BlueZ revision 410；Core 的 `/etc` 只有指定子路径可写，不能
直接向其顶层添加临时配置文件。
不能提前创建后者：`current` 尚未由 snapd 创建时会变成普通目录，导致
BlueZ seeding 报 `cannot remove snap current symlink` / `file exists`。

## VMware 与 USB

新建 Ubuntu 64-bit VM，使用生成的 VMDK，EFI 且关闭 Secure Boot。
将 **Realtek 0bda:f851 整个原生 USB 复合设备**连接到虚拟机。
CH340 下载口不能代替原生 USB。仅一块匹配板时可使用 VMX 设置：

```text
usb.present = "TRUE"
ehci.present = "FALSE"
usb_xhci.present = "TRUE"
usb.vbluetooth.startConnected = "FALSE"
usb.autoConnect.device0 = "vid:0x0bda pid:0xf851 autoclean:1"
```

原生 USB 由 VMware 独占，不能同时给 WSL usbipd；串口和摄像头可继续
留在 WSL。NAN 数据经直通板的无线接口传输，NAT 仅用于 SSH 管理。

从 WSL 转交及多次重启 VM 后，本次出现过 WHC `wait ret value timeout!!`
及 managed MAC 全零。停止应用、正常复位模组后重新枚举恢复。全零 AP
占位接口本身不代表错误，应检查 managed 接口。这不构成任意 USB 热切换
恢复验证；镜像不会自动复位其他设备。

## 管理与诊断

```sh
ssh zxf@VM_IP
sudo green2-nan-ble.status
sudo snap services green2-nan-ble
sudo snap logs green2-nan-ble -n=50
sudo snap restart green2-nan-ble
sudo snap stop green2-nan-ble
sudo bluez.btmon -w /var/snap/bluez/common/test.btsnoop
```

运行状态和配对缓存位于 `/var/snap/green2-nan-ble/common/run`、
`/var/snap/green2-nan-ble/common/nan`。同一块板迁移旧配对时单独复制缓存，
设为 root 所有、目录 0700 / 文件 0600，不提交或打包密钥。

本次抓到 BlueZ 反向读取 iPhone 的受保护特征，发出 Security Request
后主动断连，尚未收到 BLE-PING。专用外设镜像通过
`/var/snap/bluez/410/etc/main.conf` 设置 `ReverseServiceDiscovery=false`
和 `[GATT] Client=false`，避免该路径。此配置用于 GATT 外设测试。
选项定义见 [BlueZ 5.85 main.conf](https://github.com/bluez/bluez/blob/5.85/src/main.conf)。
`btmon` 还需要连接 `bluez:network-control`，首次启动脚本已处理。

## 手机测试及结果

1. Flash Studio → NAN，搜索服务并连接；新配对选择 Green2 Core26，
   测试 PIN `123456`，确认收到 TCP 回复。
2. nRF Connect 连接 Green2 Core26 BLE，对特征 UUID
   `7b183224-9168-443e-a927-7aeea07e0002` 开启 Notify，写入文本
   `BLE-PING`，应收到 `BLE-PONG\n`。
3. 保持 BLE 连接，切回 Flash Studio 再连接 NAN，检查回包和 BLE 断连。
   日志应对应本次操作，不将客户端旧值计作新回包。

2026-11-09 用户确认两路均收到回复。UTC 06:08:03，虚拟机记录
`BLE-PING received` / `notify bytes=9`，HCI 中对应 Write Request
`424c452d50494e47`、Notification `424c452d504f4e470a`；06:08:14，NAN
记录 `bytes=9 valid=True`。该 BLE 连接至 NAN 回包之间未记录
Disconnect Complete。已验证基本收发与共存，未做长期压测、吞吐和功耗测试。

将上述配置固化后，最终工厂镜像另用未直通 Green2 的副本验证首次启动：
NoCloud 初始化无错误、SSH 公钥登录正常、BlueZ 进程能读取外设配置、
`whc_usb` / `btusb` 模块可加载，配对缓存为空。VMDK 与 raw 内容比较一致。
硬件收发日志来自持续运行的测试 VM；验证副本检查完成后关闭。

本机产物：

- 工作目录：`/home/zxf/green2-ubuntu-core26-20261109/`
- 镜像：`image/pc.img`；摘要：`image.sha256` / `artifacts.sha256`
- VMware 工厂磁盘：`D:\VMs\Green2-Ubuntu-Core26\green2-core26-factory.vmdk`
- VMware：`D:\VMs\Green2-Ubuntu-Core26\Green2-Ubuntu-Core26.vmx`
- WSL SSH：`ssh -F /home/zxf/green2-ubuntu-core26-20261109/ssh_config green2-core26`
- 原始 UART、HCI、服务、内核日志留在工作目录，不加入源码仓库。

WSL 无法直达 VMware NAT 时，经 Windows TCP relay 转发 SSH，仍使用
本地私钥和固定 known_hosts 验证；relay 不解密 SSH。IP 由 DHCP 分配。

官方说明：[Core 26](https://documentation.ubuntu.com/core/uc26/)、
[ubuntu-image](https://documentation.ubuntu.com/core/how-to-guides/image-creation/use-ubuntu-image/)、
[gadget 格式](https://documentation.ubuntu.com/core/reference/gadget-snap-format/)。

## 摄像头 SRT over NAN

运行中的 VMware 测试 VM 已将 `30c9:00a6` 摄像头直通，与 Green2 USB
设备同时使用。关机后在对应 VMX 中增加以下规则可保持重新开机后自动连接：

```ini
usb.autoConnect.device1 = "vid:0x30c9 pid:0x00a6 autoclean:1"
ehci.present = "FALSE"
usb_xhci.present = "TRUE"
```

不要同时让 usbipd/WSL 占用摄像头。`run-camera` 只选择该 VID/PID 且
index=0 的 V4L2 采集节点；出现多个匹配设备时拒绝自动选择。当前节点为
`/dev/video0`，`/dev/video1` 是元数据接口。服务不录音、不保存视频文件。

camera daemon 使用摄像头原生 MJPEG 1280×720@30。`camera-srt.cpp`
直接读取 V4L2，只做 multipart 封装，经 libsrt 发送，无解码/重编码。
监听 `[nan0 的 IPv6 link-local%nan0]:9000`，不监听管理网卡。启用 SRT
live、150 ms latency、tlpktdrop。V4L2 请求4个缓冲，独立采集线程只保留
最新一帧，网络拥塞不会阻塞采集；丢弃驱动标记损坏及发送前已超过200ms的帧。
multipart 附带采集时间和序号，原始 JPEG 内容不变。
MJPEG 码率随画面变化，不再沿用此前 H.264 的 1.5 Mbps 码率限制。
一个客户端断开后直接等待下一次连接，NAN/BLE 服务独立运行。

本机 VMware 同时开启 EHCI/xHCI 时，摄像头落在 EHCI，出现大量损坏
MJPEG/空帧；禁用 EHCI 后确认摄像头由 xHCI 驱动，对照采集恢复约30fps。
仅查询摄像头支持的格式不能证明采集质量；必须检查有效帧和画面。

`build-in-container.sh userspace` 在 Core 配置中增加第二个 publish：
`_flashstudio._udp:9000`，保留原 TCP echo/测速。libnanapi 根据服务后缀
生成 NDP transport protocol：UDP=17、TCP=6，不改变结构体 ABI，也不需要
重新烧录 Green2。`tests/test_nan_transport.c` 校验该字段的实际编码结果。

更新运行中的开发 VM：

```sh
sudo snap install --dangerous --devmode ./green2-nan-ble-srt.snap
sudo snap connect green2-nan-ble:camera
sudo snap start green2-nan-ble.camera
snap services green2-nan-ble
sudo journalctl -u snap.green2-nan-ble.camera -f
```

配套 Flash Studio 使用 MobileVLCKit + libsrt；在 NAN 页选择“播放摄像头”。
原工厂 VMDK 不会因安装新版 app snap 自动更新；需要分发新工厂镜像时，
将新版 snap 纳入既有 image build 流程重新生成。当前功能只更新测试 VM。

早期 H.264 版本的主机自测曾得到8秒240帧，但随后手机反馈花屏，不能
作为当前 MJPEG 版本的验收结果。当前通过原生 MJPEG、xHCI 和最新帧
队列继续验证；端到端延迟需要单独测量。

2026-11-09 MJPEG 实机记录：iPhone/MobileVLCKit 经 NAN UDP/SRT 连续接收
约154秒，净接收增量294,436,996字节（含multipart封装），平均15.3Mbps，
显示2020帧（约13.1fps），SRT接收缓冲58–221ms。此时摄像头配置为
720p/30。用户反馈该旧路径仍有5–6秒延迟，缩小 VLC 预读后也未改善。
随后67帧 ioctl 取样测得旧 FFmpeg 路径取帧延迟0.78–1.12秒；改为独立
V4L2 采集后，发送前帧龄约36–65ms，手机收帧约220–300ms（依赖两端时钟
同步，未包含显示时间）。用户确认画面延迟改善到约1–2秒。
随后 iPhone 改为 VLC `stream://` 私有 FIFO 输入、50ms file-caching、
单线程解码及独立 UDP actor 后，用户估计约1秒；尚未验证500ms以内。
VLC displayedPictures 可能包含重复显示，不能当成唯一新帧计数；新增
deliveredJPEGFrames 与 decodedFrames 供核对。测试数据和原始日志保存在
`/home/zxf/green2-core26-srt-20261109/`。

本次多次刷新 app snap 后曾出现发布进程存活但服务不可发现；重置已确认
的 Green2 USB 板并重启 NAN/BLE/camera 服务后恢复。恢复过程保留配对缓存。
此现象与 MJPEG/SRT 接收逻辑独立，尚未归因到具体固件状态。

## USB 缓冲与冷启动修复（2026-11-09 晚）

COM11 已由用户确认连接本板下载口，使用 1.5 Mbps 仅更新 `app.bin`，
保留 boot 和配对缓存。内核更新为 `7.0.0-38.38r1-green2.3`，应用 snap
当前更新为 `20261109.11`。增加的是缓冲数量，非聚合包长：

| 参数 | 原值 | 本次配置 |
| --- | ---: | ---: |
| 模组共享 skb 池 | 20 | 160 |
| Linux USB RX 请求 | 10 | 64 |
| Linux USB TX 请求 | 32 | 128 |
| skb 数据容量 | 1632 B | 1632 B |
| Linux USB 单次 RX/TX 限制 | 1600 B | 1600 B |

原始失败中，32 个 USB OUT 请求同时滞留，最长 23.149 秒，未出现 URB
错误；共享 skb 几乎用满并发生 RX 分配失败。另观察到 Auth1 先于新 MAC
的 Subscribe 到达，原库没有 peer 对象时不会把 PASN 请求交给主机。
这些是本机复现的不同故障路径，不代表每次启动慢都由同一个原因造成。

固件构建额外开启 `AMEBA_GREEN2_NAN_STARTUP_TRACE`、
`AMEBA_GREEN2_NAN_AUTH_PEER_FIX` 和 `AMEBA_GREEN2_NAN_USB_RX_RESERVE`。
前两项依赖 CMake 校验的固定 Green2 库 SHA-256；只在合法 NAN Auth1
缺少 peer 时创建普通未认证对象，仍由原 PASN 路径验证密钥。诊断日志仅
包含帧类型、时间、MAC 和状态，不输出密钥或载荷。

USB 拥塞保护按 SRT 包头 Flag 分类，不使用 DSCP 或包长判定优先级。
解析 Ethernet、IPv4/IPv6 和 UDP 后，仅对源/目的端口为 9000、具有完整
16 字节 SRT 头的报文检查首字节最高位：1 为控制，0 为数据。
空闲 skb 少于 16 时，数据包丢弃并重新挂接接收缓冲；控制包可使用余量。
短 JPEG 尾片和重传 DATA 同样受限；ARP、IPv6 ND 和无载荷 TCP 报文保留
基本建链能力。截断或分片 IP 报文不授予控制优先级。包头定义见
[SRT Packet Structure](https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html#section-3)。
这属于接收准入保护，不改变 Wi-Fi WMM 队列或为控制包创建独立 USB 端点。
彻底分配失败时也重新
挂接 NAN 接收缓冲，避免堵住全部 OUT 端点。阈值不是对其他异步分配者的
硬内存隔离。USB 小栈任务使用 `RTK_LOGS`，避免 newlib `printf` 的栈开销。

仅增大池仍复现首帧 21 秒及 SRT 握手失败，因此发送端同时配置
`SRTO_MAXBW=1500000` B/s。摄像头保持原生 MJPEG；采集线程持续替换
未发送的旧帧，SRT 控制包和数据包由库进行节奏控制，没有添加重连等待。
`SRTO_MAXBW` 的单位和不限速默认值见
[SRT 官方 socket options](https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_maxbw)。

Flash Studio 的发现浏览器保留到 NAN 连接就绪后结束，避免发现后关闭
订阅、建链时重新订阅。冷启动验证使用 `--video-startup-rounds 5
--video-reprepare`：每轮拆除数据链路，仍保留授权；两秒实际播放后进入
下一轮。它不覆盖重新输入 PIN 的配对流程，也不等同于关闭 Wi-Fi 后的
射频冷启动。原始私有证据保存在 `/home/zxf/green2-coldstart-20261109/`。

2026-11-09 SRT Flag 版验证：固件 SHA-256
`addf2667463e2847577cf8b2d8e5684e759d13a6238bbe2fd13d42556223464a`，
COM11 1.5 Mbps 烧录并校验通过。分类器的 IPv4/IPv6、VLAN、扩展头、
截断和分片测试通过 ASan/UBSan；不同 DSCP 值不影响分类。
连续拆链重连 5/5 出画面，预览 3.84–5.29 秒，SRT 握手 14–470 ms。
采集区间 USB OUT 最大完成耗时 29.166 ms，无完成错误；skb 峰值 146/160，
RX 分配失败为 0。但刷写后首次 NAN 建链仍超时，随后强制关闭 App
重开仍复现 SRT 握手超时，因此不能将本次缓冲准入修复视为冷启动问题
已完全解决。详细统计：本机私有工作目录 `srt-flag-results.json`。

### NDP 断链后的旧视频入队修复

`AMEBA_GREEN2_NAN_STALE_TX_FIX=ON` 额外启用固定库版本的队列修复。
iPhone 强退 App 会先拆除 NDP，主机上的旧 SRT socket 随后才因超时关闭。
在 NDI=NMI 时，原库保留管理站点用于发现/PASN；这段间隔内旧视频仍能
进入该站点的发送队列，从而占用新连接需要的共享 skb。

- 在 WHC 的 Wi-Fi 发送任务中检查该目标 NDI 是否还有有效 NDP；没有就
  释放旧包，覆盖已经排入 WHC 队列以及主机后续重传的包。
- 最后一条安全 NDP 释放时，对 NDI=NMI 的保留站点调用原库发送队列清理，
  使用与 `rtw_free_stainfo` 相同的互斥锁及私有字段。继续调用原安全释放
  函数，不删除管理站点，不改变密钥验证或配对缓存。
- 私有布局受原始 vendor archive SHA-256 检查约束。链接后应确认
  `rtw_nan_ndp_terminate_indicate` 调用 `__wrap_rtw_nan_ndi_sec_stainfo_free`。

固件 `f549d35d5b24192d45c35d6f0977bbc2a9c07f3fe5be43ab1a40dbf326fae1ea`
于 2026-11-09 19:44 经 COM11 烧录校验；先完成 5 次普通拆链重连，再完成
5 次播放中强制终止/重启 App，均出画面。后者期间明确记录旧 NDI 包被丢弃，
skb 峰值 147/160、RX 分配失败 0；USB OUT 75,365 次完成无错误，最长
15.403 ms。旧 camera 服务仍可能在握手后等待旧连接，单轮首帧最长 11.5 秒。

camera `20261109.9` 进一步在发送循环中同时检查监听 socket；新 SRT
连接到达便关闭旧连接，禁用旧视频 linger 排空，继续发送最新原生 JPEG。
单摄像头服务采用最新连接接替旧连接的规则，不引入新控制协议或 DSCP。
`test_nan_stale_tx.py` 覆盖失效 NDI 拒绝、有效 NDP 放行和保留站点清队列；
`test_camera_handover.cpp` 使用真实 libsrt 回环验证仍在线的旧客户端可被
替换且新客户端收到数据。现场测试统计另行记录，单元测试不代表空口时延。

### NAN 重启、接口重建和硬件队列回收

服务重启还暴露出两个独立问题：

- NAN 初始化成功、发布命令返回成功，但空口没有发现广播。最初观察到
  DW 软件定时器未启动；仅补开定时器后，仍复现定时器运行、TXBD 为空、
  TWT1 停在 warmup 值 `0xefffffffffffffff`。反汇编显示重启保留旧 cluster ID，
  `rtw_nan_cluster_operation(1)` 在 ID 相同时跳过整个更新分支，也跳过
  新调度的初始化事件。
  `AMEBA_GREEN2_NAN_RESTART_FIX=ON` 在新的 NAN 启动成功、两个 cluster ID
  相同时，补发与该原生分支一致的事件 21/11/5，设置调度更新标记并重启
  DW 定时器；ID 不同时仅在定时器未活动时补开。正常运行中不重复初始化。
  保留 cluster ID、TSF 和原生频道调度。此选项依赖 `STALE_TX_FIX` 和固定库校验。
- NAN 关闭和 WHC 发送任务并发，旧发送保护可能访问已释放的 peer-list
  mutex。现在包装 `rtw_nan_start_api` / `rtw_nan_stop_api`：关闭前先阻止
  新发送，再等待已进入的查找及 `wifi_if_send_skb` 返回，最后调用原生关闭。
  启动成功后才重新接受 NAN 发送；其他 Wi-Fi 接口保持原发送路径。

camera `20261109.10` 在 snap 启动顺序中排在 NAN 后面，并跟踪
`(ifindex, IPv6 link-local)`。仅重启 NAN 会删除旧 `nan0`，即便新接口具有
相同地址，旧 socket 仍绑定已失效的数字 scope ID。监督程序现在终止旧
sender，等待新接口 UP 且 IPv6 不处于 tentative/dadfailed 后重新监听。
`test_camera_scope.py` 使用实际子进程验证旧 socket 所属进程先退出，
再启动替代进程；现场已验证 ifindex 32 → 33 后自动恢复视频。

进一步强退复测发现，清理软件 pending queue 后仍可能卡死：BE 硬件队列
共 4 个 TXBD，其中 3 个被已断链 MACID 12 的旧视频占用。其 FAW 已撤销，
MACID 保持暂停，描述符不会完成；原库检查所有硬件队列的余量，任一队列
剩余不超过 1 个便不再推进软件 pending queue。此时主机持续收到 SRT
握手并发出回复，USB 无阻塞，但空口没有 Green2 的数据回复。

`STALE_TX_FIX` 现在也在最后一条 NDP 的保留站点清理中，先调用原生
`wififw_media_macid_drop_action(0, macid)` 标记旧 DATA 丢弃，再调用
`wifi_hal_nan_macid_release` 让硬件回收描述符。顺序不能颠倒，否则可能
发出已过期的加密数据。随后撤销 FAW 的流程还会再次暂停旧 MACID，因此
同时包装 `wifi_hal_nan_macid_pause`，在已标记丢弃期间阻止这次迟到的暂停，
保证硬件能够完成回收。所有六处调用已在链接后的反汇编中核对。
原生 pairwise key 安装成功后，恢复该 MACID 的
发送；安装失败不解除丢弃状态。进入终止状态 10/11 的 NDP 也立即拒绝
新的主机 DATA，覆盖原库清除 active 位之前的间隔。管理站点和配对缓存
继续保留。该路径目前针对现场的 NDI=NMI 保留站点，未声称验证了不同 NDI。

现场先只回收被卡住的 MACID 12，观察 TXBD 占用从 3 降至 0，随后无需
重启模组或服务即恢复 SRT 视频；再将操作接入固件。`test_nan_stale_tx.py`
用硬件队列模型验证丢弃先于解暂停、迟到暂停不能中断回收、密钥安装成功
才恢复正常调度和发送，以及终止中
NDP 的拒绝策略；ASan/UBSan 测试和 Green2 固件构建通过。

应用 `20261109.11` 还将 NIK 缓存更新改为同目录临时文件加原子替换。
原发布进程使用 `fopen(..., "wb")`，会让并行的 PASN 读取看到被截断的文件。
验证器现在按解析、NIK 快照、NIRA 匹配、NPK 快照及 PMKSA 阶段报告失败，
不记录密钥。原有一次 `Verification NIRA/NPK unavailable` 未包含具体阶段，
不能仅凭那条日志断言该次必然由文件竞态造成。
`test_nan_cache_file.c` 验证并行更新时读者只见完整旧/新记录、已打开的旧
读者不受替换影响，文件权限保持 0600；300 次写入期间超过百万次读取通过。

当前测试板固件（2026-11-09 21:14，经 COM11 1.5 Mbps 烧录、校验 PASS）：

```text
boot.bin  f25111408ab301aca60445af8790a6a7649bef8100e797e878561c02f2255a22
app.bin   6ccea2b5678998638f35296b6a26c1bd332df969e730cc8ccca76fc07f23337d
app snap  181ef2ca9b124027a0569ee24ec926e3331b65047d6dca8cf0f721ce33f2ca61
```

该版本在同一已配对 iPhone 上完成以下现场验证（2.4 GHz 发布配置，
原生 MJPEG、SRT UDP 9000、未改 DSCP）：

| 场景 | 成功/次数 | 连续视频首帧 |
| --- | ---: | ---: |
| 刷写重启固件后首次打开 App | 1/1 | 5.973 s |
| 播放中重启整套 snap，再打开 App | 1/1 | 4.623 s |
| 播放中仅重启 NAN，再打开 App | 1/1 | 6.311 s |
| 每轮重建 NAN 链路，播放 2 s 后自动重连 | 5/5 | 4.218–5.247 s |
| 出画面后立即强退并重新启动 App | 5/5 | 4.304–5.557 s |

13 次认证均通过，未出现 NIRA/NPK 拒绝、Auth1 处理失败或 SRT 超时。
首个可见 JPEG 预览为 3.355–5.613 s，连续视频为 4.218–6.311 s，
SRT 握手为 18–484 ms。NAN 单独重启时，camera 自动从 ifindex 44 改绑 45。
USB 记录窗口内 58,083 次 OUT 完成无错误，最长 31.193 ms；固件 skb
峰值 148/160，TX/RX 分配失败均为 0。

这是本轮复现路径的回归结果，并非全部冷启动条件的长期稳定性保证：
未覆盖重新配对、iPhone Wi-Fi 关开、断电上电或多手机并发。
空口抓包有文件容量上限，2.4 GHz 文件在满额后停止记录；未将其宣称为
全部 13 次的完整空口证据。每轮 App 日志、主机日志及汇总保存在本机私有
目录 `/home/zxf/green2-coldstart-20261109/final-validation/`，不提交密钥或原始
PASN 日志。测试结束后恢复 RouterOS 原来的 5180/2472 MHz、20/40 MHz 配置。

这些更新已部署到运行中的测试 VM / 模组，尚未重新生成前述工厂 VMDK。

### 复现当前实验固件的构建选项

上述固定库 ABI 修复默认关闭。先按 `../module/build-firmware.sh` 使用
`green2_nan_usb_bt_usb.config` 生成独立 USB 固件构建目录；再在 SDK 根目录
对该目录开启以下选项并重建（`$work` 是先前的固件输出目录）：

```sh
cmake -S component/soc/amebagreen2/project -B "$work/build" \
  -DAMEBA_GREEN2_NAN_STARTUP_TRACE=ON \
  -DAMEBA_GREEN2_NAN_AUTH_PEER_FIX=ON \
  -DAMEBA_GREEN2_NAN_USB_RX_RESERVE=ON \
  -DAMEBA_GREEN2_NAN_STALE_TX_FIX=ON \
  -DAMEBA_GREEN2_NAN_RESTART_FIX=ON
cmake --build "$work/build" -j8
```

CMake 保留原构建目录的 USB 配置、toolchain、PASN 修复和频段选项；
本轮使用 `NAN_2G_ONLY=ON`。原始 vendor archive 的 SHA-256 必须为
`9ade71dee6186bfb5bdc634869d577e38746971bcbf09d908d87a87015cdbe6a`，
不匹配时构建拒绝继续，不能跳过校验套用到其他版本。

## 2026-11-10：USB 退出与 NAN 创建竞态

在上述 VMware 中，用 USB `authorized=0/1` 模拟移除/重接，并同时执行
`iw phy <phy> interface add nan0 type __nan`。旧驱动实际触发：

```text
BUG: kernel NULL pointer dereference, address: 0000000000000438
rtw_nan_iface_alloc+0x112/0x2c0 [whc_usb]
whc_host_add_virtual_intf -> nl80211_new_interface
```

STA 网卡已释放，而 wiphy 尚未注销；并发 NAN 创建继续读取
`global_idev.pndev[0]->dev_addr`。此外，probe 失败路径原先会直接释放
已注册的 wiphy，USB probe 还忽略了上层初始化失败。

修复在 RTNL 下关闭接口创建入口，先停止 USB 回调、RX 线程和事件工作，
再移除 NAN、STA/AP、注销并释放 wiphy。USB disconnect 使用绑定的
`intfdata` 判断所有权；释放整个 URB 数组前等待全部完成回调，包含忙碌
的 TX 请求。TX 取消/错误也回收 skb 和计数。固件用户配置读取失败会
终止 probe 并撤销无线对象；退出时完成本地队列/扫描清理，不等待离线固件。

### 快速重接的固件修复

仅修复主机对象生命周期的 kernel `.4` 仍会遇到 USB 命令超时。
联合 USB、串口与源码继续定位到以下问题，并在模组固件中修复：

- 主机断开时不能再发送 NAN deinit；重接直接 init 会覆盖仍在运行的
  NAN 状态和定时器。初始化前先执行可重复调用的 `rtw_nan_intfs_deinit()`。
- 每次 USB set_config 重新分配三个 RX skb，旧指针被覆盖。改为一次分配、
  由工作线程复用；配置代次隔离旧 RX/TX，防止重配置打断 skb 所有权交接。
- 取消 IN 传输没有正常完成回调，可能留下 TX 缓冲及信号量。停止 DMA 后
  返回所有权，由线程回收；重复完成、提交失败和跨配置等待也分别处理。
- 蓝牙 USB RX/完成中断直接分配或释放内存，而 Green2 的 FreeRTOS 堆只
  暂停调度、不屏蔽中断。长测实际出现堆链表及队列损坏、MemManage 和
  看门狗复位。RX 改为固定大小队列按值复制；独立 TX 工作线程回收内存，
  避免 RX 处理同步回包时等待自身回收而死锁。

主机 kernel `.5` 同时记录超时 API ID，将 NAN init/start/stop/deinit
传输失败返回给调用者；init 失败不再留下一个表面创建成功的 NAN 接口。
未通过增加轮次间延时或延长 API 超时掩盖故障。

最终部署 kernel `7.0.0-38.38r1-green2.5`（x4），WHC 模块 srcversion
`1AD9C521FCE404702F02A96`，应用仍为 `20261109.11`。新 `app.bin`
SHA-256 为 `c3fd052ceb51ddafa78375222f62d9de9af10df00af4963c2045e9e9118a476e`，
通过 COM11 / 1.5 Mbps 只更新 app 分区，设备校验通过。
固件保留现有 PASN/USB 修复选项，`NAN_2G_ONLY=OFF`；下面的回归由主机
显式启动 2.4 GHz NAN。工厂 VMDK 尚未重新生成。

两组测试连续运行，每轮先启动 NAN，再并发移除设备与创建接口：

| 路径 | 成功/次数 | 单轮耗时 |
| --- | ---: | ---: |
| 复合 USB `authorized=0/1`，包括蓝牙接口 | 100/100 | 0.115–2.225 s |
| 仅 WHC_USB unbind/bind，保留蓝牙接口 | 100/100 | 0.093–0.165 s |

每轮均验证旧 PHY/接口消失、旧 PHY 拒绝创建、新 PHY 创建/删除 NAN
成功，且无新增 WHC 超时、短响应、BUG/Oops/WARNING。两组期间 Linux
boot ID 和 USB devnum 均未变化，串口无 MemManage/HardFault/看门狗复位。
复合设备测试中，强制取消蓝牙初始化仍有 HCI 命令超时日志，造成部分
轮次约 2 秒；这不计作 WHC 通信成功的证据，也不等于正常 BLE 业务超时。
测试结束后 NAN、BLE、camera 均恢复 active，BLE powered 且广播实例为 1，
TCP 8000 与 `nan0` 上的 SRT 9000 正在监听。手机端收发未在本轮复测。

`amebagreen2_usb_nan_defconfig`、`amebagreen2_usb_wpaoh_fwdl_defconfig`、
`amebagreen2_sdio_nan_defconfig` 均在 GCC 15 / `7.0.0-38-generic` headers
下编译通过，后两项仅编译验证。确定性回归
[test_usb_reconfigure.py](../../tests/test_usb_reconfigure.py) 编译实际生产函数，
覆盖 1000 次 RX 重配置、RX 所有权交接竞态、TX 取消/重复完成/失败提交、
旧配置发送者和蓝牙 ISR 无堆操作；四项测试均通过。

复现工具 [usb_nan_hotplug.py](../../tests/usb_nan_hotplug.py) 先校验明确的
USB 路径、VID/PID、序列号和 managed MAC；执行前停止相关业务，保留
虚拟机串口记录。脚本要求目标 PHY 上没有已有 NAN 接口；停止服务后
核对并删除该接口（本机为 `nan0`）。`__nan` 是 iw 接受的类型名称，
`type nan` 无效。

```sh
sudo snap stop green2-nan-ble
sudo /snap/green2-nan-ble/current/usr/sbin/iw dev nan0 del
sudo /snap/green2-nan-ble/current/usr/bin/python3 usb_nan_hotplug.py \
  --usb-device 2-4.1 --serial 00E04C000001 --mac 94:c9:60:59:06:fc \
  --iw /snap/green2-nan-ble/current/usr/sbin/iw \
  --ip /snap/green2-nan-ble/current/usr/bin/ip \
  --active --rounds 100 --output /home/zxf/usb-hotplug.json
sudo snap start green2-nan-ble
```

`--active` 在移除前启动 NAN；`--mode interface` 只解绑/重绑 WHC_USB。
默认会同时中断该复合设备的 BLE。脚本没有轮次间固定延时，只有枚举
状态轮询；失败时保存结果并尝试恢复绑定。脚本也检查新增内核错误和
USB devnum，防止将静默超时或固件重启当成通过。此操作不等同于物理断电，
不能对生产设备直接运行，也不代表每轮完成了空口配对与传输。原始内核
日志、逐轮 JSON、构建日志及 kernel snap 留在
`/home/zxf/green2-usb-reconnect-20261110/`；此前空指针复现记录仍在
`/home/zxf/green2-usb-lifecycle-20261109/`，未把配对密钥写入仓库。
