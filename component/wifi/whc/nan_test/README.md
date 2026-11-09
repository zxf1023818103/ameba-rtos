# Green2 SDIO NAN：iPhone 配对、数据链路与 TCP 回包

本目录保存 2026-11-03 至 11-04 验证使用的实验配置和复现入口。SDK 基线为
`89b83feb6cd919db351e8751092516a8b7f96f30`（20261027）。

实机组合：Ameba Green2 RTL8711F / WHC SDIO Flash Boot / Group1，
树莓派 4B / Raspberry Pi OS Lite 64-bit / Linux `6.18.50+rpt-rpi-v8`，
iPhone 的 Flash Studio NAN 页面。最终测试从 SD 卡启动；原先的 SanDisk
USB 启动盘不属于本次成功验证的配置。

Ubuntu Core 26 / VMware 的 Green2 原生 USB NAN + BLE 构建、启动和实测
说明见 [ubuntu-core/README.md](ubuntu-core/README.md)。

## 文件与修复范围

| 内容 | 源码/文件 |
| --- | --- |
| 模组修正库 | `component/soc/amebagreen2/project/project_km4tz/lib/application/lib_wifi_whc_dev_nan_fixed.a` 及 `.a.sha256` |
| PASN cipher 修复 | `../whc_dev/whc_dev_nan_pasn_cipher_fix.c` |
| FAW ID 修复生成器 | `../whc_dev/make_nan_faw_id_fix.py` |
| NDL peer/重传修复 | `../whc_dev/{make_nan_ndl_peer_fix.py,whc_dev_nan_ndl_peer_fix.c}` |
| NDL/NDC 调度属性修复 | `../whc_dev/{whc_dev_nan_ndl_immutable_fix.c,whc_dev_nan_ndc_control_fix.c}` |
| 完整静态库打包脚本 | `../whc_dev/make_nan_fixed_library.py` |
| 模组配置/构建入口 | `module/green2_nan_sdio.config`、`module/build-firmware.sh` |
| 树莓派驱动 | `../whc_host_linux/driver/`，配置 `configs/amebagreen2_sdio_nan_defconfig` |
| NAN 发布与事件解析 | `../whc_host_linux/app/wifi_nan_utility/{rtw_aware,src/rtw_nan_api}/` |
| 常驻 PASN 应答器 | 同上 `pasn_probe/{pasn_live,pasn_vendor_events}.c` |
| 服务构建/启动/回包源码 | `rpi/{build-services.sh,run-services.sh,nan_echo.py}` |

模组修复（第三项及第四项的完整稳定性仍待实测）：

1. `rtw_nan_ndp_response_prehandle` 原本把 PASN-128 请求的 cipher 7
   改成 SK-128 的 1。包装函数只修正成功的 PASN 响应，发生在构帧和 MIC
   计算之前；open、PSK、拒绝和失败路径保持原行为。
2. `rtw_nan_schdl_faw_act_add` 从调度项读出 32 位 bitmap，却用 `UXTB r0,r6`
   返回，导致 `0x100` 变成 0，被当作资源分配失败。生成器校验对象 SHA-256
   和指令后提取该函数，把返回指令改为 `MOV r0,r6`，保留其他指令和重定位。

3. 实验性 `rtw_nan_sdf_rx` 包装：已有 peer TK 时，原接收函数在解析 NPBA
   前丢弃所有未加密单播 SDF。新版本仅放行格式受限的全新 bootstrap 请求，
   保留后续 PIN/PASN 验证，不修改已有密钥或普通报文的保护检查。
   `make_nan_bootstrap_fix.py` 校验整个对象哈希，提取原函数并仅替换
   `+0x56` 的目的地址比较调用；`whc_dev_nan_bootstrap_fix.c` 检查完整属性边界。

4. `rtw_nan_ndl_nego_rx`：同一已认证 peer 的受保护 NDP Request 复用安全
   上下文，避免新请求触发 free/reallocate 后丢失 PMK。另对正在等待 Confirm
   的同 ID、token、NDI 重传保留 NDL 状态，避免重复请求将 NDL 切回 Rx Request。
   原有取消配对、超时和密钥清理路径保留；见文末 17:20 的验证边界。

5. Accepted NDL Response 不再新增 Immutable Schedule，避免后续窗口收缩
   与此前声明冲突；NDC Control 保留位清零。两处均在 MIC/CCMP 生成前
   修正属性，具体边界及两组 5 轮验证见文末 18:24 记录。

`lib_wifi_whc_dev_nan_fixed.a` 包含原库的 267 个对象和八个修复对象。
原厂对象逐字节不变；这不是原厂闭源驱动的完整源码。必须通过 CMake 的
`--wrap=rtw_nan_ndp_response_prehandle` 和
`--wrap=rtw_nan_schdl_faw_act_add`、`--wrap=rtw_nan_sdf_rx`、
`--wrap=rtw_nan_ndl_nego_rx`、`--wrap=rtw_nan_ndl_attri_construct` 和
`--wrap=rtw_nan_ndc_attri_contruct` 重定向调用，单独替换库却遗漏链接选项不会生效。
本分支的 CMake 已处理两种构建方式：源码生成修复对象，或使用打包库。

Linux 端修正 NAN 事件的接口索引、Host API 错误传播以及不适用于 NAN 的
`wifi_get_setting` 查询（`Host API 0x1005 ret too short`）；发布程序通过
libnl 持续订阅驱动事件，并修正服务匹配过滤及 PASN 完成回调。
外部应答器直接接收 nl80211 vendor event 29/30，处理 Auth1/2/3、NPK/NIRA
验证和 TK/KDK/ND-PMK 回传，通过本地完成通知补齐 responder 的 NIK 交换。

## 编译模组固件与静态库

以下命令从仓库根目录执行。先按 SDK 安装 ASDK 12.3.1、CMake、Ninja 和 Python
依赖；SDK 的 `prebuilts-linux-1.0.3/bin` 需在 PATH 中（包括 `ccache`）。

```sh
export PATH="$HOME/rtk-toolchain/prebuilts-linux-1.0.3/bin:$PATH"
component/wifi/whc/nan_test/module/build-firmware.sh "$PWD/build_RTL8711Dx_nan"
```

默认启用 `AMEBA_GREEN2_NAN_PASN_CIPHER_FIX=ON` 和
`AMEBA_GREEN2_NAN_PREBUILT_LIBRARY=ON`，输出目录包含 `boot.bin`、`app.bin`
及 `build/` 下的 ELF/map。配置明确启用 NAN、SDIO Group1 和 Flash Boot。
改变编译器安装位置时可设置 `TOOLCHAIN_DIR`。

EV711FL0 同时使用蓝牙 HCI UART 时，可选择独立配置（保留 SDIO Group1）：

```sh
FIRMWARE_CONFIG="$PWD/component/wifi/whc/nan_test/module/green2_nan_sdio_bt_h4.config" \
NAN_2G_ONLY=ON \
  component/wifi/whc/nan_test/module/build-firmware.sh /tmp/green2-nan-bt-h4
```

外部蓝牙接口为 UART0 H4，115200 baud、8N1、RTS/CTS 硬件流控。按
`HDK-EV711FL0-3V2/SCH/SCH-EV711FL0-R05.pdf` 第 4、8 页，全部接在 J21：

| J21 针脚 | Green2 信号 | 接外部 HCI 主机 |
| --- | --- | --- |
| 5 | PA25 / TX | RX |
| 8 | PA26 / RX | TX |
| 3 | PA22 / CTS | RTS |
| 4 | PA23 / RTS | CTS |
| 1 或 2 | GND | GND |

使用 3.3 V UART 电平并共地。排针编号以 PCB 丝印的 1 脚为准；COM33 的板载
LOGUART 继续用于日志和烧录，速率仍是 1500000，与此 HCI 接口不同。
HCI 控制器按 SDK 行为在收到首条主机命令时初始化，固件不会自行启动 BLE 广播。
四个引脚可通过 `CONFIG_BT_INIC_H4_{TX,RX,CTS,RTS}_PIN` 配置，编码为
PA=0..31、PB=32..63、PC=64..95；需核对实际板卡连线。
本配置不启用新增休眠策略。2026-11-07 已验证编译、COM33 烧录校验及启动日志中
H4/SDIO 初始化；外部 HCI 接线后的命令收发仍需验证。

### J11 40 针与树莓派直接对插：两线 HCI

对于 PC2/PC4 分别接到 J11 32/33 脚的板卡，可使用下面的独立配置。
该引脚定义来自本次板卡的 J11 原理图，与上述 EV711FL0 R05 的 J21 编号不同；
必须确认 PC2/PC4 未用于当前启动 Flash。

| 物理针脚 | 树莓派 4B | Green2 |
| --- | --- | --- |
| 32 | GPIO12 / UART5 TX | PC2 / UART0 RX |
| 33 | GPIO13 / UART5 RX | PC4 / UART0 TX |
| 6 等地脚 | GND | GND |

```sh
FIRMWARE_CONFIG="$PWD/component/wifi/whc/nan_test/module/green2_nan_sdio_bt_h4_rpi_header.config" \
NAN_2G_ONLY=OFF TOOLCHAIN_DIR="$HOME/rtk-toolchain" \
  component/wifi/whc/nan_test/module/build-firmware.sh /tmp/green2-hci-header
```

该配置使用 115200 baud、8N1、H4，双方关闭 RTS/CTS。配置片段使用
`CONFIG_BT_INIC_H4_FLOW_CONTROL=n` 显式关闭选项；合并片段时不能依靠
`# CONFIG_... is not set` 注释覆盖默认值。原 J21 配置仍默认开启流控。
H4 初始化会先释放遗留的 UART0 引脚复用，再应用所选引脚，避免软件重启或
下载后 PA26 与 PC2 同时保留 RX 功能而无法接收。

树莓派 `/boot/firmware/config.txt` 添加 `dtoverlay=uart5`，删除此前测试的
`dtoverlay=uart3,ctsrts`。UART5 就绪后安装服务：

```sh
sudo install -m 644 component/wifi/whc/nan_test/rpi/green2-hci-uart.service \
  /etc/systemd/system/green2-hci-uart.service
sudo systemctl daemon-reload
sudo systemctl enable --now green2-hci-uart
sudo btmgmt info
```

服务运行 `btattach -B /dev/ttyAMA5 -P h4 -S 115200 -N`，其中 `-N` 关闭流控。
控制器索引可能变化，应按 Realtek 厂商号 93 和 UART5 的 sysfs 路径识别，
不要把树莓派内置的蓝牙控制器当作 Green2。若控制器被 rfkill 软件禁用，
先用 `sudo rfkill list` 查出该控制器编号，再只解除它的屏蔽。

2026-11-09 已完成两线配置的编译、COM33 烧录校验和 BlueZ 实测：Green2
识别为 Realtek 93 / Bluetooth 5.4，12 秒 LE 扫描收到 911 条设备报告；
Green2 的 `Green2-HCI-Test` 广播由树莓派内置蓝牙收到 6 次，测试后已移除
临时广播。扫描结束时 HCI RX/TX 错误计数均为 0。测试期间 NAN 发布服务
运行；本次没有验证 BLE 连接传输、休眠或 NAN 数据传输并发性能。

编辑修复源码后，选择源码构建，或先重建打包库：

```sh
NAN_PREBUILT_LIBRARY=OFF \
  component/wifi/whc/nan_test/module/build-firmware.sh "$PWD/build_RTL8711Dx_nan_source"

python3 component/wifi/whc/whc_dev/make_nan_fixed_library.py \
  --cross-compile "$HOME/rtk-toolchain/asdk-12.3.1-4600/linux/newlib/bin/arm-none-eabi-" \
  component/soc/amebagreen2/project/project_km4tz/lib/application/lib_wifi_whc_dev.a \
  component/soc/amebagreen2/project/project_km4tz/lib/application/lib_wifi_whc_dev_nan_fixed.a
```

生成器只接受 SHA-256 为
`9ade71dee6186bfb5bdc634869d577e38746971bcbf09d908d87a87015cdbe6a`
的原始库；私有结构偏移不适用于未经核对的其他 SDK 库。
硬件验证使用的 UART 下载参数为 1500000 baud，命令 `reboot uartburn`；
每次烧录前重新核对模组和串口。构建脚本不会操作硬件。

## 树莓派 SDIO 与驱动

已验证 1-bit / 24 MHz 接线：

| 树莓派 BCM GPIO（物理针脚） | Green2 Group1 |
| --- | --- |
| GPIO22（15） | CLK PA18 |
| GPIO23（16） | CMD PA19 |
| GPIO24（18） | D0 PA5 |
| GPIO25（22） | D1 PA20，含 SDIO 中断 |

共地并按模组要求供电；D2 PA4、D3 PA21 未用于本次 1-bit 测试。
在树莓派仓库根目录编译并安装本次使用的限频 overlay：

```sh
sudo apt-get install build-essential pkg-config linux-headers-rpi-v8 \
  device-tree-compiler iw net-tools git libnl-3-dev libnl-genl-3-dev \
  libssl-dev libjson-c-dev libglib2.0-dev python3
dtc -@ -I dts -O dtb -o /tmp/sdio-24mhz.dtbo \
  component/wifi/whc/nan_test/rpi/sdio-24mhz-overlay.dts
sudo install -m 644 /tmp/sdio-24mhz.dtbo /boot/firmware/overlays/
```

在 `/boot/firmware/config.txt` 的 `[all]` 下添加（已有则核对，避免重复）：

```ini
dtoverlay=sdio,poll_once=on,bus_width=1,gpios_22_25
dtoverlay=sdio-24mhz
```

要切换到 4-bit，Group1 还须接通 D2、D3：

| 树莓派 GPIO（物理针） | Green2 Group1 |
| --- | --- |
| GPIO26（37） | D2 PA4 |
| GPIO27（13） | D3 PA21 |

先确认六根 SDIO 信号线均已接好。将上述 `sdio` 行改为
`dtoverlay=sdio,poll_once=on,bus_width=4`，去掉 `gpios_22_25`，这样默认
启用 GPIO22–27。保留 `sdio-24mhz` 便于只比较总线宽度。Group1 模组固件
已配置 D0–D3，无需为此重编固件。停止服务、卸载 `whc_sdio` 后重启 Pi，
核对 `sudo cat /sys/kernel/debug/mmc1/ios` 的 `bus width: 2 (4 bits)`，
以及 `pinctrl get 22-27` 中 DAT0–DAT3 的复用。配置文件写成 4 并不等于
运行时已成功切换；还须检查枚举、CRC/超时日志及实际数据传输。

Pi 4B 的 `bcm2835-mmc` 使用偶数分频器。默认 250 MHz 输入下，仅设置
`sdio_overclock=80` 得到的是 62.5 MHz，不能据配置值声称已达到 80 MHz。
`sdio-80mhz-overlay.dts` 将外部 EMMC 输入设为 160 MHz，再以二分频输出
80 MHz；2026-11-09 此配置实际触发 `Overclocking to 80000002Hz`，但
Green2 在初始化时反复 `-110`，复位模组后仍失败，不能作为可用配置。
该实验文件保留用于诊断，正式运行不要默认启用。

`sdio-50mhz-overlay.dts` 使用独立的外部 EMMC 时钟 200 MHz / 4，目标为
标准高速模式的 50 MHz。两份 overlay 都只改 `fe300000.mmc` 的时钟 28，
不改根文件系统 SD 卡使用的 EMMC2；它们替换 `sdio-24mhz`，不能叠加。
Realtek RTL8711F 数据手册 v0.2.2 §7.7.1 列出的无线带宽是 20 MHz，
§7.15/§9.19 列出的 SDIO 高速上限是 50 MHz。Green2 的
`autoconf_8721f.h` 同样设置 `CONFIG_BW_MODE=0x00`；共享结构中的
`bw_40_enable` 字段及 Linux 驱动的通用 HT40 标志不能作为本芯片支持
40 MHz 的证据。

2026-11-09 改用 50 MHz 后，运行时确认为 4-bit / 50,000,001 Hz，网卡
正常枚举。iPhone NDP TCP 每方向 10 秒、共 3 轮，接收端平均上传
27.282 Mbps、下载 29.998 Mbps，双方字节数一致。未观察到 SDIO CRC 或
超时错误；下载期间仍有 6 次 `TXBD unavailable, TX FAIL`。这只完成了
短时负载验证。固件和双频设置沿用此前 5 GHz 测试，但 COM33 掉线导致
本轮缺少新的 NDL 信道记录，不能把实际数据频道视为已再次核实。

在 Pi 上编译安装 50 MHz overlay，并以它替换 `sdio-24mhz`：

```sh
dtc -@ -I dts -O dtb -o /tmp/sdio-50mhz.dtbo rpi/sdio-50mhz-overlay.dts
sudo install -m 644 /tmp/sdio-50mhz.dtbo /boot/firmware/overlays/
```

```ini
dtoverlay=sdio,poll_once=on,bus_width=4
dtoverlay=sdio-50mhz
```

在完整 SDK 源码目录编译驱动，`make prepare` 会复制必要的 SDK 头文件：

```sh
cd component/wifi/whc/whc_host_linux
make amebagreen2_sdio_nan_defconfig
make prepare
make -j4
sudo install -Dm644 driver/sdio/whc_sdio.ko "/lib/modules/$(uname -r)/extra/whc_sdio.ko"
sudo depmod -a
```

使用上述新驱动和模组固件冷启动后，运行 `sudo modprobe whc_sdio`，核对
`iw dev`、`dmesg` 与 SDIO vendor/device `024c:8006`。驱动名为 `WHC_SDIO`。
旧版本曾在卸载/重启时卡住，安装文件本身不会替换已加载的驱动。

## 树莓派服务编译

从仓库根目录执行。hostap 是独立依赖，固定到已验证提交，按其许可证获取源码：

```sh
git clone https://github.com/zephyrproject-rtos/hostap.git /tmp/hostap-pasn
git -C /tmp/hostap-pasn checkout --detach 1ce844ea5a9d8860d8690a125925fcc7274461df
cp component/wifi/whc/nan_test/rpi/hostap-pasn.config /tmp/hostap-pasn/wpa_supplicant/.config
make -C /tmp/hostap-pasn/wpa_supplicant -j4 libpasn.so
component/wifi/whc/nan_test/rpi/build-services.sh /tmp/hostap-pasn /tmp/green2-nan
sudo install -d /opt/green2-nan
sudo cp -a /tmp/green2-nan/. /opt/green2-nan/
```

产物包含 `rtw_aware`、`libnanapi.so`、`pasn_live`、`pasn_vendor_events`、
`libpasn.so`、配置和 TCP 回包脚本；库通过 `$ORIGIN` 从同目录加载。
`nan_r3`/`wpa_supplicant` 配置键是上游 JSON 格式所需，本测试路径不会启动它们。
`pasn_probe` 中较早的 `live_auth2.sh`/`live_pasn.sh` 仅保留作诊断工具，
正式复现使用直接 vendor-event 输入。

## 启动、配对与连接

停止之前的发布/应答/echo 测试进程。使用有线网络管理树莓派，核对 `iw dev`
中 Green2 对应的 PHY 和接口。下面示例假定它们为 `phy0`、`wlan0`、`wlan1`：

```sh
sudo nmcli device set wlan0 managed no
sudo nmcli device set wlan1 managed no
# nan0 已存在且属于 Green2 PHY 时跳过创建。
sudo iw phy phy0 interface add nan0 type __nan
sudo /opt/green2-nan/prepare-radio.sh wlan0 2GHz
sudo /opt/green2-nan/run-services.sh wlan0
```

NetworkManager 通常不列出 NAN 类型的 `nan0`，无需对它执行 `nmcli device set`。
`prepare-radio.sh` 在服务停止时重启 NAN 功能并明确设置频段，保留配对缓存。
当前使用 `2GHz` 做重复配对稳定性验证；`dual` 可恢复 2.4/5 GHz 对照。
该命令会中断现有 NAN 数据链路，不能在服务运行中执行；它不会卸载 SDIO 驱动。
`run-services.sh` 检查驱动、PHY、NAN 类型、重复进程与 NetworkManager 状态，
从实际网卡读取 MAC 写入运行配置，依次启动 vendor-event reader、PASN responder、
TCP echo 和无限时长发布（`-t 0`）。停止任一子进程会结束本次服务组。
不要再在该 PHY 上启动通用 `wpa_supplicant`：接口类型切换曾停止 NAN，导致随后
发布触发固件故障。示例 `rpi/green2-nan-test.service` 可用于手动 `systemctl start`，
前提是已完成上述接口准备；它不负责开机创建接口。

iPhone 打开 Flash Studio → NAN →「发现并配对 Green2」，选择设备并输入测试
PIN `123456`。已配对时保留授权，点击「搜索服务并连接」。发布服务名为
`_flashstudio._tcp`，IPv6 TCP 端口 8000；应用发送 `NAN-PING\n`，服务返回
`NAN-PONG\n`。echo 是最小测试端点，监听所有 IPv6 接口，不用于生产服务。

### NDP TCP 吞吐量

更新后的 `rpi/nan_echo.py` 同时提供旧版回包和 `NAN-THROUGHPUT/1` 双向
吞吐协议，继续使用 `_flashstudio._tcp` / IPv6 TCP 8000。WHC 模组负责
NDP 和无线收发，TCP 收发端点在 Linux 主机。iOS Flash Studio → NAN →
「NDP 吞吐量」可选择每方向 10、20、60 秒，然后「开始双向测速」。
自动启动参数为 `--nan --nan-throughput 10`；测试需要已有 Green2 授权。

上传、下载顺序复用一条 TCP 连接。发包不插入延迟，写入使用背压，发送阶段
结束后允许已排队数据排空。上传 Mbps 使用主机实际接收的字节和时间，下载
Mbps 使用 iPhone 实际接收的字节和时间；双方必须确认相同测试 ID、方向和
载荷字节数。发现/建链耗时另记，控制消息、帧头和无线协议开销不计入有效载荷。
因此结果是该 NDP 链路上的 TCP 有效吞吐，不是 PHY 速率。

协议（网络字节序）：

1. 客户端发送 `NAN-THROUGHPUT/1 <test-id> UPLOAD|DOWNLOAD <seconds>\n`；
   时长限 1–60 秒，服务端返回 `READY\n`。
2. 数据帧为 4 字节无符号长度和对应载荷，默认 64 KiB，上限 256 KiB。
   长度 0 表示本方向结束，不作为有效载荷计数。
3. 上传由客户端发帧，下载由服务端发帧。服务端在本方向结束后发一行 JSON，
   包含 `version/test_id/direction/bytes/seconds/mbps/counter`。
   上传的 `counter=received`，下载的 `counter=submitted`，下载最终速率由
   iPhone 的接收计时计算。每条控制消息最长 256 字节；异常/截断/超时只关闭
   当前客户端，监听服务继续运行。

App 可导出 `Documents/nan-throughput-<UUID>.json`，保留每方向双方字节数、
发送与接收时间、Mbps、发现/ready 时间及失败/取消状态。退到后台或停止时，
未完成的方向不记为成功。旧 `NAN-PING\n` 客户端仍保持一次请求后关闭的行为。
回归入口：`python3 component/wifi/whc/tests/test_nan_echo.py`。

5 GHz 对照需在模组构建时设置 `NAN_2G_ONLY=OFF`，解除此前的 2.4 GHz
硬件限制。NAN 必须保留 2.4 GHz 支持，不能仅启用 5 GHz 发现；应开启双频，
再核对每次 NDP 实际调度信道。保留 SDIO/H4 配置示例：

```sh
FIRMWARE_CONFIG="$PWD/component/wifi/whc/nan_test/module/green2_nan_sdio_bt_h4.config" \
NAN_2G_ONLY=OFF \
component/wifi/whc/nan_test/module/build-firmware.sh /tmp/green2-nan-5g
```

烧录新固件、重新枚举 SDIO、创建 `nan0` 后，用更新的服务脚本启动：

```sh
sudo /opt/green2-nan/prepare-radio.sh wlan0 dual
sudo /opt/green2-nan/run-services.sh wlan0
```

先用 `iw reg get` 核对设备所在地的国家码。测试环境为 CN，使用
`sudo iw reg set CN` 后同时核对 global 和 Green2 PHY 的规则；其他地区须
使用对应国家码。默认 `00` 的 5 GHz `no IR` 会使 Linux 6.18 拒绝启动，
报 `5 GHz band operation is not allowed`。

切换前先停止服务组，保留两端配对缓存。只切换发现频段不构成数据频段
证据；实测需核对运行时调度信道或空口记录，不能把“双频”直接标为 5 GHz。

2026-11-09 实测：iPhone 13 Pro ↔ Green2 SDIO ↔ Pi 4B，1-bit / 实际
20.83 MHz；每方向 10 秒、每组 3 轮，两端载荷计数全部一致。2.4 GHz
平均上传/下载 5.94/11.62 Mbps；5 GHz NDL 频道 36/149、20 MHz，平均
10.41/11.27 Mbps。5 GHz 组有两次 `TXBD unavailable`，TCP 测试仍完成；
本次不代表长期稳定性或无线速率上限。详细报告在配套 Flash Studio 仓库的
`NAN_VALIDATION.md` 和 `nan-test-results/20261109-throughput/`。

同日改为 4-bit、保持实际时钟 20.83 MHz 后，5 GHz 三轮全部完成，平均
上传/下载 **20.96/24.16 Mbps**。运行时确认 `bus width: 2 (4 bits)`，
DAT0–DAT3 复用正确，未观察到 CRC 错误；仍记录两次 `TXBD unavailable`。
报告位于配套 App 仓库的 `nan-test-results/20261109-throughput-4bit/`。

运行状态保存于 `/run/green2-nan`，配对缓存位于 `/var/lib/nan`（权限 0700，
NPK/NIK 文件 0600）。缓存只支持最新的单个 NPK；不要把密钥、原始 PASN 事件、
串口调试日志或抓包加入版本库。无需重新配对时保留两端缓存；需要清除配对时，
使用保持本机 NIK 的清理接口，并在 iPhone 设置中忘记对应设备。

## 验证记录与边界

2026-11-03 22:26 CST：iPhone 和树莓派均报告 datapath established，树莓派
收到 `NAN-PING\n`，用户确认 iPhone 已连接并收到回复。随后三次重新连接均达到
NDP established 和 TCP 输入。固件日志确认 `0x100` 调度 ID 正常返回，后续
使用至 `0x8000` 并正确移除，流程通过 Confirm → Security Install。

实机测试固件的 app SHA-256 为
`7a8217d87cfc602269e3636fef69cd19bff49d743fc99e384e4f2b342aa4e395`，
boot SHA-256 为
`91a8f9b458b299803da93df5f9fc83e3becb333715b409e714027b0945a52297`。
该实机版本采用源码包装方式；打包库的两个修复函数机器码已与其逐字节核对。
库打包方式和脚本整理后的服务另做编译验证，未重复烧录或替换正在运行的服务。
源码构建和打包库构建均生成完整 boot/app；修正库重复生成的 SHA-256 一致。
树莓派驱动与服务已在上述内核环境隔离编译，动态库依赖解析完整。

加密套件包装函数覆盖 216 组输入与失败/空指针路径，可运行：

```sh
gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  component/wifi/whc/tests/test_nan_pasn_cipher_fix.c -o /tmp/test_nan_cipher
/tmp/test_nan_cipher
```

本次结论限于单个 iPhone 的配对、验证、NDP 和小包 TCP 回包；长期稳定性、吞吐、
多设备并发、其他模组库版本尚未验证。库中私有 ABI 修复和单 NPK 应答器仍属实验实现。

### 2026-11-04：连续连接时漏收 NDP 确认

旧的 `nan_event.c` 在文本事件日志超过 102400 字节后执行 `killall iw`，
关闭读线程、删除文件，再重启 `iw event`。现场第五轮连接的 Auth3 成功，
但 08:28:22 CST 接收器正好重启，主机漏掉 Confirm/Established，20 秒后
报 `Data confirm not receive` 并主动结束链路。Linux 已收到该连接的 TCP SYN，
但没有确认事件就不会安装该 peer 的 IPv6 邻居项，因此没有正常回包。

当前实现使用独立 libnl socket 持续订阅 `nl80211/vendor`，按 Realtek OUI
和 NAN ifindex 筛选，每次解析完整二进制 payload。不存在事件文件轮转或
`killall iw`；停止时用私有唤醒管道退出接收线程。短报文/不完整可变长报文
不会触发业务回调。模拟回归测试覆盖 2000 组 NDP 生命周期、2238000 字节事件、
接口/OUI 过滤和长度边界：

```sh
gcc -std=gnu11 -g -fsanitize=address,undefined -fno-omit-frame-pointer -pthread \
  component/wifi/whc/tests/test_nan_vendor_events.c \
  $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) -o /tmp/test_nan_events
/tmp/test_nan_events
```

实机复测：用户确认连续 10 轮均连接并收到回复。08:35:36 CST 启动的新接收器
保持同一进程运行，随后日志累计 18 次 NDP established、18 次 `NAN-PING`，
没有短 payload 或 netlink 接收错误，旧事件文件也未继续增长。
同一测试期间另有 2 次 NDP Confirm 等待超时（08:36:55、08:37:36），后续连接
继续成功；这些单次建立失败尚未归因，本次修复不代表所有尝试都无超时。

另一次服务消失来自旧运行命令 `-t 86400` 在 `wait_time(uint16_t)` 中被截断。
部署时已切换为本目录启动脚本使用的 `-t 0`，表示持续发布。

### 2026-11-04：取消配对后的重新配对与发现

在 Flash Studio 改用 AccessorySetupKit 后，已完成应用内移除的真机验证。
重新输入 PIN 时，Green2 仍可能沿用前一次 verification 状态：事件类型为 2，
但空口 Auth1 是无 PMKID/NIRA 的 SAE commit，并带有 NPBA。`pasn_live.c`
只在完整、无歧义的 setup 报文上修正类型，同时将 Auth2 的旧 NIRA 改为
本地 DCEA 和请求的 NPBA，保留本地 CSIA/发布实例 ID。原 verification 的
NIRA/NPK 校验不变，PIN 和 Auth3 MIC 仍由 libpasn 验证，密钥只在校验后安装。

此外，iPhone 在 setup 完成后删除临时会话密钥，而 Green2 会继续用这把密钥
加密单播 Publish 回复，导致刚完成配对却搜索不到服务。对于 pairing 服务，
`rtw_nan_api_publish()` 设置 `solicited_tx_type = 1`，将发现回复发往 NAN
多播地址。保留服务的安全要求、PASN 校验和 NDP 加密；09:40:55 CST 空口已
确认 `51:6f:9a:01:00:00` 的未加密 SDF Publish。验证结果见本节后续记录。

在已有的 hostap `libpasn.so` 构建环境运行离线分类/属性回归测试：

```sh
NAN_HOSTAP=/tmp/hostap-pasn
cc -std=gnu11 -g -O1 -Wall -fsanitize=undefined -DCONFIG_SAE -DCONFIG_PASN \
  -I"$NAN_HOSTAP/src" -I"$NAN_HOSTAP/src/utils" \
  component/wifi/whc/tests/test_nan_pasn_setup.c \
  -L"$NAN_HOSTAP/wpa_supplicant" -Wl,-rpath,"$NAN_HOSTAP/wpa_supplicant" \
  -lpasn -lcrypto $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) \
  -o /tmp/test_nan_setup
UBSAN_OPTIONS=halt_on_error=1 /tmp/test_nan_setup
```

该测试覆盖 setup、220 种截断、PMKID/NIRA 验证请求、重复 IE、错误算法、
属性长度/容量边界、保留本机 CSIA 和配置位，以及拒绝时不部分改写事件。
测试不发送无线帧或访问配对缓存；已在树莓派通过 UBSan。

重复配对另有完成通知竞态：09:44:47 CST 的 native PASN_RESULT 仍携带旧的
verification 类型，先把发布程序推进到 GET_PASN_RESULT；外部应答器已验证
Auth3 的 setup 通知随后被当作 inactive 丢弃，漏发本端 NIK follow-up。
`rtw_aware.c` 现在允许同一 responder 在这一特定状态接受 setup 完成通知。
已完成的 setup、其他 peer、initiator、正在建立或已建立的 NDP 均不会重放。
不改变 PIN/MIC 校验或实际 verification；09:51:12 CST 已部署。
09:52:13、09:53:50、09:59:52 CST 均在实机触发该竞态并补发 NIK，配对完成。

完成通知回归测试只使用临时通知文件和模拟回调：

```sh
cc -std=gnu11 -g -O1 -fsanitize=undefined -ffunction-sections -fdata-sections \
  -Icomponent/wifi/whc/whc_host_linux/app/wifi_nan_utility/src/rtw_nan_api \
  component/wifi/whc/tests/test_nan_pasn_completion.c \
  $(pkg-config --cflags --libs json-c) -Wl,--gc-sections \
  -o /tmp/test_nan_completion
UBSAN_OPTIONS=halt_on_error=1 /tmp/test_nan_completion
```

09:55:09 CST 空口记录同一序列号的 Auth1 连续重传三次。原应答器每次重建
SAE/PASN 状态，Auth3 随后校验失败。当前在 10 秒窗口内按同一 peer 与完整
认证正文识别重传，保留握手状态并重发同一 Auth2；MAC Retry/Sequence/Duration
变化不影响识别，新的 commit/public key/bootstrap token 必须重新握手。
成功安装密钥后忽略重复 Auth3，避免重复安装导致 packet number 重置。
`test_nan_pasn_retransmit.c` 使用真实事件入口和模拟 nl80211 发送，通过 UBSan；
编译方式与 `test_nan_pasn_setup.c` 相同。实机 09:59:35、09:59:52 的 setup
和 09:59:41、10:00:23 的 TCP 回包成功，尚不能据此认定连续循环完全稳定。

后续 NDP 等待另有手机端异常：10:00 前及 10:03 的失败，与 iPhone 日志中的
`BCMWLAN Chip Trap~Type=4,PC=0x429FC4,LR=0x429FC1` 对齐。芯片重置后
加密 NDP 会话被终止，应用继续等待/重试。已排除“旧密钥加密”的初步判断：
首次密钥取证存在日志缓冲延迟，不能按事件行时间给所取密钥归属。
10:13:36 CST 在树莓派临时将 `gtk_enable` 设为 0 做单变量对照；这只是诊断，
未修改仓库默认配置，根因和最终解决方案尚待验证。

10:24 CST：组密钥关闭的对照未进入 PIN/PASN 阶段，无法据此判断对 NDP 芯片
异常是否有效；运行配置已恢复 `gtk_enable=1`。另修复发布程序的定时器生命周期：
Linux POSIX timer ID 0 也是有效 ID，原来的 `if (timerid)` 会漏删第一个定时器，
替换后旧定时器继续递增重试次数，解释了现场 5 秒周期却约 10 秒超时的现象。
现在显式跟踪 timer_active，创建前删除旧定时器，创建/启动失败及时清理。
responder setup 留出 120 秒人工输入 PIN，verification/NDP 仍为 20 秒。
`test_nan_pasn_completion.c` 增加真实定时器替换/失效检查及分别验证两类超时，
已在树莓派通过 UBSan。10:24:30 CST 已部署；iPhone 芯片异常仍未证实解决。

10:25–10:30 CST PIN 失败进一步定位：第一轮 iPhone 在发送 Auth1 后约 0.1 秒
报告 `Authentication request transmission failed`，Green2 没有 PASN start 事件。
手机重开 Wi-Fi 后，10:30:37 Green2 收到 Auth1 并发送 Auth2；iPhone 日志确认
Auth2 校验成功并进入 Auth3，但 Auth3 四次发送均返回失败，Green2 未收到 Auth3。
因此这一轮不属于 PIN/MIC 校验失败。频道 6 空口中的 Auth2 位于 DW 起始后
约 3 TU；手机日志同时存在 5 GHz map 的 OOB 发送。跨频段调度仍是待验证假设，
不能仅凭 map 编号认定发错信道。Linux `whc_host_mgmt_tx` 当前忽略请求的
`tx_ch`，应答器命令行的 2437 MHz 不能作为实际发送信道的保证。
定时器修复的实机观测为 10:24:55 至 10:26:55，完整等待 120 秒。

10:39 CST：在停止发布/应答进程、取消已有发布后，通过 `iw wdev 0x5 nan stop`
和 `ip link set nan0 down` 完成 NAN 功能重启，未卸载 SDIO 驱动、重启树莓派
或删除配对缓存。该驱动的 NAN 接口具有 netdev；接口仍为 UP 时再次 start 会
被 cfg80211 以 EEXIST 拒绝，必须先 down。随后执行
`iw wdev 0x5 nan start pref 112 bands 2GHz`、`ip link set nan0 up` 并重启服务。
空口确认 Supported Bands=0x04、5 GHz DW=0。这是运行时单频对照，仓库默认
配置未改，PIN/连接结果待实测；wdev ID 每次必须用 `iw dev nan0 info` 重新确认。

10:40 CST：2.4 GHz 发现对照完成一次配对、verification、NDP 和 TCP 回复，
但连续测试第二轮仍卡在 PIN 前，因此不能认定频段限制已解决重复配对。
10:40:50 手机记录 bootstrap TX success，模组没有对应 BSTRAP 事件。
库内的 plaintext SDF 过滤条件与此吻合，但空口未捕获该次请求；新 RX 包装
是待验证假设，不是已经确认的根因。10:53 CST 实验固件经 COM33 烧录并校验
PASS；app SHA-256 `0123a27aa1e5c1764828ebd5ad2de1aea682432db9b0b44d2c76cd731b80daee`。
判定修正命中需要串口出现 `fresh bootstrap admitted with previous peer TK`，
并完成至少三轮取消/重新配对/回包。发现只宣告 2GHz 并不保证 NDP 也在 2GHz：
成功记录仍有 peer ch=36。

bootstrap 回归测试（主机运行，不操作硬件）：

```sh
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  component/wifi/whc/tests/test_nan_bootstrap_fix.c \
  component/wifi/whc/whc_dev/whc_dev_nan_bootstrap_fix.c \
  -o /tmp/test_nan_bootstrap_fix
/tmp/test_nan_bootstrap_fix
```

覆盖截断、重复/错误属性、错误帧类型、protected/DS/multicast、拒绝其他安全
属性和保留原目的地址比较；实际 iPhone 337 字节引导请求亦通过解析。

11:25 CST 阶段记录：实验 bootstrap RX 条件未在实机命中，不能据五次回包
宣称重复配对已修复。iPhone 在 10:58:45 和 10:59:13 发生同一 Wi-Fi 芯片
Trap；此时 PASN 已完成，但主机未收到 NDP request，也未发送 NDP response。
后续自动重试才回包。GTK=0 对照的身份 NIRA 校验通过，手机持续收到发现
结果，但未推进到 PASN/NDP，不能用来判断 NDP Trap。11:14 已恢复 GTK=1。
11:17:50 PASN/NDP 建立，11:17:51 收到 TCP，用户确认秒连。该次 iPhone
日志归档截断，不能声称手机侧“未发生 Trap”；以主机/空口和用户观察为准。
用户随后选择保留配对的 100 次连续重连压测。测试固件新增显式
`NAN_2G_ONLY=ON` / `AMEBA_GREEN2_NAN_2G_ONLY`，通过 SDK 的
`wifi_user_config.freq_band_support=RTW_SUPPORT_BAND_2_4G` 限制硬件频段，
避免只设置发现 DW 后数据链路仍选择 5 GHz。默认 OFF。压测结果待记录。

11:35 CST 2.4 GHz 压测准备完成：专用固件已烧录校验 PASS，
app SHA-256 `ae54431f53143e0a678445ff4ff9e1db29e104e18c8f4777df9c1439fbba54fe`，
产物保存于 `build_RTL8711Dx/nan_2g_stress_20261104/`。通过符号地址核对
`wifi_user_config.freq_band_support=1`，运行时 MLME band=1；NANDOW
device capability 返回 supported_bands=0x04。已恢复 2GHz NAN、发布、
PASN 应答器和 TCP 服务，GTK=1，原有 NIK/NPK 缓存保留。

iPhone 自动压测代码位于 flash-studio-ios 的 `NANBench.swift`，
通过 `--nan --nan-stress 100` 启动（或 NAN 页的“开始 100 次”）。
逐轮创建浏览器和连接、校验完整 9 字节 NAN-PONG、关闭连接，间隔 3 秒，
每轮 30 秒超时；每轮原子保存 Documents/nan-stress-<epoch>.json，
包含成功/失败、发现/ready/总耗时及错误。先做少量实机预检，然后正式 100 轮；
须核对主机 NDP teardown 次数和实际协商信道，不能仅按 TCP 回包数认定
100 次 NAN 数据链路重建。当前 Xcode 构建通过，但 iPhone unavailable，
**尚未安装压测版，也尚未开始正式 100 轮测试**，等待 USB 重新连接。

### 2026-11-04 16:34 CST：100 轮实测及 TCP 服务超时修复

iPhone 接回后已安装压测版，保留配对、2.4 GHz 专用固件完成 100 轮应用
发现/TCP 重连：67 成功、33 失败；成功耗时中位 6.61 秒，P95 25.31 秒。
iOS 会复用部分底层 NDP，因此不能视为 100 次独立 NDP 重建。
第 92 轮期间旧 TCP 服务在 `recv()` 超时后整个进程退出，影响最后阶段；
退出前前 91 轮仍有 24 次失败，故不能把所有失败归因于 TCP 服务。

`rpi/nan_echo.py` 现按客户端隔离网络异常，并发处理连接，按字节流读取
完整请求且限制总读取时间。回归：`python3 component/wifi/whc/tests/test_nan_echo.py`。
本地两项测试通过；已部署树莓派，并验证真实 10 秒空闲连接超时不再杀死
监听或阻塞其他客户端。修复后 iPhone 3 轮为 2 次建链超时、1 次成功回包，
服务保持运行。NAN 建链稳定性仍待解决。
完整结果见本机 `/home/zxf/flash-studio-ios/NAN_VALIDATION.md` 及
`nan-test-results/20261104-iphone-2g/`；修复后尚未重跑完整 100 轮。

### 2026-11-04 16:46：三路同步抓到后续 NDP 的 PMK 丢失

保持配对与当前固件做 5 轮：1 成功、4 超时。第二轮同一 peer 先完成
PASN 与 NDP ID 1；收到后续 ID 2 请求时固件释放 peer、清除 pairwise key
及 publish PMK，再分配新 peer，响应日志明确报 `ndp setup rsp fail no nm-pmk`。
iPhone 随后报 request retries exceeded。精确 ELF 的 `rtw_nan_ndl_nego_rx`
在 0x04044aea 调用 `rtw_nan_peer_info_free` 的分支与日志一致；
`rtw_nan_ndp_response_prehandle` 在 PMK 为空且 peer 安全上下文缺失时进入
该错误路径。优先分析/修复新 NDL 请求下的 peer/PASN 生命周期，不能简单
全局关闭密钥清理。此轮仅采集和分析，尚未实施这个修复。

第五轮已 ready 但无 TCP 回包，空口同一 Green2 数据帧有 26 次 Retry，
这是另外一个待确认的问题。完整时间线、边界和反汇编证据见
`/home/zxf/flash-studio-ios/NAN_VALIDATION.md` 的“三路同步采集”记录，
数据在该项目 `nan-test-results/20261104-failure-threeway/`。

### 2026-11-04 17:20：NDL peer 保留与重复请求处理

新增 `whc_dev_nan_ndl_peer_fix.c` 和对象生成器。生成器固定校验
`rtw_nan_data_ndl.o` SHA-256
`ccd8b4dc90f1e228faf3d46d71cb9ab65b312171529e5f373be0a10005fc8817`，
只把 `rtw_nan_ndl_nego_rx+0x3c` 的 CMP/BNE 换成跳转门；原厂对象不改。
接收受保护、同 NMI、已安装 TK 且安全上下文非空的 NDP Request 时，跳过
旧 peer 的释放/重建。其他请求走原分支，取消配对和超时清理不变。

第一版两组各 5 轮分别为 5/5、2/5 成功，未再出现 `no nm-pmk`，但捕获到
重复 ID 1 Request 在等待 Confirm 时把 NDL 从 None 切到 Rx Request，随后
连续出现 `no ndl attri & ndl state not none` / `NDL yet established`。
第二版通过有界属性解析、NDP ID/token/NDI 及 entry state=4 匹配，令这类
重传跳过 NDL 重新协商，仍由原 NDP 接收函数检查其状态。

本机 ASan/UBSan 回归覆盖截断、同/异事务、错误来源、安全状态、冲突属性；
源码和打包库两条构建路径均通过。267 个原库成员仍逐字节相同。
重传修正版于 17:11:58 经 COM33 烧录并校验 PASS，产物在
`build_RTL8711Dx/nan_ndl_peer_fix_v2_20261104/`；app SHA-256 为
`6bd11c079538c0530e2e2fcda1439b7dfb61ef4c32d5d53e5aaa914a05aeaea2`。
更新后的修正库 SHA-256 为
`fdbb5b6ebe59a1221444afbc57bcd5c9518316b5fe350694e7ec783ecfeae088`。

```sh
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  component/wifi/whc/tests/test_nan_ndl_peer_fix.c \
  component/wifi/whc/whc_dev/whc_dev_nan_ndl_peer_fix.c \
  -o /tmp/test_nan_ndl_peer_fix
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 /tmp/test_nan_ndl_peer_fix
```

17:14:45–17:17:19 保留配对、GTK=1、2.4 GHz 的 10 轮应用重连为 **8 成功、
2 超时**；成功中位 4.09 秒，最慢 29.42 秒。观测到 5 次 PASN/NDP 成功
协商，部分应用轮次复用底层链路，不能视作 10 次独立 NDP 建立。
本轮没有 `no nm-pmk` 或 NDL 状态冲突，但重传专用门尚未命中，不能据此
断言该修复已通过实机回归。手机仍记录 5 次 `BCMWLAN Chip Trap`，第二、
第四轮超时与其中两次对应；其它重置被自动恢复掩盖，**连续重连尚未修好**。

重置前空口有单播及广播调度更新，尚未证明触发关系。Wireshark 对广播帧
尾部 MMIE 的 NAN 属性长度报错不能直接当作报文损坏：其尾部实际为
Element ID 76、长度 16 的 MMIE，需先区分解码器边界与真正的格式问题。
本轮未导出密钥或解密 Action。三路证据与轮次结果保存在本机
`/home/zxf/flash-studio-ios/nan-test-results/20261104-ndl-peer-fix/`。
采集已结束，RouterOS 已恢复原频道，Pi 三个测试服务保持 active。

### 2026-11-04 17:31：不改配置的 5 轮复核

三路采集确认就绪后，以同一 NDL v2 固件做 5 轮：第 1/3/5 轮分别在
3.39/2.96/3.46 秒收到回复，第 2/4 轮 30 秒超时。两次失败均已发现服务，
手机尝试使用已有 endpoint，随后发生 `BCMWLAN Chip Trap`，未 ready；
Pi 服务均 active，没有新出现的 `no nm-pmk` 或 NDL 状态冲突。

本轮 3 次 Green2 Committed Availability 收缩到 `0e-00-00-00` 后约
301–437 ms 手机重置，其中一次发生在最后一轮回包之后。另 5 次较大窗口
更新没有在 1 秒内触发 Trap，故下一步集中检查调度收缩与既有 NDP 状态。
但上轮相同位图存在未立即重置的反例，不能将该位图单独认定为根因。
完整时间线与 PCAP 帧号在本机 `flash-studio-ios/NAN_VALIDATION.md`，
证据在该项目 `nan-test-results/20261104-five-rounds-1731/`。本轮未改代码、
未刷新配对或烧录；采集结束后已恢复 RouterOS，Pi 服务仍运行。

### 2026-11-04 18:00：解密调度通知后的新定位

只读提取仍驻留的最后一个测试会话密钥后，已对 5 个 NDP 握手帧及 10 个
后续管理帧完成 CCMP 标签校验。私有密钥/解密原始帧未入库；脱敏字段与
精确 ELF 反汇编存于本机 `flash-studio-ios/nan-test-results/20261104-schedule-root-cause/`。

原始帧 1085 的 NDL Response 为 Accepted (`0x11`)，却新增了手机未请求的
Immutable Schedule，覆盖 1024 TU 周期内槽位 2–7、34–39（16 TU/slot）。
`rtw_nan_ndl_attri_construct` 在 `0x040396da` 无条件序列化 committed
schedule 并于 `0x040396ea` 标记 Immutable Present；没有区分 Accepted
Response。参考 hostap 的 `nan_ndl_attr_handle_resp()` 会拒绝这个组合。
后续 Schedule Update 不带 NDL 属性，原始帧 1203 将 Committed 缩为
`0e000000` 后，缺少先前 Immutable 中的槽位 4–7、36–39。
这一已证实的字段矛盾是下一步单变量修复的优先对象，尚未通过实机对照
证明它就是 iPhone Chip Trap 的唯一触发原因。

另一个独立缺陷是 NDC Control 保留位未初始化：
`rtw_nan_ndc_attri_contruct` 的 `0x04039496–0x0403949e` 只对原缓冲字节
OR 1；同一帧实际发出 `0x5b`，后续通知则是 `0x01`。

前述两个“相同位图反例”已进一步解释：一次在 0.687 ms 内恢复大窗口；
另一次 `wifip2pd` 已在 313 ms 后报告驱动不可用，只是 `wifid` 的 Chip Trap
记录更晚。跨两批测试，8 次未立即恢复的小窗口更新均在 170–314 ms 后
驱动掉线，8 次固件重置的 PC/LR 都是 `0x429FC4/0x429FC1`。
本次没有修改固件或运行配置；下一步先修正 Accepted Response 的 Immutable
语义并单独复测，再处理 NDC Control 初始化。详细边界和证据见
`flash-studio-ios/NAN_VALIDATION.md` 对应记录。

### 2026-11-04 18:24：调度响应修复与两组 5 轮验证

新增两项源码 wrapper，并同步接入源码构建、打包库及链接选项：

- `whc_dev_nan_ndl_immutable_fix.c`：仅处理 Accepted NDL Response。在原构造
  函数返回后、下一属性及 MIC/CCMP 生成前，移除 Immutable Schedule，清除
  Present 位，修正属性长度、帧长度和写入游标。保留 dialog、status、NDC、
  QoS 及可选 peer/idle 字段；其他协商类型和异常布局保持原输出。
- `whc_dev_nan_ndc_control_fix.c`：对已构造的有效 NDC 属性清零 Control
  保留位，仅保留 Selected NDC；不改 NDC ID、调度、长度或游标。

对应两个 `tests/test_nan_*_fix.c` 使用捕获的原始属性回归，覆盖后续 TLV
位置、截断、长度不一致、其他协商状态、可选字段及保留位，ASan/UBSan
通过。源码与打包库构建均通过；反汇编确认两个构造调用均进入 wrapper。
打包库保留 267 个原厂成员逐字节不变，另含 8 个修复对象，基础库 SHA-256
仍受严格检查。

先只烧录 Immutable 修正，在 18:15:41 开始 5 轮：**5/5 回包成功**，
耗时 7.58/1.70/3.17/1.68/2.21 秒，中位 2.21 秒。空口仍有 6 次广播收缩到
`0e000000`，手机日志持续至 18:19:25，未出现驱动重置或 Chip Trap。
解密并校验帧 360，确认 Accepted NDL Control=`0x0c`、无 Immutable；
这轮原 NDC Control 恰为正常的 `0x01`，所以不能仅凭这组对照排除 NDC
未初始化内容曾参与旧故障。

再加入 NDC Control 修正，18:20:54 烧录校验 PASS，18:24:00 开始第二组：
**5/5 回包成功**，耗时 5.43/1.17/2.60/2.14/1.55 秒，中位 2.14 秒。
已解密确认帧 310 的 NDL Control=`0x0c`、无 Immutable，NDC Control=`0x01`。
两组各只观察到一次 PASN/NDP 建立，后续应用重连复用 NDP；不能将 10 次
回包当作 10 次独立 NDP 建立，也还没有完成 100 轮或取消配对回归。

最终在板固件：`build_RTL8711Dx/nan_schedule_fix_20261104/`，app SHA-256：
`4d57a5b94921b7077186390285bada35ea15ddc3387b354cfd58d17569d82455`。
打包库 SHA-256：
`5f56e4d4cf7d7d9af44b162f23bf4f5185bca3b26b88a91cbaf175cfcdef96d2`。
第一组对照固件保留在 `build_RTL8711Dx/nan_immutable_fix_20261104/`。
两组脱敏证据分别位于本机 `flash-studio-ios/nan-test-results/` 下的
`20261104-immutable-fix/` 与 `20261104-schedule-fix/`；密钥不入库。

## 2026-11-08：NAN over USB / VMware Ubuntu

EV711FL0 已通过原生 USB 连接 VMware Ubuntu 26.04，内核
`7.0.0-38-generic`。USB 枚举为 `0bda:f851`，`WHC_USB` 驱动绑定成功，
总线速率为 High-Speed 480 Mbps（不是实测无线吞吐）。
日志确认 PIN/PASN 配对成功、2 次 NDP established、6 次合法的
`NAN-PING\n` 请求；iPhone 用户确认连接并收到回复。
该结果证明基本发现、配对和数据通路，不代表已完成 USB 长时间压测。

模组配置保留 UART0 蓝牙 H4，改用 USB WHC 和 Flash Boot：

```sh
export RTK_TOOLCHAIN_DIR="$HOME/rtk-toolchain"
export PATH="$PWD/.venv/bin:$RTK_TOOLCHAIN_DIR/prebuilts-linux-1.0.3/bin:$PATH"
FIRMWARE_CONFIG="$PWD/component/wifi/whc/nan_test/module/green2_nan_usb_bt_h4.config" \
NAN_2G_ONLY=ON \
  component/wifi/whc/nan_test/module/build-firmware.sh "$HOME/green2-build/nan-usb-bt-h4"
```

两种 WHC 总线使用同一 `lib_wifi_whc_dev.a`。CMake 已允许 USB 使用现有
NAN 修复，仍校验原库、私有 NDP 对象和修正库的 SHA-256，未放宽 ABI 检查。
本次使用 ASDK 12.3.1 build 4600，打包修正库构建；COM37 UART 下载后
boot/app 均通过设备校验，启动日志显示 `USB device init done!`。

主机驱动使用以下配置，不启用 HCI firmware download：

```sh
cd component/wifi/whc/whc_host_linux
make amebagreen2_usb_nan_defconfig
make prepare
make -j4
sudo install -Dm644 driver/usb/whc_usb.ko "/lib/modules/$(uname -r)/extra/whc_usb.ko"
sudo depmod -a
sudo modprobe whc_usb
```

EV711FL0 的 USB1（Type-A）连接 PA4 D+ / PA5 D−，须断开复用的 SDIO
接线；板上 Type-C/USB 串口用于日志和下载。VMware 应将运行态的
`0bda:f851` 网卡接入 Ubuntu，下载串口留在 Windows。不要只依据下载模式
曾出现的 `0bda:8006` 设置运行态设备过滤。

服务继续按上文构建。`prepare-radio.sh` 和 `run-services.sh` 已支持
`WHC_USB`，并识别其位于 USB device 子接口下的 driver 绑定。
用 `iw dev` 确定真实 base interface 和 PHY；本次 base 为
`wlx94c9605906fe`，NAN 设备为 `nan0`。

Ubuntu 的 udev 可能把刚创建的 `nan0` 重命名为 `enx<MAC>`：创建后先运行
`sudo udevadm settle`，再用 `iw dev` 确认名称。若发生重命名，须将对应
NAN 接口置 down 并用 `ip link set dev <实际名称> name nan0` 改回，再调用
`prepare-radio.sh <base> 2GHz` 和 `run-services.sh <base>`。
本轮通过手动改名验证，尚未加入自动创建接口或开机启动流程。

固件 SHA-256：

- boot.bin：`5b5cc9de84132d757e65ba025c9ec02114f4a2449f832e75e5d6f9782391a28d`
- app.bin：`36e36d47e97c711595199564a4ae2a618aab7d779186f4cd83e3907271eac103`

### NAN + BLE 共用 USB（Flash Boot）

`module/green2_nan_usb_bt_usb.config` 将蓝牙从 UART H4 切换到
`CONFIG_BT_INIC_SHARE`，SDK 自动选中 `CONFIG_BT_INIC_USB`，编译
`bt_inic_usbd.c` 和 `bt_inic_usb.c`。WHC 负责唯一的 USB device 实例，
蓝牙接入其 HCI command、ACL、event 回调；不能再初始化第二套 USB stack。

```sh
export RTK_TOOLCHAIN_DIR="$HOME/rtk-toolchain"
export PATH="$PWD/.venv/bin:$PATH"
FIRMWARE_CONFIG="$PWD/component/wifi/whc/nan_test/module/green2_nan_usb_bt_usb.config" \
NAN_2G_ONLY=ON \
  component/wifi/whc/nan_test/module/build-firmware.sh "$HOME/green2-build/nan-usb-bt-usb"
```

本次 EV711FL0 的 NIC 模式 BT 使能位为 0，SDK 原本会隐藏 USB BT 接口。
新增默认关闭的 `CONFIG_BT_INIC_USB_SW_ENABLE`，仅在这份配置中启用，
让具备蓝牙硬件的 Flash Boot 开发板通过软件暴露 BT；不写 OTP。
枚举仍是 `0bda:f851`：接口 0 为 HCI、接口 1 为 SCO、接口 2 为 WHC Wi-Fi。
USB 端点：BT `81/02/82/03/83`，Wi-Fi `84/05/06/07`。

主机侧必须同时具备两项修正：

- 本目录 WHC 驱动在 probe 开始前检查 Wi-Fi bulk 端点，避免按 VID/PID
  匹配时抢占 BT 接口或清空已经运行的 Wi-Fi 全局状态。
- `rpi/patches/0001-btusb-green2-flash-boot.patch` 在 Linux `btusb` 的
  Realtek 通配项之前加入 `0bda:f851` 例外，使用通用 USB HCI。
  模组已经加载控制器固件，无需 `btrtl` ROM 下载流程。未修正时，Ubuntu
  的 `0xfc61` 厂商命令超时会反复 reset 整个复合设备，连带中断 WHC。
  此补丁针对 Flash Boot，不适用于需要主机下载 BT 固件的 ROM 配置。

本次 `btusb` 使用与运行内核匹配的 Ubuntu
`linux-source-7.0.0=7.0.0-38.38`。从 source package 解出源码后：

```sh
# 在解出的 linux-source-7.0.0 根目录操作，PATCH 指向上述补丁的绝对路径。
patch -p1 < "$PATCH"
printf 'obj-m += btusb.o\n' > drivers/bluetooth/Makefile
make -C "/lib/modules/$(uname -r)/build" M="$PWD/drivers/bluetooth" modules -j4
sudo install -Dm644 drivers/bluetooth/btusb.ko \
  "/lib/modules/$(uname -r)/updates/green2/btusb.ko"
sudo depmod -a
```

安装后须重载 `btusb` 或重启，`modinfo -n btusb` 应指向 `updates/green2`。
卸载 `btusb` 会断开这台主机的所有 USB 蓝牙设备，应先结束相关连接。
内核升级后需要重新编译安装；这里没有安装 DKMS 自动构建。

BLE 测试使用 Ubuntu BlueZ 的 GATT server；模组负责 HCI controller 和射频。
先用 `bluetoothctl list`、`/sys/class/bluetooth/hci*/device` 确认适配器归属，
不要把 `hci1` 当成固定编号。本次 Green2 是 `hci1`，地址
`94:C9:60:59:06:FF`；另一只 USB 蓝牙是空口客户端 `hci0`。

```sh
sudo apt install bluez python3-dbus python3-gi
sudo python3 rpi/ble_gatt.py --adapter hci1
# 在另一终端，用独立蓝牙控制器扫描、连接并验证通知：
sudo python3 rpi/ble_client_smoke.py --adapter hci0 --rounds 10
```

广播名 `Green2 BLE`，service UUID `7b183224-9168-443e-a927-7aeea07e0001`，
characteristic UUID `7b183224-9168-443e-a927-7aeea07e0002`，支持 read/write/notify。
写入 `BLE-PING\n`，返回 `BLE-PONG\n` 通知。向 GATT server 进程发送
`SIGUSR1` 可对已订阅客户端发送 `NAN-READY\n`，供后续唤醒流程接入。
手动调试也接受不带换行的 `BLE-PING` 或 CRLF 结尾；回复保持 LF 结尾。
本程序尚未接入 iOS AccessorySetupKit、CoreBluetooth 后台恢复或休眠控制，
也没有对测试 GATT 特征强制配对加密。

2026-11-08 18:43:58–18:44:59（UTC+8）共存验证：同一条 BLE 连接完成
1000/1000 次 write + notification 回包，中位 60 ms，最大 112 ms；
同一时间窗口 NAN TCP 服务收到 48 次有效请求，iPhone 用户确认收到回复。
这验证了两个 USB 接口和无线业务的并行通路，不等同于 1000 次重新连接，
也不代表已经完成长时间稳定性或休眠功耗测试。测试后两个服务保持运行。

此次固件经 COM37 下载，boot/app 校验均通过：

- boot.bin：`b7dd3adeec09710f0cbfdaa2f854de6b4784290f57a227ae6125bb95094a3dab`
- app.bin：`585fa20deaa4c20257896f0dae5aa05bb84629a8da70e20a65e4e3ae0c4a9f53`

### 2026-11-09：WSL USB/IP 启动顺序

Ubuntu 24.04 WSL2 使用 `6.6.87.2-microsoft-standard-WSL2`。从 Microsoft
`WSL2-Linux-Kernel` 的 `linux-msft-wsl-6.6.87.2` tag、运行内核的
`/proc/config.gz` 和 GCC 11 构建 `Module.symvers`，再编译本仓库 WHC USB
驱动和上述 btusb 例外。模块安装到
`/lib/modules/$(uname -r)/updates/green2/`；没有替换运行内核。

新板 Wi-Fi MAC 为 `94:C9:60:59:06:FC`，USB HCI 地址为
`94:C9:60:59:06:FD`。usbipd-win 5.3.0 将原生 USB `0bda:f851`、
COM3 的 CH340 `1a86:7523` 和摄像头 `30c9:00a6` 分别直通。
摄像头生成 `/dev/video0`，640×480 MJPEG、60 帧采集测试通过。
BUSID 和 Linux 接口编号应每次重新确认，不能当作固定硬件身份。

复合设备的 HCI 接口可能先于 WHC 完成 probe。旧固件收到第一个
HCI Reset 时，串口显示 `WiFi is OFF! Please Restart BT after Wifi on!`，
Linux 随后报告 `Opcode 0x0c03 failed: -110`。在 Wi-Fi 就绪后单独重新
绑定 btusb，控制器即能完成初始化，证实启动顺序依赖。

Green2 USB HCI 固件现按以下顺序启动：

1. 创建 WHC 发送队列和 API 事件锁。
2. 初始化 Wi-Fi；USB 尚未配置时释放待上报数据，不访问 USB 端点。
3. 加载蓝牙控制器补丁并完成内部 HCI Reset，暂用内部 HCI 接收回调。
4. 建立 USB 同步资源、BT 收发队列，再接入 HCI 转发回调并启动 USB。
5. 主机请求 Wi-Fi-on 时补发早期未送达的 STA MAC 信息。

Wi-Fi 或蓝牙初始化失败时不启动 USB，错误保留在下载串口。
这仍需要主机的 btusb Flash Boot 补丁，不能使用 stock btrtl 下载路径。

COM3 已确认 DTR 控制 BOOT、RTS 控制 EN；后续下载默认 1.5 Mbps。
测试产物和逐轮记录位于本机 `/home/zxf/green2-wsl-test-20261109/`。

WSL 的 CH340 USB/IP 串口在 1.5 Mbps 下出现长回读超时及写入帧校验错误；
因此本轮暂时将该串口交回 Windows，以 1.5 Mbps、每页 SENSE 确认完成下载，
boot/app 均校验 PASS，再将串口挂回 WSL。Windows 重装驱动后原 COM3
变为 COM39；脚本按已核对的 USB InstanceId、VID/PID 识别，不硬编码新 COM 号。
这不代表已验证 1.5 Mbps 经 USB/IP 烧录可靠；NAN/BLE 运行态 USB 仍直通 WSL。

修正后的 EN 复位启动日志按顺序出现 `Wi-Fi ready before USB`、
`BT controller ready before USB`、`[USBD-A] INIT`。第一次 USB attach 即完成
HCI 初始化，btmon 中首个 Reset 在 15.325 ms 后收到 Success，无需重新绑定。
WHC 也正确获得 STA MAC，NAN 接口为 `nan0`，发布名 `Green2 WSL`，
服务 `_flashstudio._tcp`，测试 PIN `123456`，本轮 NAN 使用 2.4 GHz。

13:08 的 iPhone 测试已完成 PIN/PASN、NDP 建链，用户确认连接并收到回复。
同轮 WSL 接收上传 17,235,968 bytes / 10.171 s，即 **13.56 Mbps**。
下载服务器提交 13,434,880 bytes / 10.162 s，即 **10.58 Mbps**；此数值为
发送端提交计数，尚未读取 iPhone 的最终接收计数，不能当作接收端有效吞吐。
BlueZ 的 `Green2 BLE` GATT 广播同时保持运行，BLE 空口收发另行核对。

后续将本板 BLE 广播名设为 `Green2 WSL BLE`（`ble_gatt.py --name`），
避免与其他 Green2 混淆。13:17:22，nRF Connect 写入不带换行的
`BLE-PING`，服务日志记录 `BLE-PING received`、`notify bytes=9`；UART
HCI ACL 同时确认 ATT Write Response 和 `BLE-PONG\n` Notification。
早先缺少换行的写入曾被旧服务拒绝，未计入通过次数。

保留 BLE 连接时，13:11:55 的 NAN 请求 `bytes=9 valid=True`，用户确认
收到回复；该连接在 13:12:18 仍在线且能发送 `NAN-READY\n` 通知。
这是基本功能及连接共存验证，未进行 100 次自动收发或长时间压测。
Windows 自带 `2c7c:0130` 适配器报告不支持 BLE Central，本轮 BLE 对端
使用 iPhone nRF Connect；没有修改 Windows 的蓝牙驱动或配对记录。

当前运行服务为 `green2-wsl-nan.service` 和 `green2-wsl-ble-test.service`，
由 `systemd-run` 启动。它们在本次 WSL 会话内持续运行；WSL 重启或 USB
重新接入后需重新确认接口并启动，尚未部署自动启动服务。

13:18 清理串口时，`stty -F /dev/ttyUSB0 -hupcl` 打开串口触发了控制线，
导致板卡进入复位、原生 USB 断开。该次断开由维护操作触发，不能计为
固件自行崩溃。随后显式释放 DTR/RTS、保留关闭 HUPCL 的设置，并重新
挂载原生 USB；恢复启动日志再次确认 Wi-Fi、BT 就绪后才启动 USB。
13:22 两项服务重新启动，核对到 `nan0` 为 UP、NAN 发布成功、TCP 8000
监听、BlueZ 广播实例为 1；恢复后尚未另做手机端收发测试。串口记录
进程已退出，避免继续占用下载口。此板打开串口前必须确认工具不会
自动拉动 DTR/RTS，不能把普通串口属性查询视为无副作用的操作。

本轮在板固件 SHA-256：

- boot.bin：`f25111408ab301aca60445af8790a6a7649bef8100e797e878561c02f2255a22`
- app.bin：`f0b1c3d5b27164cf8ff552df0294d375647d905f2d12eabd46265856b2d24127`

### VMware 内核串口与 panic 修复

关闭测试虚拟机后，在其 `.vmx` 中添加串口文件输出，启动前保留原配置备份：

```ini
serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "green2-kernel-serial.log"
serial0.startConnected = "TRUE"
serial0.yieldOnMsrRead = "TRUE"
```

Guest 中安装 `rpi/vmware-serial-console.cfg` 为
`/etc/default/grub.d/99-green2-serial.cfg`，执行 `sudo update-grub` 后重启。
`/proc/cmdline` 应含 `console=ttyS0,115200n8` 和 `earlycon=uart8250,io,0x3f8,115200n8`。
日志在宿主机虚拟机目录中的 `green2-kernel-serial.log`，SSH 失效时仍可读取；
不依赖截图。`panic=0` 保留崩溃现场，不自动重启。再次开机前先备份已有日志。

本次已验证早期启动和运行期内核日志都能输出。之前的 panic 栈为
`cleanup_net → addrconf_ifdown → rtw_inet6addr_notifier_call → __fortify_panic`：
WHC 地址 notifier 收到 loopback 等其他设备的事件，却把其 `netdev_priv`
当作 WHC 私有结构，用 `memcmp` 读取 9 字节，触发 FORTIFY。
现改为先按 `netdev_ops` 确认设备属于 WHC，再访问私有数据；注销时先停止
IPv4/IPv6 notifier，再排空工作队列。安装后，20 轮创建网络命名空间、
添加 loopback IPv4/IPv6 地址并销毁的回归通过，未再触发该 panic。

随后在停止发布、删除 NAN 接口时捕获到另一处 Oops：
`nl80211_del_interface → nl80211_post_doit → dev_put(wdev->netdev)`。
驱动在回调返回前释放了 `wireless_dev`，而 nl80211 仍持有对应 netdev 引用。
现通过 `needs_free_netdev` / `priv_destructor` 在引用排空后释放两者；
重复创建返回 `-EBUSY`，不再误清理现有接口；分配失败时先注销已注册网卡。
USB 移除路径先在 RTNL 下关闭 NAN netdev，再获取 wiphy mutex 进行注销。

还修正了 `prepare-radio.sh` 的停止顺序：先把 NAN netdev 置 down，
再执行 NAN stop。该驱动为 NAN 附加了数据 netdev，若先 stop 后 down，
cfg80211 会重复停止 NAN、扣减 opencount，导致 `wiphy_unregister` 永久等待。
原始 `iw ... nan stop` 也应遵守上述顺序。
修正后 20 轮创建/启动/关闭/删除、重复创建检查、整驱动卸载重载，以及
NAN 保持 UP 时卸载驱动的回归均通过。测试 VM 暂固定在
`7.0.0-38-generic`，配置位于 `/etc/default/grub.d/98-green2-test-kernel.cfg`；
解除固定前需给新内核重新构建 WHC 和 btusb 补丁模块。

### 2026-11-08：宿主机热点 TCP 测速

Green2 通过 WHC USB 接入 VMware Ubuntu，连接 Windows 宿主机热点 `AIoT`。
当前 `NAN_2G_ONLY=ON` 实际限制整个固件的频段，所以把无客户端的原
5 GHz 热点切为 2.4 GHz 后测试，没有重新烧录固件。协商结果为
Wi-Fi 6、信道 11（2462 MHz）、20 MHz、WPA3-SAE H2E、强制 PMF；
RSSI 约 −46 至 −47 dBm，观测 TX PHY 速率约 103.2–114.7 Mbps。
NAN 发布暂停，BLE 广播开启。测试不经过 Internet。

Linux iperf3 3.20 客户端绑定 Green2 的 `192.168.137.162`，连接 Windows
iperf3 3.21 服务端 `192.168.137.1:5201`。每项测试 15 秒，另省略开始 3 秒，
均报告接收端有效 TCP 吞吐；上行指 Green2 → 宿主机，下行反之。

| 条件 | 上行 Mbps | 下行 Mbps |
| --- | ---: | ---: |
| 默认省电，单流 3 次平均 | 8.53 | 6.66 |
| 默认省电，单流范围 | 6.92–9.92 | 4.61–8.67 |
| 默认省电，4 路并发 1 次 | 13.28 | 7.34 |
| 关闭省电，单流 1 次 | 10.46 | 7.41 |

同一 VM 经桥接以太网到宿主机的 5 秒 TCP 对照约 877 Mbps。
关闭省电未消除低吞吐，具体无线/USB 数据路径瓶颈尚未定位；
这不是 Green2 的峰值规格，也不是 NAN 数据链路吞吐测试。
修复后的当前启动周期未观察到 Oops、panic 或 WHC 命令超时。
原始 iperf JSON、路由/链路信息和串口现场保存在本机
`codex-debug/green2-hotspot-throughput-20261108/`；热点口令不写入工程。
结束后恢复 Wi-Fi 省电为 on，停止临时 iperf 服务，保留热点连接与 BLE 广播，
NAN 发布仍暂停。热点保持 2.4 GHz 以匹配当前固件。

### USB bulk 2048 字节对照配置

模组配置 `module/green2_nan_usb_bt_usb_bulk2048.config` 和主机驱动配置
`whc_host_linux/configs/amebagreen2_usb_nan_bulk2048_defconfig` 同时启用
`CONFIG_WHC_USB_BULK_2048`（默认关闭）。模组 USB RX 容量从 1536 调为
2048 字节，配套扩大 SKB 池；Linux RX URB 容量和 TX 长度上限从 1600
调为 2048 字节。启动时检查模组 SKB 是否覆盖 RX 容量及预留头部，避免
只扩大 DMA 接收长度而越过实际缓冲边界。

这是传输缓冲容量调整，High-Speed 端点的 `wMaxPacketSize` 保持 512。
每次发送仍使用实际帧长度，没有填充到 2048 字节，也没有新增 USB 聚合。
测试 5 GHz 时，模组构建需显式指定 `NAN_2G_ONLY=OFF`；原开关会限制
整个固件的频段。默认缓冲和 2048 缓冲的两份固件均采用双频配置对照。

实板启动日志确认 SKB 容量从 1632 增至 2144 字节，USB RX 预留头部
均为 64 字节；20 个 SKB 共多占 10240 字节，启动剩余堆差值与此一致。
usbmon 确认 Linux 实际提交的 RX URB 从 1600 变为 2048 字节，
数据帧的典型 TX 长度仍为 1530 字节。

2026-11-08 实测：两版均连接 AIoT 的 5 GHz 信道 149 / 20 MHz，
WPA3-SAE H2E、PMF、默认省电开启，BLE 广播开启、NAN 发布暂停。
沿用上面的 iperf3 15 秒加 3 秒预热方法，单流各测 3 次，四流各测 1 次，
均取接收端有效吞吐。

| 缓冲配置 | 单流上行均值 Mbps | 单流下行均值 Mbps | 四流上行 Mbps | 四流下行 Mbps |
| --- | ---: | ---: | ---: | ---: |
| 默认（主机 1600 / 模组 1536） | 53.41 | 49.73 | 50.14 | 49.35 |
| 主机与模组均为 2048 | 51.74 | 47.88 | 49.82 | 47.12 |

本轮没有观察到扩大缓冲带来的吞吐收益，单流约低 3–4%；样本量有限，
不能把该差异全部归因于缓冲大小。两版测速期间均未出现新的内核
Oops/panic、WHC 超时或 USB 重置。切换前直接卸载仍关联的 STA 曾触发
cfg80211 WARNING；后续先 `wpa_cli disconnect`、停 WPA 服务、关闭 STA
接口，再卸载驱动，未再次触发该警告。此顺序规避不代表卸载路径已修复。

Windows iperf3 在测试交接时偶尔拒绝或重置控制连接。脚本只对尚未建立
任何测试流的请求重试，并保留失败 JSON；不重试或抹去已经开始传输的
失败测试。完整原始数据、固件、驱动、usbmon、模组串口和内核日志位于
本机 `codex-debug/green2-usb-bulk2048-20261108/`。
结束时保留双频 2048 固件及对应主机驱动、AIoT 5 GHz 连接和 BLE 广播，
停止临时 iperf 服务；NAN 发布仍暂停。本次结果是 STA 热点测速，
不代表 NAN 吞吐或长期稳定性验证。

### 2026-11-09：Green2 SDIO 经 MikroTik 的 STA TCP 测速

树莓派 4B 的 Green2 使用 4-bit SDIO，运行时实际时钟 50,000,001 Hz。
暂停 NAN 后，以 STA 连接 MikroTik hAP ax²（RouterOS 7.25）的 `wifi1`：
频道 36 / 5180 MHz / 20 MHz，802.11ax 1x1，WPA2-PSK、MFP 开启。
测试期间未改 AP 配置；AP 发射功率为 4 dBm，原有 3 台其他客户端。
Green2 接收信号约 −59 至 −65 dBm，观测到最高 TX PHY 速率 114.7 Mbps。

Pi 的 iperf3 3.18 同时用 `-B 192.168.2.181 --bind-dev wlan0` 绑定
Green2，连接有线 Windows/WSL 主机上的 iperf3 3.16（192.168.2.69）。
每项测 15 秒，另省略 3 秒预热；表中均为接收端有效 TCP 吞吐，上传指
Green2 → 有线主机，下载反之。有线对照为 798.04 Mbps。流量经过
MikroTik AP 桥接；未在 RouterOS CPU 上生成测速流量。

| 条件 | 上传 Mbps | 下载 Mbps |
| --- | ---: | ---: |
| 省电开启，单流第 1 次 | 33.37 | 28.87 |
| 省电开启，单流第 2 次 | 36.88 | 24.96 |
| 省电开启，单流第 3 次 | 47.92 | 13.63 |
| 省电开启，单流平均 | 39.39 | 22.49 |
| 省电开启，4 流各 1 次 | 23.72 | 23.07 |
| 省电关闭，单流各 1 次 | 32.98 | 29.92 |

初次 TCP 建连超时一次，保留失败 JSON；连通性复查成功后，10 项正式
测试均完成。正式测试期间没有观察到 SDIO CRC、超时或内核崩溃，但
4 流上传期间出现 7 次 `TXBD unavailable, TX FAIL`；此前短时连通性
复查另出现 2 次。Pi 未报告降频/欠压，测得温度约 48°C。

下载存在明显波动，AP 发送 PHY 速率曾降至 17.2 Mbps。省电关闭对照
每方向只有 1 个样本，且无线速率及共享 AP 的负载未固定，不能据此把
波动全部归因于省电、SDIO 或某一个驱动环节；本表不是芯片峰值规格。

原始 iperf JSON、AP/STA 链路状态、内核记录、测试脚本及汇总保存于本机
`codex-debug/green2-sta-mikrotik-20261109/`。结束后恢复省电开启，删除
临时 STA 连接及运行时口令，停止测试服务器，恢复原 NAN 发布/PASN/TCP
服务，保留 4-bit / 50 MHz。配对缓存和 MikroTik 配置保持原状。

### Green2 HCI iBeacon 广播与 1 米参考功率

`rpi/ibeacon.py` 经 BlueZ 使用 UART5 的 Realtek `hci1`，默认广播
UUID `7b183224-9168-443e-a927-7aeea07e1001`、Major/Minor 1、100 ms legacy
非连接广播。`--duration` 控制时长，退出时删除本次广播，不覆盖其他广播。
`--duration 0` 持续广播，直到 SIGTERM/SIGINT；仍会在退出时清理广播实例。
树莓派已部署 `rpi/green2-ibeacon.service`，使用校准文件持续广播并开机自启，
依赖 HCI UART 服务启动，进程失败后每 5 秒重试。管理命令：

```sh
sudo systemctl status green2-ibeacon.service
sudo journalctl -u green2-ibeacon.service -n 20
sudo systemctl stop green2-ibeacon.service       # 本次停止
sudo systemctl disable --now green2-ibeacon.service  # 停止并取消开机自启
sudo systemctl enable --now green2-ibeacon.service   # 持续开启并开机自启
```

做临时广播测试前先停止此服务，避免广播实例冲突；测试完成后可再启动。
脚本会自动读取同目录 `ibeacon-calibration.json`；`--calibration PATH` 可指定
文件，`--measured-power DBM` 为显式覆盖。无文件且未覆盖时仍使用未经校准的
−59 dBm 占位值。校准文件必须匹配控制器地址、UUID、Major/Minor 和 1 米
参考距离；不匹配时在添加广播之前报错。

2026-11-09 在用户确认的约 1 米位置，用 iPhone 13 Pro 采集两段 RSSI，
排除每段前 10 秒后共 31 个有效样本，均值 −43.52 dBm、标准差 2.00 dB。
当前板卡参考功率取 −44 dBm，已保存于树莓派 `/home/axk/ibeacon-calibration.json`。
该值只更新 iBeacon 广播中的 1 米接收信号参考，不调整射频发射功率。
校准受环境和姿态影响，不能把距离估算视作精确定位。
固定位置的独立复测 RSSI 又降至平均 −49.42 dBm，估算距离约 1.86～2.04 米；
因此 −44 dBm 仅是本轮参考值，不能宣称已经验证精确的物理 1 米边界。

Flash Studio 使用有效估算距离 ≤ 1 米触发后台实时活动提醒，同一区域停留只
提醒一次，离开后重置。区域进入本身只启动测距。后台测距有时限，超过窗口
才靠近可能要等下次测距才会提醒。原始采样和结果位于 iOS 仓库
`nan-test-results/20261109-ibeacon-wake/`。
