# Green2 SDIO NAN：iPhone 配对、数据链路与 TCP 回包

本目录保存 2026-11-03 验证通过的实验配置和复现入口。SDK 基线为
`89b83feb6cd919db351e8751092516a8b7f96f30`（20261027）。

实机组合：Ameba Green2 RTL8711F / WHC SDIO Flash Boot / Group1，
树莓派 4B / Raspberry Pi OS Lite 64-bit / Linux `6.18.50+rpt-rpi-v8`，
iPhone 的 Flash Studio NAN 页面。最终测试从 SD 卡启动；原先的 SanDisk
USB 启动盘不属于本次成功验证的配置。

## 文件与修复范围

| 内容 | 源码/文件 |
| --- | --- |
| 模组修正库 | `component/soc/amebagreen2/project/project_km4tz/lib/application/lib_wifi_whc_dev_nan_fixed.a` 及 `.a.sha256` |
| PASN cipher 修复 | `../whc_dev/whc_dev_nan_pasn_cipher_fix.c` |
| FAW ID 修复生成器 | `../whc_dev/make_nan_faw_id_fix.py` |
| 完整静态库打包脚本 | `../whc_dev/make_nan_fixed_library.py` |
| 模组配置/构建入口 | `module/green2_nan_sdio.config`、`module/build-firmware.sh` |
| 树莓派驱动 | `../whc_host_linux/driver/`，配置 `configs/amebagreen2_sdio_nan_defconfig` |
| NAN 发布与事件解析 | `../whc_host_linux/app/wifi_nan_utility/{rtw_aware,src/rtw_nan_api}/` |
| 常驻 PASN 应答器 | 同上 `pasn_probe/{pasn_live,pasn_vendor_events}.c` |
| 服务构建/启动/回包源码 | `rpi/{build-services.sh,run-services.sh,nan_echo.py}` |

模组的两处修复：

1. `rtw_nan_ndp_response_prehandle` 原本把 PASN-128 请求的 cipher 7
   改成 SK-128 的 1。包装函数只修正成功的 PASN 响应，发生在构帧和 MIC
   计算之前；open、PSK、拒绝和失败路径保持原行为。
2. `rtw_nan_schdl_faw_act_add` 从调度项读出 32 位 bitmap，却用 `UXTB r0,r6`
   返回，导致 `0x100` 变成 0，被当作资源分配失败。生成器校验对象 SHA-256
   和指令后提取该函数，把返回指令改为 `MOV r0,r6`，保留其他指令和重定位。

`lib_wifi_whc_dev_nan_fixed.a` 包含原库的 267 个对象和两个修复对象。
原厂对象逐字节不变；这不是原厂闭源驱动的完整源码。必须通过 CMake 的
`--wrap=rtw_nan_ndp_response_prehandle` 和
`--wrap=rtw_nan_schdl_faw_act_add` 重定向调用，单独替换库却遗漏链接选项不会生效。
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
sudo ip link set nan0 up
sudo /opt/green2-nan/run-services.sh wlan0
```

NetworkManager 通常不列出 NAN 类型的 `nan0`，无需对它执行 `nmcli device set`。
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
