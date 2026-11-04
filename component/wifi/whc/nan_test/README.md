# Green2 SDIO NAN：iPhone 配对、数据链路与 TCP 回包

本目录保存 2026-11-03 至 11-04 验证使用的实验配置和复现入口。SDK 基线为
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
