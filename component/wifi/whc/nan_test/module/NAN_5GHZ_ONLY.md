# 强制 5 GHz NAN 实验

分支：`experiment/nan-5ghz-only`。默认关闭，不能视为量产能力。

保持现有 iPhone FlashStudio APP，使用 Green2 原生 USB + BT / bulk 2048 配置：

```sh
NAN_5G_ONLY=ON TOOLCHAIN_DIR="$HOME/rtk-toolchain" \
FIRMWARE_CONFIG="$PWD/component/wifi/whc/nan_test/module/green2_nan_usb_bt_usb_bulk2048.config" \
bash component/wifi/whc/nan_test/module/build-firmware.sh /path/to/new-build
```

设备侧实验约束：

- 软件频段 `RTW_SUPPORT_BAND_5G`；CN 的实验信道计划为 `0x6F`，保留 CN 功率表。
- `make_nan_5g_only_library.py` 检查输入 archive SHA256、成员 SHA256 和指令原始字节，拒绝未知库。
- 阻止初始化自动补回 2.4 GHz；NAN 自动选频改为 5 GHz；两个发现信道槽都初始化为 149。
- WHC NAN_START 忽略主机的其他频段请求，强制 mask=2，检查 mask 和发现信道，并输出不含密钥的状态日志。
- 原始库不改写，实验库在构建目录生成，旁边保存逐项修改及哈希 JSON。

主机同时需要 green2-linux-driver 同名实验分支的 cfg80211 补丁，模块参数
`nan_allow_5g_only=1`，以及 `nan-band=5GHz`、PASN 5745 MHz。
主机脚本会拒绝在 2.4 GHz 信道仍可用或模块未 opt-in 时启动 5GHz 实验。
原生产 Snap 的 configure hook 不接受该新值，实测使用独立 transient service，未重打 Snap 镜像。

2026-11-12 实测：固件 `Band=5G`；主机 `bands=2`；固件状态
`mask=2 primary=149 secondary=149 enabled=1 ret=0`。仅 9 个非 DFS 5GHz 信道可用，
2.4 GHz 无可用信道；发布服务命令成功、TCP 8000 监听。
UART 出现信道 149 的同步/cluster merge 日志，但不能据此断言服务发布及手机互通成功。

用户报告找不到服务，并说明已经删除配对；后续首次添加设备列表也完全不可见。
保留配对状态下的互通尚未完成独立验证。
板端没有收到该轮配对/认证请求。因此本实验尚未通过 iPhone 首次发现/配对，
更未通过纯 5GHz NDP/TCP/吞吐。不能把该结果扩大为所有 iPhone 或 NAN 的固有能力限制。
强制两个发现槽为 149 也可能影响固件广播/调度语义，需进一步隔离。

没有写 eFuse/OTP，没有修改 bootloader。正常双频固件与主机模块保留，可恢复。

双频对照：刷回原 app.bin、加载原 cfg80211、恢复双频 CN 后，同一手机重新看到设备并收到 PONG。对照完成后，按用户要求重新切回纯 5GHz 实验状态；首次发现仍未通过。
