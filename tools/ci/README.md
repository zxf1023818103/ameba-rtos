# Green2 固件构建与发布

工作流：`.github/workflows/green2-firmware.yml`。

默认使用当前 Green2 NAN 原生 USB Wi-Fi + USB Bluetooth 方案：
`green2_nan_usb_bt_usb_bulk2048.config`，启用 NAN 修复及 bulk 2048。
手动运行可选择 module 目录中已有的 SDIO / USB / H4 配置。
仅使用校验 SHA256 的官方预编译 ASDK 12.3.1 build 4600，缓存工具链；
主机 Python 依赖使用本目录的精简 requirements，无需完整 MCP / GUI 环境。

## 触发与下载

- 向 `fix/green2-nan-ios-interop` 推送固件或构建文件变更：构建 ZIP，保存为 Actions artifact，保留 14 天。
- 推送 `green2-fw-*` 标签：构建同一个默认配置，并发布 GitHub Release，提供 ZIP 和外部 SHA256 文件。
- `workflow_dispatch`：可选择配置及是否发布 Release；需要 GitHub 默认分支已包含此工作流。
  手动发布使用运行编号生成独立标签。已有 Release 不覆盖，重发请使用新标签。

例如，在包含本工作流的提交上发布：

```sh
git tag green2-fw-20261111-1
git push github green2-fw-20261111-1
```

## ZIP 内容

```text
green2-<config>-<commit>-<run>/
├── original/          # 构建输出的原始 *.bin：boot、app、ota_all、可选 fullmac
├── Image_All.bin      # 以 NOR Flash 偏移 0 为起点的合成镜像
├── firmware.config    # 输入配置片段
├── build.config       # 实际解析后的 Kconfig
├── flash-layout.json  # 合成使用的地址和分区大小
├── manifest.json      # 源码提交、工具链和固件 SHA256
├── SHA256SUMS         # 包内文件校验
└── README.txt
```

复用 SDK 的 `RTL8711F_NOR.rdev` 和 `combine_profile_images`；
boot 偏移为 `0`，app 偏移为 `0x40000`，空隙填充 `0xFF`。
不使用名字相近但属于另一芯片的 `RTL8711Dx.rdev`。
`ota_all.bin` 原样保留，不能当作完整 Flash 镜像使用。
打包前校验原始镜像、分区容量、合成后字节及填充，缺失或超出分区立即失败。
构建通过只代表编译和打包检查通过，不代表本次固件已做实板无线回归。

本机打包同一构建输出：

```sh
python tools/ci/package-firmware.py --build-dir /path/to/build-work \
  --config component/wifi/whc/nan_test/module/green2_nan_usb_bt_usb_bulk2048.config \
  --output-dir dist --name green2-local
python -m unittest discover -s tools/ci/tests -v
```
