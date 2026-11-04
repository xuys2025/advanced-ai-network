# 构建与维护

Windows x64，PowerShell 5.1，.NET Framework 4.8。界面运行时使用 Electron 45.0.0。源码构建在普通目录内进行。

## 从发布包修改

完整解压 Windows 发布包。在 `Sources` 目录执行以下命令，编译 C# 服务、控制器、启动器和测试。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1 -ManagedOnly
powershell -NoProfile -ExecutionPolicy Bypass -File .\Update-Payload.ps1
```

`Build.ps1` 自动运行 DNS 解析、网关地址边界、内置 CLI 路径和签名识别、317 项域名守护检查，以及 IPv4 / ASN / 程序规则测试。`Update-Payload.ps1` 更新解压包内的可执行文件和界面。完成后保存工作、退出 高级 AI，再运行包根目录的 `Install.cmd`。

只修改 HTML、CSS 或 JS 时，把 `Sources/client` 的对应文件复制到解压包的 `App/resources/app` 即可。正式应用更改时仍需通过安装流程。

## 从 GitHub 克隆

```powershell
git clone https://github.com/xuys2025/advanced-ai-network.git
cd advanced-ai-network
powershell -NoProfile -ExecutionPolicy Bypass -File .\Sources\Build.ps1 -ManagedOnly
node .\Clash.Tests.cjs
```

仓库包含自有源码、安装脚本、ProxyBridge 修改源码和 WinDivert SDK。运行时文件在 Release 的 Windows 包中。从 GitHub 克隆后，可以将所修改的源码复制到完整解压的发布包，再按上一节构建和更新。

## 编译原生 C 转发

安装 Zig 0.15.1 Windows x86_64，指定 `zig.exe` 路径。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Sources\Build.ps1 -Zig C:\tools\zig\zig.exe
```

该步骤编译修改后的 ProxyBridge 并继续编译 C# 组件。ProxyBridge 的 MIT 许可和修改后完整 C/H 源码位于 `Sources/third_party/ProxyBridge`。 [Zig 0.15.1](https://ziglang.org/download/0.15.1/)

## 第三方核心与源码

Release 同时提供 `AdvancedAINetwork-ThirdParty-Sources.zip`。将其解压到 Windows 包根目录，再运行下面的还原脚本，会补齐 `Sources/third_party` 下的 WinDivert、sing-box 和精确 Go 依赖源码归档。上游归档以 Base64 保存；还原后按 SHA-256 验证，与原始归档逐字节一致。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Restore-ThirdParty.ps1
```

sing-box 1.14.3 使用未修改的官方 Windows amd64 可执行文件，对应 revision `7054cac5124465ffdb145870d7c01885566711b1`。构建信息见 `Sources/third_party/sing-box-build-info.txt`，包含 Go 版本、构建标签与依赖版本。源码归档、依赖归档和原二进制的匹配信息随发布提供。 [sing-box 官方构建说明](https://sing-box.sagernet.org/installation/build-from-source/)

替换核心时，同时更新 `Sources/guard/BuildFacts.cs` 和 `Guard/Guard-Setup.ps1` 的核心哈希，再重编守护服务。运行时的完整性校验依赖这两个值。

Electron 可从官方 v45.0.0 的 win32-x64 发行包取得。完整保留运行时资源与许可，把 `electron.exe` 命名为 `AdvancedAINetwork.exe`，`Sources/client` 放入 `App/resources/app`。编译出的代理控制器放入 `App/resources/native`，启动器放入 `App`。 [Electron v45.0.0](https://github.com/electron/electron/releases/tag/v45.0.0)

## 验证与发布

公开文案统一使用「高级 AI」「高级公司」。必要的原始域名、程序名和签名字段集中保存在 `compatibility/values.json`，采用可逆编码；运行时还原后按原值匹配。界面显示代称，不修改规则内容。修改映射后执行 `node .\compatibility\generate.cjs`，再重新构建。详见 [兼容字段说明](../compatibility/README.md)。

编译后的普通单元测试只使用临时目录、解析器与隔离数据。`Check.ps1` 会检查已安装服务并访问出口检测站点，生成包含本机信息的报告，分享前请脱敏。抓包、路由与驱动探针需要在隔离测试环境运行。

本次公开发布已验证源码编译、原生构建、Clash 合并、离线界面和包校验。全新机器完整安装还需要实际验收。
