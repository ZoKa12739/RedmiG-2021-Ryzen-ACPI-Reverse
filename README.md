# Redmi G 2021 (锐龙版 / Ryzen Edition) ACPI WMI 逆向成果与硬件控制工具

[![Reverse Engineered with REA](https://img.shields.io/badge/Reverse%20Engineered%20with-REA-blue.svg)](https://github.com/ZoKa12739)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows 10/11](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey.svg)](https://microsoft.com)

本项目针对 **Redmi G 2021 锐龙版**（机型代号：A7 / 模具：英业达 XMCC1806 / Quanta 衍生），借助 **REA (Reverse Engineer Anything)** 逆向分析官方 `GamingBoxHost.exe` 与 BIOS 原生 ACPI AML 固件表（`SSD5` / `DSDT`），彻底逆向出底层 **ACPI WMI (`MICommonInterface` / `WMAA`)** 的通信协议与内存数据结构。

基于该逆向成果，本项目提供了无需依赖官方臃肿后台（CEF 渲染进程 / GamingBox 常驻守护进程）的轻量化硬件控制方案（包含 **PowerShell** 与 **Python** 双版本脚本）以及详尽的 **ACPI 硬件接口协议规范白皮书**。

---

## 🌟 核心特性与亮点

- ⚡ **原生直通硬件，零常驻开销**：告别数百 MB 内存占用的官方 GamingBox CEF 前端与后台服务，直接通过 Windows 原生 WMI 接口与 EC / BIOS 固件握手。
- 🎯 **全模式平滑切换**：
  - 🚀 **狂暴模式 (Turbo / 3)**：释放最大功耗与性能上限。
  - ⚖️ **均衡模式 (Normal / 1)**：默认动态温控与能效平衡。
  - 🍃 **静音模式 (Quiet / 2)**：限制功耗与风扇转速，静音运行。
- 📊 **硬件遥测数据读取**：
  - 实时查询当前性能模式（直接读取 EC `ITSM` 寄存器状态）。
  - 双风扇独立转速（CPU Fan / GPU Fan 实时 RPM 转速表）。
  - 板载温度探针读数（EC `TSR6` / `TSR7` 硬件温度）。
- 🖥️ **终端实时监控面板 (Monitor Mode)**：支持以低延迟循环刷新 CPU/GPU 风扇转速、当前模式与温度。
- 📚 **完整规范文档**：详尽公开 ACPI `WMAA` 32 字节输入/输出缓冲区对齐、ASCII 协议结构与 EC 寄存器映射。

---

## 📂 项目结构

```text
├── ControlGamingBox.ps1            # PowerShell 交互式与 CLI 控制脚本 (推荐日常使用)
├── control_gamingbox.py            # Python 版控制脚本 (支持无依赖纯原生/自动化调用)
├── RedmiG_2021_ACPI_WMAA_Manual.md # ACPI WMI 逆向规范白皮书与底层协议手册
├── README.md                       # 项目总体说明与快速指南
└── LICENSE                         # MIT 开源许可证
```

---

## 🚀 快速上手

> [!IMPORTANT]
> **权限要求**：Windows WMI 底层调用 `root\wmi` 下的 ACPI 接口需要 **管理员权限 (Administrator)**。请务必在以管理员身份运行的终端中执行脚本。

### 1. PowerShell 脚本 (`ControlGamingBox.ps1`)

推荐日常通过 Windows 终端直接使用：

#### 交互式菜单模式
直接右键以管理员运行，或在管理员 PowerShell 中执行：
```powershell
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1
```

#### 命令行静默调用
```powershell
# 切换为狂暴模式
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1 Set-FastMode

# 切换为均衡模式
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1 Set-NormalMode

# 切换为静音模式
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1 Set-QuietMode

# 查询当前状态（当前模式、双风扇转速、温度）
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1 Get-Status

# 读取当前风扇转速
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1 Get-FanSpeed

# 进入终端实时监控模式 (默认 2 秒刷新一次)
powershell -ExecutionPolicy Bypass -File .\ControlGamingBox.ps1 Monitor -Interval 2
```

---

### 2. Python 脚本 (`control_gamingbox.py`)

适用于跨语言集成、定时后台任务或无 PowerShell 环境：

```bash
# 交互式菜单
python control_gamingbox.py

# 命令行直调
python control_gamingbox.py --fast      # 切换狂暴模式
python control_gamingbox.py --normal    # 切换均衡模式
python control_gamingbox.py --quiet     # 切换静音模式
python control_gamingbox.py --status    # 查询状态
python control_gamingbox.py --fans      # 查询风扇
python control_gamingbox.py --monitor   # 实时监控
```

---

## 🔬 逆向协议解析速览

本项目通过 **REA (Reverse Engineer Anything)** 逆向分析 `GamingBoxHost.exe` 与 BIOS `SSD5` ACPI 表，关键发现如下：

1. **WMI 接口元数据**：
   - 命名空间：`root\wmi`
   - 类名：`MICommonInterface`
   - 方法名：`MiInterface` (ACPI 对应 `\_SB.PCI0.LPC0.H_EC.WMAA`)
2. **32 字节输入缓冲区 (InData)**：
   - MOF 定义约束 `InData` 长度必须严格为 **32 字节 (0x20)**，否则系统抛出 `0x80041008` (Invalid Parameter)。
   - 官方底层采用紧凑 ASCII 文本协议传输十六进制命令：
     - `Offset 0x00 ~ 0x03`：命令字 (如 `"FA00"` GET / `"FB00"` SET)
     - `Offset 0x05 ~ 0x08`：子功能 (如 `"0100"` 性能模式 / `"0000"` 风扇遥测)
     - `Offset 0x0A ~ 0x11`：8 字节参数 (如 `"00000003"` 狂暴模式)
     - `Offset 0x12 ~ 0x1F`：`0x00` 填充
3. **输出缓冲区 (OutData)**：
   - 返回 30 字节数据，前 8 字符通过 Hex 编码返回 CPU RPM 与 GPU RPM，后续对应 EC 硬件探针 TSR6/TSR7 传感器读数。

👉 完整协议技术白皮书请阅读：[RedmiG_2021_ACPI_WMAA_Manual.md](RedmiG_2021_ACPI_WMAA_Manual.md)。

---

## 📜 许可证与致谢

- 本项目采用 [MIT License](LICENSE) 开源。
- 感谢 **REA (Reverse Engineer Anything)** 提供的逆向工程与静态反编译分析能力。
- 仅供学习与逆向工程研究交流使用。
