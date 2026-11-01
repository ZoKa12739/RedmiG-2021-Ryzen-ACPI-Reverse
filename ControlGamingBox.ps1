<#
.SYNOPSIS
    小米游戏本 (A7 / 英业达 / Redmi G 模具) 脱机硬件控制与监控脚本
    基于 ACPI WMI MICommonInterface 原生接口逆向分析（通过 DSDT/SSDT AML WMAA 汇编还原）
.DESCRIPTION
    无需启动任何臃肿的 CEF / GamingBox 客户端，直接通过 Windows WMI 穿透调用 BIOS ACPI 固件：
    1. 性能模式切换：极速模式 (Turbo - 3) / 均衡模式 (Normal - 1) / 静谧模式 (Quiet - 2)
    2. 当前性能模式查询 (读取 EC ITSM 寄存器状态)
    3. 双风扇实时转速读取 (CPU Fan / GPU Fan 智能 Tachometer 解码)
    4. 硬件温度传感器读取 (EC TSR6 / TSR7 核心温度)
    5. 控制台实时刷新监控屏 (Monitor Loop)
.NOTES
    必须以【管理员身份 (Run as Administrator)】运行 PowerShell！
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Get-Status', 'Get-FanSpeed', 'Set-QuietMode', 'Set-NormalMode', 'Set-FastMode', 'Monitor', 'Interactive')]
    [string]$Action = 'Interactive',

    [Parameter()]
    [int]$Interval = 2 # 监控刷新间隔(秒)
)

# 确保以管理员权限运行
$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[ERROR] 权限不足！" -ForegroundColor Red
    Write-Host "访问 root\wmi 下的 ACPI 固件设备 (MICommonInterface) 必须具备管理员权限。" -ForegroundColor Yellow
    Write-Host "请右键点击 PowerShell 并选择【以管理员身份运行】后重试。`n" -ForegroundColor Yellow
    exit 1
}

# WMI 连接上下文
$wmiNamespace = "root\wmi"
$wmiClass = "MICommonInterface"

try {
    $wmiInstance = Get-CimInstance -Namespace $wmiNamespace -ClassName $wmiClass -ErrorAction Stop
} catch {
    Write-Host "`n[ERROR] 无法获取 WMI 类 $wmiClass 实例: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "可能原因：当前机器不是英业达/小米 A7 系列模具，或者 BIOS ACPI 中未暴露 MIFS_0 设备。`n" -ForegroundColor Yellow
    exit 1
}

<#
=============================================================================
底层 InData / OutData 固件二进制通信规范（经 SSD5 AML WMAA 方法 100% 确认）：
- InData (输入缓冲区，总长度严格 32 字节，MOF 限定 MAX=32)：
  Offset 0..1 (UInt16 LE) : SGET 命令大类 (0xFA00: 读/查询, 0xFB00: 写/设置)
  Offset 2..3 (UInt16 LE) : FUNT 功能编号 (0x0800: 性能模式, 0x0900: 风扇与温度, 0x0A00: 热键/锁)
  Offset 4..5 (UInt16 LE) : FND0 功能参数 (设置模式时: 1=均衡, 2=静谧, 3=极速)
  Offset 6..31             : 填充 0x00

- OutData (固件返回缓冲区，30~33 字节)：
  Offset 0..1 (UInt16 LE) : SGER 固件执行状态 (0x8000: 成功, 0xE000: 指令被固件拒绝/无效)
  Offset 2..3 (UInt16 LE) : FUTR 回显功能码 (0x0800 / 0x0900)
  Offset 4..5 (UInt16 LE) : FRD0 读出数据0 (模式查询时: 1=均衡, 2=静谧, 3=极速; 风扇查询时: CPU 风扇原始读数)
  Offset 6..9 (UInt32 LE) : FRD1 读出数据1 (风扇查询时: GPU 风扇原始读数)
  Offset 10..13 (UInt32 LE): FRD2 读出数据2 (风扇查询时: TSR6 温度传感器，低字节为摄氏度)
  Offset 14..17 (UInt32 LE): FRD3 读出数据3 (风扇查询时: TSR7 温度传感器，低字节为摄氏度)
=============================================================================
#>
function Invoke-MiInterfaceRaw {
    param(
        [Parameter(Mandatory = $true)]
        [uint16]$SGet,

        [Parameter(Mandatory = $true)]
        [uint16]$Funt,

        [Parameter()]
        [uint16]$Fnd0 = 0
    )

    # 1. 严格分配 32 字节二进制输入缓冲区
    $inData = New-Object byte[] 32

    # 写入 UInt16 Little-Endian
    $inData[0] = [byte]($SGet -band 0xFF)
    $inData[1] = [byte](($SGet -shr 8) -band 0xFF)

    $inData[2] = [byte]($Funt -band 0xFF)
    $inData[3] = [byte](($Funt -shr 8) -band 0xFF)

    $inData[4] = [byte]($Fnd0 -band 0xFF)
    $inData[5] = [byte](($Fnd0 -shr 8) -band 0xFF)

    # Offset 6..31 保持 0x00

    $cimArgs = @{ InData = $inData }

    try {
        $result = Invoke-CimMethod -InputObject $wmiInstance -MethodName "MiInterface" -Arguments $cimArgs -ErrorAction Stop
        return $result
    } catch {
        Write-Error "调用 MiInterface 抛出异常: $($_.Exception.Message)"
        return $null
    }
}

# 辅助函数：格式化输出 Hex 与 ASCII 对比
function Show-HexDump {
    param([byte[]]$Bytes, [string]$Title = "OutData")
    if (-not $Bytes -or $Bytes.Length -eq 0) {
        Write-Host "  [$Title] (空响应)" -ForegroundColor DarkGray
        return
    }
    
    $hexStr = ($Bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
    $ascChars = $Bytes | ForEach-Object {
        if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
    }
    $ascStr = -join $ascChars

    Write-Host "  [$Title : $($Bytes.Length) Bytes]" -ForegroundColor DarkCyan
    Write-Host "    HEX: $hexStr" -ForegroundColor Gray
    Write-Host "    ASC: $ascStr" -ForegroundColor Gray
}

# 1. 切换性能模式 (固件参数: 1: 均衡, 2: 静谧, 3: 极速)
function Set-GamingMode {
    param(
        # 接收模式代号：1=均衡, 2=静谧, 3=极速 (同时兼容旧版传参 0=极速)
        [int]$Mode
    )

    # 兼容映射：若用户传入 0，转换为固件的极速模式代号 3
    if ($Mode -eq 0) { $Mode = 3 }

    $modeInfo = @{
        1 = @{ Name = "均衡模式 (NORMAL)"; Color = "Yellow"; FwVal = 1 }
        2 = @{ Name = "静谧模式 (QUIET)"; Color = "Cyan";   FwVal = 2 }
        3 = @{ Name = "极速模式 (FAST)";  Color = "Red";    FwVal = 3 }
    }

    $target = $modeInfo[$Mode]
    if (-not $target) {
        Write-Host "`n[ERROR] 未知的性能模式代号: $Mode (支持 1=均衡, 2=静谧, 3=极速)" -ForegroundColor Red
        return
    }

    Write-Host "`n>>> [执行] 正在下发固件指令: $($target.Name) (FND0=$($target.FwVal)) ..." -ForegroundColor $target.Color
    if ($target.FwVal -eq 3) {
        Write-Host "    [提示] 极速模式通常需要插入电源适配器方可发挥最大性能！" -ForegroundColor DarkYellow
    }

    # 下发指令: SGET=0xFB00 (SET), FUNT=0x0800 (MODE), FND0=$target.FwVal
    $res = Invoke-MiInterfaceRaw -SGet 0xFB00 -Funt 0x0800 -Fnd0 $target.FwVal

    if ($res) {
        $bytes = $res.OutData
        Show-HexDump -Bytes $bytes -Title "模式切换应答 OutData"
        
        if ($bytes -and $bytes.Length -ge 2) {
            $sger = [BitConverter]::ToUInt16($bytes, 0)
            if ($sger -eq 0x8000) {
                Write-Host "  [成功] 固件成功执行模式切换 (SGER=0x8000 SUCCESS)" -ForegroundColor Green
            } elseif ($sger -eq 0xE000) {
                Write-Host "  [失败] 固件拒绝该指令 (SGER=0xE000 REJECTED)" -ForegroundColor Red
            } else {
                Write-Host "  [状态] 固件返回码: 0x$("{0:X4}" -f $sger)" -ForegroundColor Yellow
            }
        }
    }
}

# 2. 读取当前性能模式
function Get-GamingMode {
    param([switch]$Quiet)

    if (-not $Quiet) {
        Write-Host "`n>>> [查询] 正在获取当前性能模式..." -ForegroundColor Cyan
    }
    
    # 查询指令: SGET=0xFA00 (GET), FUNT=0x0800 (MODE), FND0=0
    $res = Invoke-MiInterfaceRaw -SGet 0xFA00 -Funt 0x0800 -Fnd0 0

    if ($res -and $res.OutData) {
        $bytes = $res.OutData
        if (-not $Quiet) {
            Show-HexDump -Bytes $bytes -Title "模式查询 OutData"
        }

        if ($bytes.Length -ge 6) {
            $sger = [BitConverter]::ToUInt16($bytes, 0)
            $futr = [BitConverter]::ToUInt16($bytes, 2)
            $frd0 = [int][BitConverter]::ToUInt16($bytes, 4)

            if ($sger -eq 0x8000) {
                switch ($frd0) {
                    1 { $name = "均衡模式 (NORMAL)"; $color = "Yellow" }
                    2 { $name = "静谧模式 (QUIET)"; $color = "Cyan" }
                    3 { $name = "极速模式 (FAST / TURBO)"; $color = "Red" }
                    default { $name = "未知模式 ($frd0)"; $color = "Magenta" }
                }

                if (-not $Quiet) {
                    Write-Host "  [当前状态] 固件性能模式: $name (EC_ID: $frd0)" -ForegroundColor $color
                }
                return $frd0
            } else {
                Write-Host "  [警告] 固件返回异常状态码: 0x$("{0:X4}" -f $sger)" -ForegroundColor Yellow
            }
        }
    }
    return $null
}

# 辅助函数：智能解码风扇 RPM (处理 BIOS 固件字节顺序)
function Normalize-FanRpm([uint32]$raw) {
    if ($raw -eq 0) { return 0 }
    
    # 正常转速在 400 ~ 9000 RPM 之间
    if ($raw -ge 400 -and $raw -le 9000) {
        return [int]$raw
    }

    # 尝试字节调换 (处理 AML 中 F1HI | (F1LO << 8) 固件小端高低位反转)
    $swapped = (($raw -band 0xFF) -shl 8) -bor (($raw -shr 8) -band 0xFF)
    if ($swapped -ge 400 -and $swapped -le 9000) {
        return [int]$swapped
    }

    return [int]$raw
}

# 3. 读取双风扇转速与传感器温度
function Get-FanSpeedData {
    param([switch]$Quiet)

    if (-not $Quiet) {
        Write-Host "`n>>> [查询] 正在读取硬件传感器 (SGET=0xFA00, FUNT=0x0900)..." -ForegroundColor Cyan
    }
    
    # 查询指令: SGET=0xFA00 (GET), FUNT=0x0900 (FAN/TEMP), FND0=0
    $res = Invoke-MiInterfaceRaw -SGet 0xFA00 -Funt 0x0900 -Fnd0 0

    if ($res -and $res.OutData) {
        $bytes = $res.OutData
        if (-not $Quiet) {
            Show-HexDump -Bytes $bytes -Title "硬件传感器 OutData"
        }

        if ($bytes.Length -ge 18) {
            $sger = [BitConverter]::ToUInt16($bytes, 0)
            if ($sger -eq 0x8000) {
                # FRD0 (Offset 4..5, UInt16): CPU Fan Tachometer
                $rawCpu = [BitConverter]::ToUInt16($bytes, 4)
                $cpuRpm = Normalize-FanRpm $rawCpu

                # FRD1 (Offset 6..9, UInt32): GPU Fan Tachometer
                $rawGpu = [BitConverter]::ToUInt32($bytes, 6)
                $gpuRpm = Normalize-FanRpm $rawGpu

                # FRD2 (Offset 10..13, UInt32): TSR6 传感器温度 (低字节为摄氏度)
                $temp1 = [int]$bytes[10]

                # FRD3 (Offset 14..17, UInt32): TSR7 传感器温度 (低字节为摄氏度)
                $temp2 = [int]$bytes[14]

                if (-not $Quiet) {
                    Write-Host "  ==================== 硬件传感器状态 ====================" -ForegroundColor Green
                    Write-Host "  CPU 风扇转速 : $cpuRpm RPM (原始读数: 0x$("{0:X4}" -f $rawCpu))" -ForegroundColor White
                    Write-Host "  GPU 风扇转速 : $gpuRpm RPM (原始读数: 0x$("{0:X4}" -f $rawGpu))" -ForegroundColor White
                    if ($temp1 -gt 0 -and $temp1 -lt 120) {
                        Write-Host "  传感器 TSR6 (GPU/核心温度) : $temp1 °C" -ForegroundColor White
                    }
                    if ($temp2 -gt 0 -and $temp2 -lt 120) {
                        Write-Host "  传感器 TSR7 (辅板/环温)    : $temp2 °C" -ForegroundColor White
                    }
                    Write-Host "  ========================================================" -ForegroundColor Green
                }

                return [PSCustomObject]@{
                    CpuRpm = $cpuRpm
                    GpuRpm = $gpuRpm
                    Temp1  = $temp1
                    Temp2  = $temp2
                }
            } else {
                Write-Host "  [警告] 固件返回异常状态码: 0x$("{0:X4}" -f $sger)" -ForegroundColor Yellow
            }
        }
    }
    return $null
}

# 4. 控制台循环监控模式
function Start-HardwareMonitor {
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host "  小米游戏本硬件监控看板 (按 Ctrl+C 退出)" -ForegroundColor Green
    Write-Host "  刷新频率: 每 $Interval 秒" -ForegroundColor Green
    Write-Host "========================================================`n" -ForegroundColor Green

    while ($true) {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $modeVal = Get-GamingMode -Quiet
        $modeStr = "未知"
        if ($modeVal -eq 1) { $modeStr = "均衡模式" }
        elseif ($modeVal -eq 2) { $modeStr = "静谧模式" }
        elseif ($modeVal -eq 3) { $modeStr = "极速模式" }

        $sensor = Get-FanSpeedData -Quiet
        if ($sensor) {
            $cpuStr = "$($sensor.CpuRpm) RPM".PadLeft(8)
            $gpuStr = "$($sensor.GpuRpm) RPM".PadLeft(8)
            $t1Str  = if ($sensor.Temp1 -gt 0) { "$($sensor.Temp1)°C" } else { "--" }
            $t2Str  = if ($sensor.Temp2 -gt 0) { "$($sensor.Temp2)°C" } else { "--" }
            Write-Host "[$timestamp] 模式: $modeStr | CPU风扇: $cpuStr | GPU风扇: $gpuStr | 温度1: $t1Str | 温度2: $t2Str" -ForegroundColor Cyan
        } else {
            Write-Host "[$timestamp] 正在等待固件响应..." -ForegroundColor DarkGray
        }
        Start-Sleep -Seconds $Interval
    }
}

# 5. 交互式控制菜单
function Show-InteractiveMenu {
    while ($true) {
        Clear-Host
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host "   小米游戏本 (A7) 硬件轻量控制工具 (脱离 CEF 客户端)   " -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " [1] 切换为：极速模式 (FAST / TURBO - 固件 3)" -ForegroundColor Red
        Write-Host " [2] 切换为：均衡模式 (NORMAL - 固件 1)" -ForegroundColor Yellow
        Write-Host " [3] 切换为：静谧模式 (QUIET - 固件 2)" -ForegroundColor Cyan
        Write-Host " -------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host " [4] 查询当前性能模式状态" -ForegroundColor White
        Write-Host " [5] 查询 CPU & GPU 风扇实时转速与硬件温度" -ForegroundColor White
        Write-Host " [6] 启动实时监控看板 (Loop Monitor)" -ForegroundColor White
        Write-Host " -------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host " [Q] 退出程序" -ForegroundColor Gray
        Write-Host "=========================================================" -ForegroundColor Cyan

        $choice = Read-Host "请输入操作选项 [1-6, Q]"
        switch ($choice.ToUpper().Trim()) {
            '1' { Set-GamingMode 3; Pause }
            '2' { Set-GamingMode 1; Pause }
            '3' { Set-GamingMode 2; Pause }
            '4' { Get-GamingMode; Pause }
            '5' { Get-FanSpeedData; Pause }
            '6' { Start-HardwareMonitor }
            'Q' { Write-Host "已退出。"; break }
            default { Write-Host "无效选项，请重新输入。"; Start-Sleep -Seconds 1 }
        }
        if ($choice.ToUpper().Trim() -eq 'Q') { break }
    }
}

# 脚本主入口分发
switch ($Action) {
    'Set-QuietMode'  { Set-GamingMode 2 }
    'Set-NormalMode' { Set-GamingMode 1 }
    'Set-FastMode'   { Set-GamingMode 3 }
    'Get-Status'     { Get-GamingMode }
    'Get-FanSpeed'   { Get-FanSpeedData }
    'Monitor'        { Start-HardwareMonitor }
    'Interactive'    { Show-InteractiveMenu }
}
