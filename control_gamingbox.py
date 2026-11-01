"""
小米游戏本 (A7 / 英业达 / Redmi G 模具) 脱机硬件控制与监控脚本 (Python 版)
基于 ACPI WMI (root\\wmi -> MICommonInterface::MiInterface) 原生接口深度逆向分析开发
"""

import sys
import time
import subprocess
from typing import Optional, Tuple, Dict, Any


def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class GamingBoxController:
    """
    底层 InData / OutData 固件二进制通信规范（SSD5 AML WMAA 确认）：
    - InData (32 字节定长)：
      Offset 0..1 (UInt16 LE) : SGET (0xFA00: GET, 0xFB00: SET)
      Offset 2..3 (UInt16 LE) : FUNT (0x0800: 性能模式, 0x0900: 风扇/温度)
      Offset 4..5 (UInt16 LE) : FND0 (设置模式时: 1=均衡, 2=静谧, 3=极速)
      Offset 6..31             : 0x00 填充
    
    - OutData (30~33 字节)：
      Offset 0..1 (UInt16 LE) : SGER 状态码 (0x8000: 成功, 0xE000: 固件拒绝)
      Offset 2..3 (UInt16 LE) : FUTR 回显码
      Offset 4..5 (UInt16 LE) : FRD0 (模式查询: 1/2/3; 风扇查询: CPU风扇原始值)
      Offset 6..9 (UInt32 LE) : FRD1 (风扇查询: GPU风扇原始值)
      Offset 10..13 (UInt32 LE): FRD2 (TSR6 温度传感器)
      Offset 14..17 (UInt32 LE): FRD3 (TSR7 温度传感器)
    """

    @staticmethod
    def build_in_data(sget: int, funt: int, fnd0: int = 0) -> bytes:
        buf = bytearray(32)
        buf[0] = sget & 0xFF
        buf[1] = (sget >> 8) & 0xFF
        buf[2] = funt & 0xFF
        buf[3] = (funt >> 8) & 0xFF
        buf[4] = fnd0 & 0xFF
        buf[5] = (fnd0 >> 8) & 0xFF
        return bytes(buf)

    @staticmethod
    def invoke_mi_interface(in_data: bytes) -> Optional[Tuple[int, bytes]]:
        """
        通过 PowerShell CIM 机制跨语言调用 WMI 方法
        确保 SAFEARRAY of UI1 封送 100% 稳定
        """
        byte_list_str = ', '.join(f"0x{b:02X}" for b in in_data)
        ps_cmd = (
            f"$in = [byte[]]({byte_list_str}); "
            f"$inst = Get-CimInstance -Namespace 'root\\wmi' -ClassName 'MICommonInterface' -ErrorAction Stop; "
            f"$res = Invoke-CimMethod -InputObject $inst -MethodName 'MiInterface' -Arguments @{{ InData = $in }}; "
            f"$hex = ($res.OutData | ForEach-Object {{ '{{0:X2}}' -f $_ }}) -join ' '; "
            f"Write-Output \"RESULT:$($res.Reserved):$hex\""
        )
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                check=True
            )
            for line in p.stdout.splitlines():
                if line.startswith("RESULT:"):
                    parts = line.strip().split(":", 2)
                    reserved = int(parts[1])
                    hex_str = parts[2].strip()
                    out_bytes = bytes.fromhex(hex_str.replace(" ", "")) if hex_str else b""
                    return reserved, out_bytes
            return None
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] WMI 调用失败: {e.stderr}", file=sys.stderr)
            return None

    @classmethod
    def set_performance_mode(cls, mode: int) -> bool:
        """
        切换性能模式：1: 均衡 (Normal), 2: 静谧 (Quiet), 3: 极速 (Fast / Turbo)
        支持兼容传参 0 -> 自动转换为 3
        """
        if mode == 0:
            mode = 3

        mode_names = {
            1: "均衡模式 (NORMAL)",
            2: "静谧模式 (QUIET)",
            3: "极速模式 (FAST / TURBO)"
        }
        name = mode_names.get(mode, f"自定义模式({mode})")
        print(f"\n>>> [下发] 正在下发固件指令: {name} (FND0={mode}) ...")
        if mode == 3:
            print("    [提示] 极速模式通常需要插入电源适配器方可发挥最大性能！")

        in_buf = cls.build_in_data(sget=0xFB00, funt=0x0800, fnd0=mode)
        res = cls.invoke_mi_interface(in_buf)
        if res:
            reserved, out_bytes = res
            if len(out_bytes) >= 2:
                sger = int.from_bytes(out_bytes[0:2], byteorder='little')
                if sger == 0x8000:
                    print(f"  [成功] 固件成功执行模式切换 (SGER=0x8000 SUCCESS)")
                    return True
                elif sger == 0xE000:
                    print(f"  [失败] 固件拒绝该指令 (SGER=0xE000 REJECTED)")
                else:
                    print(f"  [返回] 固件返回码: 0x{sger:04X}")
            print(f"  [OutData] {out_bytes.hex(' ').upper()}")
        return False

    @classmethod
    def get_performance_mode(cls, quiet: bool = False) -> Optional[int]:
        """
        查询当前性能模式 (读取 EC ITSM 寄存器映射)
        """
        if not quiet:
            print("\n>>> [查询] 正在获取当前性能模式...")

        in_buf = cls.build_in_data(sget=0xFA00, funt=0x0800, fnd0=0)
        res = cls.invoke_mi_interface(in_buf)
        if res:
            _, out_bytes = res
            if len(out_bytes) >= 6:
                sger = int.from_bytes(out_bytes[0:2], byteorder='little')
                frd0 = int.from_bytes(out_bytes[4:6], byteorder='little')
                if sger == 0x8000:
                    mode_names = {
                        1: "均衡模式 (NORMAL)",
                        2: "静谧模式 (QUIET)",
                        3: "极速模式 (FAST / TURBO)"
                    }
                    name = mode_names.get(frd0, f"未知模式({frd0})")
                    if not quiet:
                        print(f"  [当前状态] 固件性能模式: {name} (EC_ID: {frd0})")
                        print(f"  [OutData] {out_bytes.hex(' ').upper()}")
                    return frd0
                else:
                    if not quiet:
                        print(f"  [警告] 固件返回异常状态码: 0x{sger:04X}")
        return None

    @staticmethod
    def normalize_rpm(raw: int) -> int:
        if raw == 0:
            return 0
        if 400 <= raw <= 9000:
            return raw
        # 字节反转校验
        swapped = ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)
        if 400 <= swapped <= 9000:
            return swapped
        return raw

    @classmethod
    def get_hardware_sensors(cls, quiet: bool = False) -> Optional[Dict[str, Any]]:
        """
        读取双风扇实时转速与硬件温度传感器 (0x0900)
        """
        if not quiet:
            print("\n>>> [查询] 正在读取硬件传感器 (SGET=0xFA00, FUNT=0x0900)...")

        in_buf = cls.build_in_data(sget=0xFA00, funt=0x0900, fnd0=0)
        res = cls.invoke_mi_interface(in_buf)
        if res:
            _, out_bytes = res
            if len(out_bytes) >= 18:
                sger = int.from_bytes(out_bytes[0:2], byteorder='little')
                if sger == 0x8000:
                    raw_cpu = int.from_bytes(out_bytes[4:6], byteorder='little')
                    raw_gpu = int.from_bytes(out_bytes[6:10], byteorder='little')
                    cpu_rpm = cls.normalize_rpm(raw_cpu)
                    gpu_rpm = cls.normalize_rpm(raw_gpu)
                    temp1 = out_bytes[10]
                    temp2 = out_bytes[14]

                    data = {
                        "cpu_rpm": cpu_rpm,
                        "gpu_rpm": gpu_rpm,
                        "raw_cpu": raw_cpu,
                        "raw_gpu": raw_gpu,
                        "temp1": temp1 if 0 < temp1 < 120 else None,
                        "temp2": temp2 if 0 < temp2 < 120 else None,
                    }
                    if not quiet:
                        print("  ==================== 硬件传感器状态 ====================")
                        print(f"  CPU 风扇转速 : {cpu_rpm} RPM (原始读数: 0x{raw_cpu:04X})")
                        print(f"  GPU 风扇转速 : {gpu_rpm} RPM (原始读数: 0x{raw_gpu:04X})")
                        if data["temp1"] is not None:
                            print(f"  传感器 TSR6 (GPU/核心温度) : {temp1} °C")
                        if data["temp2"] is not None:
                            print(f"  传感器 TSR7 (辅板/环温)    : {temp2} °C")
                        print("  ========================================================")
                    return data
                else:
                    if not quiet:
                        print(f"  [警告] 固件返回异常状态码: 0x{sger:04X}")
        return None

    @classmethod
    def monitor_loop(cls, interval: int = 2):
        print("\n========================================================")
        print("  小米游戏本硬件监控看板 (按 Ctrl+C 退出)")
        print(f"  刷新频率: 每 {interval} 秒")
        print("========================================================\n")
        mode_names = {1: "均衡模式", 2: "静谧模式", 3: "极速模式"}
        try:
            while True:
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                mode_val = cls.get_performance_mode(quiet=True)
                mode_str = mode_names.get(mode_val, "未知")

                sensor = cls.get_hardware_sensors(quiet=True)
                if sensor:
                    cpu_str = f"{sensor['cpu_rpm']} RPM".rjust(8)
                    gpu_str = f"{sensor['gpu_rpm']} RPM".rjust(8)
                    t1_str = f"{sensor['temp1']}°C" if sensor['temp1'] is not None else "--"
                    t2_str = f"{sensor['temp2']}°C" if sensor['temp2'] is not None else "--"
                    print(f"[{now_str}] 模式: {mode_str} | CPU风扇: {cpu_str} | GPU风扇: {gpu_str} | 温度1: {t1_str} | 温度2: {t2_str}")
                else:
                    print(f"[{now_str}] 正在等待固件响应...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n监控已退出。")


def interactive_menu():
    ctrl = GamingBoxController()
    while True:
        print("\n" + "=" * 57)
        print("   小米游戏本 (A7) 硬件轻量控制工具 (脱离 CEF 客户端)   ")
        print("=" * 57)
        print(" [1] 切换为：极速模式 (FAST / TURBO - 固件 3)")
        print(" [2] 切换为：均衡模式 (NORMAL - 固件 1)")
        print(" [3] 切换为：静谧模式 (QUIET - 固件 2)")
        print(" " + "-" * 55)
        print(" [4] 查询当前性能模式状态")
        print(" [5] 查询 CPU & GPU 风扇实时转速与硬件温度")
        print(" [6] 启动实时监控看板 (Loop Monitor)")
        print(" " + "-" * 55)
        print(" [Q] 退出程序")
        print("=" * 57)

        choice = input("请输入操作选项 [1-6, Q]: ").strip().upper()
        if choice == '1':
            ctrl.set_performance_mode(3)
            input("按 Enter 继续...")
        elif choice == '2':
            ctrl.set_performance_mode(1)
            input("按 Enter 继续...")
        elif choice == '3':
            ctrl.set_performance_mode(2)
            input("按 Enter 继续...")
        elif choice == '4':
            ctrl.get_performance_mode()
            input("按 Enter 继续...")
        elif choice == '5':
            ctrl.get_hardware_sensors()
            input("按 Enter 继续...")
        elif choice == '6':
            ctrl.monitor_loop()
        elif choice == 'Q':
            print("已退出。")
            break
        else:
            print("无效选项，请重新输入。")
            time.sleep(1)


def main():
    if not is_admin():
        print("\n[WARNING] 当前未检测到管理员权限。访问 root\\wmi 设备可能被系统拒绝。")
        print("若报错请右键以管理员身份运行此脚本。\n")

    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        ctrl = GamingBoxController()
        if cmd in ("--fast", "-f", "fast"):
            ctrl.set_performance_mode(3)
        elif cmd in ("--normal", "-n", "normal"):
            ctrl.set_performance_mode(1)
        elif cmd in ("--quiet", "-q", "quiet"):
            ctrl.set_performance_mode(2)
        elif cmd in ("--status", "-s", "status"):
            ctrl.get_performance_mode()
        elif cmd in ("--fans", "-fan", "fan"):
            ctrl.get_hardware_sensors()
        elif cmd in ("--monitor", "-m", "monitor"):
            ctrl.monitor_loop()
        else:
            print("未知参数，用法: python control_gamingbox.py [--fast|--normal|--quiet|--status|--fans|--monitor]")
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
