#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
厚度量測即時 UI - 第二版修正版延伸

用途：
- 讀取厚度量測數據並即時畫曲線。
- 讓使用者輸入 threshold 閥值。
- 當厚度「進入超標區」時發報，並可送出 FANUC Raw TCP 指令。
- 未使用的資料來源設定不顯示，只顯示目前模式需要的欄位。

支援資料來源：
1) Rainbow/Precitec 類型：TCP stream + 55 AA 55 AA binary packet，厚度 = probe2 - probe1。
2) SF3 類型：STX/ETX ASCII command + SOH binary GET-RESULT response。

執行：
    python thickness_realtime_ui.py

需要套件：
    pip install matplotlib

備註：
    FANUC 的實際通訊協定尚未由現場提供。這份程式先保留 Raw TCP 送訊號介面；
    若現場最後提供 FANUC Data Server / FOCAS / PMC / Modbus/TCP / 自訂 Socket 格式，
    可優先調整 FanucClient.send_signal() 或 UI 中的 Payload template。
"""

from __future__ import annotations

import csv
import queue
import socket
import struct
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import matplotlib

# 桌面執行時使用 TkAgg；在無螢幕環境做語法/單元測試時，TkAgg 可能無法載入。
try:
    matplotlib.use("TkAgg")
except ImportError:
    matplotlib.use("Agg")

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# For FANUC FOCAS Library
import ctypes
from ctypes import c_char_p, c_ushort, c_short, c_long, byref

# =========================
# 共用資料結構與工具函式
# =========================

@dataclass
class ThicknessSample:
    timestamp: float
    thickness_um: float
    source: str
    probe1_um: Optional[float] = None
    probe2_um: Optional[float] = None
    elapsed_ms: Optional[int] = None
    signal_max: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)


def now_text() -> str:
    return datetime.now().strftime("%H:%M:%S")


def safe_float(text: str, default: float) -> float:
    try:
        return float(str(text).strip())
    except Exception:
        return default


def parse_required_float(text: str, name: str) -> float:
    try:
        return float(str(text).strip())
    except Exception as exc:
        raise ValueError(f"{name} 必須是數字") from exc


def safe_int(text: str, default: int) -> int:
    try:
        return int(float(str(text).strip()))
    except Exception:
        return default


def parse_required_port(text: str, name: str = "Port") -> int:
    try:
        value = int(str(text).strip())
    except Exception as exc:
        raise ValueError(f"{name} 必須是 1 到 65535 的整數") from exc
    if value < 1 or value > 65535:
        raise ValueError(f"{name} 必須是 1 到 65535 的整數")
    return value


def parse_positive_int(text: str, name: str) -> int:
    try:
        value = int(float(str(text).strip()))
    except Exception as exc:
        raise ValueError(f"{name} 必須是正整數") from exc
    if value <= 0:
        raise ValueError(f"{name} 必須大於 0")
    return value


def parse_nonnegative_int(text: str, name: str) -> int:
    try:
        value = int(str(text).strip())
    except Exception as exc:
        raise ValueError(f"{name} 必須是 0 或正整數") from exc
    if value < 0:
        raise ValueError(f"{name} 必須是 0 或正整數")
    return value


EmitFunc = Callable[[str, Any], None]


class Tooltip:
    """Small hover popup for field explanations."""

    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 350):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id: Optional[str] = None
        self._window: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event: tk.Event) -> None:
        self._cancel_schedule()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel_schedule(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self) -> None:
        self._cancel_schedule()
        if self._window is not None:
            return

        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8

        self._window = tk.Toplevel(self.widget)
        self._window.wm_overrideredirect(True)
        self._window.wm_geometry(f"+{x}+{y}")
        self._window.attributes("-topmost", True)

        label = tk.Label(
            self._window,
            text=self.text,
            justify=tk.LEFT,
            bg="#fff7cc",
            fg="#111827",
            relief=tk.SOLID,
            borderwidth=1,
            padx=8,
            pady=6,
            wraplength=360,
            font=("Arial", 10),
        )
        label.pack()

    def _hide(self, _event: Optional[tk.Event] = None) -> None:
        self._cancel_schedule()
        if self._window is not None:
            try:
                self._window.destroy()
            except Exception:
                pass
            self._window = None


def add_help_icon(parent: ttk.Frame, row: int, column: int, text: str) -> ttk.Label:
    """Add a compact hover-help icon at the given grid position."""
    icon = ttk.Label(parent, text="ⓘ", cursor="question_arrow")
    icon.grid(row=row, column=column, sticky="w", padx=(4, 0))
    Tooltip(icon, text)
    return icon


# =========================
# 資料來源 1：Rainbow/Precitec 類型 binary TCP stream
# 來源邏輯整理自 connect_to_rainbow.py
# =========================

class RainbowPacketSource:
    MAGIC = b"\x55\xaa\x55\xaa"

    def __init__(self, host: str, port: int, timeout_s: float = 3.0):
        self.host = host
        self.port = port
        self.timeout_s = timeout_s

    @staticmethod
    def parse_probe_and_thickness(pkt: bytes) -> Optional[Tuple[float, float, float]]:
        if len(pkt) < 8:
            return None
        payload_len = struct.unpack("<I", pkt[4:8])[0]
        payload = pkt[8:8 + payload_len]

        if len(payload) < 40:
            return None
        if payload[8:12] != b"DAT\x00":
            return None

        probe1 = struct.unpack("<f", payload[32:36])[0]
        probe2 = struct.unpack("<f", payload[36:40])[0]
        thickness = probe2 - probe1
        return probe1, probe2, thickness

    def run(self, stop_event: threading.Event, emit: EmitFunc) -> None:
        emit("log", ("STATUS", f"連線 Rainbow/Precitec 類型設備 {self.host}:{self.port}"))
        buf = b""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_s)
            sock.connect((self.host, self.port))
            sock.settimeout(0.5)
            emit("status", "已連線，正在接收 binary 封包")

            while not stop_event.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue

                if not data:
                    if stop_event.is_set():
                        break
                    raise ConnectionError("設備已關閉連線")

                buf += data
                while True:
                    idx = buf.find(self.MAGIC)
                    if idx < 0:
                        # 保留最後 3 bytes，避免 MAGIC 被切在兩次 recv 之間。
                        buf = buf[-3:]
                        break
                    if idx > 0:
                        buf = buf[idx:]
                    if len(buf) < 8:
                        break

                    payload_len = struct.unpack("<I", buf[4:8])[0]
                    if payload_len <= 0 or payload_len > 1024 * 1024:
                        # 避免錯誤長度造成記憶體累積，丟掉目前 magic 後重找。
                        buf = buf[4:]
                        continue

                    total_len = 8 + payload_len
                    if len(buf) < total_len:
                        break

                    pkt = buf[:total_len]
                    buf = buf[total_len:]
                    parsed = self.parse_probe_and_thickness(pkt)
                    if parsed is None:
                        continue

                    probe1, probe2, thickness = parsed
                    emit(
                        "sample",
                        ThicknessSample(
                            timestamp=time.time(),
                            thickness_um=thickness,
                            source="Rainbow/Precitec",
                            probe1_um=probe1,
                            probe2_um=probe2,
                        ),
                    )


# =========================
# 資料來源 2：SF3 類型 STX/ETX command + GET-RESULT
# 來源邏輯整理自 connect_to_v1.py
# =========================

class SF3CommandSource:
    STX = b"\x02"
    ETX = b"\x03"
    SOH = b"\x01"

    def __init__(
        self,
        host: str,
        port: int,
        poll_interval_s: float = 0.5,
        result_index: int = 1,
        thickness_layer_index: int = 1,
        use_signal_max_as_thickness: bool = False,
        timeout_s: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.poll_interval_s = poll_interval_s
        self.result_index = result_index
        self.thickness_layer_index = thickness_layer_index
        self.use_signal_max_as_thickness = use_signal_max_as_thickness
        self.timeout_s = timeout_s
        self._transmission_no = 1

    def _next_no(self) -> int:
        value = self._transmission_no
        self._transmission_no += 1
        if self._transmission_no > 9999:
            self._transmission_no = 1
        return value

    def send_ascii_command(self, sock: socket.socket, command: str, recv_size: int = 4096) -> bytes:
        cmd = f"{self._next_no()},{command}".encode("ascii")
        sock.sendall(self.STX + cmd + self.ETX)
        return sock.recv(recv_size)

    @classmethod
    def parse_get_result_response(cls, resp: bytes) -> List[Dict[str, Any]]:
        if not resp.startswith(cls.SOH):
            raise ValueError("GET-RESULT 回應格式錯誤：不是 SOH 開頭")

        offset = 1
        if len(resp) < offset + 24:
            raise ValueError("GET-RESULT 資料長度不足，無法解讀 header")

        num_meas, result_type, num_layers, num_signals, num_refl, num_fft = struct.unpack_from("<6I", resp, offset)
        offset += struct.calcsize("<6I")

        results: List[Dict[str, Any]] = []
        for _ in range(num_meas):
            if offset + 8 + 4 * num_layers > len(resp):
                break

            elapsed_time = struct.unpack_from("<I", resp, offset)[0]
            offset += 4
            signal_max = struct.unpack_from("<f", resp, offset)[0]
            offset += 4

            thicknesses = []
            for _layer in range(num_layers):
                thicknesses.append(struct.unpack_from("<f", resp, offset)[0])
                offset += 4

            results.append(
                {
                    "elapsed_time": elapsed_time,
                    "signal_max": signal_max,
                    "thicknesses": thicknesses,
                    "result_type": result_type,
                    "num_layers": num_layers,
                    "num_signals": num_signals,
                    "num_refl": num_refl,
                    "num_fft": num_fft,
                }
            )
        return results

    def _select_thickness(self, results: List[Dict[str, Any]]) -> ThicknessSample:
        if not results:
            raise ValueError("GET-RESULT 沒有可用結果")

        idx = min(max(self.result_index, 0), len(results) - 1)
        r = results[idx]
        thicknesses = r.get("thicknesses", [])

        if self.use_signal_max_as_thickness:
            thickness = float(r["signal_max"])
        else:
            if not thicknesses:
                raise ValueError("GET-RESULT 沒有 thickness layer")
            layer_idx = min(max(self.thickness_layer_index, 0), len(thicknesses) - 1)
            thickness = float(thicknesses[layer_idx])

        return ThicknessSample(
            timestamp=time.time(),
            thickness_um=thickness,
            source="SF3",
            elapsed_ms=int(r["elapsed_time"]),
            signal_max=float(r["signal_max"]),
            extra={"thicknesses": thicknesses},
        )

    def run(self, stop_event: threading.Event, emit: EmitFunc) -> None:
        emit("log", ("STATUS", f"連線 SF3 類型設備 {self.host}:{self.port}"))
        with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as sock:
            sock.settimeout(self.timeout_s)

            emit("status", "送出 READY")
            emit("log", ("STATUS", f"READY 回應：{self.send_ascii_command(sock, 'READY')!r}"))
            time.sleep(0.2)

            emit("status", "開燈 CTRL-LIGHT,1")
            emit("log", ("STATUS", f"CTRL-LIGHT 回應：{self.send_ascii_command(sock, 'CTRL-LIGHT,1')!r}"))
            time.sleep(0.5)

            emit("status", "開始量測 MEAS-START")
            emit("log", ("STATUS", f"MEAS-START 回應：{self.send_ascii_command(sock, 'MEAS-START')!r}"))
            time.sleep(1.0)

            try:
                while not stop_event.is_set():
                    resp = self.send_ascii_command(sock, "GET-RESULT", recv_size=65536)
                    results = self.parse_get_result_response(resp)
                    sample = self._select_thickness(results)
                    emit("sample", sample)
                    stop_event.wait(self.poll_interval_s)
            finally:
                try:
                    emit("status", "停止量測 MEAS-STOP")
                    emit("log", ("STATUS", f"MEAS-STOP 回應：{self.send_ascii_command(sock, 'MEAS-STOP')!r}"))
                except Exception as exc:
                    emit("log", ("ERROR", f"MEAS-STOP 失敗：{exc}"))


# =========================
# FANUC 訊號介面
# =========================

# fwlib = ctypes.WinDLL("./Fwlib64.dll")
# fwlib.cnc_allclibhndl3.argtypes = [
#     c_char_p,                  # IP address
#     c_ushort,                  # port
#     c_long,                    # timeout seconds
#     ctypes.POINTER(c_ushort),  # handle output
# ]

@dataclass
class FanucSettings:
    enabled: bool
    host: str
    port: int
    payload_template: str
    append_newline: bool = True
    timeout_s: float = 2.0


class FanucClient:
    """FANUC 對接點。

    目前先提供 Raw TCP 傳送。實機若使用 FANUC Data Server、FOCAS、PMC、Modbus/TCP
    或廠方自訂 socket protocol，只要改這個 class 即可，UI 和 threshold 邏輯不必改。
    """

    def __init__(self, settings: FanucSettings):
        self.settings = settings
        """
        self.fwlib = ctypes.WinDLL("./Fwlib32.dll")
        self.fwlib.cnc_allclibhndl3.argtypes = [
            c_char_p,                  # IP address
            c_ushort,                  # port
            c_long,                    # timeout seconds
            ctypes.POINTER(c_ushort),  # handle output
        ]
        self.fwlib.cnc_allclibhndl3.restype = c_short
        self.handle = c_ushort()
        self.ret = self.fwlib.cnc_allclibhndl3(
            self.settings.host.encode("ascii"),
            8193, # FOCAS Ethernet Port
            3, # timeout
            byref(self.handle)
        )
        if self.ret != 0:
            self.fwlib.cnc_freelibhndl(self.handle)
        """


    def send_signal(self, thickness_um: float, threshold_um: float, condition: str) -> str:
        if not self.settings.enabled:
            return "FANUC 發送未啟用，僅記錄 threshold event"

        payload = self.settings.payload_template.format(
            thickness=thickness_um,
            threshold=threshold_um,
            condition=condition,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        )
        if self.settings.append_newline:
            payload += "\n"

        raw = payload.encode("ascii", errors="replace")
        with socket.create_connection((self.settings.host, self.settings.port), timeout=self.settings.timeout_s) as sock:
            sock.sendall(raw)

        return f"已送出 {len(raw)} bytes 到 FANUC {self.settings.host}:{self.settings.port}"


# =========================
# Tkinter UI
# =========================

class ThicknessApp(tk.Tk):
    DEVICE_RAINBOW = "Rainbow/Precitec binary packet"
    DEVICE_SF3 = "SF3 GET-RESULT"

    def __init__(self):
        super().__init__()
        self.title("厚度量測即時曲線 UI")
        self.geometry("1360x900")
        self.minsize(1180, 820)

        self.msg_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.running = False

        self.plot_times: Deque[float] = deque(maxlen=600)
        self.plot_values: Deque[float] = deque(maxlen=600)
        self.all_samples: List[ThicknessSample] = []
        self.t0: Optional[float] = None

        # threshold_latched：已對目前異常事件發過一次警報，不再重複送。
        # threshold_alarm_active：目前這一筆資料仍在異常區。
        self.threshold_latched = False
        self.threshold_alarm_active = False

        self._build_vars()
        self._build_layout()
        self._set_device_defaults(apply_values=True)
        self._refresh_visible_sections()
        self.after(0, self._fit_initial_window)
        self.after(50, lambda: self._log("STATUS", "程式已啟動，Log 視窗位於畫面下方。"))
        self.after(100, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------------------------
    # Build UI
    # -------------------------

    def _build_vars(self) -> None:
        self.device_var = tk.StringVar(value=self.DEVICE_RAINBOW)
        self.sensor_ip_var = tk.StringVar(value="192.168.170.2")
        self.sensor_port_var = tk.StringVar(value="7891")
        self.poll_ms_var = tk.StringVar(value="500")
        self.result_index_var = tk.StringVar(value="1")
        self.layer_index_var = tk.StringVar(value="1")
        self.sf3_signal_max_as_thickness_var = tk.BooleanVar(value=False)

        self.threshold_var = tk.StringVar(value="500")
        self.condition_var = tk.StringVar(value=">=")
        self.max_points_var = tk.StringVar(value="600")
        self.auto_rearm_var = tk.BooleanVar(value=False)
        self.rearm_hysteresis_var = tk.StringVar(value="5")

        self.fanuc_enabled_var = tk.BooleanVar(value=False)
        self.fanuc_ip_var = tk.StringVar(value="127.0.0.1")
        self.fanuc_port_var = tk.StringVar(value="8193")
        self.fanuc_payload_var = tk.StringVar(value="THICKNESS_ALARM,{thickness:.3f},{condition},{threshold:.3f},{timestamp}")

        self.status_var = tk.StringVar(value="尚未開始")
        self.last_value_var = tk.StringVar(value="-- µm")
        self.trigger_status_var = tk.StringVar(value="尚未觸發")
        self.alert_var = tk.StringVar(value="狀態正常：尚未觸發 threshold")

    def _build_layout(self) -> None:
        self.style = ttk.Style(self)
        self.style.configure("Alarm.TButton", font=("Arial", 10, "bold"))

        # 版面調整重點：
        # 1. 控制項與曲線圖放在上半部。
        # 2. Log 固定放在下半部，橫跨整個視窗。
        #
        # 第二版原本把 Log 放在左側最下方，當螢幕高度不足或上方欄位較多時，
        # Log 容易被擠到看不到。改成獨立的 bottom row 後，開啟程式就能看到 Log。
        main = ttk.Frame(self, padding=8)
        main.pack(fill=tk.BOTH, expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=1)
        main.rowconfigure(1, weight=0)

        top = ttk.Frame(main)
        top.grid(row=0, column=0, sticky="nsew")
        top.columnconfigure(0, weight=0)
        top.columnconfigure(1, weight=1)
        top.rowconfigure(0, weight=1)

        left = ttk.Frame(top)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 8))

        right = ttk.Frame(top)
        right.grid(row=0, column=1, sticky="nsew")

        self._build_connection_panel(left)
        self._build_threshold_panel(left)
        self._build_fanuc_panel(left)
        self._build_control_panel(left)
        self._build_plot_panel(right)
        self._build_log_panel(main)

    def _build_connection_panel(self, parent: ttk.Frame) -> None:
        frm = ttk.LabelFrame(parent, text="資料來源", padding=8)
        frm.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(frm, text="選擇模式").grid(row=0, column=0, sticky="w")
        self.device_combo = ttk.Combobox(
            frm,
            textvariable=self.device_var,
            values=[self.DEVICE_RAINBOW, self.DEVICE_SF3],
            state="readonly",
            width=31,
        )
        self.device_combo.grid(row=0, column=1, sticky="ew", pady=2)
        self.device_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_device_changed())
        frm.columnconfigure(1, weight=1)

        self.device_config_container = ttk.Frame(frm)
        self.device_config_container.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.device_config_container.columnconfigure(0, weight=1)

        self.rainbow_frame = ttk.Frame(self.device_config_container)
        self.sf3_frame = ttk.Frame(self.device_config_container)
        self._build_rainbow_fields(self.rainbow_frame)
        self._build_sf3_fields(self.sf3_frame)

    def _build_rainbow_fields(self, frm: ttk.Frame) -> None:
        ttk.Label(frm, text="Sensor IP").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.sensor_ip_var, width=20).grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Label(frm, text="Port").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.sensor_port_var, width=20).grid(row=1, column=1, sticky="ew", pady=2)
        ttk.Label(
            frm,
            text="此模式直接讀 binary 封包，厚度 = probe2 - probe1。",
            wraplength=360,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        frm.columnconfigure(1, weight=1)

    def _build_sf3_fields(self, frm: ttk.Frame) -> None:
        sf3_help = (
            "SF3 的 GET-RESULT 可能一次回多筆 result；每筆 result 裡可能有多層 thicknesses。\n"
            "Result index：選第幾筆 result，0 是第 1 筆，1 是第 2 筆。\n"
            "Layer index：選該 result 裡第幾層 thickness，0 是第 1 層，1 是第 2 層。\n"
            "目前預設 1 / 1，是沿用原始測試程式曾使用的 results[1] 與 thicknesses[1]。"
        )
        result_help = (
            "Result index 用來選 GET-RESULT 回傳的第幾筆量測結果。\n"
            "注意：這裡使用 Python index，0=第1筆、1=第2筆。"
        )
        layer_help = (
            "Layer index 用來選該筆 result 裡的第幾層厚度 thicknesses。\n"
            "注意：這裡使用 Python index，0=第1層、1=第2層。"
        )
        signal_help = "若勾選，程式會用 signal_max 當厚度；未勾選則使用 thicknesses[Layer index]。"

        ttk.Label(frm, text="Sensor IP").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.sensor_ip_var, width=20).grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Label(frm, text="Port").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.sensor_port_var, width=20).grid(row=1, column=1, sticky="ew", pady=2)
        ttk.Label(frm, text="Poll ms").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.poll_ms_var, width=20).grid(row=2, column=1, sticky="ew", pady=2)

        ttk.Label(frm, text="Result index（0=第1筆）").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.result_index_var, width=20).grid(row=3, column=1, sticky="ew", pady=2)
        add_help_icon(frm, 3, 2, result_help)

        ttk.Label(frm, text="Layer index（0=第1層）").grid(row=4, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.layer_index_var, width=20).grid(row=4, column=1, sticky="ew", pady=2)
        add_help_icon(frm, 4, 2, layer_help)

        signal_check = ttk.Checkbutton(
            frm,
            text="用 signal_max 當厚度",
            variable=self.sf3_signal_max_as_thickness_var,
        )
        signal_check.grid(row=5, column=0, columnspan=2, sticky="w", pady=(2, 0))
        add_help_icon(frm, 5, 2, signal_help)

        sf3_info = ttk.Label(frm, text="SF3 說明 ⓘ", cursor="question_arrow")
        sf3_info.grid(row=6, column=0, columnspan=3, sticky="w", pady=(4, 0))
        Tooltip(sf3_info, sf3_help)
        frm.columnconfigure(1, weight=1)

    def _build_threshold_panel(self, parent: ttk.Frame) -> None:
        frm = ttk.LabelFrame(parent, text="Threshold / 發報條件", padding=8)
        frm.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(frm, text="厚度 threshold (µm)").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.threshold_var, width=14).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(frm, text="觸發條件").grid(row=1, column=0, sticky="w")
        ttk.Combobox(
            frm,
            textvariable=self.condition_var,
            values=[">=", "<="],
            state="readonly",
            width=10,
        ).grid(row=1, column=1, sticky="w", pady=2)

        ttk.Checkbutton(
            frm,
            text="回到安全區後自動允許下一次觸發",
            variable=self.auto_rearm_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        ttk.Label(frm, text="自動復歸回差 (µm)").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.rearm_hysteresis_var, width=14).grid(row=3, column=1, sticky="ew", pady=2)

        ttk.Label(frm, text="畫面保留點數").grid(row=4, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.max_points_var, width=14).grid(row=4, column=1, sticky="ew", pady=2)

        ttk.Button(frm, text="Reset Trigger", command=self.reset_trigger, style="Alarm.TButton").grid(
            row=5, column=0, columnspan=2, sticky="ew", pady=(6, 2)
        )
        ttk.Label(frm, textvariable=self.trigger_status_var, wraplength=360).grid(row=6, column=0, columnspan=2, sticky="w")
        frm.columnconfigure(1, weight=1)

    def _build_fanuc_panel(self, parent: ttk.Frame) -> None:
        frm = ttk.LabelFrame(parent, text="FANUC 訊號介面", padding=8)
        frm.pack(fill=tk.X, pady=(0, 8))

        self.fanuc_checkbox = ttk.Checkbutton(
            frm,
            text="啟用 threshold 後自動送 FANUC TCP 指令",
            variable=self.fanuc_enabled_var,
            command=self._refresh_visible_sections,
        )
        self.fanuc_checkbox.pack(anchor="w")

        self.fanuc_details_frame = ttk.Frame(frm)
        self.fanuc_details_frame.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(self.fanuc_details_frame, text="FANUC IP").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.fanuc_details_frame, textvariable=self.fanuc_ip_var, width=20).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(self.fanuc_details_frame, text="Port").grid(row=1, column=0, sticky="w")
        ttk.Entry(self.fanuc_details_frame, textvariable=self.fanuc_port_var, width=20).grid(row=1, column=1, sticky="ew", pady=2)

        ttk.Label(self.fanuc_details_frame, text="Payload template").grid(row=2, column=0, sticky="w")
        ttk.Entry(self.fanuc_details_frame, textvariable=self.fanuc_payload_var, width=32).grid(row=2, column=1, sticky="ew", pady=2)

        ttk.Label(
            self.fanuc_details_frame,
            text="可用變數：{thickness} {threshold} {condition} {timestamp}",
            wraplength=360,
        ).grid(row=3, column=0, columnspan=2, sticky="w")

        ttk.Button(self.fanuc_details_frame, text="手動送測試訊號", command=self.manual_send_fanuc).grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(6, 2)
        )
        self.fanuc_details_frame.columnconfigure(1, weight=1)

    def _build_control_panel(self, parent: ttk.Frame) -> None:
        frm = ttk.LabelFrame(parent, text="操作 / 狀態", padding=8)
        frm.pack(fill=tk.X, pady=(0, 8))

        button_row = ttk.Frame(frm)
        button_row.pack(fill=tk.X)
        self.start_btn = ttk.Button(button_row, text="Start", command=self.start_acquisition)
        self.start_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.stop_btn = ttk.Button(button_row, text="Stop", command=self.stop_acquisition, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        button_row_2 = ttk.Frame(frm)
        button_row_2.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(button_row_2, text="清除曲線", command=self.clear_plot).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(button_row_2, text="匯出 CSV", command=self.export_csv).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        ttk.Label(frm, text="狀態").pack(anchor="w", pady=(8, 0))
        ttk.Label(frm, textvariable=self.status_var, wraplength=360).pack(anchor="w", fill=tk.X)

        ttk.Label(frm, text="最新厚度").pack(anchor="w", pady=(8, 0))
        ttk.Label(frm, textvariable=self.last_value_var, font=("Arial", 20, "bold")).pack(anchor="w")

        self.alert_label = tk.Label(
            frm,
            textvariable=self.alert_var,
            font=("Arial", 12, "bold"),
            bg="#166534",
            fg="white",
            anchor="w",
            padx=8,
            pady=6,
            wraplength=360,
        )
        self.alert_label.pack(fill=tk.X, pady=(8, 0))

    def _build_log_panel(self, parent: ttk.Frame) -> None:
        frm = ttk.LabelFrame(parent, text="重要 Log / 發報紀錄", padding=8)
        frm.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            frm,
            height=8,
            width=120,
            wrap=tk.WORD,
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#e5e7eb",
            font=("Consolas", 10),
            relief=tk.SUNKEN,
            borderwidth=2,
        )
        self.log_text.grid(row=0, column=0, sticky="ew")
        scrollbar = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        self.bold_log_font = tkfont.Font(self.log_text, self.log_text.cget("font"))
        self.bold_log_font.configure(weight="bold")
        self.log_text.tag_configure("INFO", foreground="#e5e7eb")
        self.log_text.tag_configure("STATUS", foreground="#93c5fd")
        self.log_text.tag_configure("FANUC", foreground="#fde68a", font=self.bold_log_font)
        self.log_text.tag_configure("ALARM", foreground="#ffffff", background="#b91c1c", font=self.bold_log_font)
        self.log_text.tag_configure("ERROR", foreground="#fecaca", background="#7f1d1d", font=self.bold_log_font)

    def _build_plot_panel(self, parent: ttk.Frame) -> None:
        frm = ttk.Frame(parent)
        frm.pack(fill=tk.BOTH, expand=True)

        self.fig = Figure(figsize=(8, 6), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Real-time Thickness")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Thickness (µm)")
        self.ax.grid(True)

        (self.line,) = self.ax.plot([], [], label="Thickness")
        self.threshold_line = self.ax.axhline(safe_float(self.threshold_var.get(), 0.0), linestyle="--", label="Threshold")
        self.ax.legend(loc="upper right")

        self.canvas = FigureCanvasTkAgg(self.fig, master=frm)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # -------------------------
    # UI dynamic visibility and sizing
    # -------------------------

    def _on_device_changed(self) -> None:
        self._set_device_defaults(apply_values=True)
        self._refresh_visible_sections()
        self._fit_initial_window()

    def _set_device_defaults(self, apply_values: bool = True) -> None:
        if not apply_values:
            return
        device = self.device_var.get()
        if device == self.DEVICE_RAINBOW:
            self.sensor_ip_var.set("192.168.170.2")
            self.sensor_port_var.set("7891")
        elif device == self.DEVICE_SF3:
            self.sensor_ip_var.set("192.168.1.20")
            self.sensor_port_var.set("65432")
            self.poll_ms_var.set("500")

    def _refresh_visible_sections(self) -> None:
        for frame in (self.rainbow_frame, self.sf3_frame):
            frame.pack_forget()

        device = self.device_var.get()
        if device == self.DEVICE_SF3:
            self.sf3_frame.pack(fill=tk.X)
        else:
            self.rainbow_frame.pack(fill=tk.X)

        if self.fanuc_enabled_var.get():
            if not self.fanuc_details_frame.winfo_manager():
                self.fanuc_details_frame.pack(fill=tk.X, pady=(6, 0))
        else:
            self.fanuc_details_frame.pack_forget()

    def _fit_initial_window(self) -> None:
        """讓初始視窗足以容納目前可見欄位，不需要手動拉大。"""
        try:
            self.update_idletasks()
            req_w = max(1360, self.winfo_reqwidth() + 24)
            req_h = max(900, self.winfo_reqheight() + 24)
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            width = min(req_w, max(900, screen_w - 80))
            height = min(req_h, max(820, screen_h - 80))
            x = max(0, (screen_w - width) // 2)
            y = max(0, (screen_h - height) // 2)
            self.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            # 視窗大小調整失敗不影響量測主流程。
            pass

    # -------------------------
    # Start / stop and validation
    # -------------------------

    def _validate_before_start(self) -> bool:
        try:
            parse_required_float(self.threshold_var.get(), "厚度 threshold")
            parse_positive_int(self.max_points_var.get(), "畫面保留點數")
            parse_required_float(self.rearm_hysteresis_var.get(), "自動復歸回差")

            device = self.device_var.get()
            if device in (self.DEVICE_RAINBOW, self.DEVICE_SF3):
                if not self.sensor_ip_var.get().strip():
                    raise ValueError("Sensor IP 不可空白")
                parse_required_port(self.sensor_port_var.get(), "Sensor Port")
            if device == self.DEVICE_SF3:
                parse_positive_int(self.poll_ms_var.get(), "Poll ms")
                parse_nonnegative_int(self.result_index_var.get(), "Result index")
                parse_nonnegative_int(self.layer_index_var.get(), "Layer index")

            if self.fanuc_enabled_var.get():
                if not self.fanuc_ip_var.get().strip():
                    raise ValueError("FANUC IP 不可空白")
                parse_required_port(self.fanuc_port_var.get(), "FANUC Port")
                if not self.fanuc_payload_var.get().strip():
                    raise ValueError("Payload template 不可空白")
                # 先試著 format，避免等超標才發現 template 錯。
                self.fanuc_payload_var.get().format(
                    thickness=1.23,
                    threshold=1.0,
                    condition=self.condition_var.get(),
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                )
        except Exception as exc:
            self._log(f"啟動前檢查失敗：{exc}", "ERROR")
            messagebox.showerror("設定錯誤", str(exc))
            return False
        return True

    def start_acquisition(self) -> None:
        if self.running:
            return
        if not self._validate_before_start():
            return

        self.stop_event.clear()
        self.running = True
        self.threshold_latched = False
        self.threshold_alarm_active = False
        self._set_alert_normal("狀態正常：等待資料與 threshold 事件")
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.device_combo.configure(state=tk.DISABLED)
        self.status_var.set("啟動中")
        self.trigger_status_var.set("尚未觸發")

        max_points = max(10, safe_int(self.max_points_var.get(), 600))
        self.plot_times = deque(self.plot_times, maxlen=max_points)
        self.plot_values = deque(self.plot_values, maxlen=max_points)

        source = self._make_source()
        self.worker = threading.Thread(target=self._worker_loop, args=(source,), daemon=True)
        self.worker.start()
        self._log("開始讀取", "STATUS")

    def stop_acquisition(self) -> None:
        if not self.running:
            return
        self.stop_event.set()
        self.status_var.set("停止中")
        self._log("要求停止讀取", "STATUS")

    def _make_source(self) -> Any:
        device = self.device_var.get()
        host = self.sensor_ip_var.get().strip()
        port = safe_int(self.sensor_port_var.get(), 0)
        poll_s = max(0.02, safe_float(self.poll_ms_var.get(), 500.0) / 1000.0)

        if device == self.DEVICE_RAINBOW:
            return RainbowPacketSource(host, port)
        if device == self.DEVICE_SF3:
            return SF3CommandSource(
                host=host,
                port=port,
                poll_interval_s=poll_s,
                result_index=parse_nonnegative_int(self.result_index_var.get(), "Result index"),
                thickness_layer_index=parse_nonnegative_int(self.layer_index_var.get(), "Layer index"),
                use_signal_max_as_thickness=self.sf3_signal_max_as_thickness_var.get(),
            )
        raise ValueError(f"未知的資料來源模式：{device}")

    def _worker_loop(self, source: Any) -> None:
        def emit(kind: str, payload: Any) -> None:
            self.msg_queue.put((kind, payload))

        try:
            source.run(self.stop_event, emit)
        except Exception as exc:
            emit("error", str(exc))
        finally:
            emit("finished", None)

    def _process_queue(self) -> None:
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "sample":
                    self._handle_sample(payload)
                elif kind == "status":
                    self.status_var.set(str(payload))
                    self._log(str(payload), "STATUS")
                elif kind == "log":
                    if isinstance(payload, tuple) and len(payload) == 2:
                        level, text = payload
                        self._log(str(text), str(level))
                    else:
                        self._log(str(payload), "INFO")
                elif kind == "error":
                    self._log(f"ERROR: {payload}", "ERROR")
                    self.status_var.set(f"錯誤：{payload}")
                elif kind == "finished":
                    self.running = False
                    self.start_btn.configure(state=tk.NORMAL)
                    self.stop_btn.configure(state=tk.DISABLED)
                    self.device_combo.configure(state="readonly")
                    if not self.status_var.get().startswith("錯誤"):
                        self.status_var.set("已停止")
        except queue.Empty:
            pass

        self.after(80, self._process_queue)

    # -------------------------
    # Sample handling and threshold event logic
    # -------------------------

    def _handle_sample(self, sample: ThicknessSample) -> None:
        if self.t0 is None:
            self.t0 = sample.timestamp

        x = sample.timestamp - self.t0
        y = sample.thickness_um
        self.plot_times.append(x)
        self.plot_values.append(y)
        self.all_samples.append(sample)
        self.last_value_var.set(f"{y:.4f} µm")

        self._check_threshold(sample)
        self._update_plot()

    @staticmethod
    def _is_threshold_breach(value: float, threshold: float, condition: str) -> bool:
        if condition == "<=":
            return value <= threshold
        return value >= threshold

    @staticmethod
    def _is_safe_for_rearm(value: float, threshold: float, condition: str, hysteresis: float) -> bool:
        h = max(0.0, hysteresis)
        if condition == "<=":
            return value > threshold + h
        return value < threshold - h

    def _check_threshold(self, sample: ThicknessSample) -> None:
        threshold = safe_float(self.threshold_var.get(), 0.0)
        condition = self.condition_var.get()
        hysteresis = safe_float(self.rearm_hysteresis_var.get(), 0.0)
        value = sample.thickness_um

        breached = self._is_threshold_breach(value, threshold, condition)

        if breached and not self.threshold_latched:
            # 一般實務上，threshold 是事件觸發點：從正常進入異常區時發一次，避免連續樣本狂送指令。
            self.threshold_latched = True
            self.threshold_alarm_active = True
            msg = f"已觸發：{value:.4f} {condition} {threshold:.4f} µm"
            self.trigger_status_var.set(msg)
            self._set_alert_alarm(msg)
            self._log(f"Threshold 觸發：thickness={value:.4f} µm, condition={condition} {threshold:.4f}", "ALARM")
            self._send_fanuc_for_sample(sample, threshold, condition)
            return

        if breached and self.threshold_latched:
            self.threshold_alarm_active = True
            # 已在同一個異常事件內，不重複送 FANUC。
            return

        # 沒有 breached。
        if self.threshold_alarm_active:
            self.threshold_alarm_active = False
            self._log(f"厚度已離開 threshold 異常區：thickness={value:.4f} µm", "STATUS")

        if self.threshold_latched and self.auto_rearm_var.get() and self._is_safe_for_rearm(value, threshold, condition, hysteresis):
            self.threshold_latched = False
            msg = f"已回安全區並自動復歸：目前 {value:.4f} µm"
            self.trigger_status_var.set(msg)
            self._set_alert_normal(msg)
            self._log(msg, "STATUS")
        elif not self.threshold_latched:
            self._set_alert_normal("狀態正常：尚未觸發 threshold")

    def _send_fanuc_for_sample(self, sample: ThicknessSample, threshold: float, condition: str) -> None:
        settings = self._fanuc_settings()
        client = FanucClient(settings)
        try:
            result = client.send_signal(sample.thickness_um, threshold, condition)
            self._log(result, "FANUC")
        except Exception as exc:
            self._log(f"FANUC 發送失敗：{exc}", "ERROR")
            self._set_alert_error(f"FANUC 發送失敗：{exc}")

    def _fanuc_settings(self) -> FanucSettings:
        return FanucSettings(
            enabled=self.fanuc_enabled_var.get(),
            host=self.fanuc_ip_var.get().strip(),
            port=safe_int(self.fanuc_port_var.get(), 0),
            payload_template=self.fanuc_payload_var.get(),
        )

    def manual_send_fanuc(self) -> None:
        threshold = safe_float(self.threshold_var.get(), 0.0)
        last = self.all_samples[-1].thickness_um if self.all_samples else threshold
        try:
            if not self.fanuc_ip_var.get().strip():
                raise ValueError("FANUC IP 不可空白")
            parse_required_port(self.fanuc_port_var.get(), "FANUC Port")
            settings = self._fanuc_settings()
            settings.enabled = True
            result = FanucClient(settings).send_signal(last, threshold, self.condition_var.get())
            self._log(f"手動測試：{result}", "FANUC")
        except Exception as exc:
            messagebox.showerror("FANUC 測試失敗", str(exc))
            self._log(f"FANUC 手動測試失敗：{exc}", "ERROR")

    def reset_trigger(self) -> None:
        self.threshold_latched = False
        self.threshold_alarm_active = False
        self.trigger_status_var.set("已重置，等待下一次觸發")
        self._set_alert_normal("狀態正常：已人工 Reset，等待下一次 threshold 事件")
        self._log("Threshold trigger 已重置", "STATUS")

    # -------------------------
    # Plot / export / logging
    # -------------------------

    def clear_plot(self) -> None:
        self.plot_times.clear()
        self.plot_values.clear()
        self.all_samples.clear()
        self.t0 = None
        self.last_value_var.set("-- µm")
        self.reset_trigger()
        self._update_plot()
        self._log("已清除曲線與暫存資料", "STATUS")

    def export_csv(self) -> None:
        if not self.all_samples:
            messagebox.showinfo("匯出 CSV", "目前沒有資料可匯出")
            return

        filename = filedialog.asksaveasfilename(
            title="儲存厚度資料",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"thickness_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not filename:
            return

        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "datetime",
                    "timestamp",
                    "source",
                    "thickness_um",
                    "probe1_um",
                    "probe2_um",
                    "elapsed_ms",
                    "signal_max",
                    "extra",
                ]
            )
            for s in self.all_samples:
                writer.writerow(
                    [
                        datetime.fromtimestamp(s.timestamp).isoformat(timespec="milliseconds"),
                        f"{s.timestamp:.6f}",
                        s.source,
                        f"{s.thickness_um:.6f}",
                        "" if s.probe1_um is None else f"{s.probe1_um:.6f}",
                        "" if s.probe2_um is None else f"{s.probe2_um:.6f}",
                        "" if s.elapsed_ms is None else s.elapsed_ms,
                        "" if s.signal_max is None else f"{s.signal_max:.6f}",
                        repr(s.extra),
                    ]
                )
        self._log(f"已匯出 CSV：{filename}", "STATUS")

    def _update_plot(self) -> None:
        xs = list(self.plot_times)
        ys = list(self.plot_values)
        self.line.set_data(xs, ys)

        threshold = safe_float(self.threshold_var.get(), 0.0)
        self.threshold_line.set_ydata([threshold, threshold])

        if xs:
            self.ax.set_xlim(max(0.0, xs[-1] - 30.0), max(30.0, xs[-1] + 1.0))
        else:
            self.ax.set_xlim(0, 30)

        values_for_ylim = ys + [threshold]
        if values_for_ylim:
            ymin = min(values_for_ylim)
            ymax = max(values_for_ylim)
            if abs(ymax - ymin) < 1e-6:
                ymin -= 1
                ymax += 1
            pad = max((ymax - ymin) * 0.15, 1.0)
            self.ax.set_ylim(ymin - pad, ymax + pad)

        self.canvas.draw_idle()

    def _set_alert_normal(self, text: str) -> None:
        self.alert_var.set(text)
        self.alert_label.configure(bg="#166534", fg="white")

    def _set_alert_alarm(self, text: str) -> None:
        self.alert_var.set(f"警報：{text}")
        self.alert_label.configure(bg="#b91c1c", fg="white")

    def _set_alert_error(self, text: str) -> None:
        self.alert_var.set(f"錯誤：{text}")
        self.alert_label.configure(bg="#7f1d1d", fg="white")

    def _log(self, text: str, level: str = "INFO") -> None:
        tag = level if level in {"INFO", "STATUS", "FANUC", "ALARM", "ERROR"} else "INFO"
        line = f"[{now_text()}] {text}\n"
        self.log_text.insert(tk.END, line, tag)
        self.log_text.see(tk.END)

    def on_close(self) -> None:
        self.stop_event.set()
        self.destroy()


if __name__ == "__main__":
    app = ThicknessApp()
    app.mainloop()
