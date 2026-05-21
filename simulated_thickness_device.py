#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
厚度量測設備與 FANUC TCP 模擬器

用途：
- 假裝 Rainbow/Precitec 設備，讓 thickness_realtime_ui.py 連線後收到 binary 封包。
- 假裝 SF3 設備，回應 READY / CTRL-LIGHT / MEAS-START / GET-RESULT / MEAS-STOP。
- 假裝 FANUC TCP 接收端，印出 UI 送出的 threshold 指令。

建議測試：
    python simulated_thickness_device.py --mode all

接著開另一個終端機：
    python thickness_realtime_ui.py

UI 測試設定：
- Rainbow 模式：Sensor IP = 127.0.0.1, Port = 7891
- SF3 模式：Sensor IP = 127.0.0.1, Port = 65432
- FANUC：勾選啟用，FANUC IP = 127.0.0.1, Port = 8193
"""

from __future__ import annotations

import argparse
import math
import random
import socket
import struct
import threading
import time
from datetime import datetime
from typing import List, Tuple


MAGIC = b"\x55\xaa\x55\xaa"
STX = b"\x02"
ETX = b"\x03"
SOH = b"\x01"


def simulated_thickness(start: float, base: float, amplitude: float, noise: float) -> float:
    t = time.time() - start
    return base + amplitude * math.sin(t * 1.15) + random.uniform(-noise, noise)


def make_rainbow_packet(thickness_um: float) -> bytes:
    """建立符合 UI 解析位置的 Rainbow/Precitec 假封包。"""
    probe1 = 1000.0
    probe2 = probe1 + thickness_um
    payload = bytearray(48)
    payload[8:12] = b"DAT\x00"
    struct.pack_into("<f", payload, 32, probe1)
    struct.pack_into("<f", payload, 36, probe2)
    return MAGIC + struct.pack("<I", len(payload)) + bytes(payload)


def make_sf3_result(thickness_um: float, elapsed_ms: int) -> bytes:
    """建立 SF3 GET-RESULT 假回應。

    UI 預設讀 result_index = 1, layer_index = 1，
    所以第二筆資料的第二層放入主要厚度值。
    """
    num_meas = 2
    result_type = 0
    num_layers = 2
    num_signals = 1
    num_refl = 0
    num_fft = 0
    data = bytearray()
    data += SOH
    data += struct.pack("<6I", num_meas, result_type, num_layers, num_signals, num_refl, num_fft)

    # 第 0 筆：放一個接近值，方便測試不同 index。
    data += struct.pack("<I", max(0, elapsed_ms - 5))
    data += struct.pack("<f", 123.0)
    data += struct.pack("<f", thickness_um - 8.0)
    data += struct.pack("<f", thickness_um - 4.0)

    # 第 1 筆：UI 預設讀取這筆的 layer 1。
    data += struct.pack("<I", elapsed_ms)
    data += struct.pack("<f", 456.0)
    data += struct.pack("<f", thickness_um - 2.0)
    data += struct.pack("<f", thickness_um)
    return bytes(data)


class StoppableServer:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []

    def add_thread(self, target, *args) -> None:
        th = threading.Thread(target=target, args=args, daemon=True)
        self.threads.append(th)
        th.start()

    def wait_forever(self) -> None:
        try:
            while not self.stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            print("\n[sim] 收到 Ctrl+C，準備停止。")
            self.stop_event.set()


def rainbow_server(host: str, port: int, interval: float, base: float, amplitude: float, noise: float, stop_event: threading.Event) -> None:
    start = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        srv.settimeout(0.5)
        print(f"[rainbow] listening on {host}:{port}")
        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            print(f"[rainbow] client connected: {addr}")
            with conn:
                while not stop_event.is_set():
                    try:
                        value = simulated_thickness(start, base, amplitude, noise)
                        conn.sendall(make_rainbow_packet(value))
                        print(f"[rainbow] send thickness={value:.3f} um")
                        time.sleep(interval)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        print("[rainbow] client disconnected")
                        break


def read_stx_command(conn: socket.socket) -> Tuple[int, str]:
    buf = b""
    while True:
        data = conn.recv(1024)
        if not data:
            raise ConnectionError("client closed")
        buf += data
        start = buf.find(STX)
        end = buf.find(ETX, start + 1)
        if start >= 0 and end > start:
            body = buf[start + 1:end].decode("ascii", errors="replace")
            if "," in body:
                no_text, command = body.split(",", 1)
                try:
                    no = int(no_text)
                except ValueError:
                    no = 0
                return no, command
            return 0, body


def sf3_ascii_ack(no: int, command: str, ok: bool = True) -> bytes:
    status = "OK" if ok else "NG"
    return STX + f"{no},{command},{status}".encode("ascii", errors="replace") + ETX


def sf3_server(host: str, port: int, base: float, amplitude: float, noise: float, stop_event: threading.Event) -> None:
    start = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        srv.settimeout(0.5)
        print(f"[sf3] listening on {host}:{port}")
        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            print(f"[sf3] client connected: {addr}")
            with conn:
                conn.settimeout(5.0)
                while not stop_event.is_set():
                    try:
                        no, command = read_stx_command(conn)
                        upper = command.upper()
                        print(f"[sf3] recv command no={no} command={command}")
                        if upper == "GET-RESULT":
                            value = simulated_thickness(start, base, amplitude, noise)
                            elapsed_ms = int((time.time() - start) * 1000)
                            conn.sendall(make_sf3_result(value, elapsed_ms))
                            print(f"[sf3] send thickness={value:.3f} um")
                        else:
                            conn.sendall(sf3_ascii_ack(no, command))
                    except socket.timeout:
                        continue
                    except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError):
                        print("[sf3] client disconnected")
                        break


def fanuc_receiver(host: str, port: int, stop_event: threading.Event) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        srv.settimeout(0.5)
        print(f"[fanuc] listening on {host}:{port}")
        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            with conn:
                chunks = []
                conn.settimeout(0.2)
                while True:
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                payload = b"".join(chunks)
                text = payload.decode("ascii", errors="replace").strip()
                print(f"[fanuc] {datetime.now().isoformat(timespec='seconds')} from {addr}: {text!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate thickness devices and FANUC TCP receiver.")
    parser.add_argument("--mode", choices=["rainbow", "sf3", "fanuc", "all"], default="all")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Use 0.0.0.0 for LAN tests.")
    parser.add_argument("--rainbow-port", type=int, default=7891)
    parser.add_argument("--sf3-port", type=int, default=65432)
    parser.add_argument("--fanuc-port", type=int, default=8193)
    parser.add_argument("--interval", type=float, default=0.1, help="Rainbow send interval seconds.")
    parser.add_argument("--base", type=float, default=500.0)
    parser.add_argument("--amplitude", type=float, default=35.0)
    parser.add_argument("--noise", type=float, default=2.0)
    args = parser.parse_args()

    manager = StoppableServer()
    if args.mode in ("rainbow", "all"):
        manager.add_thread(rainbow_server, args.host, args.rainbow_port, args.interval, args.base, args.amplitude, args.noise, manager.stop_event)
    if args.mode in ("sf3", "all"):
        manager.add_thread(sf3_server, args.host, args.sf3_port, args.base, args.amplitude, args.noise, manager.stop_event)
    if args.mode in ("fanuc", "all"):
        manager.add_thread(fanuc_receiver, args.host, args.fanuc_port, manager.stop_event)

    print("[sim] started. Press Ctrl+C to stop.")
    manager.wait_forever()


if __name__ == "__main__":
    main()
