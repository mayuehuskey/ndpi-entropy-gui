# -*- coding: utf-8 -*-
"""
ndpi_entropy_gui.py  (v1.3-mac)
macOS GUI 工具：调用 ndpiReader 分析 pcap，提取并展示高熵（Susp Entropy）流
新增功能：
  - 为“疑似加密服务器（按端口聚类）”增加地理位置与运营商识别（Location, ISP）
  - 离线优先（MaxMind GeoLite2 .mmdb + maxminddb 模块），在线兜底（ip-api.com）
  - 查询结果缓存，避免重复查询

兼容 Python 3.6+(推荐 3.11.0 实测稳定)仅依赖标准库（tkinter）。离线定位需额外安装 maxminddb 并放置 .mmdb 文件。
"""

from __future__ import print_function
import os
import re
import sys
import json
import ipaddress
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# 在线兜底所需
import time
try:
    # Python 3.6 兼容写法
    from urllib.request import urlopen, Request
except Exception:
    urlopen = None
    Request = None


try:
    import sys, os
    # 优先 PyInstaller 解包目录；否则用脚本文件的绝对目录
    if hasattr(sys, "_MEIPASS"):
        SCRIPT_DIR = sys._MEIPASS
    else:
        SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
except Exception:
    # 极端情况下退回当前工作目录
    SCRIPT_DIR = os.path.abspath(os.getcwd())

# 根据平台拼接 ndpiReader 可执行文件的绝对路径
NDPI_READER = os.path.join(
    SCRIPT_DIR,
    "ndpiReader.exe" if os.name == "nt" else "ndpiReader"
)

# （可选）再准备 GeoIP 数据库候选路径
GEOIP_DB_CANDIDATES = [
    os.path.join(SCRIPT_DIR, "GeoLite2-City.mmdb"),
    os.path.join(SCRIPT_DIR, "GeoLite2-Country.mmdb"),
]

# 调试输出（确认路径是否正确，稳定后可注释掉）
#print("SCRIPT_DIR =", SCRIPT_DIR)
#print("NDPI_READER =", NDPI_READER)

APP_TITLE = "翻墙流量检测(macOS GUI) — v1.3"
DEFAULT_ENTROPY_TH = "7.5"
CONFIG_PATH = os.path.expanduser("~/.ndpi_entropy_gui.json")

#

# 若存在 .mmdb 且安装了 maxminddb，则可离线解析
_MAXMINDDB_AVAILABLE = False
_GEOIP_DB_PATH = None
try:
    import maxminddb  # type: ignore
    for _p in GEOIP_DB_CANDIDATES:
        if os.path.exists(_p):
            _GEOIP_DB_PATH = _p
            _MAXMINDDB_AVAILABLE = True
            break
except Exception:
    _MAXMINDDB_AVAILABLE = False
    _GEOIP_DB_PATH = None

# 匹配 nDPI -v 2 输出中包含 “Susp Entropy” 的流
RE_ENTROPY_LINE = re.compile(
    r'^\s*(\d+)\s+'
    r'(TCP|UDP)\s+'
    r'([0-9a-fA-F\.:]+):(\d+)\s+(?:<->|->)\s+([0-9a-fA-F\.:]+):(\d+)'
    r'.*?Susp Entropy.*?Entropy:\s*([0-9.]+)',
    re.IGNORECASE
)

def is_broadcast_or_multicast(ip):
    """仅排除广播/组播（按用户要求，不排除私网/CGNAT）。"""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast:
            return True
        if ip == "255.255.255.255":
            return True
        return False
    except Exception:
        return False

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def is_ephemeral_port(p):
    """粗略判定动态端口（避免把本机高位临时端口当成“服务器端口”）。"""
    try:
        p = int(p)
        return p >= 49152
    except Exception:
        return False

# -------- 地理位置查询（离线优先，在线兜底） --------
class GeoResolver(object):
    def __init__(self):
        self.cache = {}
        self.reader = None
        self.backend = "none"
        if _MAXMINDDB_AVAILABLE and _GEOIP_DB_PATH:
            try:
                import maxminddb  # noqa
                self.reader = maxminddb.open_database(_GEOIP_DB_PATH)
                self.backend = "maxminddb"
            except Exception:
                self.reader = None
                self.backend = "none"

    def close(self):
        try:
            if self.reader:
                self.reader.close()
        except Exception:
            pass

    def _format_loc(self, country=None, region=None, city=None):
        parts = [x for x in [country, region, city] if x]
        return " / ".join(parts) if parts else "N/A"

    def lookup_offline(self, ip):
        try:
            if not self.reader:
                return None
            data = self.reader.get(ip) or {}
            # 根据 City/Country 库字段差异做兼容
            country = None
            region = None
            city = None
            names = {}
            if "country" in data:
                names = data["country"].get("names", {})
                country = names.get("zh-CN") or names.get("en")
            if "subdivisions" in data and data["subdivisions"]:
                names = data["subdivisions"][0].get("names", {})
                region = names.get("zh-CN") or names.get("en")
            if "city" in data:
                names = data["city"].get("names", {})
                city = names.get("zh-CN") or names.get("en")
            loc = self._format_loc(country, region, city)
            # ISP 信息离线库一般没有
            return {"location": loc, "isp": "N/A", "source": "offline"}
        except Exception:
            return None

    def lookup_online(self, ip):
        if not urlopen or not Request:
            return None
        try:
            url = "http://ip-api.com/json/{}?fields=status,message,country,regionName,city,isp".format(ip)
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=5) as resp:
                content = resp.read().decode("utf-8", "ignore")
            data = json.loads(content)
            if data.get("status") != "success":
                return None
            country = data.get("country")
            region = data.get("regionName")
            city = data.get("city")
            isp = data.get("isp") or "N/A"
            loc = self._format_loc(country, region, city)
            return {"location": loc, "isp": isp, "source": "online"}
        except Exception:
            return None

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        info = None
        # 离线优先
        if self.backend == "maxminddb":
            info = self.lookup_offline(ip)
        # 在线兜底
        if info is None:
            info = self.lookup_online(ip)
        # 最后兜底
        if info is None:
            info = {"location": "N/A", "isp": "N/A", "source": "none"}
        self.cache[ip] = info
        return info

class App(tk.Tk):
    def __init__(self):
        super(App, self).__init__()
        self.title(APP_TITLE)
        self.geometry("1100x780")

        self.pcap_path_var = tk.StringVar()
        self.entropy_th_var = tk.StringVar(value=DEFAULT_ENTROPY_TH)
        self.exclude_broadcast_var = tk.BooleanVar(value=True)

        # 顶部：PCAP + 参数
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=8)

        ttk.Label(top, text="PCAP 文件:").grid(row=0, column=0, sticky="w")
        self.pcap_entry = ttk.Entry(top, textvariable=self.pcap_path_var, width=70)
        self.pcap_entry.grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(top, text="选择...", command=self.choose_pcap).grid(row=0, column=2, padx=4)

        opts = ttk.Frame(self)
        opts.pack(fill="x", padx=12)

        ttk.Label(opts, text="熵阈值(≥)：").grid(row=0, column=0, sticky="w")
        self.entropy_entry = ttk.Entry(opts, textvariable=self.entropy_th_var, width=8)
        self.entropy_entry.grid(row=0, column=1, sticky="w", padx=(4,12))

        self.cb_broadcast = ttk.Checkbutton(opts, text="排除广播/组播", variable=self.exclude_broadcast_var)
        self.cb_broadcast.grid(row=0, column=2, padx=(0,12))

        self.run_btn = ttk.Button(opts, text="开始分析", command=self.start_analysis)
        self.run_btn.grid(row=0, column=3, padx=(12,0))

        self.export_btn = ttk.Button(opts, text="导出 CSV（高熵流）", command=self.export_csv, state="disabled")
        self.export_btn.grid(row=0, column=4, padx=(8,0))

        # 上半：高熵流列表
        frame1 = ttk.LabelFrame(self, text="高熵流（Susp Entropy 命中）")
        frame1.pack(fill="both", expand=True, padx=12, pady=(8,6))

        cols = ("FlowID", "Proto", "SrcIP", "Sport", "DstIP", "Dport", "Entropy", "ServerMark")
        self.tree = ttk.Treeview(frame1, columns=cols, show="headings", height=14)
        widths = (80, 60, 170, 70, 170, 70, 80, 180)
        headers = ("FlowID", "Proto", "SrcIP", "Sport", "DstIP", "Dport", "Entropy", "服务器候选")
        for c, w, h in zip(cols, widths, headers):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)

        yscroll = ttk.Scrollbar(frame1, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=yscroll.set)
        yscroll.pack(side="right", fill="y")

        # 下半：服务器候选列表（带地理位置）
        frame2 = ttk.LabelFrame(self, text="疑似加密服务器（按端口聚类）")
        frame2.pack(fill="both", expand=True, padx=12, pady=(6,8))

        server_cols = ("Port", "ServerIP", "Occurrences", "Location", "ISP")
        self.server_tree = ttk.Treeview(frame2, columns=server_cols, show="headings", height=8)
        for c, w in zip(server_cols, (90, 210, 120, 300, 260)):
            self.server_tree.heading(c, text=c)
            self.server_tree.column(c, width=w, anchor="center")
        self.server_tree.pack(side="left", fill="both", expand=True)

        yscroll2 = ttk.Scrollbar(frame2, orient="vertical", command=self.server_tree.yview)
        self.server_tree.configure(yscroll=yscroll2.set)
        yscroll2.pack(side="right", fill="y")

        # 最下：日志
        bottom = ttk.LabelFrame(self, text="统计 / 日志")
        bottom.pack(fill="both", expand=False, padx=12, pady=(0,12))
        self.log_text = tk.Text(bottom, height=8, wrap="word")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.insert("end", "准备就绪，如需离线定位，把 GeoLite2-*.mmdb 也放在同目录。\n")

        # 数据
        self.results = []            # 高熵流记录
        self.server_candidates = []  # (port, ip, count, location, isp)
        self.geo = GeoResolver()     # 地理定位器

        # 提示后端
        if self.geo.backend == "maxminddb":
            self.log_text.insert("end", "GeoIP 后端：MaxMind (offline) [{}]\n".format(_GEOIP_DB_PATH))
        else:
            self.log_text.insert("end", "GeoIP 后端：ip-api.com (online, no key) 或无定位\n")

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def choose_pcap(self):
        path = filedialog.askopenfilename(
            title="选择 PCAP 文件",
            filetypes=[("pcap/pcapng", "*.pcap *.pcapng *.pcap.gz *.pcapng.gz"), ("All files", "*.*")]
        )
        if path:
            self.pcap_path_var.set(path)

    def append_log(self, text):
        self.log_text.insert("end", text)
        self.log_text.see("end")

    def start_analysis(self):
        ndpi = NDPI_READER
        pcap = self.pcap_path_var.get().strip()

        if not os.path.exists(ndpi) or not os.access(ndpi, os.X_OK):
            messagebox.showerror("错误", "未在脚本同目录找到可执行的 ndpiReader。")
            return
        if not pcap or not os.path.exists(pcap):
            messagebox.showerror("错误", "请先选择存在的 PCAP 文件。")
            return

        try:
            th = float(self.entropy_th_var.get().strip())
        except:
            messagebox.showerror("错误", "熵阈值格式不正确。")
            return

        # 保存配置（仅保存阈值）
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump({"entropy_th": th}, f, indent=2, ensure_ascii=False)
        except:
            pass

        self.run_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.server_tree.delete(*self.server_tree.get_children())
        self.results = []
        self.server_candidates = []
        self.append_log("\n==== 开始分析 ====\n")

        t = threading.Thread(
            target=self._run_ndpi_and_parse,
            args=(ndpi, pcap, th, self.exclude_broadcast_var.get())
        )
        t.daemon = True
        t.start()

    def _run_ndpi_and_parse(self, ndpi, pcap, th, excl_bcast):
        # 调用 ndpiReader：-e 5 + -v 2（输出含 Risk Info: Entropy）
        cmd = [ndpi, "-i", pcap, "-e", "5", "-v", "2"]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            out, err = proc.communicate()
        except Exception as e:
            self.append_log("运行 ndpiReader 失败：{}\n".format(e))
            self.run_btn.config(state="normal")
            return

        if err:
            self.append_log("[ndpiReader stderr]\n{}\n".format(err))

        lines = out.splitlines()

        # 先扫一遍，提取所有高熵命中的行
        raw_hits = []
        for ln in lines:
            if "Susp Entropy" not in ln:
                continue
            m = RE_ENTROPY_LINE.search(ln)
            if not m:
                continue
            flow_id, proto, sip, sport, dip, dport, entropy = m.groups()
            try:
                entropy = float(entropy)
            except:
                continue

            if entropy < th:
                continue

            if excl_bcast and (is_broadcast_or_multicast(sip) or is_broadcast_or_multicast(dip)):
                continue

            raw_hits.append({
                "FlowID": flow_id.strip(),
                "Proto": proto.strip(),
                "SrcIP": sip.strip(),
                "Sport": sport.strip(),
                "DstIP": dip.strip(),
                "Dport": dport.strip(),
                "Entropy": entropy,
            })

        if not raw_hits:
            self.append_log("没有发现达到阈值的高熵流量（阈值：{}）。\n".format(th))
            self.run_btn.config(state="normal")
            return

        # 统计端口出现频率（分别统计作为源端口/目的端口）
        dst_port_count = {}
        src_port_count = {}
        for r in raw_hits:
            dst_port_count[r["Dport"]] = dst_port_count.get(r["Dport"], 0) + 1
            src_port_count[r["Sport"]] = src_port_count.get(r["Sport"], 0) + 1

        # 依据“端口聚类 + 公网优先 + 避免临时端口”的启发式，标注服务器端
        server_counter = {}  # (ip, port) -> occurrences
        decided_hits = []
        for r in raw_hits:
            sip, sport, dip, dport = r["SrcIP"], r["Sport"], r["DstIP"], r["Dport"]

            dst_freq = dst_port_count.get(dport, 0)
            src_freq = src_port_count.get(sport, 0)
            sip_private = is_private_ip(sip)
            dip_private = is_private_ip(dip)

            server_ip = None
            server_port = None

            if dst_freq >= 2 and not dip_private and not is_ephemeral_port(dport):
                server_ip, server_port = dip, dport
            elif src_freq >= 2 and not sip_private and not is_ephemeral_port(sport):
                server_ip, server_port = sip, sport
            elif sip_private and not dip_private:
                server_ip, server_port = dip, dport
            elif dip_private and not sip_private:
                server_ip, server_port = sip, sport
            else:
                if dst_freq > src_freq:
                    server_ip, server_port = dip, dport
                elif src_freq > dst_freq:
                    server_ip, server_port = sip, sport
                else:
                    server_ip, server_port = None, None

            if server_ip and server_port:
                server_counter[(server_ip, server_port)] = server_counter.get((server_ip, server_port), 0) + 1
                mark = "{}:{}".format(server_ip, server_port)
            else:
                mark = ""

            rr = r.copy()
            rr["ServerMark"] = mark
            decided_hits.append(rr)

        # GUI：填充高熵流表
        self.results = decided_hits
        for item in self.results:
            self.tree.insert("", "end", values=(
                item["FlowID"], item["Proto"], item["SrcIP"], item["Sport"],
                item["DstIP"], item["Dport"], "{:.3f}".format(item["Entropy"]),
                item.get("ServerMark", "")
            ))

        self.append_log("发现 {} 条高熵流。\n".format(len(self.results)))

        # 服务器候选：聚合 (ip,port) 并做地理定位
        # 先把 server_counter 转成：port -> [(ip, count, location, isp)...]
        port_to_servers = {}
        unique_ips = set(ip for (ip, _p) in server_counter.keys())

        # 地理位置查询（带缓存）
        ip_geo = {}
        for ip in unique_ips:
            ip_geo[ip] = self.geo.lookup(ip)
            # 为了避免在线接口速率限制，轻微 sleep（离线模式不会走这里）
            if ip_geo[ip].get("source") == "online":
                time.sleep(0.2)

        for (ip, port), cnt in server_counter.items():
            info = ip_geo.get(ip, {"location": "N/A", "isp": "N/A"})
            loc = info.get("location") or "N/A"
            isp = info.get("isp") or "N/A"
            port_to_servers.setdefault(port, []).append((ip, cnt, loc, isp))

        # 排序并填充“服务器候选”表格
        summary_lines = []
        for port, lst in sorted(port_to_servers.items(),
                                key=lambda kv: (-sum(c for _ip, c, _loc, _isp in kv[1]), int(kv[0]))):
            lst_sorted = sorted(lst, key=lambda x: -x[1])
            for ip, cnt, loc, isp in lst_sorted:
                self.server_tree.insert("", "end", values=(port, ip, cnt, loc, isp))
            total = sum(cnt for _ip, cnt, _loc, _isp in lst_sorted)
            ips = ", ".join("{}({})".format(ip, cnt) for ip, cnt, _loc, _isp in lst_sorted)
            summary_lines.append("  - 端口 {}：合计 {} 次，IP: {}".format(port, total, ips))

        if summary_lines:
            self.append_log("疑似加密服务器（按端口聚类）：\n")
            for line in summary_lines:
                self.append_log(line + "\n")
        else:
            self.append_log("未形成“重复端口”聚类，暂无法标注服务器候选（样本可能过少）。\n")

        self.export_btn.config(state="normal" if self.results else "disabled")
        self.run_btn.config(state="normal")

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("提示", "没有可导出的结果。")
            return
        path = filedialog.asksaveasfilename(
            title="导出 CSV（仅高熵流）",
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")]
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=["FlowID","协议","源IP","源端口","目的IP","目的端口","墒","加密服务器"]
                )
                w.writeheader()
                for r in self.results:
                    row = r.copy()
                    row["Entropy"] = "{:.3f}".format(row["Entropy"])
                    w.writerow(row)
            messagebox.showinfo("成功", "已导出到：{}".format(path))
        except Exception as e:
            messagebox.showerror("错误", "导出失败：{}".format(e))

    def on_close(self):
        try:
            self.geo.close()
        except Exception:
            pass
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()
