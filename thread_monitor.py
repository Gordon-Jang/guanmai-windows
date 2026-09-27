# -*- coding: utf-8 -*-
"""WinScope Monitor：Windows 进程、线程与端口监控。

纯 Python 标准库实现：
  - 界面：tkinter / ttk（Notebook 分页）
  - 进程/线程数据：PowerShell CIM（Win32_Process / Win32_Thread）
  - 端口占用数据：port_monitor（Get-NetTCPConnection / Get-NetUDPEndpoint，netstat 兜底）
  - 线程创建时间：ctypes 调用 kernel32.GetThreadTimes（能取则取）
  - 代码签名：PowerShell Get-AuthenticodeSignature（按需，仅选中进程/端口）
  - 结束进程/线程：ctypes kernel32.TerminateProcess / TerminateThread（仅用户明确点击并确认）

端口页只读：不提供关闭端口、停止监听或任何网络修改动作。
"""

import ctypes
import ctypes.wintypes as wintypes
import datetime
import queue
import sys
import threading

from port_monitor import (
    _PS_PROLOGUE,
    _as_list,
    _parse_json,
    _run_powershell,
    SIG_STATUS_ZH,
    classify_path_clue,
    collect_ports,
    explain_process,
    get_signature,
    quick_purpose,
)

try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import messagebox
    TK_AVAILABLE = True
except Exception:  # pragma: no cover - 无显示环境时仍可自测数据层
    TK_AVAILABLE = False


# ---------------------------------------------------------------------------
# 常量与映射表
# ---------------------------------------------------------------------------

# Win32_Thread.ThreadState 取值（公开文档约定）
THREAD_STATES = {
    0: "初始化",
    1: "就绪",
    2: "运行",
    3: "备用",
    4: "已终止",
    5: "等待",
    6: "转换",
    7: "延迟就绪",
    8: "门等待(旧)",
}

# Win32_Thread.ThreadWaitReason 取值
THREAD_WAIT_REASONS = {
    0: "Executive",
    1: "FreePage",
    2: "PageIn",
    3: "SystemAllocation",
    4: "ExecutionDelay",
    5: "Suspended",
    6: "UserRequest",
    7: "EventPairHigh",
    8: "EventPairLow",
    9: "LPCReceive",
    10: "LPCReply",
    11: "VirtualMemory",
    12: "PageOut",
    13: "Rendezvous",
    14: "Spare",
    15: "Spare2",
    16: "Spare3",
    17: "Spare4",
    18: "Spare5",
    19: "ExecutionDelayAbortible",
}

# TCP 状态（CIM 英文值）到中文的映射；UDP 无连接状态显示为“无(连接无关)”。
PORT_STATES_ZH = {
    "Listen": "监听",
    "Established": "已建立",
    "TimeWait": "等待(TimeWait)",
    "CloseWait": "关闭等待(CloseWait)",
    "FinWait1": "FIN等待1",
    "FinWait2": "FIN等待2",
    "LastAck": "最后确认(LastAck)",
    "SynSent": "SYN已发送",
    "SynReceived": "SYN已接收",
    "Closing": "关闭中",
    "Bound": "已绑定",
    "DeleteTcb": "删除TCB",
    "Unknown": "未知",
}


# ---------------------------------------------------------------------------
# PowerShell 采集脚本（进程 / 线程）
# ---------------------------------------------------------------------------

_PS_PROCESSES = _PS_PROLOGUE + r'''
$rows = @()
Get-CimInstance Win32_Process | ForEach-Object {
  $rows += [PSCustomObject]@{
    pid      = [int]$_.ProcessId
    name     = [string]$_.Name
    ppid     = [int]$_.ParentProcessId
    threads  = [int]$_.ThreadCount
    created  = $(if ($_.CreationDate) { $_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss') } else { $null })
    path     = [string]$_.ExecutablePath
  }
}
$rows | ConvertTo-Json -Compress -Depth 3
'''

_PS_THREADS = _PS_PROLOGUE + r'''
$p = '__PID__'
$rows = @()
Get-CimInstance Win32_Thread -Filter "ProcessHandle = '$p'" | ForEach-Object {
  $rows += [PSCustomObject]@{
    tid   = [int]$_.Handle
    state = [int]$_.ThreadState
    wait  = [int]$_.ThreadWaitReason
    prio  = [int]$_.Priority
  }
}
$rows | ConvertTo-Json -Compress -Depth 3
'''


# ---------------------------------------------------------------------------
# 数据采集（进程 / 线程）
# ---------------------------------------------------------------------------

def collect_processes():
    """返回全部进程列表，每项含 pid/name/ppid/threads/created/path。"""
    out = _run_powershell(_PS_PROCESSES)
    return _as_list(_parse_json(out))


def collect_threads(pid):
    """返回指定进程的线程列表，每项含 tid/state/wait/prio。"""
    if not isinstance(pid, int) or pid < 0:
        return []
    script = _PS_THREADS.replace("__PID__", str(pid))
    out = _run_powershell(script)
    return _as_list(_parse_json(out))


def _filetime_to_datetime(ft):
    """Windows FILETIME（1601-01-01 起 100ns 单位）转本地 datetime。"""
    if not ft or ft <= 0:
        return None
    epoch_100ns = 116444736000000000
    seconds = (ft - epoch_100ns) / 1e7
    utc = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
    return utc.astimezone()


def get_thread_creation_times(tids):
    """用 GetThreadTimes 批量获取线程创建时间，失败则对应值为 None。"""
    result = {}
    if not tids:
        return result
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.GetThreadTimes.restype = wintypes.BOOL
    kernel32.GetThreadTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    THREAD_QUERY_INFORMATION = 0x0040
    for tid in tids:
        try:
            h = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, int(tid))
            if not h:
                result[tid] = None
                continue
            try:
                c = wintypes.FILETIME()
                e = wintypes.FILETIME()
                k = wintypes.FILETIME()
                u = wintypes.FILETIME()
                ok = kernel32.GetThreadTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
                if ok:
                    ft = (c.dwHighDateTime << 32) | c.dwLowDateTime
                    result[tid] = _filetime_to_datetime(ft)
                else:
                    result[tid] = None
            finally:
                kernel32.CloseHandle(h)
        except Exception:
            result[tid] = None
    return result


# ---------------------------------------------------------------------------
# 结束进程/线程（ctypes kernel32；仅由用户在确认框明确点击后触发）
# ---------------------------------------------------------------------------

def _win32_error_text(err):
    mapping = {
        5: "拒绝访问（权限不足）",
        6: "句柄无效（目标可能已退出）",
        87: "参数错误（目标可能已退出）",
    }
    return mapping.get(err, "错误码 %d" % err)


def _kernel32_bindings():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateThread.restype = wintypes.BOOL
    kernel32.TerminateThread.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32


PROCESS_TERMINATE = 0x0001
THREAD_TERMINATE = 0x0001


def terminate_process(pid):
    """结束指定进程。返回 (是否成功, 说明文本)。"""
    kernel32 = _kernel32_bindings()
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
    if not h:
        return False, "无法打开进程：%s" % _win32_error_text(ctypes.get_last_error())
    try:
        if not kernel32.TerminateProcess(h, 1):
            return False, "结束进程失败：%s" % _win32_error_text(ctypes.get_last_error())
        return True, "已结束进程 PID %d" % pid
    finally:
        kernel32.CloseHandle(h)


def terminate_thread(tid):
    """结束指定线程。返回 (是否成功, 说明文本)。"""
    kernel32 = _kernel32_bindings()
    h = kernel32.OpenThread(THREAD_TERMINATE, False, int(tid))
    if not h:
        return False, "无法打开线程：%s" % _win32_error_text(ctypes.get_last_error())
    try:
        if not kernel32.TerminateThread(h, 1):
            return False, "结束线程失败：%s" % _win32_error_text(ctypes.get_last_error())
        return True, "已结束线程 TID %d" % tid
    finally:
        kernel32.CloseHandle(h)


# ---------------------------------------------------------------------------
# 展示格式化
# ---------------------------------------------------------------------------

def _fmt_dt(dt):
    if not dt:
        return "未知"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_state(state):
    return THREAD_STATES.get(state, "未知(%d)" % state)


def _fmt_wait(wait):
    return THREAD_WAIT_REASONS.get(wait, "未知(%d)" % wait)


def _fmt_port_state(state):
    s = (state or "").strip()
    if not s:
        return "无(连接无关)"
    return PORT_STATES_ZH.get(s, s)


def _format_endpoint(addr, port):
    a = addr if addr not in (None, "", "*") else "*"
    if ":" in str(a) and not str(a).startswith("["):
        a = "[%s]" % a
    try:
        p = int(port)
    except (TypeError, ValueError):
        p = 0
    if a == "*" and p == 0:
        return "*"
    return "%s:%s" % (a, p)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class ThreadMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WinScope Monitor | 进程、线程与端口监控")
        self.root.geometry("1240x760")
        self.msg_queue = queue.Queue()
        self.processes = []
        self.selected_pid = None
        self.selected_tid = None
        self.current_proc = {}
        self.refreshing = False
        self.proc_rows = []
        self.thread_rows = []
        self.proc_cols = ("pid", "name", "ppid", "nthreads", "created", "clue", "purpose", "path")
        self.thread_cols = ("tid", "state", "wait", "prio", "created")
        self.proc_sort_col = "name"
        self.proc_sort_desc = False
        self.thread_sort_col = None
        self.thread_sort_desc = False

        # 端口页状态
        self.ports = []
        self.port_items = []
        self.port_rows = []
        self.port_full = []
        self.port_cols = ("protocol", "local", "remote", "state", "pid", "name", "ppid", "path", "purpose")
        self.port_sort_col = None
        self.port_sort_desc = False
        self.port_refreshing = False
        self.selected_port_index = None

        self.auto_var = tk.BooleanVar(value=True)
        self.interval_var = tk.DoubleVar(value=5.0)
        self.filter_var = tk.StringVar()
        self.port_filter_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")
        self.detail_var = tk.StringVar(value="尚未选择进程")
        self.port_detail_var = tk.StringVar(value="尚未选择端口")

        self._build_ui()
        self._poll_queue()
        self.root.after(300, self.refresh_processes)
        self.root.after(400, self.refresh_ports)

    # ---- UI 构建 ----
    def _build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self._build_process_tab(nb)
        self._build_port_tab(nb)

        status = ttk.Frame(self.root, padding=(6, 0, 6, 6))
        status.pack(fill="x")
        ttk.Label(status, textvariable=self.status_var, anchor="w").pack(side="left")
        ttk.Label(status, text="结束进程/线程需二次确认，风险自担；端口页只读",
                  anchor="e").pack(side="right")

    def _build_process_tab(self, nb):
        tab = ttk.Frame(nb)
        nb.add(tab, text="进程 / 线程")

        toolbar = ttk.Frame(tab, padding=6)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="立即刷新", command=self.refresh_processes).pack(side="left")
        ttk.Checkbutton(toolbar, text="自动刷新", variable=self.auto_var,
                        command=self._on_auto_toggle).pack(side="left", padx=(12, 0))
        ttk.Label(toolbar, text="间隔(秒)").pack(side="left", padx=(6, 0))
        ttk.Spinbox(toolbar, from_=2, to=60, increment=1, width=5,
                    textvariable=self.interval_var).pack(side="left", padx=(2, 0))
        ttk.Label(toolbar, text="搜索").pack(side="left", padx=(16, 0))
        ttk.Entry(toolbar, textvariable=self.filter_var, width=24).pack(side="left", padx=(4, 0))
        self.filter_var.trace_add("write", lambda *_: self._apply_filter())

        mgmt = ttk.LabelFrame(tab, text="管理区", padding=6)
        mgmt.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(mgmt, text="刷新", command=self.refresh_processes).pack(side="left")
        ttk.Button(mgmt, text="查看来源/作用", command=self.show_source_detail).pack(side="left", padx=(8, 0))
        ttk.Button(mgmt, text="结束选中进程", command=self.terminate_selected_process).pack(side="left", padx=(8, 0))
        ttk.Button(mgmt, text="结束选中线程", command=self.terminate_selected_thread).pack(side="left", padx=(8, 0))
        ttk.Label(mgmt, text="结束操作需二次确认，风险自担").pack(side="left", padx=(16, 0))

        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        proc_frame = ttk.Frame(paned)
        paned.add(proc_frame, weight=3)
        self.proc_headers = {
            "pid": "PID", "name": "名称", "ppid": "父PID", "nthreads": "线程数",
            "created": "进程创建时间", "clue": "线索", "purpose": "用途(简要)", "path": "可执行路径",
        }
        self.proc_tree = ttk.Treeview(proc_frame, columns=self.proc_cols, show="headings", selectmode="browse")
        widths = {"pid": 60, "name": 130, "ppid": 60, "nthreads": 60, "created": 140,
                  "clue": 90, "purpose": 220, "path": 360}
        for c in self.proc_cols:
            self.proc_tree.heading(c, text=self.proc_headers[c],
                                   command=lambda col=c: self._on_proc_header_click(col))
            self.proc_tree.column(c, width=widths[c], anchor="w", stretch=(c in ("name", "purpose", "path")))
        proc_vsb = ttk.Scrollbar(proc_frame, orient="vertical", command=self.proc_tree.yview)
        proc_hsb = ttk.Scrollbar(proc_frame, orient="horizontal", command=self.proc_tree.xview)
        self.proc_tree.configure(yscrollcommand=proc_vsb.set, xscrollcommand=proc_hsb.set)
        self.proc_tree.grid(row=0, column=0, sticky="nsew")
        proc_vsb.grid(row=0, column=1, sticky="ns")
        proc_hsb.grid(row=1, column=0, sticky="ew")
        proc_frame.rowconfigure(0, weight=1)
        proc_frame.columnconfigure(0, weight=1)
        self.proc_tree.bind("<<TreeviewSelect>>", self._on_process_select)

        right = ttk.Frame(paned)
        paned.add(right, weight=2)
        self.thread_headers = {"tid": "线程ID", "state": "状态", "wait": "等待原因",
                               "prio": "优先级", "created": "线程创建时间"}
        self.thread_tree = ttk.Treeview(right, columns=self.thread_cols, show="headings", height=12)
        thread_widths = {"tid": 80, "state": 80, "wait": 140, "prio": 70, "created": 150}
        for c in self.thread_cols:
            self.thread_tree.heading(c, text=self.thread_headers[c],
                                     command=lambda col=c: self._on_thread_header_click(col))
            self.thread_tree.column(c, width=thread_widths[c], anchor="w", stretch=False)
        thread_vsb = ttk.Scrollbar(right, orient="vertical", command=self.thread_tree.yview)
        self.thread_tree.configure(yscrollcommand=thread_vsb.set)
        self.thread_tree.pack(side="top", fill="both", expand=True)
        thread_vsb.pack(side="right", fill="y")
        self.thread_tree.bind("<<TreeviewSelect>>", self._on_thread_select)

        detail = ttk.LabelFrame(right, text="选中对象说明", padding=6)
        detail.pack(side="bottom", fill="x")
        ttk.Label(detail, textvariable=self.detail_var, justify="left",
                  wraplength=520).pack(anchor="w")

    def _build_port_tab(self, nb):
        tab = ttk.Frame(nb)
        nb.add(tab, text="端口占用")

        toolbar = ttk.Frame(tab, padding=6)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="立即刷新端口", command=self.refresh_ports).pack(side="left")
        ttk.Label(toolbar, text="搜索").pack(side="left", padx=(16, 0))
        ttk.Entry(toolbar, textvariable=self.port_filter_var, width=28).pack(side="left", padx=(4, 0))
        self.port_filter_var.trace_add("write", lambda *_: self._apply_port_filter())
        ttk.Label(toolbar, text="端口数据只读，不提供关闭/停止操作").pack(side="left", padx=(16, 0))

        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.port_headers = {
            "protocol": "协议", "local": "本地地址/端口", "remote": "远端地址/端口",
            "state": "状态", "pid": "PID", "name": "进程名", "ppid": "父PID",
            "path": "路径", "purpose": "用途(简要)",
        }
        self.port_tree = ttk.Treeview(tree_frame, columns=self.port_cols, show="headings", selectmode="browse")
        port_widths = {"protocol": 60, "local": 180, "remote": 180, "state": 100,
                       "pid": 60, "name": 130, "ppid": 60, "path": 360, "purpose": 200}
        for c in self.port_cols:
            self.port_tree.heading(c, text=self.port_headers[c],
                                   command=lambda col=c: self._on_port_header_click(col))
            self.port_tree.column(c, width=port_widths[c], anchor="w",
                                  stretch=(c in ("name", "path", "purpose")))
        port_vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.port_tree.yview)
        port_hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.port_tree.xview)
        self.port_tree.configure(yscrollcommand=port_vsb.set, xscrollcommand=port_hsb.set)
        self.port_tree.grid(row=0, column=0, sticky="nsew")
        port_vsb.grid(row=0, column=1, sticky="ns")
        port_hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.port_tree.bind("<<TreeviewSelect>>", self._on_port_select)

        detail = ttk.LabelFrame(tab, text="端口占用说明", padding=6)
        detail.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Label(detail, textvariable=self.port_detail_var, justify="left",
                  wraplength=1100).pack(anchor="w")

    # ---- 进程刷新 ----
    def refresh_processes(self):
        if self.refreshing:
            return
        self.refreshing = True
        self.status_var.set("正在刷新进程列表…")
        t = threading.Thread(target=self._worker_refresh_processes, daemon=True)
        t.start()

    def _worker_refresh_processes(self):
        try:
            procs = collect_processes()
            self.msg_queue.put(("processes", procs))
        except Exception as exc:  # noqa: BLE001
            self.msg_queue.put(("error", "进程列表刷新失败：%s" % exc))

    def _on_processes(self, procs):
        self.processes = procs
        self.refreshing = False
        self._apply_filter()
        self.status_var.set("最后刷新 %s · 共 %d 个进程"
                            % (datetime.datetime.now().strftime("%H:%M:%S"), len(procs)))
        self._schedule_auto()

    def _apply_filter(self):
        keyword = self.filter_var.get().strip().lower()
        rows = []
        for p in self.processes:
            name = str(p.get("name", ""))
            pid = p.get("pid")
            if keyword:
                if keyword not in name.lower() and keyword != str(pid):
                    continue
            clue = classify_path_clue(p.get("path")) or ""
            rows.append((
                pid, name, p.get("ppid", ""), p.get("threads", ""),
                p.get("created") or "未知", clue, quick_purpose(name, p.get("path")),
                p.get("path") or "",
            ))
        self.proc_rows = rows
        self._redraw_proc()

    # ---- 排序 ----
    @staticmethod
    def _cell_sort_key(v, numeric_col, dt_col):
        if v is None or v == "":
            return (1, "")
        s = str(v)
        if numeric_col:
            try:
                return (0, float(s))
            except ValueError:
                return (1, s.lower())
        if dt_col:
            if s == "未知":
                return (1, "")
            return (0, s)
        return (0, s.lower())

    def _sort_rows(self, rows, col, desc, cols, numeric_cols, dt_cols):
        if col is None or col not in cols:
            return rows
        idx = cols.index(col)
        numeric_col = col in numeric_cols
        dt_col = col in dt_cols

        def key(r):
            v = r[idx] if idx < len(r) else None
            return self._cell_sort_key(v, numeric_col, dt_col)

        return sorted(rows, key=key, reverse=desc)

    def _on_proc_header_click(self, col):
        if self.proc_sort_col == col:
            self.proc_sort_desc = not self.proc_sort_desc
        else:
            self.proc_sort_col = col
            self.proc_sort_desc = False
        self._redraw_proc()

    def _on_thread_header_click(self, col):
        if self.thread_sort_col == col:
            self.thread_sort_desc = not self.thread_sort_desc
        else:
            self.thread_sort_col = col
            self.thread_sort_desc = False
        self._redraw_threads()

    def _update_proc_headers(self):
        for col in self.proc_cols:
            text = self.proc_headers[col]
            if col == self.proc_sort_col:
                text += " ▼" if self.proc_sort_desc else " ▲"
            self.proc_tree.heading(col, text=text)

    def _update_thread_headers(self):
        for col in self.thread_cols:
            text = self.thread_headers[col]
            if col == self.thread_sort_col:
                text += " ▼" if self.thread_sort_desc else " ▲"
            self.thread_tree.heading(col, text=text)

    def _redraw_proc(self):
        self._update_proc_headers()
        self.proc_tree.delete(*self.proc_tree.get_children())
        for r in self._sort_rows(self.proc_rows, self.proc_sort_col, self.proc_sort_desc,
                                 self.proc_cols, {"pid", "ppid", "nthreads"}, {"created"}):
            self.proc_tree.insert("", "end", values=r)

    def _redraw_threads(self):
        self._update_thread_headers()
        self.thread_tree.delete(*self.thread_tree.get_children())
        for r in self._sort_rows(self.thread_rows, self.thread_sort_col, self.thread_sort_desc,
                                 self.thread_cols, {"tid", "prio"}, {"created"}):
            self.thread_tree.insert("", "end", values=r)

    # ---- 线程详情 ----
    def _on_process_select(self, _event=None):
        sel = self.proc_tree.selection()
        if not sel:
            return
        values = self.proc_tree.item(sel[0], "values")
        if not values:
            return
        try:
            pid = int(values[0])
        except (TypeError, ValueError):
            return
        name = str(values[1])
        ppid = values[2]
        path = str(values[7]) or None
        self.selected_pid = pid
        self.selected_tid = None
        self.current_proc = {"pid": pid, "name": name, "path": path, "ppid": ppid}
        self._fetch_threads(pid, name, path, ppid)

    def _fetch_threads(self, pid, name, path, ppid):
        self.status_var.set("正在获取 PID %s 的线程与签名…" % pid)
        t = threading.Thread(target=self._worker_threads,
                             args=(pid, name, path, ppid), daemon=True)
        t.start()

    def _worker_threads(self, pid, name, path, ppid):
        try:
            threads = collect_threads(pid)
            creation = get_thread_creation_times([t.get("tid") for t in threads])
            for t in threads:
                t["created"] = creation.get(t.get("tid"))
            signature = get_signature(path)
            purpose, basis = explain_process(name, path, signature)
            self.msg_queue.put(("threads", {
                "pid": pid, "name": name, "path": path, "ppid": ppid,
                "threads": threads, "signature": signature,
                "purpose": purpose, "basis": basis,
            }))
        except Exception as exc:  # noqa: BLE001
            self.msg_queue.put(("error", "线程获取失败（PID %s 可能已退出）：%s" % (pid, exc)))

    def _on_threads(self, data):
        self.current_proc = {
            "pid": data["pid"], "name": data["name"], "path": data.get("path"),
            "ppid": data.get("ppid"), "signature": data["signature"],
            "purpose": data["purpose"], "basis": data["basis"],
        }
        self._populate_threads(data["threads"])
        self._render_process_detail(data)
        self.status_var.set("PID %s · %d 个线程（线程创建时间能取则取）"
                            % (data["pid"], len(data["threads"])))

    def _populate_threads(self, threads):
        self.selected_tid = None
        rows = []
        for t in threads:
            rows.append((
                t.get("tid"),
                _fmt_state(t.get("state")),
                _fmt_wait(t.get("wait")),
                t.get("prio"),
                _fmt_dt(t.get("created")),
            ))
        self.thread_rows = rows
        self._redraw_threads()

    def _render_process_detail(self, data):
        sig = data["signature"] or {}
        status_zh = SIG_STATUS_ZH.get(sig.get("status"), sig.get("status") or "未知")
        signer = sig.get("signer") or "无"
        clue = classify_path_clue(data.get("path")) or "无明确系统目录线索"
        text = (
            "进程：%s (PID %s)\n"
            "父PID：%s\n"
            "路径：%s\n"
            "来源线索：%s\n"
            "代码签名：%s（签署者：%s）\n"
            "用途解释：%s\n"
            "解释依据：%s\n\n"
            "提示：本工具按透明规则展示来源与用途；无法证实的部分已标注"
            "“未知/需人工确认”。"
        ) % (
            data["name"], data["pid"], data.get("ppid", "未知"),
            data.get("path") or "（无，可能为内核/受保护进程）",
            clue, status_zh, signer,
            data["purpose"], data["basis"],
        )
        self.detail_var.set(text)

    def _on_thread_select(self, _event=None):
        sel = self.thread_tree.selection()
        if not sel:
            self.selected_tid = None
            return
        vals = self.thread_tree.item(sel[0], "values")
        if not vals:
            self.selected_tid = None
            return
        self.selected_tid = vals[0]
        self._render_thread_detail(vals)

    def _render_thread_detail(self, vals):
        tid = vals[0]
        state = vals[1]
        wait = vals[2]
        prio = vals[3]
        created = vals[4]
        proc = self.current_proc or {}
        sig = proc.get("signature") or {}
        status_zh = SIG_STATUS_ZH.get(sig.get("status"), sig.get("status") or "未知")
        signer = sig.get("signer") or "无"
        text = (
            "线程：TID %s\n"
            "状态：%s · 等待原因：%s\n"
            "优先级：%s · 创建时间：%s\n\n"
            "所属进程：%s (PID %s) · 父PID：%s\n"
            "进程路径：%s\n"
            "代码签名：%s（签署者：%s）\n"
            "用途解释：%s\n"
            "解释依据：%s\n\n"
            "来源说明：线程没有独立的可执行文件来源，其来源继承自所属进程；"
            "结束线程只影响该线程，可能导致所属进程状态异常或崩溃，风险自担。"
        ) % (
            tid, state, wait, prio, created,
            proc.get("name", "未知"), proc.get("pid", "未知"), proc.get("ppid", "未知"),
            proc.get("path") or "（无，可能为内核/受保护进程）",
            status_zh, signer,
            proc.get("purpose", "未知"), proc.get("basis", "未知"),
        )
        self.detail_var.set(text)

    # ---- 管理操作 ----
    def show_source_detail(self):
        if self.selected_tid is not None:
            sel = self.thread_tree.selection()
            if sel:
                vals = self.thread_tree.item(sel[0], "values")
                if vals:
                    self._render_thread_detail(vals)
                    return
        proc = self.current_proc or {}
        if proc.get("pid") is not None:
            self._fetch_threads(proc["pid"], proc.get("name", ""),
                                proc.get("path"), proc.get("ppid"))
        else:
            self.status_var.set("请先选择进程或线程")

    def _confirm_terminate(self, kind, label):
        return messagebox.askyesno(
            "确认结束%s" % kind,
            "确定要结束%s吗？\n\n目标：%s\n\n风险提示：\n"
            "- 结束进程会立即终止该进程及其所有线程，未保存数据可能丢失。\n"
            "- 结束线程可能导致所属进程状态不一致、崩溃或数据损坏。\n"
            "- 结束系统关键进程/线程可能导致系统不稳定。\n"
            "- 操作立即生效，通常不可撤销。\n\n"
            "仅当你明确理解风险且确认目标正确时，点击“是”。" % (kind, label),
            icon="warning",
        )

    def terminate_selected_process(self):
        proc = self.current_proc or {}
        pid = proc.get("pid")
        if pid is None:
            self.status_var.set("请先选择要结束的进程")
            return
        label = "%s (PID %s)" % (proc.get("name", ""), pid)
        if not self._confirm_terminate("进程", label):
            return
        threading.Thread(target=self._terminate_worker,
                         args=("process", pid, label), daemon=True).start()

    def terminate_selected_thread(self):
        if self.selected_tid is None:
            self.status_var.set("请先选择要结束的线程")
            return
        tid = self.selected_tid
        proc = self.current_proc or {}
        label = "TID %s" % tid
        if proc.get("name"):
            label = "TID %s（所属 %s PID %s）" % (tid, proc.get("name"), proc.get("pid"))
        if not self._confirm_terminate("线程", label):
            return
        threading.Thread(target=self._terminate_worker,
                         args=("thread", tid, label), daemon=True).start()

    def _terminate_worker(self, kind, target_id, label):
        try:
            if kind == "process":
                ok, msg = terminate_process(target_id)
            else:
                ok, msg = terminate_thread(target_id)
        except Exception as exc:  # noqa: BLE001
            ok, msg = False, "结束%s异常：%s" % (kind, exc)
        self.msg_queue.put(("term_result", {"ok": ok, "message": msg, "kind": kind}))

    def _reload_selected_threads(self):
        proc = self.current_proc or {}
        if proc.get("pid") is not None:
            self._fetch_threads(proc["pid"], proc.get("name", ""),
                                proc.get("path"), proc.get("ppid"))

    # ---- 端口页 ----
    def refresh_ports(self):
        if self.port_refreshing:
            return
        self.port_refreshing = True
        self.status_var.set("正在刷新端口占用…")
        threading.Thread(target=self._worker_refresh_ports, daemon=True).start()

    def _worker_refresh_ports(self):
        try:
            ports = collect_ports()
            self.msg_queue.put(("ports", ports))
        except Exception as exc:  # noqa: BLE001
            self.msg_queue.put(("error", "端口刷新失败：%s" % exc))

    def _on_ports(self, ports):
        self.ports = ports
        self.port_refreshing = False
        self._apply_port_filter()
        self.status_var.set("端口最后刷新 %s · 共 %d 条"
                            % (datetime.datetime.now().strftime("%H:%M:%S"), len(ports)))

    def _apply_port_filter(self):
        keyword = self.port_filter_var.get().strip().lower()
        items = []
        for p in self.ports:
            protocol = p.get("protocol") or ""
            local = _format_endpoint(p.get("local_address"), p.get("local_port"))
            remote = _format_endpoint(p.get("remote_address"), p.get("remote_port"))
            state = p.get("state") or ""
            pid = p.get("pid")
            name = p.get("process_name") or ""
            path = p.get("path") or ""
            purpose = p.get("purpose") or ""
            if keyword:
                hay = " ".join(str(x) for x in (protocol, local, remote, state, pid, name, path, purpose)).lower()
                if keyword not in hay:
                    continue
            row = (protocol, local, remote, _fmt_port_state(state), pid, name,
                   p.get("ppid"), path, purpose)
            items.append((row, p))
        self.port_items = items
        self._redraw_ports()

    def _on_port_header_click(self, col):
        if self.port_sort_col == col:
            self.port_sort_desc = not self.port_sort_desc
        else:
            self.port_sort_col = col
            self.port_sort_desc = False
        self._redraw_ports()

    def _update_port_headers(self):
        for col in self.port_cols:
            text = self.port_headers[col]
            if col == self.port_sort_col:
                text += " ▼" if self.port_sort_desc else " ▲"
            self.port_tree.heading(col, text=text)

    def _redraw_ports(self):
        self._update_port_headers()
        self.port_tree.delete(*self.port_tree.get_children())
        items = self.port_items
        col = self.port_sort_col
        if col is not None and col in self.port_cols:
            idx = self.port_cols.index(col)
            numeric = col in {"pid", "ppid"}

            def key(it):
                v = it[0][idx] if idx < len(it[0]) else None
                return self._cell_sort_key(v, numeric, False)

            items = sorted(items, key=key, reverse=self.port_sort_desc)
        self.port_rows = [it[0] for it in items]
        self.port_full = [it[1] for it in items]
        for r in self.port_rows:
            self.port_tree.insert("", "end", values=r)

    def _on_port_select(self, _event=None):
        sel = self.port_tree.selection()
        if not sel:
            self.selected_port_index = None
            return
        idx = self.port_tree.index(sel[0])
        if idx is None or idx >= len(self.port_full):
            return
        p = self.port_full[idx]
        self.selected_port_index = idx
        self._fetch_port_detail(p)

    def _fetch_port_detail(self, p):
        self.status_var.set("正在读取签名：%s" % (p.get("process_name") or p.get("pid")))
        threading.Thread(target=self._worker_port_detail, args=(p,), daemon=True).start()

    def _worker_port_detail(self, p):
        try:
            path = p.get("path")
            name = p.get("process_name")
            sig = get_signature(path)
            purpose, basis = explain_process(name, path, sig)
            self.msg_queue.put(("port_detail", {"port": p, "signature": sig,
                                                "purpose": purpose, "basis": basis}))
        except Exception as exc:  # noqa: BLE001
            self.msg_queue.put(("error", "读取端口详情失败：%s" % exc))

    def _on_port_detail(self, data):
        p = data["port"]
        sig = data["signature"] or {}
        status_zh = SIG_STATUS_ZH.get(sig.get("status"), sig.get("status") or "未知")
        signer = sig.get("signer") or "无"
        local = _format_endpoint(p.get("local_address"), p.get("local_port"))
        remote = _format_endpoint(p.get("remote_address"), p.get("remote_port"))
        parent_name = p.get("parent_name") or "未知"
        text = (
            "端口：%s %s -> %s（状态：%s）\n"
            "PID：%s · 进程名：%s · 父PID：%s\n"
            "来源路径：%s\n"
            "父进程：%s (PPID %s)\n"
            "代码签名：%s（签署者：%s）\n"
            "用途解释：%s\n"
            "用途依据：%s\n\n"
            "说明：端口仅属于进程，不代表线程。端口由所属进程打开/监听，"
            "同一个进程可能有多个线程，端口本身并不直接对应某个线程。"
        ) % (
            p.get("protocol"), local, remote, _fmt_port_state(p.get("state")),
            p.get("pid"), p.get("process_name") or "未知", p.get("ppid"),
            p.get("path") or "（无，可能为内核/受保护进程）",
            parent_name, p.get("ppid"),
            status_zh, signer,
            data["purpose"], data["basis"],
        )
        self.port_detail_var.set(text)
        self.status_var.set("端口详情已更新")

    # ---- 自动刷新 / 队列轮询 ----
    def _on_auto_toggle(self):
        if self.auto_var.get():
            self.root.after(200, self._auto_tick)

    def _schedule_auto(self):
        if self.auto_var.get():
            ms = max(1000, int(self.interval_var.get() * 1000))
            self.root.after(ms, self._auto_tick)

    def _auto_tick(self):
        if self.auto_var.get():
            self.refresh_processes()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "processes":
                    self._on_processes(payload)
                elif kind == "threads":
                    self._on_threads(payload)
                elif kind == "ports":
                    self._on_ports(payload)
                elif kind == "port_detail":
                    self._on_port_detail(payload)
                elif kind == "term_result":
                    self._on_term_result(payload)
                elif kind == "error":
                    self.refreshing = False
                    self.port_refreshing = False
                    self.status_var.set(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _on_term_result(self, payload):
        ok = payload.get("ok")
        message = payload.get("message", "")
        kind = payload.get("kind")
        if ok:
            self.status_var.set("成功：%s" % message)
            self.refresh_processes()
            if kind == "thread":
                self._reload_selected_threads()
        else:
            self.status_var.set("失败：%s" % message)


# ---------------------------------------------------------------------------
# 自测（无 GUI 也能验证数据层）
# ---------------------------------------------------------------------------

def self_test():
    print("== WinScope Monitor 数据层自测 ==")
    print("[1] 采集进程列表…")
    procs = collect_processes()
    print("    进程数:", len(procs))
    for p in procs[:5]:
        print("    ", p)

    preferred = ("explorer.exe", "taskmgr.exe", "python.exe", "pythonw.exe",
                 "powershell.exe", "pwsh.exe", "notepad.exe", "svchost.exe")
    target = None
    for name in preferred:
        for p in procs:
            if p.get("name", "").lower() == name and p.get("path"):
                target = p
                break
        if target:
            break
    if not target:
        for p in procs:
            if p.get("path"):
                target = p
                break
    if not target and procs:
        target = procs[0]
    if not target:
        print("[2] 无可用进程，跳过线程测试")
    else:
        pid = target.get("pid")
        print("[2] 测试进程:", target.get("name"), "PID", pid, "路径", target.get("path"))
        threads = collect_threads(pid)
        print("    线程数:", len(threads))
        for t in threads[:5]:
            print("    ", t)

        print("[3] 线程创建时间（GetThreadTimes）…")
        creation = get_thread_creation_times([t.get("tid") for t in threads[:10]])
        for tid, dt in list(creation.items())[:5]:
            print("    TID %s -> %s" % (tid, _fmt_dt(dt)))

        print("[4] 代码签名…")
        sig = get_signature(target.get("path"))
        print("    ", sig)

        print("[5] 用途解释…")
        purpose, basis = explain_process(target.get("name"), target.get("path"), sig)
        print("    用途:", purpose)
        print("    依据:", basis)

    print("[6] 端口占用…")
    try:
        ports = collect_ports()
        print("    端口/连接条数:", len(ports))
        for p in ports[:5]:
            print("    ", p.get("protocol"), p.get("local_address"), p.get("local_port"),
                  "->", p.get("remote_address"), p.get("remote_port"),
                  "|", p.get("state") or "-", "| PID", p.get("pid"),
                  "|", p.get("process_name") or "未知")
    except Exception as exc:  # noqa: BLE001
        print("    端口采集失败:", exc)

    print("== 自测完成 ==")


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    if not TK_AVAILABLE:
        print("错误：tkinter 不可用，无法启动图形界面。")
        print("提示：可运行 `python thread_monitor.py --self-test` 验证数据层。")
        return 1
    root = tk.Tk()
    ThreadMonitorApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
