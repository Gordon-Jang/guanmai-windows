# -*- coding: utf-8 -*-
"""Windows 端口占用采集模块（纯标准库）。

采集真实 TCP/UDP 端口占用：
  - 主路径：PowerShell Get-NetTCPConnection / Get-NetUDPEndpoint
  - 兜底：netstat -ano（解析真实端口行）
  - 进程名/父 PID/路径：Get-CimInstance Win32_Process 建立 PID 映射

统一输出字典字段：
  protocol、local_address、local_port、remote_address、remote_port、state、
  pid、process_name、ppid、path、clue、purpose、signature
（另含 parent_name，便于界面展示父进程名）。

signature 按需读取（采集时默认为 None），避免对每条端口都做签名查询拖慢刷新。
端口数据只读：不提供关闭端口、停止监听或任何网络修改能力。

本模块同时提供签名与用途解释的共享实现，供 thread_monitor 复用，避免循环导入。
"""

import base64
import json
import os
import shutil
import subprocess
import sys


# ---------------------------------------------------------------------------
# 共享映射与常量
# ---------------------------------------------------------------------------

SIG_STATUS_ZH = {
    "Valid": "签名有效",
    "NotSigned": "未签名",
    "HashMismatch": "签名哈希不匹配",
    "NotTrusted": "证书不受信任",
    "UnknownError": "签名状态未知（异常）",
}

# 基于进程名的最常见 Windows 组件用途。仅作为透明规则提示，不代表可信性证明。
KNOWN_PROCESSES = {
    "system": "系统内核进程（PID 4 常驻）",
    "system idle process": "系统空闲进程",
    "idle": "系统空闲进程",
    "registry": "注册表（通常表现为 System 进程的一部分）",
    "secure system": "安全系统进程（内核隔离相关）",
    "smss.exe": "会话管理器（系统启动早期组件）",
    "csrss.exe": "客户端/服务器运行时子系统",
    "wininit.exe": "Windows 启动初始化",
    "services.exe": "服务控制管理器",
    "lsass.exe": "本地安全认证子系统",
    "winlogon.exe": "登录与会话管理",
    "svchost.exe": "Windows 服务宿主（承载多个系统服务）",
    "explorer.exe": "资源管理器 / 桌面 Shell",
    "dwm.exe": "桌面窗口管理器（合成桌面）",
    "taskmgr.exe": "任务管理器",
    "conhost.exe": "控制台宿主",
    "cmd.exe": "命令提示符",
    "powershell.exe": "Windows PowerShell",
    "pwsh.exe": "PowerShell 7",
    "python.exe": "Python 解释器",
    "pythonw.exe": "Python（无控制台窗口）",
    "fontdrvhost.exe": "字体驱动宿主",
    "sihost.exe": "Shell 基础设施宿主",
    "taskhostw.exe": "任务宿主",
    "spoolsv.exe": "打印后台处理程序",
    "audiodg.exe": "Windows 音频设备图隔离进程",
    "runtimebroker.exe": "运行时代理（应用权限中间层）",
    "searchindexer.exe": "搜索索引器",
    "ctfmon.exe": "输入法 / 文本服务框架监控",
    "dllhost.exe": "COM 代理宿主",
    "wmiprvse.exe": "WMI 提供程序宿主",
    "mmc.exe": "Microsoft 管理控制台",
    "regedit.exe": "注册表编辑器",
    "notepad.exe": "记事本",
    "mspaint.exe": "画图",
}


# ---------------------------------------------------------------------------
# PowerShell 调用层
# ---------------------------------------------------------------------------

_PS_PROLOGUE = (
    "$ProgressPreference = 'SilentlyContinue'\n"
    "$WarningPreference = 'SilentlyContinue'\n"
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
    "$ErrorActionPreference = 'SilentlyContinue'\n"
)

_PS_SIGNATURE = _PS_PROLOGUE + r'''
$env:PSModulePath = (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules') + ';' + 'C:\Program Files\WindowsPowerShell\Modules' + ';' + 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
$p = '__PATH__'
$sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue
if ($null -eq $sig) {
  [PSCustomObject]@{ status = '不可用'; signer = $null } | ConvertTo-Json -Compress
} else {
  [PSCustomObject]@{
    status = $sig.Status.ToString()
    signer = $(if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null })
  } | ConvertTo-Json -Compress
}
'''


def _find_powershell():
    """优先 powershell.exe（Windows 10/11 必然存在），退回 pwsh。"""
    for name in ("powershell.exe", "pwsh.exe", "pwsh"):
        p = shutil.which(name)
        if p:
            return p
    raise RuntimeError("未找到 PowerShell（powershell.exe / pwsh），无法采集系统数据")


def _run_powershell(script, timeout=20.0):
    """以 -EncodedCommand 运行脚本，避免路径/引号转义问题，返回 stdout 文本。"""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    ps = _find_powershell()
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", encoded],
        capture_output=True,
        timeout=timeout,
        creationflags=creationflags,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and not out.strip():
        raise RuntimeError("PowerShell 退出码 %d：%s" % (proc.returncode, err or "未知错误"))
    return out


def _parse_json(text):
    """解析 PowerShell 输出；容错处理 BOM 或首部混入的杂项文本。"""
    text = text.strip().lstrip("\ufeff").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for marker in ("[", "{"):
        idx = text.find(marker)
        if idx >= 0:
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                continue
    raise ValueError("无法把 PowerShell 输出解析为 JSON")


def _as_list(data):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# 签名与用途解释（共享逻辑）
# ---------------------------------------------------------------------------

def get_signature(path):
    """按需获取 exe 代码签名，返回 {status, signer}。"""
    if not path or not os.path.isfile(path):
        return {"status": "不可用", "signer": None}
    safe_path = path.replace("'", "''")
    script = _PS_SIGNATURE.replace("__PATH__", safe_path)
    try:
        data = _parse_json(_run_powershell(script))
    except Exception:
        return {"status": "不可用", "signer": None}
    if isinstance(data, list) and data:
        data = data[0]
    if not isinstance(data, dict):
        return {"status": "不可用", "signer": None}
    return {"status": data.get("status", "不可用"), "signer": data.get("signer")}


def classify_path_clue(path):
    if not path:
        return None
    low = path.lower().replace("/", "\\")
    if "\\windows\\system32\\" in low:
        return "System32"
    if "\\windows\\syswow64\\" in low:
        return "SysWOW64"
    if low.startswith("c:\\windows\\"):
        return "Windows 目录"
    return None


def quick_purpose(name, path):
    """列表用快速用途（不查签名）。"""
    name_l = (name or "").lower()
    clue = classify_path_clue(path)
    if name_l in KNOWN_PROCESSES:
        return KNOWN_PROCESSES[name_l] + "（名称规则）"
    if clue:
        return "系统目录 %s（路径规则）" % clue
    return "未知/需人工确认"


def explain_process(name, path, signature=None):
    """返回 (用途解释, 依据)。规则透明、确定，未证实内容明确标注。"""
    name_l = (name or "").lower()
    clue = classify_path_clue(path)
    sig_status = None
    sig_signer = None
    if signature:
        sig_status = signature.get("status")
        sig_signer = signature.get("signer")

    if name_l in KNOWN_PROCESSES:
        purpose = KNOWN_PROCESSES[name_l]
        if clue:
            return purpose + "（同时位于系统目录）", "内置进程名规则 + 路径规则(%s)" % clue
        return purpose, "内置进程名规则"

    if clue:
        if sig_status == "Valid":
            if sig_signer and "microsoft" in sig_signer.lower():
                return ("Windows 系统组件（位于 %s，Microsoft 签名有效）；具体职责未知" % clue,
                        "路径规则(%s) + 签名规则(Valid/Microsoft)" % clue)
            return ("位于系统目录 %s，签名有效；具体职责未知/需人工确认" % clue,
                    "路径规则(%s) + 签名规则(Valid)" % clue)
        if sig_status == "NotSigned":
            return ("位于系统目录 %s 但无签名，来源可信度未知" % clue,
                    "路径规则(%s) + 签名规则(NotSigned)" % clue)
        return ("位于 Windows 系统目录 %s，可能为系统组件；具体职责未知/需人工确认" % clue,
                "路径规则(%s)" % clue)

    if sig_status == "Valid":
        return ("代码签名有效（%s），更可能为已安装软件；具体用途未知/需人工确认"
                % (sig_signer or "未知签名者")), "签名规则(Valid)"
    if sig_status == "NotSigned":
        return "代码未签名，来源可信度未知；需人工确认", "签名规则(NotSigned)"
    if sig_status in ("HashMismatch", "NotTrusted", "UnknownError"):
        return ("代码签名异常（%s），来源可信度未知；需人工确认" % sig_status), "签名规则(%s)" % sig_status

    return "未知/需人工确认", "无可用规则"


# ---------------------------------------------------------------------------
# 端口采集
# ---------------------------------------------------------------------------

_PS_PROC_MAP = _PS_PROLOGUE + r'''
$rows = @()
Get-CimInstance Win32_Process | ForEach-Object {
  $rows += [PSCustomObject]@{
    pid = [int]$_.ProcessId
    name = [string]$_.Name
    ppid = [int]$_.ParentProcessId
    path = [string]$_.ExecutablePath
  }
}
$rows | ConvertTo-Json -Compress -Depth 3
'''

_PS_PORTS = _PS_PROLOGUE + r'''
$rows = @()
$tcpOk = $false
$udpOk = $false
try {
  Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
    $rows += [PSCustomObject]@{
      protocol = 'TCP'
      local_address = [string]$_.LocalAddress
      local_port = [int]$_.LocalPort
      remote_address = [string]$_.RemoteAddress
      remote_port = [int]$_.RemotePort
      state = $_.State.ToString()
      pid = [int]$_.OwningProcess
    }
  }
  $tcpOk = $true
} catch {}
try {
  Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
    $rows += [PSCustomObject]@{
      protocol = 'UDP'
      local_address = [string]$_.LocalAddress
      local_port = [int]$_.LocalPort
      remote_address = $(if ($_.RemoteAddress) { [string]$_.RemoteAddress } else { '*' })
      remote_port = $(if ($_.RemotePort) { [int]$_.RemotePort } else { 0 })
      state = ''
      pid = [int]$_.OwningProcess
    }
  }
  $udpOk = $true
} catch {}
if (-not $tcpOk -and -not $udpOk) { '##NETSTAT##' } else { $rows | ConvertTo-Json -Compress -Depth 3 }
'''


def _normalize_state(state):
    """把 CIM 或 netstat 的状态文本统一成一致的英文名。"""
    s = (state or "").strip()
    if not s:
        return ""
    mapping = {
        "LISTENING": "Listen",
        "LISTEN": "Listen",
        "ESTABLISHED": "Established",
        "TIME_WAIT": "TimeWait",
        "TIMEWAIT": "TimeWait",
        "CLOSE_WAIT": "CloseWait",
        "CLOSEWAIT": "CloseWait",
        "FIN_WAIT_1": "FinWait1",
        "FINWAIT1": "FinWait1",
        "FIN_WAIT_2": "FinWait2",
        "FINWAIT2": "FinWait2",
        "LAST_ACK": "LastAck",
        "LASTACK": "LastAck",
        "SYN_SENT": "SynSent",
        "SYNSENT": "SynSent",
        "SYN_RECEIVED": "SynReceived",
        "SYNRECEIVED": "SynReceived",
        "CLOSING": "Closing",
        "BOUND": "Bound",
    }
    return mapping.get(s.upper(), s)


def _split_endpoint(token):
    """解析 netstat 的 'addr:port' 或 '[v6]:port' 或 '*:*'。"""
    if not token:
        return None, None
    if token == "*":
        return "*", None
    addr, sep, port = token.rpartition(":")
    if not sep:
        return (token or "*"), None
    addr = addr.strip("[]")
    return (addr or "*"), _to_int(port)


def collect_process_map():
    """返回 {pid: {name, ppid, path}}。失败返回空字典。"""
    try:
        out = _run_powershell(_PS_PROC_MAP)
        data = _as_list(_parse_json(out))
    except Exception:
        return {}
    result = {}
    for p in data:
        if not isinstance(p, dict):
            continue
        pid = _to_int(p.get("pid"))
        if pid is None:
            continue
        result[pid] = {
            "name": p.get("name"),
            "ppid": _to_int(p.get("ppid")),
            "path": p.get("path") or None,
        }
    return result


def _collect_ports_ps():
    """用 Get-NetTCPConnection / Get-NetUDPEndpoint 采集，失败返回 None。"""
    out = _run_powershell(_PS_PORTS).strip()
    if not out or out == "##NETSTAT##":
        return None
    rows = []
    for r in _as_list(_parse_json(out)):
        if not isinstance(r, dict):
            continue
        rows.append({
            "protocol": (r.get("protocol") or "TCP").upper(),
            "local_address": r.get("local_address"),
            "local_port": _to_int(r.get("local_port")),
            "remote_address": r.get("remote_address"),
            "remote_port": _to_int(r.get("remote_port")),
            "state": _normalize_state(r.get("state")),
            "pid": _to_int(r.get("pid")),
        })
    return rows


def _collect_ports_netstat():
    """netstat -ano 兜底，解析真实 TCP/UDP 端口行。"""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            timeout=15,
            creationflags=creationflags,
        )
    except Exception:
        return []
    text = proc.stdout.decode("utf-8", errors="replace")
    rows = []
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        if len(parts) < 4:
            continue
        local = parts[1]
        remote = parts[2]
        if proto == "TCP":
            if len(parts) < 5:
                continue
            state = _normalize_state(parts[3])
            pid = _to_int(parts[4])
        else:
            state = ""
            pid = _to_int(parts[3])
        la, lp = _split_endpoint(local)
        ra, rp = _split_endpoint(remote)
        rows.append({
            "protocol": proto,
            "local_address": la,
            "local_port": lp,
            "remote_address": ra,
            "remote_port": rp,
            "state": state,
            "pid": pid,
        })
    return rows


def collect_ports():
    """采集端口并合并进程信息，返回统一字典列表。"""
    proc_map = collect_process_map()
    raw = None
    try:
        raw = _collect_ports_ps()
    except Exception:
        raw = None
    if not raw:
        raw = _collect_ports_netstat()

    ports = []
    for r in raw:
        pid = r.get("pid")
        info = proc_map.get(pid) if pid is not None else {}
        info = info or {}
        ppid = info.get("ppid")
        parent = proc_map.get(ppid) if ppid is not None else {}
        parent = parent or {}
        path = info.get("path")
        name = info.get("name")
        ports.append({
            "protocol": r.get("protocol"),
            "local_address": r.get("local_address"),
            "local_port": r.get("local_port"),
            "remote_address": r.get("remote_address"),
            "remote_port": r.get("remote_port"),
            "state": r.get("state"),
            "pid": pid,
            "process_name": name,
            "ppid": ppid,
            "path": path,
            "clue": classify_path_clue(path),
            "purpose": quick_purpose(name, path),
            "signature": None,
            "parent_name": parent.get("name"),
        })
    return ports


# ---------------------------------------------------------------------------
# 自测（无 GUI 也能验证数据层）
# ---------------------------------------------------------------------------

def self_test():
    print("== Windows 端口监控 数据层自测 ==")
    print("[1] 采集进程映射…")
    proc_map = collect_process_map()
    print("    进程数:", len(proc_map))

    print("[2] 采集端口占用…")
    ports = collect_ports()
    print("    端口/连接条数:", len(ports))
    for p in ports[:10]:
        print("    ", p.get("protocol"), p.get("local_address"), p.get("local_port"),
              "->", p.get("remote_address"), p.get("remote_port"),
              "|", p.get("state") or "-", "| PID", p.get("pid"),
              "|", p.get("process_name") or "未知", "| ppid", p.get("ppid"))

    tcp = sum(1 for p in ports if p.get("protocol") == "TCP")
    udp = sum(1 for p in ports if p.get("protocol") == "UDP")
    print("    TCP:", tcp, "UDP:", udp)

    target = None
    for p in ports:
        if p.get("path"):
            target = p
            break
    if target:
        print("[3] 按需签名与用途解释…")
        sig = get_signature(target.get("path"))
        print("    签名:", sig)
        purpose, basis = explain_process(target.get("process_name"), target.get("path"), sig)
        print("    用途:", purpose)
        print("    依据:", basis)
    else:
        print("[3] 无带路径的端口进程，跳过签名验证")

    print("== 自测完成 ==")


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    print("port_monitor.py 是数据层模块，不提供独立 GUI。")
    print("请运行 `python thread_monitor.py` 启动界面，")
    print("或 `python port_monitor.py --self-test` 验证端口数据层。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
