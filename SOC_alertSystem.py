"""
SSOC Monitor for Windows
-------------------------------------
Logs:
  soc_alerts.log             JSONL security/system alerts
  network_connections.jsonl  All visible TCP/UDP connections and listening ports
  process_resources.jsonl    Per-process CPU, memory, executable path and command line
  system_metrics.jsonl       Overall CPU, RAM, disk and network throughput




Windows may still restrict some protected processes/connections.
Stop with Ctrl+C.
"""

import json
import os
import time
from collections import Counter, defaultdict
from datetime import datetime

import psutil

try:
    import win32evtlog
except ImportError:
    win32evtlog = None


CONFIG = {
    "poll_interval": 10,
    "process_snapshot_interval": 30,
    "alert_cooldown": 300,
    "alert_log_file": "soc_alerts.log",
    "network_log_file": "network_connections.jsonl",
    "process_log_file": "process_resources.jsonl",
    "system_log_file": "system_metrics.jsonl",

    "cpu_threshold": 90,
    "ram_threshold": 90,
    "disk_threshold": 90,
    "sustained_samples": 3,

    "failed_login_threshold": 5,
    "event_lookback_sec": 60,
    "max_events_per_read": 500,

    # These are alert indicators, not proof of malicious activity.
    "suspicious_ports": {4444, 1337, 31337, 6667, 5555, 9001, 12345},
    "conn_per_ip_threshold": 50,
    "net_spike_mbps": 50,
}


WATCHED_EVENTS = {
    ("Security", 4625): ("MEDIUM", "Failed logon attempt"),
    ("Security", 4720): ("HIGH", "New user account created"),
    ("Security", 4722): ("MEDIUM", "User account enabled"),
    ("Security", 4724): ("MEDIUM", "Password reset attempt"),
    ("Security", 4732): ("HIGH", "User added to a privileged local group"),
    ("Security", 1102): ("CRITICAL", "Security audit log was cleared"),
    ("System", 104): ("CRITICAL", "Event log was cleared"),
    ("System", 7045): ("HIGH", "New service installed"),
    ("System", 7040): ("LOW", "Service start type changed"),
}
LOGS_TO_READ = ["Security", "System"]


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_jsonl(path, data):
    """Append one JSON object per line; creates the file if needed."""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, default=str) + "\n")


def safe_process_info(pid):
    """Return process identity/resource fields when Windows allows access."""
    if pid is None:
        return {
            "pid": None, "process_name": "unknown",
            "exe_path": None, "command_line": None,
            "process_cpu_percent": None, "process_memory_percent": None,
            "process_rss_mb": None,
        }

    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            try:
                name = proc.name()
            except psutil.Error:
                name = "unknown"
            try:
                exe = proc.exe()
            except (psutil.Error, OSError):
                exe = None
            try:
                cmdline = proc.cmdline()
            except (psutil.Error, OSError):
                cmdline = None
            try:
                cpu = proc.cpu_percent(interval=None)
            except psutil.Error:
                cpu = None
            try:
                mem = proc.memory_percent()
            except psutil.Error:
                mem = None
            try:
                rss_mb = proc.memory_info().rss / (1024 * 1024)
            except psutil.Error:
                rss_mb = None

        return {
            "pid": pid,
            "process_name": name,
            "exe_path": exe,
            "command_line": cmdline,
            "process_cpu_percent": cpu,
            "process_memory_percent": mem,
            "process_rss_mb": round(rss_mb, 2) if rss_mb is not None else None,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return {
            "pid": pid, "process_name": "unknown",
            "exe_path": None, "command_line": None,
            "process_cpu_percent": None, "process_memory_percent": None,
            "process_rss_mb": None,
        }


class Alerter:
    def __init__(self):
        self.last_sent = {}

    def send(self, severity, category, message, details=None):
        key = f"{category}:{message}"
        now = time.time()
        if now - self.last_sent.get(key, 0) < CONFIG["alert_cooldown"]:
            return
        self.last_sent[key] = now

        alert = {
            "time": now_iso(),
            "severity": severity,
            "category": category,
            "message": message,
            "details": details or {},
        }
        print(f"[{alert['time']}] [{severity}] [{category}] {message}")
        if details:
            print("    ->", details)
        append_jsonl(CONFIG["alert_log_file"], alert)


alerter = Alerter()


class EventLogMonitor:
    """Reads selected Windows events; continues gracefully when access is denied."""

    def __init__(self):
        self.seen = set()
        self.warned = set()

    def _read_recent(self, log_name):
        if win32evtlog is None:
            if "pywin32" not in self.warned:
                self.warned.add("pywin32")
                print("[!] pywin32 unavailable; Windows Event Log monitoring disabled.")
            return []

        events = []
        cutoff = time.time() - CONFIG["event_lookback_sec"]
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
        except Exception as exc:
            if log_name not in self.warned:
                self.warned.add(log_name)
                print(f"[!] Can't open '{log_name}' log: {exc}")
            return []

        try:
            done = False
            while not done and len(events) < CONFIG["max_events_per_read"]:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for event in batch:
                    try:
                        event_time = time.mktime(event.TimeGenerated.timetuple())
                    except (AttributeError, OverflowError, OSError, ValueError):
                        event_time = time.time()
                    if event_time < cutoff:
                        done = True
                        break
                    events.append(event)
        except Exception as exc:
            print(f"[!] Error reading '{log_name}' log: {exc}")
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
        return events

    def check(self):
        for log_name in LOGS_TO_READ:
            grouped = defaultdict(list)
            for event in self._read_recent(log_name):
                event_id = event.EventID & 0xFFFF
                if (log_name, event_id) not in WATCHED_EVENTS:
                    continue
                key = (log_name, event.RecordNumber)
                if key in self.seen:
                    continue
                self.seen.add(key)
                grouped[event_id].append(event)

            # Keep memory bounded during long-running monitoring.
            if len(self.seen) > 10000:
                self.seen = set(list(self.seen)[-5000:])

            for event_id, events in grouped.items():
                severity, description = WATCHED_EVENTS[(log_name, event_id)]
                if event_id == 4625:
                    # Event insertion order differs by Windows event version.
                    # Log raw inserts rather than claiming fixed fields are always correct.
                    if len(events) >= CONFIG["failed_login_threshold"]:
                        alerter.send(
                            "HIGH", "EVENTLOG",
                            f"Possible brute force: {len(events)} failed logons",
                            {"log": log_name, "event_id": event_id,
                             "raw_event_data": [list(e.StringInserts or []) for e in events[:10]]},
                        )
                    else:
                        for event in events:
                            alerter.send(
                                severity, "EVENTLOG", description,
                                {"log": log_name, "event_id": event_id,
                                 "time": str(event.TimeGenerated),
                                 "raw_event_data": list(event.StringInserts or [])},
                            )
                    continue

                for event in events:
                    alerter.send(
                        severity, "EVENTLOG", f"{description} (EventID {event_id})",
                        {"log": log_name, "time": str(event.TimeGenerated),
                         "source": event.SourceName,
                         "raw_event_data": list(event.StringInserts or [])},
                    )


class SystemMonitor:
    def __init__(self):
        self.high_count = defaultdict(int)
        self.last_net = psutil.net_io_counters()
        self.last_net_time = time.time()

    def _check_threshold(self, name, value, threshold):
        if value >= threshold:
            self.high_count[name] += 1
            if self.high_count[name] >= CONFIG["sustained_samples"]:
                alerter.send(
                    "MEDIUM", "SYSTEM",
                    f"{name} usage high: {value:.1f}% (>= {threshold}%)",
                    {"value_percent": round(value, 2), "threshold_percent": threshold},
                )
        else:
            self.high_count[name] = 0

    def check(self):
        # Non-blocking CPU sample; the first sample can be 0.0.
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        try:
            disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").percent
        except (OSError, ValueError):
            disk = None

        io = psutil.net_io_counters()
        current_time = time.time()
        elapsed = max(current_time - self.last_net_time, 0.001)
        sent_rate = (io.bytes_sent - self.last_net.bytes_sent) / elapsed
        recv_rate = (io.bytes_recv - self.last_net.bytes_recv) / elapsed
        total_mb_s = (sent_rate + recv_rate) / 1_000_000
        self.last_net, self.last_net_time = io, current_time

        data = {
            "time": now_iso(),
            "cpu_percent": cpu,
            "ram_percent": ram,
            "ram_used_mb": round(psutil.virtual_memory().used / (1024 * 1024), 2),
            "ram_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 2),
            "disk_percent": disk,
            "network_sent_mb_s": round(sent_rate / 1_000_000, 4),
            "network_received_mb_s": round(recv_rate / 1_000_000, 4),
            "network_total_mb_s": round(total_mb_s, 4),
        }
        append_jsonl(CONFIG["system_log_file"], data)

        self._check_threshold("CPU", cpu, CONFIG["cpu_threshold"])
        self._check_threshold("RAM", ram, CONFIG["ram_threshold"])
        if disk is not None:
            self._check_threshold("System drive disk", disk, CONFIG["disk_threshold"])
        if total_mb_s >= CONFIG["net_spike_mbps"]:
            alerter.send("MEDIUM", "NETWORK", f"Traffic spike: {total_mb_s:.1f} MB/s", data)


class NetworkMonitor:
    """Logs every connection visible to psutil, including local/remote endpoints."""

    def __init__(self):
        self.known_listen = None
        self.last_connections = set()
        self.last_snapshot = 0

    @staticmethod
    def endpoint(address):
        if not address:
            return None
        try:
            return {"ip": address.ip, "port": address.port}
        except AttributeError:
            try:
                return {"ip": address[0], "port": address[1]}
            except (IndexError, TypeError):
                return str(address)

    def check(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            alerter.send(
                "LOW", "NETWORK",
                "Access denied reading connections; run this program as Administrator",
            )
            return
        except (OSError, psutil.Error) as exc:
            alerter.send("LOW", "NETWORK", f"Could not enumerate connections: {exc}")
            return

        current_keys = set()
        listening_ports = set()
        per_ip = Counter()
        timestamp = now_iso()

        for conn in connections:
            local = self.endpoint(conn.laddr)
            remote = self.endpoint(conn.raddr)
            if conn.status == psutil.CONN_LISTEN and local:
                listening_ports.add(local["port"])
            if remote and conn.status == psutil.CONN_ESTABLISHED:
                per_ip[remote["ip"]] += 1

            # Include protocol, endpoints, state, PID, executable and resource info.
            # Connection snapshots are written each polling cycle so all visible ports
            # (not only "suspicious" ports) are represented.
            protocol = "TCP" if conn.type == 1 else "UDP" if conn.type == 2 else str(conn.type)
            identity = (
                protocol,
                local.get("ip") if local else None,
                local.get("port") if local else None,
                remote.get("ip") if remote else None,
                remote.get("port") if remote else None,
                conn.status,
                conn.pid,
            )
            current_keys.add(identity)
            proc_info = safe_process_info(conn.pid)

            row = {
                "time": timestamp,
                "protocol": protocol,
                "local_endpoint": local,
                "remote_endpoint": remote,
                "status": conn.status,
                "direction_hint": "local_to_remote" if remote else "listening_or_local",
                **proc_info,
            }
            append_jsonl(CONFIG["network_log_file"], row)

            if remote and remote["port"] in CONFIG["suspicious_ports"]:
                alerter.send(
                    "HIGH", "NETWORK",
                    f"Connection involving configured suspicious port {remote['port']}",
                    {"remote_ip": remote["ip"], "protocol": protocol,
                     "local_endpoint": local, **proc_info},
                )

        # Alert only for newly observed listening ports after the initial baseline.
        if self.known_listen is None:
            self.known_listen = set(listening_ports)
        else:
            new_ports = listening_ports - self.known_listen
            closed_ports = self.known_listen - listening_ports
            if new_ports:
                alerter.send("MEDIUM", "NETWORK", "New listening port(s) detected",
                             {"ports": sorted(new_ports)})
            if closed_ports:
                print(f"[INFO] Listening port(s) no longer present: {sorted(closed_ports)}")
            self.known_listen = set(listening_ports)

        for ip, count in per_ip.items():
            if count >= CONFIG["conn_per_ip_threshold"]:
                alerter.send("HIGH", "NETWORK",
                             f"{count} established connections to remote IP {ip}",
                             {"remote_ip": ip, "connection_count": count})

        # Report changes in connection set for quick console visibility.
        if self.last_connections:
            added = current_keys - self.last_connections
            removed = self.last_connections - current_keys
            if added:
                print(f"[NET] {len(added)} new/changed connection(s) observed.")
            if removed:
                print(f"[NET] {len(removed)} connection(s) disappeared since last check.")
        self.last_connections = current_keys


class ProcessResourceMonitor:
    """Periodically records resource use and executable path for visible processes."""

    def __init__(self):
        self.last_snapshot = 0

    def check(self):
        now = time.time()
        if now - self.last_snapshot < CONFIG["process_snapshot_interval"]:
            return
        self.last_snapshot = now
        timestamp = now_iso()

        for proc in psutil.process_iter():
            try:
                with proc.oneshot():
                    pid = proc.pid
                    name = proc.name()
                    exe = proc.exe()
                    cmdline = proc.cmdline()
                    cpu = proc.cpu_percent(interval=None)
                    memory = proc.memory_info()
                    mem_percent = proc.memory_percent()
                    threads = proc.num_threads()
                    try:
                        username = proc.username()
                    except (psutil.AccessDenied, psutil.Error):
                        username = None

                append_jsonl(CONFIG["process_log_file"], {
                    "time": timestamp,
                    "pid": pid,
                    "process_name": name,
                    "exe_path": exe,
                    "command_line": cmdline,
                    "username": username,
                    "cpu_percent": cpu,
                    "memory_percent": round(mem_percent, 4),
                    "rss_mb": round(memory.rss / (1024 * 1024), 2),
                    "vms_mb": round(memory.vms / (1024 * 1024), 2),
                    "threads": threads,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                # Processes can exit or deny access between enumeration and reading.
                continue


def main():
    print("=== Mini SOC Monitor started ===")
    print("Stop with Ctrl+C.")
    print("Logs:")
    for key in ("alert_log_file", "network_log_file", "process_log_file", "system_log_file"):
        print(f"  - {CONFIG[key]}")
    print("\nNetwork logs include all connections visible to this process.")
    print("Run elevated for better visibility; protected processes may remain inaccessible.\n")

    monitors = [
        EventLogMonitor(),
        SystemMonitor(),
        NetworkMonitor(),
        ProcessResourceMonitor(),
    ]
    # Prime psutil's non-blocking per-process CPU measurements.
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except psutil.Error:
            pass

    try:
        while True:
            for monitor in monitors:
                try:
                    monitor.check()
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    print(f"[!] {monitor.__class__.__name__} error: {exc}")
            time.sleep(CONFIG["poll_interval"])
    except KeyboardInterrupt:
        print("\nStopped. Logs have been saved in the current working directory.")


if __name__ == "__main__":
    main()
