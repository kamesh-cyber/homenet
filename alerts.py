"""Alert engine.

Raises lightweight, de-duplicated alerts on:
  * a never-before-seen device joining the network
  * a device exceeding a bandwidth threshold (bytes/sec, configurable)
  * queries to blocked domains being observed

Alerts are kept in a rolling in-memory feed for the dashboard.
"""

import json
import os
import threading
import time
from collections import deque

STATE_DIR = os.path.expanduser("~/.netscope")
KNOWN_FILE = os.path.join(STATE_DIR, "known_macs.json")


class AlertEngine:
    def __init__(self, cfg):
        cfg = cfg or {}
        self.threshold_bps = float(cfg.get("threshold_bps", 0)) or 0   # 0 = off
        self.alerts = deque(maxlen=200)
        self.known = set()
        self.recent_keys = {}        # de-dup key -> last fired ts
        self.lock = threading.Lock()
        self._load()

    def _load(self):
        try:
            with open(KNOWN_FILE) as fh:
                self.known = set(json.load(fh).get("macs", []))
        except Exception:
            self.known = set()

    def _save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(KNOWN_FILE + ".tmp", "w") as fh:
                json.dump({"macs": sorted(self.known)}, fh)
            os.replace(KNOWN_FILE + ".tmp", KNOWN_FILE)
        except Exception:
            pass

    def set_threshold(self, bps):
        try:
            self.threshold_bps = max(float(bps), 0)
            return True
        except Exception:
            return False

    def _fire(self, level, kind, msg, key, cooldown=120):
        now = time.time()
        with self.lock:
            last = self.recent_keys.get(key, 0)
            if now - last < cooldown:
                return
            self.recent_keys[key] = now
            self.alerts.appendleft({"t": now, "level": level,
                                    "kind": kind, "msg": msg})

    def evaluate(self, devices_snapshot, traffic_snapshot, dns_snapshot):
        # new device
        new_macs = []
        for d in devices_snapshot.get("devices", []):
            mac = d.get("mac")
            if mac and mac not in self.known:
                new_macs.append(mac)
                self._fire("warn", "new_device",
                           f"New device joined: {d.get('display_name')} "
                           f"({d.get('ip')} · {d.get('vendor') or 'unknown'})",
                           key=f"new:{mac}", cooldown=86400)
        if new_macs:
            with self.lock:
                self.known.update(new_macs)
            self._save()

        # bandwidth threshold
        if self.threshold_bps > 0:
            for t in traffic_snapshot.get("devices", []):
                if t.get("total_bps", 0) >= self.threshold_bps:
                    self._fire("warn", "bandwidth",
                               f"{t.get('name') or t.get('ip')} over threshold: "
                               f"{t['total_bps']/1024:.0f} KB/s",
                               key=f"bw:{t.get('ip')}", cooldown=60)

        # blocked-domain hits
        for domain, count in dns_snapshot.get("blocked_hits", []):
            self._fire("info", "blocked",
                       f"Blocked domain queried: {domain} (x{count})",
                       key=f"blk:{domain}", cooldown=300)

    def snapshot(self):
        with self.lock:
            return {"threshold_bps": self.threshold_bps,
                    "alerts": list(self.alerts)[:80]}
