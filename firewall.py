"""macOS packet-filter (pf) integration — opt-in IP blocking.

Safety model (important):
  * Disabled by default. Nothing here runs unless config.json has
    {"firewall": {"enabled": true}}.
  * All blocking happens inside a DEDICATED pf anchor + table named "homescope".
    We never touch your main ruleset, so a single flush removes every rule this
    tool ever added. "panic_flush" clears it instantly.
  * Inputs are validated as real IPs/CIDRs with the stdlib `ipaddress` module and
    passed to pfctl as argv (never shell-interpolated), so a crafted value cannot
    inject a command.

Honest scope:
  pf on a normal Mac filters only THIS machine's traffic. To block a device for
  the whole house, block it on your router, or use the DNS sinkhole (resolver.py)
  for domain-level blocking network-wide.
"""

import ipaddress
import json
import os
import subprocess
import threading
import time

STATE_DIR = os.path.expanduser("~/.netscope")
FW_FILE = os.path.join(STATE_DIR, "blocked_ips.json")
ANCHOR = "homescope"
TABLE = "homescope_block"


def valid_target(value):
    """Return a normalized IP/CIDR string, or None if not valid."""
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except Exception:
        return None


class PFFirewall:
    def __init__(self, cfg):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled"))
        self.is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
        self.blocked = set()
        self.lock = threading.Lock()
        self.last_error = None
        self.load()

    # ---- persistence ----
    def load(self):
        try:
            with open(FW_FILE) as fh:
                for t in json.load(fh).get("ips", []):
                    n = valid_target(t)
                    if n:
                        self.blocked.add(n)
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with self.lock:
                data = {"ips": sorted(self.blocked)}
            with open(FW_FILE + ".tmp", "w") as fh:
                json.dump(data, fh)
            os.replace(FW_FILE + ".tmp", FW_FILE)
        except Exception:
            pass

    # ---- pf status (read-only, always allowed) ----
    def status(self):
        info = self._pfctl(["-s", "info"], read_only=True)
        enabled_in_pf = "Status: Enabled" in (info or "")
        return {
            "enabled": self.enabled,
            "is_root": self.is_root,
            "pf_enabled": enabled_in_pf,
            "blocked_ips": sorted(self.blocked),
            "anchor": ANCHOR,
            "active": self.enabled and self.is_root,
            "error": self.last_error,
            "note": ("pf filters only this Mac unless it is your gateway; "
                     "use the DNS sinkhole or your router for network-wide blocks."),
        }

    def _pfctl(self, args, read_only=False):
        if not read_only and not (self.enabled and self.is_root):
            self.last_error = "firewall disabled or not root"
            return None
        try:
            r = subprocess.run(["pfctl"] + args, capture_output=True,
                               text=True, timeout=8)
            return (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            self.last_error = "pfctl not found (not macOS?)"
            return None
        except Exception as e:
            self.last_error = str(e)
            return None

    # ---- mutating ops (gated) ----
    def _rules_text(self):
        # Dedicated anchor: block traffic to/from the homescope table.
        return (f"table <{TABLE}> persist\n"
                f"block drop quick from <{TABLE}>\n"
                f"block drop quick to <{TABLE}>\n")

    def _apply(self):
        """Load the anchor rules and sync the table to self.blocked."""
        if not (self.enabled and self.is_root):
            self.last_error = "firewall disabled or not root"
            return False
        # load anchor ruleset from stdin
        try:
            p = subprocess.run(["pfctl", "-a", ANCHOR, "-f", "-"],
                               input=self._rules_text(), text=True,
                               capture_output=True, timeout=8)
            if p.returncode != 0:
                self.last_error = p.stderr.strip() or "pfctl load failed"
        except Exception as e:
            self.last_error = str(e)
            return False
        # replace table contents with the validated set:
        #   pfctl -a homescope -t homescope_block -T replace <ip> <ip> ...
        with self.lock:
            targets = sorted(self.blocked)
        args = ["pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "replace"] + targets
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=8)
        except Exception as e:
            self.last_error = str(e)
            return False
        # ensure pf is on
        self._pfctl(["-e"])
        return True

    def preview(self, target):
        n = valid_target(target)
        if not n:
            return {"ok": False, "error": "not a valid IP or CIDR"}
        return {"ok": True, "target": n,
                "rules": self._rules_text() + f"# table <{TABLE}> add {n}"}

    def block_ip(self, target):
        n = valid_target(target)
        if not n:
            return {"ok": False, "error": "not a valid IP or CIDR"}
        with self.lock:
            self.blocked.add(n)
        self.save()
        ok = self._apply()
        return {"ok": ok, "target": n, "error": self.last_error if not ok else None}

    def unblock_ip(self, target):
        n = valid_target(target)
        with self.lock:
            self.blocked.discard(n)
        self.save()
        ok = self._apply()
        return {"ok": ok, "target": n}

    def panic_flush(self):
        """Remove every rule/table entry this tool added."""
        self._pfctl(["-a", ANCHOR, "-F", "all"])
        self._pfctl(["-a", ANCHOR, "-t", TABLE, "-T", "flush"])
        with self.lock:
            self.blocked.clear()
        self.save()
        return {"ok": True}
