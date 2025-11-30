# detector.py
import time
from collections import deque, defaultdict
from logger import log_intrusion
from firewall_blocker import block_ip

class Detector:
    """
    Sustained-rate detector:
      - counts packets per 1-second bucket
      - keeps last N buckets (window_seconds)
      - triggers only if packets-per-second exceeds pps_threshold
        for sustain_windows consecutive buckets.
    Also rate-limits alerts per-IP.
    """

    def __init__(
        self,
        pps_threshold: int = 120,        # packets per second threshold
        window_seconds: int = 1,         # bucket size (seconds)
        keep_windows: int = 5,           # how many buckets to keep
        sustain_windows: int = 3,        # how many consecutive buckets must exceed threshold
        alert_suppression_seconds: int = 300  # suppress repeat alerts per IP
    ):
        self.pps_threshold = pps_threshold
        self.window_seconds = window_seconds
        self.keep_windows = keep_windows
        self.sustain_windows = sustain_windows
        self.alert_suppression_seconds = alert_suppression_seconds

        # For each IP -> deque of (bucket_start_ts, count)
        self.ip_buckets = defaultdict(lambda: deque(maxlen=self.keep_windows))
        # Last alert time per IP
        self.last_alert = {}
        # Blocked IP set in memory (helps avoid repeated block attempts)
        self.blocked = set()

    def _current_bucket(self, now=None):
        now = now if now is not None else time.time()
        # floor to window_seconds boundary
        return int(now // self.window_seconds) * self.window_seconds

    def observe_packet(self, src_ip: str, now=None):
        """Record a packet from src_ip. Returns action string if any: 'alert', 'block', or None"""
        if not src_ip:
            return None

        now = now if now is not None else time.time()
        bucket = self._current_bucket(now)

        dq = self.ip_buckets[src_ip]

        # If dq empty or last bucket != current, append new bucket
        if not dq or dq[-1][0] != bucket:
            dq.append((bucket, 1))
        else:
            # increment last bucket's count
            last_bucket, last_count = dq.pop()
            dq.append((last_bucket, last_count + 1))

        # If we don't have enough windows collected, don't evaluate yet
        if len(dq) < self.sustain_windows:
            return None

        # Check last sustain_windows buckets for threshold
        # We examine the most recent sustain_windows buckets
        recent = list(dq)[-self.sustain_windows:]
        # For clarity compute per-second rates (they already are per-window)
        exceed_counts = [count >= self.pps_threshold for (_b, count) in recent]

        if all(exceed_counts):
            # sustained exceed -> suspicious
            last = self.last_alert.get(src_ip, 0)
            if time.time() - last < self.alert_suppression_seconds:
                # already alerted recently => ensure block exists but do not spam logs
                if src_ip not in self.blocked:
                    self._block_and_log(src_ip)
                    return "block"
                return None
            # Not alerted recently -> log alert and block
            self.last_alert[src_ip] = time.time()
            self._block_and_log(src_ip)
            return "block"

        return None

    def _block_and_log(self, ip):
        # block via OS firewall
        try:
            block_ip(ip)
            self.blocked.add(ip)
            log_intrusion(f"[AUTO-BLOCKED] {ip} after sustained high-rate traffic")
        except Exception as e:
            log_intrusion(f"[ERROR] Failed to block {ip}: {e}")
