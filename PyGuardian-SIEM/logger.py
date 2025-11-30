# logger.py
import os, time
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "intrusion_log.txt")
BLOCK_FILE = os.path.join(LOG_DIR, "blocked_ips.txt")

def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def log_intrusion(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] {msg}\n")

def log_block(ip):
    with open(BLOCK_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] BLOCKED {ip}\n")
    # Also add a short intrusion log line
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] [AUTO-BLOCKED] {ip}\n")
