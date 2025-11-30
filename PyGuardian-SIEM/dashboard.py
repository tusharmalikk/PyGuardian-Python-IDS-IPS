from rich.live import Live
from rich.table import Table
from rich import box
import time
from logger import LOG_FILE, BLOCK_FILE


def load_data():
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-8:]
    except:
        logs = ["No intrusion logs yet"]

    try:
        with open(BLOCK_FILE, "r") as f:
            blocked = f.readlines()[-5:]
    except:
        blocked = []

    return logs, blocked


def make_table():
    logs, blocked_ips = load_data()

    table = Table(title="🔥 PyGuardian IDS/IPS Live Dashboard", box=box.ROUNDED)

    table.add_column("Recent Intrusions", style="bold red")
    table.add_column("Blocked IPs", style="bold green")

    max_rows = max(len(logs), len(blocked_ips))

    for i in range(max_rows):
        log = logs[i].strip() if i < len(logs) else ""
        block = blocked_ips[i].strip() if i < len(blocked_ips) else ""
        table.add_row(log, block)

    return table


def start_dashboard():
    with Live(refresh_per_second=1) as live:
        while True:
            live.update(make_table())
            time.sleep(1)


if __name__ == "__main__":
    start_dashboard()
