import psutil
import time

def collect_metrics():
    """
    Collect current system runtime metrics.
    Returns a dictionary of metrics.
    """

    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent

    net_io_1 = psutil.net_io_counters()
    time.sleep(1)
    net_io_2 = psutil.net_io_counters()

    network_bytes = (
        (net_io_2.bytes_sent - net_io_1.bytes_sent) +
        (net_io_2.bytes_recv - net_io_1.bytes_recv)
    )

    process_count = len(psutil.pids())

    return {
        "cpu": cpu,
        "memory": memory,
        "network": network_bytes,
        "process_count": process_count
    }