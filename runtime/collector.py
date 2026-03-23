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
    
    # Optional Enhancement: Grab active network connections
    active_connections = []
    try:
        # Extract established connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                    proc_name = "Unknown"
                    
                active_connections.append({
                    "process": proc_name,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port
                })
    except psutil.AccessDenied:
        pass # May require Admin/Root rights on some OS

    # 2. Find top CPU consumer
    top_proc = None
    max_cpu = 0
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            p_info = proc.info
            if p_info['cpu_percent'] > max_cpu:
                max_cpu = p_info['cpu_percent']
                top_proc = {
                    "pid": p_info['pid'],
                    "name": p_info['name'],
                    "cpu": max_cpu
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return {
        "cpu": cpu,
        "memory": memory,
        "network": network_bytes,
        "process_count": process_count,
        "active_connections": active_connections[:5],
        "top_process": top_proc
    }