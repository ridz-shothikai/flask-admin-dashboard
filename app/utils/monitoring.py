import psutil
from datetime import datetime
from app import db
from app.models import SystemMetric


def get_system_health():
    """Get current system health metrics"""
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=1)
    # Memory usage
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    memory_total = memory.total
    memory_used = memory.used
    # Disk usage
    disk = psutil.disk_usage('/')
    disk_percent = disk.percent
    disk_total = disk.total
    disk_used = disk.used

    return {
        'cpu': {
            'usage_percent': round(cpu_percent, 2)
        },
        'memory': {
            'usage_percent': round(memory_percent, 2),
            'total_bytes': memory_total,
            'used_bytes': memory_used,
            'total_gb': round(memory_total / (1024**3), 2),
            'used_gb': round(memory_used / (1024**3), 2)
        },
        'disk': {
            'usage_percent': round(disk_percent, 2),
            'total_bytes': disk_total,
            'used_bytes': disk_used,
            'total_gb': round(disk_total / (1024**3), 2),
            'used_gb': round(disk_used / (1024**3), 2)
        },
        'timestamp': datetime.utcnow().isoformat()
    }


def save_system_metrics():
    """Save current system metrics to database"""
    health = get_system_health()
    metric = SystemMetric(
        cpu_usage=health['cpu']['usage_percent'],
        memory_usage=health['memory']['usage_percent'],
        memory_total=health['memory']['total_bytes'],
        memory_used=health['memory']['used_bytes'],
        disk_usage=health['disk']['usage_percent'],
        disk_total=health['disk']['total_bytes'],
        disk_used=health['disk']['used_bytes']
    )
    db.session.add(metric)
    db.session.commit()
    return metric

