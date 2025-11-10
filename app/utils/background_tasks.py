import threading
import time
from app.utils.monitoring import save_system_metrics


class MetricsCollector(threading.Thread):
    """Background thread to collect system metrics periodically"""
    def __init__(self, app, interval=300):  # Default: every 5 minutes
        threading.Thread.__init__(self, daemon=True)
        self.app = app
        self.interval = interval
        self.running = True

    def run(self):
        """Run the metrics collection loop"""
        while self.running:
            with self.app.app_context():
                try:
                    save_system_metrics()
                    print(f"System metrics saved at {time.ctime()}")
                except Exception as e:
                    print(f"Error saving metrics: {e}")
            time.sleep(self.interval)

    def stop(self):
        """Stop the metrics collector"""
        self.running = False

