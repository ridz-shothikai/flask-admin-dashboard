from app import db
from datetime import datetime


class SystemMetric(db.Model):
    __tablename__ = 'system_metrics'
    id = db.Column(db.Integer, primary_key=True)
    cpu_usage = db.Column(db.Float)  # Percentage
    memory_usage = db.Column(db.Float)  # Percentage
    memory_total = db.Column(db.BigInteger)  # Bytes
    memory_used = db.Column(db.BigInteger)  # Bytes
    disk_usage = db.Column(db.Float)  # Percentage
    disk_total = db.Column(db.BigInteger)  # Bytes
    disk_used = db.Column(db.BigInteger)  # Bytes
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'cpu_usage': round(self.cpu_usage, 2) if self.cpu_usage else None,
            'memory_usage': round(self.memory_usage, 2) if self.memory_usage else None,
            'memory_total': self.memory_total,
            'memory_used': self.memory_used,
            'disk_usage': round(self.disk_usage, 2) if self.disk_usage else None,
            'disk_total': self.disk_total,
            'disk_used': self.disk_used,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    def __repr__(self):
        return f'<SystemMetric at {self.timestamp}>'

