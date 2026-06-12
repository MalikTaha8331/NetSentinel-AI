from app import db
from datetime import datetime
import json

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    profile = db.Column(db.String(50), nullable=False)
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    duration = db.Column(db.Float)
    total_ports_scanned = db.Column(db.Integer)
    open_count = db.Column(db.Integer)
    open_ports = db.Column(db.Text)  # JSON string
    risk_score = db.Column(db.String(20), default='Pending')
    ai_summary = db.Column(db.Text, default=None)

    def set_ports(self, ports_list):
        self.open_ports = json.dumps(ports_list)

    def get_ports(self):
        return json.loads(self.open_ports) if self.open_ports else []

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip': self.ip,
            'profile': self.profile,
            'scan_time': self.scan_time.isoformat(),
            'duration': self.duration,
            'total_ports_scanned': self.total_ports_scanned,
            'open_count': self.open_count,
            'open_ports': self.get_ports(),
            'risk_score': self.risk_score,
            'ai_summary': self.ai_summary
        }