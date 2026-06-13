from app import create_app, db
from app.scanner.engine import run_scan
from app.scanner.models import ScanResult

app = create_app()

with app.app_context():
    result = run_scan('scanme.nmap.org', profile='quick')
    
    scan_record = ScanResult(
        hostname=result['hostname'],
        ip=result['ip'],
        profile=result['profile'],
        duration=result['duration'],
        total_ports_scanned=result['total_ports_scanned'],
        open_count=result['open_count']
    )
    scan_record.set_ports(result['open_ports'])
    db.session.add(scan_record)
    db.session.commit()

    print(f"Saved! Scan ID: {scan_record.id}")
    print(f"Host: {scan_record.hostname}")
    print(f"Open ports: {scan_record.open_count}")