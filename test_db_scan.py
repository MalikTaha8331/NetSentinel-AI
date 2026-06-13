from app import create_app, db
from app.scanner.engine import run_scan
from app.scanner.models import ScanResult
from app.scanner.cve import correlate_scan_with_cves

app = create_app()

with app.app_context():
    result = run_scan('scanme.nmap.org', profile='quick')
    enriched = correlate_scan_with_cves(result)

    scan_record = ScanResult(
        hostname=enriched['hostname'],
        ip=enriched['ip'],
        profile=enriched['profile'],
        duration=enriched['duration'],
        total_ports_scanned=enriched['total_ports_scanned'],
        open_count=enriched['open_count'],
        risk_score=enriched['risk_score']
    )
    scan_record.set_ports(enriched['open_ports'])
    db.session.add(scan_record)
    db.session.commit()

    print(f"\n✅ Scan saved! ID: {scan_record.id}")
    print(f"Host: {enriched['hostname']} ({enriched['ip']})")
    print(f"Risk Score: {enriched['risk_score']}")
    print(f"\nOpen Ports & CVEs:")
    for port in enriched['open_ports']:
        print(f"\n  Port {port['port']} ({port['service']})")
        print(f"  Banner: {port['banner']}")
        if port['cves']:
            for cve in port['cves']:
                print(f"    ⚠ {cve['id']} [{cve['severity']}] Score:{cve['score']} - {cve['description'][:80]}")
        else:
            print(f"    ✓ No known CVEs")