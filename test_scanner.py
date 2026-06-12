from app.scanner.engine import run_scan

result = run_scan('scanme.nmap.org', profile='quick')
print(f"Host: {result['host']}")
print(f"IP: {result['ip']}")
print(f"Duration: {result['duration']}s")
print(f"Open ports: {result['open_count']}")
for port in result['open_ports']:
    print(f"  Port {port['port']}: {port['service']} | Banner: {port['banner']}")