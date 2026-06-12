import asyncio
import socket
import struct
import time
from datetime import datetime

# Common ports with service names
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
    135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    1521: 'Oracle', 2181: 'Zookeeper', 3306: 'MySQL',
    3389: 'RDP', 4444: 'Metasploit', 5000: 'Flask',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    7001: 'WebLogic', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
    27017: 'MongoDB', 27018: 'MongoDB'
}

SCAN_PROFILES = {
    'quick': list(COMMON_PORTS.keys()),
    'standard': list(range(1, 1025)),
    'full': list(range(1, 65536)),
    'custom': []
}

async def scan_port(host, port, timeout=1.0):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        service = COMMON_PORTS.get(port, 'Unknown')
        return {
            'port': port,
            'state': 'open',
            'service': service,
            'banner': None
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

async def grab_banner(host, port, timeout=2.0):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        # Send probe based on port
        if port == 80 or port == 8080:
            writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 21:
            pass  # FTP sends banner automatically
        else:
            writer.write(b'\r\n')

        await writer.drain()

        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner_text = banner.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            banner_text = None

        writer.close()
        await writer.wait_closed()
        return banner_text if banner_text else None

    except Exception:
        return None

async def scan_host(host, ports, timeout=1.0, on_progress=None):
    start_time = time.time()
    open_ports = []

    # Scan in batches of 100 to avoid overwhelming the target
    batch_size = 100
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i + batch_size]
        tasks = [scan_port(host, port, timeout) for port in batch]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                open_ports.append(result)
                if on_progress:
                    on_progress(result)

    # Grab banners for open ports
    for port_info in open_ports:
        banner = await grab_banner(host, port_info['port'], timeout=2.0)
        port_info['banner'] = banner

    end_time = time.time()

    return {
        'host': host,
        'scan_time': datetime.utcnow().isoformat(),
        'duration': round(end_time - start_time, 2),
        'total_ports_scanned': len(ports),
        'open_ports': open_ports,
        'open_count': len(open_ports)
    }

def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None

def run_scan(host, profile='quick', custom_ports=None, timeout=1.0):
    ip = resolve_host(host)
    if not ip:
        return {'error': f'Could not resolve host: {host}'}

    if profile == 'custom' and custom_ports:
        ports = custom_ports
    else:
        ports = SCAN_PROFILES.get(profile, SCAN_PROFILES['quick'])

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(scan_host(ip, ports, timeout))
        result['hostname'] = host
        result['ip'] = ip
        result['profile'] = profile
        return result
    finally:
        loop.close()