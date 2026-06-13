import requests
import re

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Local CVE map for common services when API fails or for speed
LOCAL_CVE_MAP = {
    'OpenSSH': [
        {'id': 'CVE-2023-38408', 'severity': 'Critical', 'score': 9.8, 'description': 'Remote code execution in ssh-agent'},
        {'id': 'CVE-2023-51385', 'severity': 'High', 'score': 7.5, 'description': 'OS command injection via invalid characters in hostname'},
        {'id': 'CVE-2016-0777', 'severity': 'Medium', 'score': 6.4, 'description': 'Information leak via roaming feature'},
    ],
    'OpenSSH_6': [
        {'id': 'CVE-2016-0777', 'severity': 'High', 'score': 8.1, 'description': 'Memory disclosure in OpenSSH client roaming'},
        {'id': 'CVE-2015-5600', 'severity': 'High', 'score': 8.5, 'description': 'MaxAuthTries bypass via keyboard-interactive auth'},
        {'id': 'CVE-2014-2532', 'severity': 'Medium', 'score': 5.8, 'description': 'AcceptEnv wildcard restriction bypass'},
    ],
    'Apache': [
        {'id': 'CVE-2021-41773', 'severity': 'Critical', 'score': 9.8, 'description': 'Path traversal and RCE in Apache 2.4.49'},
        {'id': 'CVE-2021-42013', 'severity': 'Critical', 'score': 9.8, 'description': 'Path traversal and RCE in Apache 2.4.49-2.4.50'},
        {'id': 'CVE-2022-31813', 'severity': 'High', 'score': 7.5, 'description': 'HTTP request smuggling via mod_proxy'},
    ],
    'nginx': [
        {'id': 'CVE-2021-23017', 'severity': 'High', 'score': 7.7, 'description': 'Off-by-one error in DNS resolver'},
        {'id': 'CVE-2022-41741', 'severity': 'High', 'score': 7.8, 'description': 'Memory corruption in HTTP/2 module'},
    ],
    'MySQL': [
        {'id': 'CVE-2023-21980', 'severity': 'High', 'score': 7.1, 'description': 'MySQL Server optimizer vulnerability'},
        {'id': 'CVE-2022-21589', 'severity': 'Medium', 'score': 4.9, 'description': 'MySQL Server privilege escalation'},
    ],
    'PostgreSQL': [
        {'id': 'CVE-2023-2454', 'severity': 'High', 'score': 7.2, 'description': 'Row security policies bypass'},
        {'id': 'CVE-2022-1552', 'severity': 'High', 'score': 8.8, 'description': 'Autovacuum, REINDEX bypass row security'},
    ],
    'SMB': [
        {'id': 'CVE-2017-0144', 'severity': 'Critical', 'score': 9.8, 'description': 'EternalBlue - SMBv1 remote code execution (WannaCry)'},
        {'id': 'CVE-2020-0796', 'severity': 'Critical', 'score': 10.0, 'description': 'SMBGhost - SMBv3 remote code execution'},
        {'id': 'CVE-2017-0145', 'severity': 'Critical', 'score': 9.8, 'description': 'EternalRomance - SMBv1 remote code execution'},
    ],
    'RDP': [
        {'id': 'CVE-2019-0708', 'severity': 'Critical', 'score': 9.8, 'description': 'BlueKeep - RDP pre-auth remote code execution'},
        {'id': 'CVE-2021-34535', 'severity': 'Critical', 'score': 9.0, 'description': 'Remote Desktop Client RCE vulnerability'},
    ],
    'FTP': [
        {'id': 'CVE-2011-2523', 'severity': 'Critical', 'score': 10.0, 'description': 'vsftpd 2.3.4 backdoor command execution'},
        {'id': 'CVE-2010-4221', 'severity': 'High', 'score': 7.5, 'description': 'ProFTPD sreplace buffer overflow'},
    ],
    'Telnet': [
        {'id': 'CVE-2020-10188', 'severity': 'Critical', 'score': 9.8, 'description': 'Telnet remote code execution via environment variables'},
    ],
    'DNS': [
        {'id': 'CVE-2020-1350', 'severity': 'Critical', 'score': 10.0, 'description': 'SIGRed - Windows DNS Server RCE'},
        {'id': 'CVE-2021-25216', 'severity': 'Critical', 'score': 9.8, 'description': 'BIND9 TKEY buffer overflow'},
    ],
    'Redis': [
        {'id': 'CVE-2022-0543', 'severity': 'Critical', 'score': 10.0, 'description': 'Lua sandbox escape in Debian Redis packages'},
        {'id': 'CVE-2023-28425', 'severity': 'Medium', 'score': 5.5, 'description': 'Denial of service via MSETNX command'},
    ],
    'MongoDB': [
        {'id': 'CVE-2021-20328', 'severity': 'Medium', 'score': 6.8, 'description': 'Client-side field level encryption bypass'},
    ],
    'Elasticsearch': [
        {'id': 'CVE-2021-22145', 'severity': 'Medium', 'score': 6.5, 'description': 'Memory disclosure via malformed request'},
        {'id': 'CVE-2023-31419', 'severity': 'High', 'score': 7.5, 'description': 'Stack overflow in Elasticsearch _search API'},
    ],
    'VNC': [
        {'id': 'CVE-2023-26045', 'severity': 'High', 'score': 7.5, 'description': 'Heap buffer overflow in LibVNCServer'},
    ],
}

def extract_version_from_banner(banner, service):
    if not banner:
        return None
    patterns = [
        r'(\d+\.\d+\.\d+)',
        r'(\d+\.\d+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return None

def get_cves_from_nvd(service, version=None):
    try:
        keyword = f"{service} {version}" if version else service
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 5,
            'startIndex': 0
        }
        headers = {'User-Agent': 'NetSentinel-AI/1.0'}
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                descriptions = cve.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description')
                metrics = cve.get('metrics', {})
                score = 0.0
                severity = 'Unknown'
                if 'cvssMetricV31' in metrics:
                    cvss = metrics['cvssMetricV31'][0]['cvssData']
                    score = cvss.get('baseScore', 0.0)
                    severity = cvss.get('baseSeverity', 'Unknown')
                elif 'cvssMetricV2' in metrics:
                    cvss = metrics['cvssMetricV2'][0]['cvssData']
                    score = cvss.get('baseScore', 0.0)
                    severity = 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low'

                cves.append({
                    'id': cve_id,
                    'severity': severity.capitalize(),
                    'score': score,
                    'description': description[:200]
                })
            return cves
    except Exception:
        pass
    return []

def get_cves_for_service(service, banner=None):
    version = extract_version_from_banner(banner, service) if banner else None
    cves = []

    # Check local map first for speed
    for key in LOCAL_CVE_MAP:
        if key.lower() in service.lower() or (banner and key.lower() in banner.lower()):
            cves.extend(LOCAL_CVE_MAP[key])
            break

    # Try NVD API for version-specific CVEs
    if version:
        nvd_cves = get_cves_from_nvd(service, version)
        if nvd_cves:
            # Merge avoiding duplicates
            existing_ids = {c['id'] for c in cves}
            for c in nvd_cves:
                if c['id'] not in existing_ids:
                    cves.append(c)

    return cves[:5]  # Return top 5 CVEs

def calculate_risk_score(open_ports_with_cves):
    if not open_ports_with_cves:
        return 'Low'

    max_score = 0.0
    critical_count = 0
    high_count = 0

    for port_data in open_ports_with_cves:
        for cve in port_data.get('cves', []):
            score = cve.get('score', 0)
            if score > max_score:
                max_score = score
            if cve.get('severity') == 'Critical':
                critical_count += 1
            elif cve.get('severity') == 'High':
                high_count += 1

    if max_score >= 9.0 or critical_count >= 2:
        return 'Critical'
    elif max_score >= 7.0 or critical_count >= 1 or high_count >= 3:
        return 'High'
    elif max_score >= 4.0 or high_count >= 1:
        return 'Medium'
    else:
        return 'Low'

def correlate_scan_with_cves(scan_result):
    enriched_ports = []
    for port_info in scan_result.get('open_ports', []):
        service = port_info.get('service', 'Unknown')
        banner = port_info.get('banner')
        cves = get_cves_for_service(service, banner)
        enriched_ports.append({
            **port_info,
            'cves': cves,
            'cve_count': len(cves)
        })

    risk_score = calculate_risk_score(enriched_ports)

    return {
        **scan_result,
        'open_ports': enriched_ports,
        'risk_score': risk_score
    }