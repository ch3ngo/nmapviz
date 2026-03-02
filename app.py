#!/usr/bin/env python3
"""
NmapViz - Graphical nmap results visualizer
Port: 12221
"""

import xml.etree.ElementTree as ET
import json
import os
import re
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB (multiple files)

HISTORY_DIR = Path('history')
HISTORY_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# PORT CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

CRITICAL_PORTS = {
    23:   {"name": "Telnet",       "reason": "No encryption. Credentials sent in plaintext. Replace with SSH."},
    21:   {"name": "FTP",          "reason": "File transfer with no encryption. Credentials exposed."},
    69:   {"name": "TFTP",         "reason": "No authentication. Allows arbitrary file read/write."},
    512:  {"name": "rexec",        "reason": "Remote execution without encryption. Obsolete and dangerous."},
    513:  {"name": "rlogin",       "reason": "Remote login without encryption. Replaced by SSH."},
    514:  {"name": "rsh/syslog",   "reason": "Remote shell with no authentication. Extremely dangerous."},
    79:   {"name": "Finger",       "reason": "Reveals system users. Facilitates enumeration attacks."},
    161:  {"name": "SNMP",         "reason": "Default community strings (public/private). Sensitive system info."},
    2049: {"name": "NFS",          "reason": "File sharing potentially without proper authentication."},
    111:  {"name": "RPCbind",      "reason": "Allows RPC service enumeration. Frequent attack vector."},
    135:  {"name": "MSRPC",        "reason": "Windows RPC. History of critical CVEs (MS03-026, etc)."},
    137:  {"name": "NetBIOS-NS",   "reason": "Enables LLMNR/NBT-NS poisoning attacks."},
    138:  {"name": "NetBIOS-DGM",  "reason": "Network information exposed."},
    4444: {"name": "Backdoor",     "reason": "Commonly used by reverse shells and backdoors (Metasploit default)."},
    6666: {"name": "IRC/Backdoor", "reason": "Frequently used by botnets and malware."},
    6667: {"name": "IRC",          "reason": "Unencrypted IRC. Frequently exploited by botnets."},
}

INTERESTING_PORTS = {
    22:    {"name": "SSH",           "reason": "Remote access. Check version, authentication and root access."},
    3389:  {"name": "RDP",           "reason": "Windows remote desktop. Frequent brute force target."},
    445:   {"name": "SMB",           "reason": "Windows file sharing. Critical CVE history (EternalBlue)."},
    139:   {"name": "NetBIOS-SSN",   "reason": "SMB over NetBIOS. Same risk as port 445."},
    5985:  {"name": "WinRM HTTP",    "reason": "Windows remote management. May allow command execution."},
    5986:  {"name": "WinRM HTTPS",   "reason": "Windows remote management (encrypted)."},
    5900:  {"name": "VNC",           "reason": "Remote desktop. Frequently weak or no authentication."},
    1433:  {"name": "MSSQL",         "reason": "SQL Server. Should not be externally exposed."},
    3306:  {"name": "MySQL",         "reason": "MySQL database. Should not be externally exposed."},
    5432:  {"name": "PostgreSQL",    "reason": "PostgreSQL database. Should not be externally exposed."},
    1521:  {"name": "Oracle DB",     "reason": "Oracle database. Should not be externally exposed."},
    6379:  {"name": "Redis",         "reason": "Redis has no auth by default. Possible RCE."},
    27017: {"name": "MongoDB",       "reason": "MongoDB no auth by default in old versions."},
    9200:  {"name": "Elasticsearch", "reason": "No auth by default. Massive data exposure risk."},
    11211: {"name": "Memcached",     "reason": "No authentication. DDoS amplification attacks."},
    389:   {"name": "LDAP",          "reason": "Active directory. User and object enumeration possible."},
    636:   {"name": "LDAPS",         "reason": "LDAP over SSL. Verify anonymous query permissions."},
    88:    {"name": "Kerberos",      "reason": "Kerberos auth. AS-REP Roasting, Kerberoasting possible."},
    53:    {"name": "DNS",           "reason": "DNS server. Check zone transfers (AXFR)."},
    25:    {"name": "SMTP",          "reason": "Mail. Check open relay and user enumeration (VRFY/EXPN)."},
    110:   {"name": "POP3",          "reason": "Unencrypted mail. Credentials exposed."},
    143:   {"name": "IMAP",          "reason": "Unencrypted mail. Credentials exposed."},
    8080:  {"name": "HTTP-Alt",      "reason": "Alternative web server. Common for admin panels."},
    8443:  {"name": "HTTPS-Alt",     "reason": "Alternative HTTPS server."},
    2375:  {"name": "Docker API",    "reason": "Docker API without TLS. Full host control if exposed."},
    2376:  {"name": "Docker TLS",    "reason": "Docker API with TLS. Verify certificate configuration."},
    6443:  {"name": "Kubernetes",    "reason": "Kubernetes API. Cluster control if misconfigured."},
    9090:  {"name": "Prometheus",    "reason": "Exposed system metrics. Sensitive infrastructure info."},
    3000:  {"name": "Grafana/Dev",   "reason": "Common for Grafana or dev apps. Verify authentication."},
    7001:  {"name": "WebLogic",      "reason": "Oracle WebLogic. Multiple critical RCE CVEs."},
    8161:  {"name": "ActiveMQ",      "reason": "ActiveMQ Admin. Documented RCE vulnerabilities."},
    9000:  {"name": "SonarQube",     "reason": "Common for SonarQube/PHP-FPM. Verify access."},
}

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_vulnerabilities(host_data):
    """Analyse services and scripts to detect potential vulnerabilities."""
    vulns = []

    for port in host_data.get('ports', []):
        port_num = port.get('portid', 0)
        service  = port.get('service', {})
        svc_name = service.get('name', '').lower()
        product  = service.get('product', '').lower()
        version  = service.get('version', '').lower()
        scripts  = port.get('scripts', [])
        full_ver = f"{product} {version}".strip()

        # ── SMB ──────────────────────────────────────────────────────────────
        if port_num in (445, 139) or 'smb' in svc_name:
            for script in scripts:
                output = script.get('output', '').lower()
                sid    = script.get('id', '').lower()

                if 'smb-security-mode' in sid:
                    if 'message_signing: disabled' in output or 'signing: disabled' in output:
                        vulns.append({"severity": "HIGH", "port": port_num,
                            "title": "SMB Signing Disabled",
                            "description": "SMB without digital signing. Enables NTLM Relay attacks (Pass-the-Hash, etc).",
                            "cve": "N/A", "script": sid})
                    if 'account_used: guest' in output or 'anonymous' in output:
                        vulns.append({"severity": "CRITICAL", "port": port_num,
                            "title": "SMB Anonymous/Guest Access",
                            "description": "SMB allows access without valid credentials.",
                            "cve": "N/A", "script": sid})

                if 'smb-vuln-ms17-010' in sid or 'eternalblue' in output:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "EternalBlue (MS17-010)",
                        "description": "RCE as SYSTEM. Patch immediately. Used by WannaCry and NotPetya.",
                        "cve": "CVE-2017-0144", "script": sid})

                if 'smb-vuln-ms08-067' in sid:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "MS08-067 NetAPI RCE",
                        "description": "Classic RCE on Windows XP/2003.",
                        "cve": "CVE-2008-4250", "script": sid})

                if 'smb2-security-mode' in sid and 'signing enabled and required' not in output:
                    vulns.append({"severity": "MEDIUM", "port": port_num,
                        "title": "SMBv2 Signing Not Required",
                        "description": "SMBv2 signing is not enforced. Relay attacks possible.",
                        "cve": "N/A", "script": sid})

            if 'smbv1' in full_ver:
                vulns.append({"severity": "CRITICAL", "port": port_num,
                    "title": "SMBv1 Enabled",
                    "description": "Obsolete protocol. EternalBlue/WannaCry vector. Disable immediately.",
                    "cve": "CVE-2017-0144", "script": "version-detection"})

        # ── SSH ───────────────────────────────────────────────────────────────
        if 'ssh' in svc_name or port_num == 22:
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'ssh-auth-methods' in sid and 'password' in output:
                    vulns.append({"severity": "MEDIUM", "port": port_num,
                        "title": "SSH Allows Password Authentication",
                        "description": "Recommended to disable password auth in favour of SSH keys.",
                        "cve": "N/A", "script": sid})
                if 'ssh-hostkey' in sid and 'rsa 1024' in output:
                    vulns.append({"severity": "MEDIUM", "port": port_num,
                        "title": "SSH Weak RSA Key (1024-bit)",
                        "description": "1024-bit RSA keys are considered weak. Use minimum 2048 bits.",
                        "cve": "N/A", "script": sid})

            if version and any(v in version for v in ['openssh 4.', 'openssh 5.', 'openssh 6.']):
                vulns.append({"severity": "HIGH", "port": port_num,
                    "title": f"Outdated OpenSSH Version ({version})",
                    "description": "Old OpenSSH version with multiple known vulnerabilities. Update.",
                    "cve": "Multiple", "script": "version-detection"})

        # ── SSL/TLS ───────────────────────────────────────────────────────────
        for script in scripts:
            sid    = script.get('id', '').lower()
            output = script.get('output', '').lower()
            if 'ssl-heartbleed' in sid and 'vulnerable' in output:
                vulns.append({"severity": "CRITICAL", "port": port_num,
                    "title": "Heartbleed (OpenSSL)",
                    "description": "Reads server memory including private keys and session data.",
                    "cve": "CVE-2014-0160", "script": sid})
            if 'ssl-poodle' in sid and 'vulnerable' in output:
                vulns.append({"severity": "HIGH", "port": port_num,
                    "title": "POODLE Attack (SSLv3)",
                    "description": "Server accepts SSLv3. Vulnerable to POODLE.",
                    "cve": "CVE-2014-3566", "script": sid})
            if 'ssl-drown' in sid and 'vulnerable' in output:
                vulns.append({"severity": "CRITICAL", "port": port_num,
                    "title": "DROWN Attack",
                    "description": "Server supports SSLv2. Allows decryption of TLS connections.",
                    "cve": "CVE-2016-0800", "script": sid})

        # ── FTP ───────────────────────────────────────────────────────────────
        if 'ftp' in svc_name or port_num == 21:
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'ftp-anon' in sid and ('allowed' in output or 'anonymous' in output):
                    vulns.append({"severity": "HIGH", "port": port_num,
                        "title": "FTP Anonymous Access",
                        "description": "FTP server allows access without credentials. Possible file read/write.",
                        "cve": "N/A", "script": sid})

        # ── Redis ─────────────────────────────────────────────────────────────
        if 'redis' in svc_name or port_num == 6379:
            for script in scripts:
                if 'redis-info' in script.get('id', '').lower():
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "Redis Without Authentication",
                        "description": "Redis exposed without password. Data access and possible RCE.",
                        "cve": "N/A", "script": script['id']})

        # ── HTTP ──────────────────────────────────────────────────────────────
        if svc_name in ('http','https','http-alt','https-alt') or port_num in (80,443,8080,8443):
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'http-shellshock' in sid and 'vulnerable' in output:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "Shellshock (Bash RCE)",
                        "description": "Web server vulnerable to Shellshock. RCE via CGI scripts.",
                        "cve": "CVE-2014-6271", "script": sid})
                if 'http-default-accounts' in sid and 'valid' in output:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "Default Credentials Accepted",
                        "description": "Web service accepts default credentials. Change passwords immediately.",
                        "cve": "N/A", "script": sid})

        # ── RDP ───────────────────────────────────────────────────────────────
        if port_num == 3389 or 'rdp' in svc_name or 'ms-wbt' in svc_name:
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'rdp-vuln-ms12-020' in sid and 'vulnerable' in output:
                    vulns.append({"severity": "HIGH", "port": port_num,
                        "title": "MS12-020 RDP DoS",
                        "description": "RDP vulnerable to denial of service.",
                        "cve": "CVE-2012-0152", "script": sid})
                if 'rdp-enum-encryption' in sid and 'rdp security layer' in output:
                    vulns.append({"severity": "MEDIUM", "port": port_num,
                        "title": "RDP Without NLA",
                        "description": "RDP not using Network Level Authentication. More exposed to brute force.",
                        "cve": "N/A", "script": sid})

        # ── Telnet ────────────────────────────────────────────────────────────
        if 'telnet' in svc_name or port_num == 23:
            vulns.append({"severity": "CRITICAL", "port": port_num,
                "title": "Telnet Active",
                "description": "Transmits everything in plaintext including credentials. Replace with SSH.",
                "cve": "N/A", "script": "port-classification"})

        # ── Outdated versions ─────────────────────────────────────────────────
        for pattern, svc_friendly in [
            (r'apache[/ ]([12]\.\d+)', 'Apache HTTP Server'),
            (r'nginx[/ ](0\.\d+)', 'Nginx'),
            (r'php[/ ]([45]\.\d+)', 'PHP'),
            (r'iis[/ ]([456]\.\d+)', 'Microsoft IIS'),
        ]:
            m = re.search(pattern, full_ver)
            if m:
                vulns.append({"severity": "MEDIUM", "port": port_num,
                    "title": f"Outdated Version: {svc_friendly} {m.group(1)}",
                    "description": f"Old {svc_friendly} version with multiple known vulnerabilities. Update.",
                    "cve": "Multiple", "script": "version-detection"})

    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# NMAP XML PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_content):
    """Parse nmap XML output and return a structured dict."""
    root = ET.fromstring(xml_content)
    scan_info = {
        "scanner":     root.get('scanner', 'nmap'),
        "args":        root.get('args', ''),
        "start":       root.get('startstr', ''),
        "version":     root.get('version', ''),
        "has_version": False,
        "has_scripts": False,
        "hosts":       []
    }
    args = scan_info['args'].lower()
    if any(f in args for f in ['-sv', '-a ', '-sc', '--script']):
        scan_info['has_version'] = True
    if any(f in args for f in ['--script', '-sc', '-a ']):
        scan_info['has_scripts'] = True

    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue

        host_data = {"ip": "", "hostname": "", "os": "", "os_accuracy": 0,
                     "mac": "", "vendor": "", "state": "up", "ports": [], "vulns": []}

        for addr in host.findall('address'):
            t = addr.get('addrtype')
            if t == 'ipv4':
                host_data['ip'] = addr.get('addr', '')
            elif t == 'ipv6' and not host_data['ip']:
                host_data['ip'] = addr.get('addr', '')
            elif t == 'mac':
                host_data['mac']    = addr.get('addr', '')
                host_data['vendor'] = addr.get('vendor', '')

        hostnames_el = host.find('hostnames')
        if hostnames_el is not None:
            hn = hostnames_el.find('hostname')
            if hn is not None:
                host_data['hostname'] = hn.get('name', '')

        os_el = host.find('os')
        if os_el is not None:
            for match in os_el.findall('osmatch'):
                acc = int(match.get('accuracy', 0))
                if acc > host_data['os_accuracy']:
                    host_data['os']          = match.get('name', '')
                    host_data['os_accuracy'] = acc

        ports_el = host.find('ports')
        if ports_el is not None:
            for port_el in ports_el.findall('port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue

                port_num   = int(port_el.get('portid', 0))
                protocol   = port_el.get('protocol', 'tcp')
                service_el = port_el.find('service')
                service    = {}
                if service_el is not None:
                    service = {
                        "name":      service_el.get('name', ''),
                        "product":   service_el.get('product', ''),
                        "version":   service_el.get('version', ''),
                        "extrainfo": service_el.get('extrainfo', ''),
                        "method":    service_el.get('method', 'table'),
                    }
                    if service.get('method') == 'probed':
                        scan_info['has_version'] = True

                scripts = []
                for s in port_el.findall('script'):
                    scripts.append({"id": s.get('id',''), "output": s.get('output','')})
                if scripts:
                    scan_info['has_scripts'] = True

                classification, class_reason = "normal", ""
                if port_num in CRITICAL_PORTS:
                    classification = "critical"
                    class_reason   = CRITICAL_PORTS[port_num]['reason']
                elif port_num in INTERESTING_PORTS:
                    classification = "interesting"
                    class_reason   = INTERESTING_PORTS[port_num]['reason']

                host_data['ports'].append({
                    "portid": port_num, "protocol": protocol,
                    "service": service, "scripts": scripts,
                    "classification": classification, "class_reason": class_reason,
                })

        host_data['vulns'] = detect_vulnerabilities(host_data)
        scan_info['hosts'].append(host_data)

    return scan_info


def merge_scans(scan_list):
    """Merge multiple scan results, deduplicating hosts by IP."""
    merged = {
        "scanner":     "nmap",
        "args":        " | ".join(s['args'] for s in scan_list if s.get('args')),
        "start":       scan_list[0].get('start', '') if scan_list else '',
        "version":     scan_list[0].get('version', '') if scan_list else '',
        "has_version": any(s.get('has_version') for s in scan_list),
        "has_scripts": any(s.get('has_scripts') for s in scan_list),
        "hosts":       []
    }
    hosts_by_ip = {}
    for scan in scan_list:
        for host in scan.get('hosts', []):
            ip = host['ip']
            if ip not in hosts_by_ip:
                hosts_by_ip[ip] = host
            else:
                existing = hosts_by_ip[ip]
                # Merge ports — union, prefer entries with version info
                existing_ports = {p['portid']: p for p in existing['ports']}
                for port in host['ports']:
                    pid = port['portid']
                    if pid not in existing_ports:
                        existing_ports[pid] = port
                    else:
                        ep = existing_ports[pid]
                        if not ep['service'].get('product') and port['service'].get('product'):
                            existing_ports[pid] = port
                        # Merge scripts
                        existing_script_ids = {s['id'] for s in ep.get('scripts', [])}
                        for script in port.get('scripts', []):
                            if script['id'] not in existing_script_ids:
                                ep.setdefault('scripts', []).append(script)
                existing['ports'] = list(existing_ports.values())
                # Prefer OS with higher accuracy
                if host.get('os_accuracy', 0) > existing.get('os_accuracy', 0):
                    existing['os']          = host['os']
                    existing['os_accuracy'] = host['os_accuracy']
                # Re-run vulnerability detection with merged data
                existing['vulns'] = detect_vulnerabilities(existing)
    merged['hosts'] = list(hosts_by_ip.values())
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY
# ─────────────────────────────────────────────────────────────────────────────

def save_to_history(scan_data, filenames):
    ts      = datetime.now()
    scan_id = ts.strftime('%Y%m%d_%H%M%S')
    total_vulns = sum(len(h.get('vulns', [])) for h in scan_data.get('hosts', []))
    crit_ports  = sum(
        len([p for p in h.get('ports', []) if p.get('classification') == 'critical'])
        for h in scan_data.get('hosts', [])
    )
    meta = {
        "id":                scan_id,
        "timestamp":         ts.isoformat(),
        "timestamp_display": ts.strftime('%Y-%m-%d %H:%M:%S'),
        "filenames":         filenames,
        "host_count":        len(scan_data.get('hosts', [])),
        "total_ports":       sum(len(h.get('ports', [])) for h in scan_data.get('hosts', [])),
        "vuln_count":        total_vulns,
        "critical_ports":    crit_ports,
        "args":              scan_data.get('args', ''),
    }
    record = {**meta, "scan": scan_data}
    with open(HISTORY_DIR / f"{scan_id}.json", 'w') as f:
        json.dump(record, f, indent=2)
    return meta


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(scan, meta):
    ts       = meta.get('timestamp_display', '')
    files    = ', '.join(meta.get('filenames', []))
    sev_color = {'CRITICAL': '#f85149', 'HIGH': '#d98634', 'MEDIUM': '#d29922', 'LOW': '#58a6ff'}
    hosts_html = ""
    for host in scan.get('hosts', []):
        ports_html  = ""
        sorted_ports = sorted(host.get('ports', []),
                              key=lambda p: {'critical':0,'interesting':1,'normal':2}.get(p['classification'],2))
        for p in sorted_ports:
            svc = p.get('service', {})
            ver = ' '.join(filter(None, [svc.get('product',''), svc.get('version',''), svc.get('extrainfo','')]))
            badge = {'critical':'🔴','interesting':'🟠','normal':'🟢'}.get(p['classification'],'')
            ports_html += f"<tr><td>{badge} {p['portid']}/{p['protocol']}</td><td>{svc.get('name','')}</td><td>{ver}</td><td>{p.get('class_reason','')}</td></tr>"

        vulns_html = ""
        sev_order  = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
        for v in sorted(host.get('vulns',[]), key=lambda x: sev_order.get(x['severity'],9)):
            col = sev_color.get(v['severity'],'#888')
            vulns_html += f"<tr><td style='color:{col};font-weight:700'>{v['severity']}</td><td>{v['title']}</td><td>{v['description']}</td><td>{v.get('cve','N/A')}</td><td>:{v['port']}</td></tr>"

        hosts_html += f"""
        <div class='host-block'>
          <h3>{host.get('ip','')} {('<span class=hn>' + host['hostname'] + '</span>') if host.get('hostname') else ''}</h3>
          <p class='meta'>OS: {host.get('os','Unknown')} {('('+str(host['os_accuracy'])+'%)') if host.get('os_accuracy') else ''} | MAC: {host.get('mac','N/A')} {host.get('vendor','')}</p>
          <h4>Open Ports ({len(host.get('ports',[]))})</h4>
          <table><tr><th>Port</th><th>Service</th><th>Version</th><th>Note</th></tr>{ports_html}</table>
          {'<h4>Potential Vulnerabilities ('+str(len(host.get("vulns",[])))+')</h4><table><tr><th>Severity</th><th>Title</th><th>Description</th><th>CVE</th><th>Port</th></tr>'+vulns_html+'</table>' if host.get('vulns') else '<p class="ok">✅ No vulnerabilities detected</p>'}
        </div>"""

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>NmapViz Report - {ts}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;padding:40px;}}
  h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px}}
  h2{{color:#58a6ff;margin-top:30px}}h3{{color:#e6edf3;margin:20px 0 4px}}h4{{color:#8b949e;margin:12px 0 6px}}
  .meta{{color:#8b949e;font-size:13px}}.hn{{color:#8b949e;font-weight:400}}
  .host-block{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
  th{{background:#21262d;padding:8px 10px;text-align:left;color:#8b949e}}
  td{{padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
  .ok{{color:#3fb950;font-size:13px}}.badge{{font-size:11px;padding:2px 8px;border-radius:20px;font-weight:600}}
  .stats{{display:flex;gap:30px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:20px 0}}
  .stat{{text-align:center}}.stat .val{{font-size:24px;font-weight:700;color:#58a6ff}}.stat .lbl{{font-size:12px;color:#8b949e}}
</style></head><body>
<h1>🔍 NmapViz — Scan Report</h1>
<p><strong>Generated:</strong> {ts} &nbsp;|&nbsp; <strong>Source files:</strong> {files}</p>
<p><strong>Command:</strong> <code>{scan.get('args','N/A')}</code></p>
<p><strong>Version detection:</strong> {'✅ Yes (-sV)' if scan.get('has_version') else '⚠️ No (basic scan)'} &nbsp;|&nbsp;
   <strong>NSE Scripts:</strong> {'✅ Yes' if scan.get('has_scripts') else '❌ No'}</p>
<div class='stats'>
  <div class='stat'><div class='val'>{len(scan.get('hosts',[]))}</div><div class='lbl'>Active Hosts</div></div>
  <div class='stat'><div class='val'>{sum(len(h.get('ports',[])) for h in scan.get('hosts',[]))}</div><div class='lbl'>Open Ports</div></div>
  <div class='stat'><div class='val' style='color:#f85149'>{sum(len([p for p in h.get('ports',[]) if p['classification']=='critical']) for h in scan.get('hosts',[]))}</div><div class='lbl'>Critical Ports</div></div>
  <div class='stat'><div class='val' style='color:#bc8cff'>{sum(len(h.get('vulns',[])) for h in scan.get('hosts',[]))}</div><div class='lbl'>Vulnerabilities</div></div>
</div>
<h2>Hosts</h2>{hosts_html}
<footer style='margin-top:40px;color:#8b949e;font-size:12px;border-top:1px solid #30363d;padding-top:16px'>
Generated by NmapViz · https://github.com/YOUR_USERNAME/nmap-visualizer
</footer></body></html>"""


def generate_markdown_report(scan, meta):
    ts    = meta.get('timestamp_display', '')
    files = ', '.join(meta.get('filenames', []))
    lines = [
        f"# NmapViz Scan Report",
        f"",
        f"**Generated:** {ts}  ",
        f"**Source files:** {files}  ",
        f"**Command:** `{scan.get('args','N/A')}`  ",
        f"**Version detection:** {'Yes (-sV)' if scan.get('has_version') else 'No (basic scan)'}  ",
        f"**NSE Scripts:** {'Yes' if scan.get('has_scripts') else 'No'}  ",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Active Hosts | {len(scan.get('hosts',[]))} |",
        f"| Open Ports | {sum(len(h.get('ports',[])) for h in scan.get('hosts',[]))} |",
        f"| Critical Ports | {sum(len([p for p in h.get('ports',[]) if p['classification']=='critical']) for h in scan.get('hosts',[]))} |",
        f"| Potential Vulnerabilities | {sum(len(h.get('vulns',[])) for h in scan.get('hosts',[]))} |",
        f"",
        f"---",
        f"",
        f"## Hosts",
        f"",
    ]
    sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
    for host in scan.get('hosts', []):
        lines.append(f"### {host.get('ip','')}  {host.get('hostname','')}")
        lines.append(f"")
        if host.get('os'):
            lines.append(f"- **OS:** {host['os']} ({host.get('os_accuracy',0)}%)")
        if host.get('mac'):
            lines.append(f"- **MAC:** {host['mac']} {host.get('vendor','')}")
        lines.append(f"- **Open Ports:** {len(host.get('ports',[]))}")
        lines.append(f"")

        if host.get('ports'):
            lines.append(f"#### Open Ports")
            lines.append(f"")
            lines.append(f"| Port | Service | Version | Classification | Note |")
            lines.append(f"|------|---------|---------|----------------|------|")
            sorted_ports = sorted(host['ports'],
                                  key=lambda p: {'critical':0,'interesting':1,'normal':2}.get(p['classification'],2))
            for p in sorted_ports:
                svc = p.get('service', {})
                ver = ' '.join(filter(None,[svc.get('product',''),svc.get('version',''),svc.get('extrainfo','')]))
                icon = {'critical':'🔴','interesting':'🟠','normal':'🟢'}.get(p['classification'],'')
                lines.append(f"| {p['portid']}/{p['protocol']} | {svc.get('name','')} | {ver} | {icon} {p['classification'].title()} | {p.get('class_reason','')} |")
            lines.append(f"")

        if host.get('vulns'):
            lines.append(f"#### ⚠️ Potential Vulnerabilities")
            lines.append(f"")
            for v in sorted(host['vulns'], key=lambda x: sev_order.get(x['severity'],9)):
                sev_icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵'}.get(v['severity'],'⚪')
                lines.append(f"**{sev_icon} [{v['severity']}] {v['title']}** (Port {v['port']})")
                lines.append(f"")
                lines.append(f"> {v['description']}")
                lines.append(f">")
                lines.append(f"> CVE: `{v.get('cve','N/A')}` | Source: `{v.get('script','')}`")
                lines.append(f"")
        else:
            lines.append(f"✅ No vulnerabilities detected")
            lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    lines.append(f"*Generated by [NmapViz](https://github.com/YOUR_USERNAME/nmap-visualizer)*")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


@app.route('/api/parse', methods=['POST'])
def parse_files():
    """Accept one or more nmap XML files, parse and merge them."""
    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({"error": "No files provided"}), 400

    scans     = []
    filenames = []
    for file in files:
        if not file.filename.lower().endswith('.xml'):
            return jsonify({"error": f"'{file.filename}' is not an XML file"}), 400
        try:
            content = file.read().decode('utf-8', errors='replace')
            scans.append(parse_nmap_xml(content))
            filenames.append(file.filename)
        except ET.ParseError as e:
            return jsonify({"error": f"Invalid XML in '{file.filename}': {str(e)}"}), 400
        except Exception as e:
            return jsonify({"error": f"Error processing '{file.filename}': {str(e)}"}), 500

    data = scans[0] if len(scans) == 1 else merge_scans(scans)
    meta = save_to_history(data, filenames)
    return jsonify({"success": True, "data": data, "scan_id": meta['id'], "merged": len(scans) > 1})


@app.route('/api/history')
def get_history():
    items = []
    for f in sorted(HISTORY_DIR.glob('*.json'), reverse=True):
        try:
            with open(f) as fp:
                d = json.load(fp)
            items.append({k: d[k] for k in
                ['id','timestamp','timestamp_display','filenames','host_count',
                 'total_ports','vuln_count','critical_ports','args'] if k in d})
        except Exception:
            continue
    return jsonify(items)


@app.route('/api/history/<scan_id>')
def get_scan(scan_id):
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists():
        return jsonify({"error": "Scan not found"}), 404
    with open(path) as f:
        d = json.load(f)
    return jsonify({"success": True, "data": d['scan'], "meta": {k: d[k] for k in
        ['id','timestamp_display','filenames','host_count','total_ports','vuln_count','critical_ports'] if k in d}})


@app.route('/api/history/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    path = HISTORY_DIR / f"{scan_id}.json"
    if path.exists():
        path.unlink()
    return jsonify({"success": True})


@app.route('/api/report/<scan_id>/<fmt>')
def download_report(scan_id, fmt):
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists():
        return jsonify({"error": "Scan not found"}), 404
    with open(path) as f:
        stored = json.load(f)
    scan = stored['scan']
    meta = {k: stored[k] for k in ['id','timestamp_display','filenames'] if k in stored}

    if fmt == 'json':
        return Response(
            json.dumps(scan, indent=2),
            mimetype='application/json',
            headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.json"}
        )
    elif fmt == 'html':
        return Response(
            generate_html_report(scan, meta),
            mimetype='text/html',
            headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.html"}
        )
    elif fmt == 'markdown':
        return Response(
            generate_markdown_report(scan, meta),
            mimetype='text/markdown',
            headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.md"}
        )
    else:
        return jsonify({"error": "Unknown format. Use: json, html, markdown"}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12221, debug=False)