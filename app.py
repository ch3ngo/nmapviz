#!/usr/bin/env python3
"""
NmapViz - Graphical nmap results visualizer (BloodHound-style)
Port: 12221
"""

import xml.etree.ElementTree as ET
import json
import os
import re
import io
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

HISTORY_DIR = Path('history')
HISTORY_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# PORT CLASSIFICATION  (critical = direct vulnerability just by being exposed)
# ─────────────────────────────────────────────────────────────────────────────

CRITICAL_PORTS = {
    # ── Cleartext remote access ───────────────────────────────────────────
    23:    {"name": "Telnet",        "reason": "No encryption. Credentials sent in plaintext. Replace with SSH."},
    512:   {"name": "rexec",         "reason": "Remote execution without encryption. Obsolete and dangerous."},
    513:   {"name": "rlogin",        "reason": "Remote login without encryption. Replaced by SSH."},
    514:   {"name": "rsh/syslog",    "reason": "Remote shell with no authentication. Extremely dangerous."},
    # ── Cleartext file transfer ───────────────────────────────────────────
    21:    {"name": "FTP",           "reason": "File transfer with no encryption. Credentials exposed."},
    69:    {"name": "TFTP",          "reason": "No authentication. Allows arbitrary file read/write."},
    873:   {"name": "rsync",         "reason": "Can allow unauthenticated file access depending on config."},
    # ── Legacy info disclosure ────────────────────────────────────────────
    79:    {"name": "Finger",        "reason": "Reveals system users. Facilitates enumeration attacks."},
    # ── SNMP / network management ─────────────────────────────────────────
    161:   {"name": "SNMP UDP",      "reason": "Default community strings (public/private). Full device info exposed."},
    162:   {"name": "SNMP Trap",     "reason": "SNMP trap receiver. Sensitive network events may be intercepted."},
    # ── Windows / SMB legacy ─────────────────────────────────────────────
    135:   {"name": "MSRPC",         "reason": "Windows RPC. History of critical CVEs (MS03-026, etc)."},
    137:   {"name": "NetBIOS-NS",    "reason": "Enables LLMNR/NBT-NS poisoning attacks."},
    138:   {"name": "NetBIOS-DGM",   "reason": "NetBIOS datagrams. Network information exposed."},
    # ── NFS / RPC ─────────────────────────────────────────────────────────
    111:   {"name": "RPCbind",       "reason": "Allows RPC service enumeration. Frequent attack vector."},
    2049:  {"name": "NFS",           "reason": "File sharing potentially without proper authentication."},
    # ── ICS / SCADA protocols (should NEVER be internet-exposed) ─────────
    102:   {"name": "S7comm (Siemens)","reason": "Siemens PLC protocol. Direct ICS/OT control possible if reachable."},
    502:   {"name": "Modbus",        "reason": "ICS protocol with no authentication. Direct hardware control."},
    20000: {"name": "DNP3",          "reason": "ICS/SCADA protocol. No native authentication."},
    44818: {"name": "EtherNet/IP",   "reason": "Industrial Ethernet protocol. CIP direct device access."},
    47808: {"name": "BACnet",        "reason": "Building automation protocol. Device control possible."},
    4840:  {"name": "OPC-UA",        "reason": "Industrial OPC protocol. Verify authentication is enforced."},
    # ── Network device management ─────────────────────────────────────────
    623:   {"name": "IPMI",          "reason": "BMC/IPMI. Authentication bypass CVEs (CVE-2013-4786). Remote OS control."},
    4786:  {"name": "Cisco Smart Install","reason": "Unauthenticated. Allows complete device takeover (IOS configs, RCE)."},
    7911:  {"name": "OMAPI (DHCP)",  "reason": "OMAPI interface for ISC DHCP. Can modify DHCP leases without auth."},
    9100:  {"name": "JetDirect / RAW Print","reason": "HP JetDirect raw printing. Can read/write printer file system."},
    # ── Backdoor / common malware ports ──────────────────────────────────
    4444:  {"name": "Backdoor",      "reason": "Commonly used by reverse shells and backdoors (Metasploit default)."},
    5554:  {"name": "Backdoor",      "reason": "Associated with backdoors and historical worms."},
    6666:  {"name": "IRC/Backdoor",  "reason": "Frequently used by botnets and IRC-based malware."},
    6667:  {"name": "IRC",           "reason": "Unencrypted IRC. Frequently exploited by botnets."},
    1524:  {"name": "Ingreslock Backdoor","reason": "Classic backdoor port. No legitimate services should use this."},
    # ── X11 (display servers) ─────────────────────────────────────────────
    6000:  {"name": "X11",           "reason": "X Window System. Can allow screen capture and input injection."},
    6001:  {"name": "X11 (display 1)","reason": "X Window System alternate display. Same risks as 6000."},
    # ── Compiler / debug services ─────────────────────────────────────────
    3632:  {"name": "distccd",       "reason": "Distributed compiler daemon. Allows arbitrary code execution (CVE-2004-2687)."},
}

INTERESTING_PORTS = {
    # ── Remote access ─────────────────────────────────────────────────────
    22:    {"name": "SSH",           "reason": "Remote access. Check version, authentication methods, and root login."},
    3389:  {"name": "RDP",           "reason": "Windows remote desktop. Frequent brute force and BlueKeep target."},
    5900:  {"name": "VNC",           "reason": "Remote desktop. Frequently weak or no authentication."},
    5901:  {"name": "VNC-1",         "reason": "VNC alternate port. Same risks : verify authentication."},
    # ── Windows services ─────────────────────────────────────────────────
    445:   {"name": "SMB",           "reason": "Windows file sharing. Critical CVE history (EternalBlue, PrintNightmare)."},
    139:   {"name": "NetBIOS-SSN",   "reason": "SMB over NetBIOS. Same risk as port 445."},
    5985:  {"name": "WinRM HTTP",    "reason": "Windows remote management. May allow command execution."},
    5986:  {"name": "WinRM HTTPS",   "reason": "Windows remote management (encrypted). Verify auth."},
    # ── Directory services / auth ─────────────────────────────────────────
    389:   {"name": "LDAP",          "reason": "Active directory. User and object enumeration possible."},
    636:   {"name": "LDAPS",         "reason": "LDAP over SSL. Verify anonymous query permissions."},
    88:    {"name": "Kerberos",      "reason": "Kerberos auth. AS-REP Roasting, Kerberoasting possible."},
    3268:  {"name": "GlobalCatalog", "reason": "AD Global Catalog LDAP. Full domain enumeration possible."},
    3269:  {"name": "GlobalCatalog SSL","reason": "AD Global Catalog LDAPS. Verify query permissions."},
    # ── Databases ────────────────────────────────────────────────────────
    1433:  {"name": "MSSQL",         "reason": "SQL Server. Should not be externally exposed."},
    3306:  {"name": "MySQL",         "reason": "MySQL database. Should not be externally exposed."},
    5432:  {"name": "PostgreSQL",    "reason": "PostgreSQL database. Should not be externally exposed."},
    1521:  {"name": "Oracle DB",     "reason": "Oracle database. Should not be externally exposed."},
    1527:  {"name": "Oracle DB alt", "reason": "Oracle alternate port. Should not be externally exposed."},
    6379:  {"name": "Redis",         "reason": "Redis has no auth by default. Possible RCE via config commands."},
    27017: {"name": "MongoDB",       "reason": "MongoDB no auth by default in old versions."},
    27018: {"name": "MongoDB (shard)","reason": "MongoDB shard port. Verify authentication."},
    9200:  {"name": "Elasticsearch", "reason": "No auth by default. Massive data exposure risk."},
    9300:  {"name": "Elasticsearch Cluster","reason": "ES cluster comms. Internal traffic that should not be exposed."},
    11211: {"name": "Memcached",     "reason": "No authentication. DDoS amplification attack vector."},
    5984:  {"name": "CouchDB",       "reason": "CouchDB. Admin party mode (no auth) in old versions."},
    6432:  {"name": "PgBouncer",     "reason": "PostgreSQL connection pooler. Verify auth configuration."},
    # ── Web ───────────────────────────────────────────────────────────────
    80:    {"name": "HTTP",          "reason": "Unencrypted web traffic. Verify content and redirect to HTTPS."},
    443:   {"name": "HTTPS",         "reason": "Encrypted web. Verify certificate and application security."},
    8080:  {"name": "HTTP-Alt",      "reason": "Alternative web. Common for admin panels and dev servers."},
    8443:  {"name": "HTTPS-Alt",     "reason": "Alternative HTTPS. Verify certificate and auth."},
    8000:  {"name": "HTTP Dev",      "reason": "Common dev server port. Verify it is not exposed to production."},
    8888:  {"name": "HTTP Dev",      "reason": "Common for Jupyter Notebooks (no auth by default)."},
    # ── Mail ─────────────────────────────────────────────────────────────
    25:    {"name": "SMTP",          "reason": "Mail. Check open relay and user enumeration (VRFY/EXPN)."},
    465:   {"name": "SMTPS",         "reason": "SMTP over SSL. Verify relay configuration."},
    587:   {"name": "SMTP Submission","reason": "Mail submission. Check for open relay."},
    110:   {"name": "POP3",          "reason": "Unencrypted mail retrieval. Credentials exposed."},
    995:   {"name": "POP3S",         "reason": "POP3 over SSL. Verify certificate."},
    143:   {"name": "IMAP",          "reason": "Unencrypted mail access. Credentials exposed."},
    993:   {"name": "IMAPS",         "reason": "IMAP over SSL. Verify certificate."},
    # ── DNS ───────────────────────────────────────────────────────────────
    53:    {"name": "DNS",           "reason": "DNS server. Check zone transfers (AXFR) and recursion."},
    # ── Container / Cloud ─────────────────────────────────────────────────
    2375:  {"name": "Docker API",    "reason": "Docker API without TLS. Full host control if exposed."},
    2376:  {"name": "Docker TLS",    "reason": "Docker API with TLS. Verify certificate configuration."},
    6443:  {"name": "Kubernetes API","reason": "K8s API. Cluster control if misconfigured."},
    2379:  {"name": "etcd",          "reason": "Kubernetes etcd. Full cluster state and secrets exposed."},
    2380:  {"name": "etcd cluster",  "reason": "etcd cluster peer port. Should be internal only."},
    10250: {"name": "Kubelet API",   "reason": "Kubelet. Can allow exec into pods and node-level actions."},
    # ── Monitoring / observability ────────────────────────────────────────
    9090:  {"name": "Prometheus",    "reason": "Exposed system metrics. Sensitive infrastructure info."},
    3000:  {"name": "Grafana/Dev",   "reason": "Common for Grafana. Default admin:admin credentials."},
    9100:  {"name": "Node Exporter", "reason": "Prometheus Node Exporter. Full system metrics exposed."},
    # ── Application servers ───────────────────────────────────────────────
    7001:  {"name": "WebLogic",      "reason": "Oracle WebLogic. Multiple critical RCE CVEs."},
    7002:  {"name": "WebLogic SSL",  "reason": "WebLogic HTTPS. Same risks : verify patching."},
    8161:  {"name": "ActiveMQ",      "reason": "ActiveMQ Admin. Documented RCE vulnerabilities."},
    61616: {"name": "ActiveMQ Broker","reason": "ActiveMQ message broker. Deserialization RCE possible."},
    4848:  {"name": "GlassFish",     "reason": "GlassFish Admin. History of critical CVEs."},
    9000:  {"name": "SonarQube/PHP-FPM","reason": "Common for SonarQube or PHP-FPM. Verify access."},
    8009:  {"name": "AJP",           "reason": "Apache JServ Protocol. Ghostcat vulnerability (CVE-2020-1938)."},
    # ── VPN / tunneling ───────────────────────────────────────────────────
    500:   {"name": "IKE (IPSec)",   "reason": "IPSec key exchange. Verify IKEv2 and strong ciphers."},
    1194:  {"name": "OpenVPN",       "reason": "OpenVPN server. Verify certificate and auth configuration."},
    1723:  {"name": "PPTP VPN",      "reason": "PPTP VPN. Weak protocol : MS-CHAPv2 is crackable."},
    4500:  {"name": "IPSec NAT-T",   "reason": "IPSec NAT traversal. Verify configuration."},
    # ── Misc high-risk ────────────────────────────────────────────────────
    5000:  {"name": "UPnP/Flask Dev","reason": "Common for UPnP or Flask dev server. Verify what is running."},
    8500:  {"name": "Consul",        "reason": "HashiCorp Consul. Service mesh : full cluster info if exposed."},
    8200:  {"name": "Vault",         "reason": "HashiCorp Vault. Secret management : should never be externally exposed."},
    5601:  {"name": "Kibana",        "reason": "Kibana dashboard. Full Elasticsearch data access."},
    15672: {"name": "RabbitMQ Mgmt","reason": "RabbitMQ management UI. Default guest:guest credentials."},
    5672:  {"name": "AMQP",          "reason": "RabbitMQ/AMQP broker. Message interception possible."},
}

# ─────────────────────────────────────────────────────────────────────────────
# FOLLOW-UP RECOMMENDATIONS (when port is open but no service detection)
# ─────────────────────────────────────────────────────────────────────────────

FOLLOWUP_COMMANDS = {
    445:   "nmap -sV -p 445 --script smb-security-mode,smb2-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067 {ip}",
    139:   "nmap -sV -p 139,445 --script smb-security-mode,smb-enum-shares {ip}",
    22:    "nmap -sV -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos {ip}",
    21:    "nmap -sV -p 21 --script ftp-anon,ftp-bounce,ftp-syst {ip}",
    23:    "nmap -sV -p 23 --script telnet-encryption,telnet-ntlm-info {ip}",
    25:    "nmap -sV -p 25 --script smtp-open-relay,smtp-enum-users,smtp-commands {ip}",
    53:    "nmap -sV -p 53 --script dns-zone-transfer,dns-recursion {ip}",
    80:    "nmap -sV -p 80 --script http-title,http-headers,http-methods,http-auth-finder {ip}",
    443:   "nmap -sV -p 443 --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,http-title {ip}",
    161:   "nmap -sU -p 161 --script snmp-brute,snmp-info,snmp-sysdescr {ip}",
    3306:  "nmap -sV -p 3306 --script mysql-empty-password,mysql-info {ip}",
    1433:  "nmap -sV -p 1433 --script ms-sql-info,ms-sql-empty-password {ip}",
    3389:  "nmap -sV -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 {ip}",
    5900:  "nmap -sV -p 5900 --script vnc-info,vnc-brute {ip}",
    6379:  "nmap -sV -p 6379 --script redis-info {ip}",
    27017: "nmap -sV -p 27017 --script mongodb-info {ip}",
    5432:  "nmap -sV -p 5432 --script pgsql-brute {ip}",
    9200:  "nmap -sV -p 9200 --script http-title {ip}",
    2375:  "nmap -sV -p 2375 --script http-title {ip}",
    623:   "nmap -sU -p 623 --script ipmi-version,ipmi-brute {ip}",
    8080:  "nmap -sV -p 8080 --script http-title,http-headers,http-auth-finder {ip}",
    8443:  "nmap -sV -p 8443 --script ssl-cert,ssl-enum-ciphers,http-title {ip}",
    5985:  "nmap -sV -p 5985 --script http-auth-finder {ip}",
}

GENERIC_FOLLOWUP = "nmap -sV -p {port} --script default {ip}"

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_vulnerabilities(host_data):
    vulns = []
    for port in host_data.get('ports', []):
        port_num = port.get('portid', 0)
        service  = port.get('service', {})
        svc_name = service.get('name', '').lower()
        product  = service.get('product', '').lower()
        version  = service.get('version', '').lower()
        scripts  = port.get('scripts', [])
        full_ver = f"{product} {version}".strip()
        method   = service.get('method', 'table')

        is_critical    = port_num in CRITICAL_PORTS
        is_interesting = port_num in INTERESTING_PORTS
        port_info      = CRITICAL_PORTS.get(port_num) or INTERESTING_PORTS.get(port_num)

        # ── No service info at all ─────────────────────────────────────────
        # Only raise a finding if the port is in our critical/interesting list.
        # A random unidentified port is not actionable noise.
        if not service.get('name') and not service.get('product'):
            if is_critical or is_interesting:
                severity = "HIGH" if is_critical else "MEDIUM"
                cmd = FOLLOWUP_COMMANDS.get(port_num, GENERIC_FOLLOWUP).format(
                    ip=host_data.get('ip', '[TARGET]'), port=port_num)
                pname = port_info['name']
                vulns.append({
                    "severity": severity,
                    "port": port_num,
                    "title": f"{pname} Open : Service Unconfirmed (No -sV)",
                    "description": (
                        f"Port {port_num} is open and typically runs {pname}. "
                        f"No service banner was captured (scan ran without -sV). "
                        f"Given the nature of this port ({port_info['reason']}), "
                        f"it should be investigated. Run the follow-up scan to confirm and check for vulnerabilities."
                    ),
                    "cve": "N/A",
                    "script": "port-classification",
                    "followup": cmd,
                })
            # Unknown port, no service info → skip silently, not actionable
            continue

        # ── Service identified by port number only (no -sV probing) ───────
        # Only flag if the port is known to be critical/interesting.
        if method == 'table' and (is_critical or is_interesting):
            severity = "MEDIUM" if is_critical else "LOW"
            cmd = FOLLOWUP_COMMANDS.get(port_num, GENERIC_FOLLOWUP).format(
                ip=host_data.get('ip', '[TARGET]'), port=port_num)
            pname = port_info['name']
            vulns.append({
                "severity": severity,
                "port": port_num,
                "title": f"{pname} : Version Unknown (Port-Only Match)",
                "description": (
                    f"{pname} on port {port_num} was identified by port number alone : "
                    f"no service banner was read (scan ran without -sV). "
                    f"Version info is needed to detect known CVEs and misconfigs. "
                    f"Run the follow-up scan below."
                ),
                "cve": "N/A",
                "script": "version-detection",
                "followup": cmd,
            })

        # ── SMB ───────────────────────────────────────────────────────────
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
                        "description": "Remote code execution as SYSTEM. Used by WannaCry and NotPetya. Patch immediately.",
                        "cve": "CVE-2017-0144", "script": sid})
                if 'smb-vuln-ms08-067' in sid:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "MS08-067 NetAPI RCE",
                        "description": "Classic RCE on Windows XP/2003.", "cve": "CVE-2008-4250", "script": sid})
                if 'smb2-security-mode' in sid and 'signing enabled and required' not in output:
                    vulns.append({"severity": "MEDIUM", "port": port_num,
                        "title": "SMBv2 Signing Not Required",
                        "description": "SMBv2 signing not enforced. Relay attacks possible.", "cve": "N/A", "script": sid})
            if 'smbv1' in full_ver:
                vulns.append({"severity": "CRITICAL", "port": port_num,
                    "title": "SMBv1 Enabled",
                    "description": "Obsolete protocol. EternalBlue/WannaCry vector. Disable immediately.",
                    "cve": "CVE-2017-0144", "script": "version-detection"})

        # ── SSH ───────────────────────────────────────────────────────────
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
                    "description": "Old OpenSSH with multiple known CVEs. Update immediately.",
                    "cve": "Multiple", "script": "version-detection"})

        # ── SSL/TLS ───────────────────────────────────────────────────────
        for script in scripts:
            sid    = script.get('id', '').lower()
            output = script.get('output', '').lower()
            if 'ssl-heartbleed' in sid and 'vulnerable' in output:
                vulns.append({"severity": "CRITICAL", "port": port_num,
                    "title": "Heartbleed (OpenSSL)", "cve": "CVE-2014-0160",
                    "description": "Reads server memory including private keys and session data.", "script": sid})
            if 'ssl-poodle' in sid and 'vulnerable' in output:
                vulns.append({"severity": "HIGH", "port": port_num,
                    "title": "POODLE Attack (SSLv3)", "cve": "CVE-2014-3566",
                    "description": "Server accepts SSLv3. Vulnerable to POODLE downgrade attack.", "script": sid})
            if 'ssl-drown' in sid and 'vulnerable' in output:
                vulns.append({"severity": "CRITICAL", "port": port_num,
                    "title": "DROWN Attack", "cve": "CVE-2016-0800",
                    "description": "Server supports SSLv2. Allows decryption of TLS connections.", "script": sid})
            if 'ssl-cert' in sid and 'expired' in output:
                vulns.append({"severity": "MEDIUM", "port": port_num,
                    "title": "Expired SSL Certificate",
                    "description": "The SSL certificate has expired. Clients may receive security warnings.",
                    "cve": "N/A", "script": sid})

        # ── FTP ───────────────────────────────────────────────────────────
        if 'ftp' in svc_name or port_num == 21:
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'ftp-anon' in sid and ('allowed' in output or 'anonymous' in output):
                    vulns.append({"severity": "HIGH", "port": port_num,
                        "title": "FTP Anonymous Access",
                        "description": "FTP allows access without credentials. Possible file read/write.",
                        "cve": "N/A", "script": sid})

        # ── Redis ─────────────────────────────────────────────────────────
        if 'redis' in svc_name or port_num == 6379:
            for script in scripts:
                if 'redis-info' in script.get('id', '').lower():
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "Redis Without Authentication",
                        "description": "Redis exposed without password. Data access and possible RCE.",
                        "cve": "N/A", "script": script['id']})

        # ── HTTP ──────────────────────────────────────────────────────────
        if svc_name in ('http','https','http-alt','https-alt') or port_num in (80,443,8080,8443):
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'http-shellshock' in sid and 'vulnerable' in output:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "Shellshock (Bash RCE)", "cve": "CVE-2014-6271",
                        "description": "Web server vulnerable to Shellshock. RCE via CGI.", "script": sid})
                if 'http-default-accounts' in sid and 'valid' in output:
                    vulns.append({"severity": "CRITICAL", "port": port_num,
                        "title": "Default Credentials Accepted",
                        "description": "Web service accepts default credentials. Change passwords immediately.",
                        "cve": "N/A", "script": sid})

        # ── RDP ───────────────────────────────────────────────────────────
        if port_num == 3389 or 'rdp' in svc_name or 'ms-wbt' in svc_name:
            for script in scripts:
                sid    = script.get('id', '').lower()
                output = script.get('output', '').lower()
                if 'rdp-vuln-ms12-020' in sid and 'vulnerable' in output:
                    vulns.append({"severity": "HIGH", "port": port_num,
                        "title": "MS12-020 RDP DoS", "cve": "CVE-2012-0152",
                        "description": "RDP vulnerable to denial of service.", "script": sid})
                if 'rdp-enum-encryption' in sid and 'rdp security layer' in output:
                    vulns.append({"severity": "MEDIUM", "port": port_num,
                        "title": "RDP Without NLA",
                        "description": "RDP not using NLA. More exposed to brute force.",
                        "cve": "N/A", "script": sid})

        # ── Telnet ────────────────────────────────────────────────────────
        if 'telnet' in svc_name or port_num == 23:
            vulns.append({"severity": "CRITICAL", "port": port_num,
                "title": "Telnet Active",
                "description": "Transmits everything in plaintext including credentials. Replace with SSH.",
                "cve": "N/A", "script": "port-classification"})

        # ── IPMI ──────────────────────────────────────────────────────────
        if port_num == 623:
            vulns.append({"severity": "CRITICAL", "port": port_num,
                "title": "IPMI / BMC Exposed",
                "description": "IPMI allows authentication bypass via cipher 0 and hash retrieval (CVE-2013-4786). Full server control possible.",
                "cve": "CVE-2013-4786", "script": "port-classification"})

        # ── Cisco Smart Install ────────────────────────────────────────────
        if port_num == 4786:
            vulns.append({"severity": "CRITICAL", "port": port_num,
                "title": "Cisco Smart Install Exposed",
                "description": "Smart Install requires no authentication. Allows reading/writing device configs and RCE.",
                "cve": "CVE-2018-0171", "script": "port-classification"})

        # ── AJP / Ghostcat ────────────────────────────────────────────────
        if port_num == 8009 or 'ajp' in svc_name:
            vulns.append({"severity": "CRITICAL", "port": port_num,
                "title": "AJP Connector Exposed (Ghostcat)",
                "description": "Apache JServ Protocol exposed. Ghostcat allows reading arbitrary files from the webapp.",
                "cve": "CVE-2020-1938", "script": "port-classification"})

        # ── Outdated versions ─────────────────────────────────────────────
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
                    "description": f"Old {svc_friendly} with multiple known CVEs. Update.",
                    "cve": "Multiple", "script": "version-detection"})

    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# NMAP XML PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_content):
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
            if t == 'ipv4':   host_data['ip'] = addr.get('addr', '')
            elif t == 'ipv6' and not host_data['ip']: host_data['ip'] = addr.get('addr', '')
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
                existing_ports = {p['portid']: p for p in existing['ports']}
                for port in host['ports']:
                    pid = port['portid']
                    if pid not in existing_ports:
                        existing_ports[pid] = port
                    else:
                        ep = existing_ports[pid]
                        if not ep['service'].get('product') and port['service'].get('product'):
                            existing_ports[pid] = port
                        existing_script_ids = {s['id'] for s in ep.get('scripts', [])}
                        for script in port.get('scripts', []):
                            if script['id'] not in existing_script_ids:
                                ep.setdefault('scripts', []).append(script)
                existing['ports'] = list(existing_ports.values())
                if host.get('os_accuracy', 0) > existing.get('os_accuracy', 0):
                    existing['os']          = host['os']
                    existing['os_accuracy'] = host['os_accuracy']
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
        for h in scan_data.get('hosts', []))
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
    with open(HISTORY_DIR / f"{scan_id}.json", 'w') as f:
        json.dump({**meta, "scan": scan_data}, f, indent=2)
    return meta


# ─────────────────────────────────────────────────────────────────────────────
# REPORT: HTML
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(scan, meta):
    ts    = meta.get('timestamp_display', '')
    files = ', '.join(meta.get('filenames', []))
    sev_color = {'CRITICAL':'#ff3333','HIGH':'#ff8c00','MEDIUM':'#ffd700','LOW':'#00bfff','INFO':'#888'}
    hosts_html = ""
    for host in scan.get('hosts', []):
        sorted_ports = sorted(host.get('ports',[]),
                              key=lambda p:{'critical':0,'interesting':1,'normal':2}.get(p['classification'],2))
        pts_parts = []
        for p in sorted_ports:
            svc = p.get('service', {})
            icon = '🔴' if p['classification']=='critical' else '🟠' if p['classification']=='interesting' else '🟢'
            ver = ' '.join(filter(None, [svc.get('product',''), svc.get('version','')]))
            pts_parts.append(
                "<tr><td>" + icon + " " + str(p['portid']) + "/" + p['protocol'] + "</td>"
                + "<td>" + svc.get('name','') + "</td>"
                + "<td>" + ver + "</td>"
                + "<td style='color:#888;font-size:11px'>" + p.get('class_reason','') + "</td></tr>"
            )
        pts = "".join(pts_parts)
        sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
        vls_parts = []
        for v in sorted(host.get('vulns',[]), key=lambda x: sev_order.get(x.get('severity','INFO'), 9)):
            col = sev_color.get(v['severity'], '#888')
            vls_parts.append(
                "<tr><td style='color:" + col + ";font-weight:700'>" + v['severity'] + "</td>"
                + "<td>" + v['title'] + "</td>"
                + "<td>" + v['description'] + "</td>"
                + "<td style='color:#bc8cff'>" + v.get('cve','N/A') + "</td>"
                + "<td style='color:#58a6ff'>" + str(v['port']) + "</td></tr>"
            )
        vls = "".join(vls_parts)
        hosts_html += f"""<div class='hb'>
          <h3>// {host.get('ip','')} {('<span style="color:#888">'+host['hostname']+'</span>') if host.get('hostname') else ''}</h3>
          <p class='meta'>OS: {host.get('os','Unknown')} | MAC: {host.get('mac','N/A')} {host.get('vendor','')}</p>
          <h4>OPEN PORTS ({len(host.get('ports',[]))})</h4>
          <table><tr><th>Port</th><th>Service</th><th>Version</th><th>Note</th></tr>{pts}</table>
          {'<h4>POTENTIAL VULNERABILITIES ('+str(len(host.get("vulns",[])))+')</h4><table><tr><th>Sev</th><th>Finding</th><th>Detail</th><th>CVE</th><th>Port</th></tr>'+vls+'</table>' if host.get('vulns') else '<p style="color:#00ff41">[ NO VULNERABILITIES DETECTED ]</p>'}
        </div>"""
    tc = sum(len([p for p in h.get('ports',[]) if p['classification']=='critical']) for h in scan.get('hosts',[]))
    tv = sum(len(h.get('vulns',[])) for h in scan.get('hosts',[]))
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>NmapViz Report {ts}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#000;color:#c9d1d9;font-family:'Share Tech Mono',monospace;padding:40px;line-height:1.6}}
  h1{{color:#00ff41;border-bottom:1px solid #00ff41;padding-bottom:8px;margin-bottom:16px;font-size:22px}}
  h2{{color:#00ff41;margin:28px 0 10px;font-size:16px}}
  h3{{color:#58a6ff;margin:16px 0 4px;font-size:14px}}
  h4{{color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin:12px 0 6px}}
  .meta{{color:#888;font-size:12px;margin-bottom:8px}}
  .hb{{background:#0d1117;border:1px solid #30363d;border-left:3px solid #58a6ff;border-radius:4px;padding:18px;margin-bottom:18px}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin:8px 0}}
  th{{background:#161b22;padding:7px 10px;text-align:left;color:#888;font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
  td{{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
  .stats{{display:flex;gap:24px;background:#0d1117;border:1px solid #30363d;padding:16px;margin:16px 0;border-radius:4px}}
  .stat{{text-align:center}}.val{{font-size:26px;font-weight:700;color:#00ff41}}.lbl{{font-size:11px;color:#888;text-transform:uppercase}}
  code{{color:#58a6ff;background:rgba(88,166,255,.1);padding:2px 6px;border-radius:3px}}
  footer{{margin-top:40px;color:#555;font-size:11px;border-top:1px solid #30363d;padding-top:16px}}
</style></head><body>
<h1>&gt;_ NMAPVIZ // SCAN REPORT</h1>
<p><strong>Date:</strong> {ts} &nbsp;|&nbsp; <strong>Source:</strong> {files}</p>
<p><strong>Command:</strong> <code>{scan.get('args','N/A')}</code></p>
<p><strong>Version detection:</strong> {'YES (-sV)' if scan.get('has_version') else 'NO : basic scan'} &nbsp;|&nbsp;
   <strong>NSE Scripts:</strong> {'YES' if scan.get('has_scripts') else 'NO'}</p>
<div class='stats'>
  <div class='stat'><div class='val'>{len(scan.get('hosts',[]))}</div><div class='lbl'>Hosts</div></div>
  <div class='stat'><div class='val'>{sum(len(h.get('ports',[])) for h in scan.get('hosts',[]))}</div><div class='lbl'>Open Ports</div></div>
  <div class='stat'><div class='val' style='color:#ff3333'>{tc}</div><div class='lbl'>Critical Ports</div></div>
  <div class='stat'><div class='val' style='color:#bc8cff'>{tv}</div><div class='lbl'>Vulnerabilities</div></div>
</div>
<h2>// HOST DETAILS</h2>{hosts_html}
<footer>Generated by NmapViz &middot; https://github.com/YOUR_USERNAME/nmap-visualizer</footer>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# REPORT: MARKDOWN
# ─────────────────────────────────────────────────────────────────────────────

def generate_markdown_report(scan, meta):
    ts    = meta.get('timestamp_display', '')
    files = ', '.join(meta.get('filenames', []))
    lines = [
        "# NmapViz Scan Report", "",
        f"**Generated:** {ts}  ", f"**Source files:** {files}  ",
        f"**Command:** `{scan.get('args','N/A')}`  ",
        f"**Version detection:** {'Yes (-sV)' if scan.get('has_version') else 'No (basic scan)'}  ", "",
        "## Summary", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Active Hosts | {len(scan.get('hosts',[]))} |",
        f"| Open Ports | {sum(len(h.get('ports',[])) for h in scan.get('hosts',[]))} |",
        f"| Critical Ports | {sum(len([p for p in h.get('ports',[]) if p['classification']=='critical']) for h in scan.get('hosts',[]))} |",
        f"| Vulnerabilities | {sum(len(h.get('vulns',[])) for h in scan.get('hosts',[]))} |", "",
        "---", "", "## Hosts", "",
    ]
    sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    for host in scan.get('hosts', []):
        lines += [f"### {host.get('ip','')}  {host.get('hostname','')}", ""]
        if host.get('os'): lines.append(f"- **OS:** {host['os']} ({host.get('os_accuracy',0)}%)")
        if host.get('mac'): lines.append(f"- **MAC:** {host['mac']} {host.get('vendor','')}")
        lines += [f"- **Open Ports:** {len(host.get('ports',[]))}", ""]
        if host.get('ports'):
            lines += ["#### Open Ports", "", "| Port | Service | Version | Class |",
                      "|------|---------|---------|-------|"]
            for p in sorted(host['ports'], key=lambda x:{'critical':0,'interesting':1,'normal':2}.get(x['classification'],2)):
                svc = p.get('service',{})
                ver = ' '.join(filter(None,[svc.get('product',''),svc.get('version','')]))
                icon = {'critical':'🔴','interesting':'🟠','normal':'🟢'}.get(p['classification'],'')
                lines.append(f"| {p['portid']}/{p['protocol']} | {svc.get('name','')} | {ver} | {icon} {p['classification']} |")
            lines.append("")
        if host.get('vulns'):
            lines += ["#### ⚠️ Vulnerabilities", ""]
            for v in sorted(host['vulns'], key=lambda x:sev_order.get(x.get('severity','INFO'),9)):
                lines += [f"**[{v['severity']}] {v['title']}** (Port {v['port']})", "",
                          f"> {v['description']}", f"> CVE: `{v.get('cve','N/A')}`", ""]
        lines += ["---", ""]
    lines.append("*Generated by [NmapViz](https://github.com/YOUR_USERNAME/nmap-visualizer)*")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# REPORT: PDF (Executive Summary)
# ─────────────────────────────────────────────────────────────────────────────

def _pdf_safe(text):
    """Replace characters unsupported by Helvetica with ASCII equivalents."""
    if not text:
        return ''
    replacements = {
        ':': '--',   # em dash
        '–': '-',    # en dash
        '‘': "'",    # left single quote
        '’': "'",    # right single quote
        '“': '"',    # left double quote
        '”': '"',    # right double quote
        '•': '*',    # bullet
        '…': '...',  # ellipsis
        'é': 'e',    # e acute
        'à': 'a',    # a grave
        'ü': 'u',    # u umlaut
        'ö': 'o',    # o umlaut
        'ä': 'a',    # a umlaut
        'è': 'e',    # e grave
        'á': 'a',    # a acute
        'ó': 'o',    # o acute
        'ú': 'u',    # u acute
        'í': 'i',    # i acute
        '·': '.',      # middle dot
        '’': "'",
        '×': 'x',    # multiplication sign
        '°': 'deg',  # degree sign
        '→': '->',   # right arrow
        '←': '<-',   # left arrow
        '▶': '>',    # triangle
        '≈': '~',    # approximately
    }
    result = str(text)
    for char, replacement in replacements.items():
        result = result.replace(char, replacement)
    # Final pass: strip any remaining non-latin1 chars
    return result.encode('latin-1', errors='replace').decode('latin-1')


def generate_pdf_report(scan, meta):
    from fpdf import FPDF, XPos, YPos

    ts    = _pdf_safe(meta.get('timestamp_display', 'N/A'))
    files = _pdf_safe(', '.join(meta.get('filenames', [])))
    hosts = scan.get('hosts', [])

    total_hosts = len(hosts)
    total_ports = sum(len(h.get('ports',[])) for h in hosts)
    crit_ports  = sum(len([p for p in h.get('ports',[]) if p['classification']=='critical']) for h in hosts)
    inter_ports = sum(len([p for p in h.get('ports',[]) if p['classification']=='interesting']) for h in hosts)
    total_vulns = sum(len(h.get('vulns',[])) for h in hosts)
    crit_vulns  = sum(len([v for v in h.get('vulns',[]) if v['severity']=='CRITICAL']) for h in hosts)
    high_vulns  = sum(len([v for v in h.get('vulns',[]) if v['severity']=='HIGH']) for h in hosts)
    med_vulns   = sum(len([v for v in h.get('vulns',[]) if v['severity']=='MEDIUM']) for h in hosts)

    # Risk score (simple: 10×CRITICAL + 5×HIGH + 2×MEDIUM + crit_ports×3)
    risk_score  = crit_vulns * 10 + high_vulns * 5 + med_vulns * 2 + crit_ports * 3
    if risk_score == 0:   risk_label = "LOW"
    elif risk_score < 20: risk_label = "MEDIUM"
    elif risk_score < 60: risk_label = "HIGH"
    else:                 risk_label = "CRITICAL"

    risk_colors = {"LOW":(63,185,80), "MEDIUM":(224,122,48), "HIGH":(248,81,73), "CRITICAL":(124,58,237)}
    sev_colors  = {"CRITICAL":(124,58,237), "HIGH":(248,81,73), "MEDIUM":(224,122,48),
                   "LOW":(63,185,80), "INFO":(77,157,224)}

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(18, 18, 18)

    # ── COVER PAGE ────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 297, 'F')

    # Header bar
    pdf.set_fill_color(22, 27, 34)
    pdf.rect(0, 0, 210, 50, 'F')

    pdf.set_text_color(88, 166, 255)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_xy(18, 14)
    pdf.cell(0, 12, "NMAPVIZ", new_x=XPos.LEFT, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(139, 148, 158)
    pdf.set_xy(18, 28)
    pdf.cell(0, 6, "Network Security Scan: Executive Summary Report")

    # Risk badge
    rc = risk_colors[risk_label]
    pdf.set_fill_color(*rc)
    pdf.set_xy(148, 12)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(13, 17, 23)
    pdf.cell(44, 10, f"RISK: {risk_label}", align="C", fill=True)

    # Divider
    pdf.set_draw_color(48, 54, 61)
    pdf.set_xy(18, 54)
    pdf.line(18, 54, 192, 54)

    # Scan metadata
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(139, 148, 158)
    pdf.set_xy(18, 58)
    pdf.multi_cell(0, 6, f"Report Date: {ts}\nSource Files: {files}\nCommand: {_pdf_safe(scan.get('args','N/A'))[:120]}\n"
                         f"Version Detection: {'Yes (-sV)' if scan.get('has_version') else 'No (basic scan)'} | "
                         f"NSE Scripts: {'Yes' if scan.get('has_scripts') else 'No'}")

    # Stats grid
    pdf.set_xy(18, 100)
    stats = [
        ("Active Hosts",    str(total_hosts),  (88,166,255)),
        ("Open Ports",      str(total_ports),  (88,166,255)),
        ("Critical Ports",  str(crit_ports),   (248,81,73)),
        ("Interesting Ports",str(inter_ports), (217,134,52)),
        ("Vulnerabilities", str(total_vulns),  (188,140,255)),
        ("Critical Findings",str(crit_vulns),  (248,81,73)),
    ]
    col_w = (192 - 18) / 3
    for i, (label, value, color) in enumerate(stats):
        col = i % 3
        row = i // 3
        x = 18 + col * col_w
        y = 100 + row * 28
        pdf.set_fill_color(22, 27, 34)
        pdf.set_draw_color(48, 54, 61)
        pdf.rect(x, y, col_w - 4, 24, 'DF')
        pdf.set_xy(x + 4, y + 3)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(*color)
        pdf.cell(col_w - 12, 9, value)
        pdf.set_xy(x + 4, y + 13)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(139, 148, 158)
        pdf.cell(col_w - 12, 5, label.upper())

    # Vulnerability severity breakdown
    pdf.set_xy(18, 164)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, "VULNERABILITY BREAKDOWN BY SEVERITY")
    pdf.set_xy(18, 174)
    sev_data = [("CRITICAL", crit_vulns, (248,81,73)), ("HIGH", high_vulns, (217,134,52)),
                ("MEDIUM", med_vulns, (210,153,34)), ("LOW+INFO", total_vulns-crit_vulns-high_vulns-med_vulns, (100,100,100))]
    bar_total = total_vulns or 1
    bar_w = 174
    for label, count, color in sev_data:
        pdf.set_xy(18, pdf.get_y())
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(139, 148, 158)
        pdf.cell(26, 6, label)
        pdf.cell(14, 6, str(count), align="R")
        bar_len = max(int((count / bar_total) * bar_w), 0)
        if bar_len > 0:
            pdf.set_fill_color(*color)
            pdf.rect(pdf.get_x() + 2, pdf.get_y() + 1, bar_len, 4, 'F')
        pdf.ln(7)

    # Footer
    pdf.set_xy(18, 275)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(48, 54, 61)
    pdf.cell(0, 5, "NmapViz Executive Summary | Confidential | For authorised use only", align="C")

    # ── PAGE 2: TOP FINDINGS ──────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 297, 'F')

    pdf.set_xy(18, 18)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, "TOP FINDINGS: CRITICAL AND HIGH SEVERITY")
    pdf.ln(10)

    all_vulns = []
    for h in hosts:
        for v in h.get('vulns', []):
            if v['severity'] in ('CRITICAL', 'HIGH'):
                all_vulns.append({**v, 'host_ip': h['ip']})
    sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    all_vulns.sort(key=lambda x: sev_order.get(x['severity'], 9))

    if not all_vulns:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(63, 185, 80)
        pdf.set_xy(18, pdf.get_y())
        pdf.cell(0, 8, "No Critical or High severity findings detected.")
    else:
        for v in all_vulns[:20]:
            if pdf.get_y() > 260:
                pdf.add_page()
                pdf.set_fill_color(13, 17, 23)
                pdf.rect(0, 0, 210, 297, 'F')
                pdf.set_xy(18, 18)
            y0 = pdf.get_y()
            sc = sev_colors.get(v['severity'], (100,100,100))
            pdf.set_fill_color(*sc)
            pdf.rect(18, y0, 3, 16, 'F')
            pdf.set_xy(24, y0 + 1)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*sc)
            pdf.cell(22, 5, v['severity'])
            pdf.set_text_color(230, 237, 243)
            pdf.cell(0, 5, _pdf_safe(v['title'])[:80])
            pdf.set_xy(24, y0 + 7)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(139, 148, 158)
            pdf.cell(0, 5, _pdf_safe(f"Host: {v['host_ip']}  Port: {v['port']}  CVE: {v.get('cve','N/A')}"))
            pdf.set_xy(24, y0 + 12)
            pdf.set_text_color(100, 110, 120)
            pdf.set_font("Helvetica", "", 7)
            desc = _pdf_safe(v['description'])[:120] + ('...' if len(_pdf_safe(v['description'])) > 120 else '')
            pdf.cell(0, 4, desc)
            pdf.ln(18)

    # ── PAGE 3+: HOST SUMMARY TABLE ───────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 297, 'F')
    pdf.set_xy(18, 18)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, "HOST SUMMARY")
    pdf.ln(10)

    # Table header
    col_widths = [36, 46, 20, 22, 22, 24]
    headers    = ["IP Address", "OS", "Ports", "Critical", "Interesting", "Vulns"]
    pdf.set_fill_color(22, 27, 34)
    for i, (h, w) in enumerate(zip(headers, col_widths)):
        pdf.set_xy(18 + sum(col_widths[:i]), pdf.get_y())
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(139, 148, 158)
        pdf.cell(w, 6, h.upper(), fill=True)
    pdf.ln(7)

    for host in sorted(hosts, key=lambda h: [int(x) for x in h.get('ip','0.0.0.0').split('.') if x.isdigit()]):
        if pdf.get_y() > 265:
            pdf.add_page()
            pdf.set_fill_color(13, 17, 23)
            pdf.rect(0, 0, 210, 297, 'F')
            pdf.set_xy(18, 18)
        hc = len([p for p in host.get('ports',[]) if p['classification']=='critical'])
        hi = len([p for p in host.get('ports',[]) if p['classification']=='interesting'])
        hv = len(host.get('vulns',[]))
        row_color = (248,81,73) if hc > 0 else (217,134,52) if hi > 0 else (63,185,80)
        pdf.set_fill_color(*row_color)
        pdf.rect(18, pdf.get_y(), 2, 5, 'F')
        values = [
            _pdf_safe(host.get('ip','?')),
            _pdf_safe(host.get('os','Unknown') or 'Unknown')[:26],
            str(len(host.get('ports',[]))),
            str(hc), str(hi), str(hv)
        ]
        text_colors = [(230,237,243),(139,148,158),(88,166,255),(248,81,73) if hc else (100,100,100),(217,134,52) if hi else (100,100,100),(188,140,255) if hv else (100,100,100)]
        x_start = 20
        for j, (val, w) in enumerate(zip(values, col_widths)):
            pdf.set_xy(x_start + sum(col_widths[:j]), pdf.get_y())
            pdf.set_font("Helvetica", "B" if j==0 else "", 8)
            pdf.set_text_color(*text_colors[j])
            pdf.cell(w, 5, val)
        pdf.ln(6)
        # Mini port list for critical hosts
        if hc > 0 or hv > 0:
            pdf.set_xy(22, pdf.get_y())
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(100, 110, 120)
            crit_list = [str(p['portid']) for p in host.get('ports',[]) if p['classification']=='critical']
            crit_list = [_pdf_safe(x) for x in crit_list]
            if crit_list:
                pdf.cell(0, 4, "Critical: " + ", ".join(crit_list[:12]))
            pdf.ln(5)

    # Footer every page
    pdf.set_xy(18, 282)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(48, 54, 61)
    pdf.cell(0, 5, f"NmapViz Report | {ts} | Confidential", align="C")

    return bytes(pdf.output())


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
    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({"error": "No files provided"}), 400
    scans, filenames = [], []
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
            with open(f) as fp: d = json.load(fp)
            items.append({k: d[k] for k in
                ['id','timestamp','timestamp_display','filenames','host_count',
                 'total_ports','vuln_count','critical_ports','args'] if k in d})
        except Exception: continue
    return jsonify(items)

@app.route('/api/history/<scan_id>')
def get_scan(scan_id):
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists(): return jsonify({"error": "Scan not found"}), 404
    with open(path) as f: d = json.load(f)
    return jsonify({"success": True, "data": d['scan'],
                    "meta": {k: d[k] for k in ['id','timestamp_display','filenames','host_count','total_ports','vuln_count','critical_ports'] if k in d}})

@app.route('/api/history/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    path = HISTORY_DIR / f"{scan_id}.json"
    if path.exists(): path.unlink()
    return jsonify({"success": True})

@app.route('/api/report/<scan_id>/<fmt>')
def download_report(scan_id, fmt):
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists(): return jsonify({"error": "Scan not found"}), 404
    with open(path) as f: stored = json.load(f)
    scan = stored['scan']
    meta = {k: stored[k] for k in ['id','timestamp_display','filenames'] if k in stored}
    if fmt == 'json':
        return Response(json.dumps(scan, indent=2), mimetype='application/json',
            headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.json"})
    elif fmt == 'html':
        return Response(generate_html_report(scan, meta), mimetype='text/html',
            headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.html"})
    elif fmt == 'markdown':
        return Response(generate_markdown_report(scan, meta), mimetype='text/markdown',
            headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.md"})
    elif fmt == 'pdf':
        try:
            pdf_bytes = generate_pdf_report(scan, meta)
            return Response(pdf_bytes, mimetype='application/pdf',
                headers={"Content-Disposition": f"attachment; filename=nmapviz_{scan_id}.pdf"})
        except Exception as e:
            return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500
    else:
        return jsonify({"error": "Unknown format. Use: json, html, markdown, pdf"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12221, debug=False)