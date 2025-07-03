#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ==============================================================================
# Nmap AIO Scan Detector - v2.1 (Consolidated Reporting Version)
#
# Features:
# - Auto-daemon creation on first run
# - Verbose JSON logging with detailed scan analysis
# - Real-time threat assessment
# - Geolocation and reputation checking
# - Auto-restart on crash
# - Enhanced port scan detection patterns
# - Consolidated reporting for single scan events
# ==============================================================================

import os
import sys
import time
import json
import re
import logging
import signal
import subprocess
import threading
import socket
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib

# --- Auto-install dependencies ---
def install_dependencies():
    """Auto-install required packages if missing"""
    required_packages = {
        'click': 'click',
        'daemon': 'python-daemon',
        'filelock': 'filelock',
        'requests': 'requests'
    }

    missing = []
    for module, package in required_packages.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"Installing missing dependencies: {', '.join(missing)}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing)
            print("Dependencies installed successfully!")
        except subprocess.CalledProcessError:
            print("Failed to install dependencies. Please run:")
            print(f"pip3 install {' '.join(missing)}")
            sys.exit(1)

# Install dependencies first
install_dependencies()

# Now import the packages
import click
import requests
from daemon import DaemonContext
from daemon.pidfile import TimeoutPIDLockFile
from filelock import FileLock, Timeout

# --- Configuration ---
PID_FILE = "/tmp/nmap_aio_detector.pid"
LOG_FILE = "/var/log/nmap_aio_detector.log"
REPORT_FILE = "/var/log/nmap_scan_detections.json"
CONFIG_FILE = "/etc/nmap_aio_detector.conf"

# Detection thresholds
SCAN_THRESHOLD = 3  # Minimum packets to consider a scan
AGGRESSIVE_THRESHOLD = 10  # Threshold for aggressive scan
STEALTH_THRESHOLD = 50  # Threshold for stealth/slow scan
TIME_WINDOW = 300  # 5 minutes window to consider a scan inactive
CLEANUP_INTERVAL = 60  # Check for inactive scans every 60 seconds

# Logging patterns for different scan types
SCAN_PATTERNS = {
    'kernel_dropped': re.compile(r'IN=\w+.*SRC=([\d.]+).*DST=([\d.]+).*PROTO=(\w+).*DPT=(\d+)'),
    'connection_refused': re.compile(r'Connection.*refused.*from\s+([\d.]+):(\d+)'),
    'port_scan': re.compile(r'SRC=([\d.]+).*DPT=(\d+).*'),
    'syn_flood': re.compile(r'SYN.*flood.*from\s+([\d.]+)'),
    'icmp_scan': re.compile(r'ICMP.*from\s+([\d.]+)')
}

# Common scan ports for categorization
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC'
}

# Whitelist configuration
WHITELISTED_IPS = {
    #'10.5.254.66',
    '10.16.254.4',
    '127.0.0.1'    # Example internal scanner
}

DEBUG_MODE = os.getenv('DEBUG_NMAP_AIO', '0') == '1'

class ThreatIntelligence:
    """Enhanced threat intelligence and analysis"""

    def __init__(self):
        self.ip_cache = {}
        self.reputation_cache = {}

    def analyze_ip(self, ip):
        """Analyze IP for geolocation and reputation"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        info = {
            'is_internal': self._is_internal_ip(ip),
            'reverse_dns': self._get_reverse_dns(ip),
            'geolocation': self._get_geolocation(ip),
            'reputation': self._check_reputation(ip)
        }

        self.ip_cache[ip] = info
        return info

    def _is_internal_ip(self, ip):
        """Check if IP is internal"""
        internal_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('192.168.1.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]

        try:
            ip_addr = int(''.join([f'{int(i):02x}' for i in ip.split('.')]), 16)
            for start, end in internal_ranges:
                start_addr = int(''.join([f'{int(i):02x}' for i in start.split('.')]), 16)
                end_addr = int(''.join([f'{int(i):02x}' for i in end.split('.')]), 16)
                if start_addr <= ip_addr <= end_addr:
                    return True
        except:
            pass
        return False

    def _get_reverse_dns(self, ip):
        """Get reverse DNS for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def _get_geolocation(self, ip):
        """Get basic geolocation info"""
        if self._is_internal_ip(ip):
            return {'country': 'Internal', 'city': 'Local Network', 'isp': 'N/A'}

        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown')
                }
        except:
            pass
        return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

    def _check_reputation(self, ip):
        """Simple reputation check based on common patterns"""
        if ip in self.reputation_cache:
            return self.reputation_cache[ip]

        reputation = 'unknown'
        score = 0

        if self._is_internal_ip(ip):
            reputation = 'internal'
            score = 0
        else:
            reputation = 'external'
            score = 5

        result = {'reputation': reputation, 'score': score}
        self.reputation_cache[ip] = result
        return result

class AdvancedScanDetector:
    """Advanced scan detection with multiple heuristics"""

    def __init__(self):
        self.scan_state = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'ports': set(),
            'protocols': set(),
            'first_seen': None,
            'last_seen': None,
            'reported': False,  # Flag to track if the final report has been generated
            'initial_alert_sent': False # Flag to log only once when threshold is first met
        })
        self.threat_intel = ThreatIntelligence()
        self.whitelisted_ips = WHITELISTED_IPS

    def process_log_entry(self, message, timestamp=None):
        """Process a single log entry and update state. Does not generate a report directly."""
        if timestamp is None:
            timestamp = time.time()

        detection = self._parse_log_message(message)
        if not detection:
            return

        src_ip = detection['src_ip']

        # Skip processing if IP is whitelisted
        if src_ip in self.whitelisted_ips:
            if DEBUG_MODE:
                logging.debug(f"Skipping whitelisted IP: {src_ip}")
            return

        self._update_scan_state(src_ip, detection, timestamp)

        state = self.scan_state[src_ip]
        # Log an initial info message when a scan is first suspected, but don't generate the full report.
        if len(state['packets']) >= SCAN_THRESHOLD and not state['initial_alert_sent']:
            logging.info(f"Potential scan detected from {src_ip}. Monitoring activity...")
            state['initial_alert_sent'] = True

    def _parse_log_message(self, message):
        """Parse log message to extract scan information"""
        for pattern_name, pattern in SCAN_PATTERNS.items():
            match = pattern.search(message)
            if match:
                if pattern_name == 'kernel_dropped':
                    return {
                        'src_ip': match.group(1),
                        'dst_ip': match.group(2),
                        'protocol': match.group(3),
                        'dst_port': int(match.group(4)),
                        'scan_type': 'port_scan'
                    }
                elif pattern_name == 'connection_refused':
                    return {
                        'src_ip': match.group(1),
                        'dst_port': int(match.group(2)),
                        'protocol': 'TCP',
                        'scan_type': 'connect_scan'
                    }
                elif pattern_name == 'syn_flood':
                    return {
                        'src_ip': match.group(1),
                        'scan_type': 'syn_flood'
                    }
        return None

    def _update_scan_state(self, ip, detection, timestamp):
        """Update scan state for an IP"""
        state = self.scan_state[ip]

        if state['first_seen'] is None:
            state['first_seen'] = timestamp
        state['last_seen'] = timestamp

        state['packets'].append({
            'timestamp': timestamp,
            'port': detection.get('dst_port'),
            'protocol': detection.get('protocol', 'unknown')
        })

        if 'dst_port' in detection:
            state['ports'].add(detection['dst_port'])
        if 'protocol' in detection:
            state['protocols'].add(detection['protocol'])

    def _analyze_scan_behavior(self, ip):
        """Analyze scan behavior and classify threat level"""
        state = self.scan_state[ip]

        if len(state['packets']) < SCAN_THRESHOLD:
            return None

        duration = state['last_seen'] - state['first_seen']
        packet_count = len(state['packets'])
        unique_ports = len(state['ports'])

        scan_analysis = self._classify_scan(packet_count, unique_ports, duration)
        threat_info = self.threat_intel.analyze_ip(ip)

        return self._generate_detection_report(ip, state, scan_analysis, threat_info)

    def _classify_scan(self, packet_count, unique_ports, duration):
        """Classify the type and severity of scan"""
        scan_type = 'unknown'
        severity = 'low'
        confidence = 50

        if unique_ports > 100:
            scan_type = 'comprehensive_port_scan'
            severity = 'critical'
            confidence = 95
        elif unique_ports > 20:
            scan_type = 'aggressive_port_scan'
            severity = 'high'
            confidence = 90
        elif unique_ports > 5:
            scan_type = 'targeted_port_scan'
            severity = 'medium'
            confidence = 80
        else:
            scan_type = 'limited_port_scan'
            severity = 'low'
            confidence = 60

        if duration > 0:
            scan_rate = packet_count / duration
            if scan_rate > 10:
                scan_type += '_aggressive'
                severity = 'high' if severity == 'medium' else severity
                confidence = min(confidence + 10, 100)
            elif scan_rate < 0.1:
                scan_type += '_stealth'
                confidence = min(confidence + 15, 100)

        return {
            'type': scan_type,
            'severity': severity,
            'confidence': confidence,
            'packet_rate': packet_count / max(duration, 1),
            'duration': duration
        }

    def _generate_detection_report(self, ip, state, scan_analysis, threat_info):
        """Generate comprehensive detection report"""
        common_ports_hit = [port for port in state['ports'] if port in COMMON_PORTS]

        report = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'detection_id': hashlib.md5(f"{ip}_{state['first_seen']}".encode()).hexdigest()[:16],
            'event_type': 'port_scan_detected',
            'source_ip': ip,
            'scan_details': {
                'start_time': datetime.fromtimestamp(state['first_seen']).isoformat(),
                'end_time': datetime.fromtimestamp(state['last_seen']).isoformat(),
                'duration_seconds': int(state['last_seen'] - state['first_seen']),
                'total_packets': len(state['packets']),
                'unique_ports_scanned': len(state['ports']),
                'protocols_used': list(state['protocols']),
                'scan_type': scan_analysis['type'],
                'severity': scan_analysis['severity'],
                'confidence': scan_analysis['confidence'],
                'packet_rate_per_second': round(scan_analysis['packet_rate'], 2)
            },
            'target_analysis': {
                'ports_targeted': sorted(list(state['ports']))[:50],
                'common_services_targeted': [
                    {'port': port, 'service': COMMON_PORTS[port]}
                    for port in common_ports_hit
                ],
                'port_range_analysis': self._analyze_port_ranges(state['ports'])
            },
            'threat_intelligence': threat_info,
            'risk_assessment': self._calculate_risk_score(scan_analysis, threat_info, len(common_ports_hit)),
            'recommendations': self._generate_recommendations(ip, scan_analysis, threat_info)
        }

        return report

    def _analyze_port_ranges(self, ports):
        """Analyze port ranges to identify scan patterns"""
        if not ports:
            return {'pattern': 'none', 'ranges': []}

        sorted_ports = sorted(ports)
        ranges = []
        if not sorted_ports: return {'pattern': 'none', 'ranges': []}

        current_range = [sorted_ports[0]]
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] - sorted_ports[i-1] <= 5:
                current_range.append(sorted_ports[i])
            else:
                if len(current_range) > 1:
                    ranges.append({'start': current_range[0], 'end': current_range[-1], 'count': len(current_range)})
                current_range = [sorted_ports[i]]

        if len(current_range) > 1:
            ranges.append({'start': current_range[0], 'end': current_range[-1], 'count': len(current_range)})

        pattern = 'random'
        if len(ranges) > 0:
            if any(r['end'] - r['start'] > 100 for r in ranges):
                pattern = 'sequential_sweep'
            elif len(ranges) > 3:
                pattern = 'multiple_ranges'
            else:
                pattern = 'targeted_ranges'

        return {'pattern': pattern, 'ranges': ranges}

    def _calculate_risk_score(self, scan_analysis, threat_info, common_ports_count):
        """Calculate overall risk score"""
        base_score = 0
        severity_scores = {'low': 20, 'medium': 50, 'high': 75, 'critical': 95}
        base_score += severity_scores.get(scan_analysis['severity'], 20)
        base_score *= (scan_analysis['confidence'] / 100)
        if not threat_info['is_internal']:
            base_score += 20
        base_score += min(common_ports_count * 5, 25)
        rep_score = threat_info.get('reputation', {}).get('score', 0)
        if rep_score > 50:
            base_score += 30

        final_score = min(int(base_score), 100)
        level = 'critical' if final_score >= 80 else 'high' if final_score >= 60 else 'medium' if final_score >= 40 else 'low'
        return {'score': final_score, 'level': level}

    def _generate_recommendations(self, ip, scan_analysis, threat_info):
        """Generate actionable recommendations"""
        recommendations = []
        if scan_analysis['severity'] in ['high', 'critical']:
            recommendations.append(f"IMMEDIATE: Block source IP {ip} in firewall.")
            recommendations.append("IMMEDIATE: Review security logs for potential breaches originating from this IP.")
        if not threat_info['is_internal']:
            recommendations.append("Consider blocking the IP range if activity persists from the same network.")
            recommendations.append("Enable or tighten rate limiting for external connections.")
        if scan_analysis['confidence'] > 80:
            recommendations.append("High confidence detection warrants immediate investigation.")
            recommendations.append("Review network segmentation and access controls for targeted services.")

        reverse_dns = threat_info.get('reverse_dns') or 'N/A'
        recommendations.append(f"Monitor IP {ip} (reverse DNS: {reverse_dns}) for further activity.")
        recommendations.append("Ensure intrusion detection/prevention system signatures are up to date.")

        return recommendations

    def report_and_cleanup_inactive_scans(self):
        """
        Identify inactive scans, generate their final reports, and clean them up.
        """
        current_time = time.time()
        inactivity_timeout = current_time - TIME_WINDOW

        scans_to_remove = []

        for ip, state in list(self.scan_state.items()):
            # Skip whitelisted IPs
            if ip in self.whitelisted_ips:
                scans_to_remove.append(ip)
                continue

            is_inactive = state['last_seen'] < inactivity_timeout

            if DEBUG_MODE and not is_inactive:
                logging.debug(f"IP {ip} is still active. Last seen: {state['last_seen']:.2f} ({(current_time - state['last_seen']):.2f}s ago).")

            if is_inactive:
                # Se la scansione è inattiva, decidiamo se segnalarla o semplicemente pulirla.
                if len(state['packets']) >= SCAN_THRESHOLD and not state['reported']:
                    logging.info(f"Scan from {ip} concluded (inactive for >{TIME_WINDOW}s). Generating final report.")

                    final_report = self._analyze_scan_behavior(ip)
                    if final_report:
                        # <<< AGGIUNTO LOG DI DEBUG
                        logging.debug(f"Final report for {ip} generated. Calling write_detection_report.")
                        write_detection_report(final_report)
                    else:
                        # <<< AGGIUNTO LOG DI DEBUG
                        logging.warning(f"Scan from {ip} was marked for reporting, but _analyze_scan_behavior returned None.")

                    state['reported'] = True # Mark as reported to prevent duplicates

                # Aggiungi l'IP alla lista di pulizia perché è comunque inattivo
                scans_to_remove.append(ip)
                if DEBUG_MODE:
                    logging.debug(f"Marking IP {ip} for cleanup due to inactivity.")

        # Rimuovi tutti gli stati inattivi dalla memoria
        if scans_to_remove:
            for ip in scans_to_remove:
                if ip in self.scan_state:
                    del self.scan_state[ip]

            logging.info(f"Cleaned up {len(scans_to_remove)} inactive scan entries.")

class JournalMonitor:
    """Enhanced journal monitoring with better error handling"""

    def __init__(self):
        self.process = None
        self.restart_count = 0
        self.max_restarts = 10

    def start(self):
        """Start journal monitoring"""
        cmd = [
            'journalctl', '-f', '-k', '--since', 'now', '-o', 'json',
            'SYSLOG_IDENTIFIER=kernel'
        ]

        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, universal_newlines=True
            )
            logging.info("Journal monitor started successfully")
        except Exception as e:
            logging.error(f"Failed to start journal monitor: {e}")
            raise

    def get_entries(self):
        """Get new journal entries"""
        if not self.process:
            return []

        entries = []
        try:
            line = self.process.stdout.readline()
            if line:
                try:
                    entry = json.loads(line.strip())
                    message = entry.get('MESSAGE', '')
                    if any(keyword in message.lower() for keyword in ['drop', 'refuse', 'scan', 'flood', 'dpt=', 'spt=']):
                        entries.append(message)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logging.error(f"Error reading journal: {e}")
            self._handle_restart()

        return entries

    def _handle_restart(self):
        """Handle process restart"""
        if self.restart_count < self.max_restarts:
            logging.warning("Restarting journal monitor")
            self.stop()
            time.sleep(2)
            self.start()
            self.restart_count += 1
        else:
            logging.critical("Max restarts exceeded, giving up")
            raise Exception("Journal monitor failed permanently")

    def stop(self):
        """Stop journal monitoring"""
        if self.process:
            self.process.terminate()
            self.process = None

def setup_logging():
    """Setup comprehensive logging"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    log_level = logging.DEBUG if DEBUG_MODE else logging.INFO
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

def write_detection_report(report):
    """Write detection report to JSON file in compact single-line format"""
    try:
        os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)

        lock_file = f"{REPORT_FILE}.lock"
        with FileLock(lock_file, timeout=10):
            with open(REPORT_FILE, 'a') as f:
                json.dump(report, f, separators=(',', ':'))
                f.write('\n')

        logging.info(f"Detection report written: {report['detection_id']} - IP: {report['source_ip']} - Risk: {report['risk_assessment']['level']}")

    except Exception as e:
        logging.error(f"Failed to write detection report: {e}")

def main_daemon_loop():
    """Main daemon execution loop"""
    logging.info(f"Starting Nmap AIO Detector daemon (PID: {os.getpid()})")

    detector = AdvancedScanDetector()
    monitor = JournalMonitor()

    def signal_handler(signum, frame):
        logging.info("Shutdown signal received, cleaning up...")
        monitor.stop()
        logging.info("Daemon shut down cleanly")
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        monitor.start()
        last_cleanup = time.time()

        logging.info("Daemon started successfully, monitoring for scan activity...")

        while True:
            try:
                # Process new log entries to update scan states
                entries = monitor.get_entries()
                for message in entries:
                    if DEBUG_MODE:
                        logging.debug(f"Processing: {message[:100]}...")
                    detector.process_log_entry(message)

                # Periodically check for inactive scans to report and clean up
                current_time = time.time()
                if current_time - last_cleanup > CLEANUP_INTERVAL:
                    detector.report_and_cleanup_inactive_scans()
                    last_cleanup = current_time

                time.sleep(0.1)  # Prevent high CPU usage

            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(5)

    except Exception as e:
        logging.critical(f"Fatal error in daemon: {e}", exc_info=True)
        sys.exit(1)
    finally:
        monitor.stop()

def auto_start_daemon():
    """Automatically start as daemon if not already running"""
    pidfile = TimeoutPIDLockFile(PID_FILE, 5)

    if pidfile.is_locked():
        pid = pidfile.read_pid()
        print(f"Daemon already running (PID: {pid})")
        return False

    if os.geteuid() != 0:
        print("ERROR: Root privileges are required to monitor system logs.")
        return False

    print("Starting Nmap AIO Detector daemon...")
    setup_logging()

    context = DaemonContext(
        working_directory='/',
        umask=0o022,
        pidfile=pidfile,
        files_preserve=[handler.stream for handler in logging.getLogger().handlers if hasattr(handler, 'stream')],
        signal_map={
            signal.SIGTERM: 'terminate',
            signal.SIGHUP: 'terminate',
        }
    )

    try:
        with context:
            main_daemon_loop()
    except Exception as e:
        logging.critical(f"Failed to start daemon: {e}")
        return False

    return True

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Nmap AIO Scan Detector - Automatic threat detection and analysis"""
    if ctx.invoked_subcommand is None:
        auto_start_daemon()

@cli.command()
def start():
    """Start the detector daemon"""
    auto_start_daemon()

@cli.command()
def stop():
    """Stop the detector daemon"""
    pidfile = TimeoutPIDLockFile(PID_FILE, 5)
    if not pidfile.is_locked():
        print("Daemon not running")
        return

    pid = pidfile.read_pid()
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1) # Give it a moment to shut down
        if pidfile.is_locked():
            os.kill(pid, signal.SIGKILL)
        print(f"Daemon stopped (PID: {pid})")
    except OSError as e:
        print(f"Error stopping daemon: {e}. It may have already stopped.")
        # Clean up stale PID file if process doesn't exist
        if 'No such process' in str(e):
            try:
                os.remove(PID_FILE)
                print("Removed stale PID file.")
            except OSError:
                pass


@cli.command()
def status():
    """Show daemon status and recent detections"""
    pidfile = TimeoutPIDLockFile(PID_FILE, 5)

    if pidfile.is_locked():
        pid = pidfile.read_pid()
        print(f"✓ Daemon is running (PID: {pid})")

        try:
            if os.path.exists(REPORT_FILE):
                with open(REPORT_FILE, 'r') as f:
                    # Read last 5 lines, which are compact JSON objects
                    detections = [json.loads(line) for line in deque(f, 5)]

                print(f"\nLast {len(detections)} Detections:")
                if not detections:
                    print("  No detections recorded yet.")
                for detection in reversed(detections): # Show newest first
                    timestamp = datetime.fromisoformat(detection['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                    source = detection['source_ip']
                    risk = detection['risk_assessment']['level']
                    scan_type = detection['scan_details']['scan_type']
                    ports = detection['scan_details']['unique_ports_scanned']
                    print(f"  - {timestamp} | Risk: {risk.upper():<8} | IP: {source:<15} | Type: {scan_type} ({ports} ports)")
            else:
                print("\nNo detection report file found. No scans detected yet.")

        except Exception as e:
            print(f"Could not read detection report: {e}")
    else:
        print("✗ Daemon is not running")

@cli.command()
@click.option('--lines', '-n', default=50, help='Number of lines to show')
def logs(lines):
    """Show recent log entries from the daemon log file"""
    try:
        with open(LOG_FILE, 'r') as f:
            log_lines = deque(f, lines)
            if not log_lines:
                print(f"Log file '{LOG_FILE}' is empty.")
                return
            for line in log_lines:
                print(line.strip())
    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
    except Exception as e:
        print(f"Error reading log file: {e}")

if __name__ == '__main__':
    cli()
