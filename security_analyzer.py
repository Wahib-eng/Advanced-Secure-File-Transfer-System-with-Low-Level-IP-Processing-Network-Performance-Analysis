#!/usr/bin/env python3
"""
Security Analyzer and Attack Simulation Module
Implements packet capture, analysis, and MITM attack simulation
"""

import threading
import time
import json
import hashlib
from datetime import datetime
from scapy.all import *
import socket
import ssl
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SecurityAnalyzer:
    """Security analysis and attack simulation"""
    
    def __init__(self):
        self.captured_packets = []
        self.analysis_results = {}
        self.is_capturing = False
        
    def start_packet_capture(self, interface=None, filter_expr="", duration=30):
        """Start packet capture for analysis"""
        print(f"[+] Starting packet capture for {duration} seconds...")
        print(f"    Interface: {interface or 'default'}")
        print(f"    Filter: {filter_expr or 'none'}")
        
        self.is_capturing = True
        self.captured_packets = []
        
        def capture_packets():
            try:
                packets = sniff(
                    iface=interface,
                    filter=filter_expr,
                    timeout=duration,
                    stop_filter=lambda x: not self.is_capturing
                )
                self.captured_packets.extend(packets)
                print(f"[+] Captured {len(packets)} packets")
            except Exception as e:
                print(f"[-] Packet capture error: {str(e)}")
        
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        return capture_thread
    
    def stop_packet_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        print("[+] Stopping packet capture...")
    
    def analyze_captured_packets(self):
        """Analyze captured packets for security insights"""
        if not self.captured_packets:
            print("[-] No packets to analyze")
            return
        
        print(f"[+] Analyzing {len(self.captured_packets)} captured packets...")
        
        analysis = {
            'total_packets': len(self.captured_packets),
            'protocols': {},
            'encrypted_traffic': 0,
            'unencrypted_traffic': 0,
            'suspicious_activity': [],
            'file_transfer_detected': [],
            'timestamp': datetime.now().isoformat()
        }
        
        for packet in self.captured_packets:
            try:
                # Protocol analysis
                if packet.haslayer(IP):
                    proto = "IP"
                    if packet.haslayer(TCP):
                        proto = "TCP"
                    elif packet.haslayer(UDP):
                        proto = "UDP"
                    elif packet.haslayer(ICMP):
                        proto = "ICMP"
                    
                    analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1
                
                # Detect encrypted vs unencrypted traffic
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw])
                    if self.is_likely_encrypted(payload):
                        analysis['encrypted_traffic'] += 1
                    else:
                        analysis['unencrypted_traffic'] += 1
                        
                        # Check for sensitive data in unencrypted traffic
                        payload_str = payload.decode('utf-8', errors='ignore').lower()
                        if any(keyword in payload_str for keyword in ['password', 'secret', 'key', 'token']):
                            analysis['suspicious_activity'].append({
                                'type': 'sensitive_data_unencrypted',
                                'packet_info': f"Src: {packet[IP].src}, Dst: {packet[IP].dst}",
                                'timestamp': time.time()
                            })
                
                # Detect file transfer patterns
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = bytes(packet[Raw])
                    if len(payload) > 1000:  # Large payload might be file transfer
                        analysis['file_transfer_detected'].append({
                            'src': packet[IP].src,
                            'dst': packet[IP].dst,
                            'port': packet[TCP].dport,
                            'size': len(payload),
                            'timestamp': time.time()
                        })
                        
            except Exception as e:
                continue
        
        self.analysis_results = analysis
        
        print(f"[+] Packet Analysis Results:")
        print(f"    Total Packets: {analysis['total_packets']}")
        print(f"    Protocol Distribution: {analysis['protocols']}")
        print(f"    Encrypted Traffic: {analysis['encrypted_traffic']}")
        print(f"    Unencrypted Traffic: {analysis['unencrypted_traffic']}")
        print(f"    Suspicious Activities: {len(analysis['suspicious_activity'])}")
        print(f"    File Transfers Detected: {len(analysis['file_transfer_detected'])}")
        
        return analysis
    
    def is_likely_encrypted(self, data):
        """Heuristic to determine if data is likely encrypted"""
        if len(data) < 16:
            return False
        
        # Check entropy (randomness)
        byte_freq = [0] * 256
        for byte in data:
            byte_freq[byte] += 1
        
        # Calculate entropy
        entropy = 0
        for freq in byte_freq:
            if freq > 0:
                p = freq / len(data)
                entropy -= p * math.log2(p)
        
        # High entropy suggests encryption (threshold: 7.5)
        return entropy > 7.5
    
    def simulate_mitm_attack(self, target_ip, target_port=80):
        """Simulate Man-in-the-Middle attack"""
        print(f"[+] Simulating MITM attack on {target_ip}:{target_port}")
        
        mitm_results = {
            'target': f"{target_ip}:{target_port}",
            'timestamp': datetime.now().isoformat(),
            'intercepted_data': [],
            'attack_success': False,
            'encryption_detected': False
        }
        
        try:
            # Create a socket to intercept traffic
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.bind(('localhost', 8080))  # Proxy port
            proxy_socket.listen(1)
            
            print("[+] MITM proxy listening on localhost:8080")
            print("[!] In a real scenario, this would require ARP spoofing")
            
            # Simulate connection interception
            def handle_mitm_connection():
                try:
                    client_socket, addr = proxy_socket.accept()
                    print(f"[+] Intercepted connection from {addr}")
                    
                    # Read initial data from client
                    data = client_socket.recv(4096)
                    if data:
                        mitm_results['intercepted_data'].append({
                            'direction': 'client_to_server',
                            'size': len(data),
                            'encrypted': self.is_likely_encrypted(data),
                            'timestamp': time.time()
                        })
                        
                        if self.is_likely_encrypted(data):
                            mitm_results['encryption_detected'] = True
                            print("[+] Encrypted data detected - MITM attack mitigated by encryption")
                        else:
                            print("[!] Unencrypted data intercepted - potential security risk")
                            # In a real attack, this data could be modified
                    
                    mitm_results['attack_success'] = True
                    client_socket.close()
                    
                except Exception as e:
                    print(f"[-] MITM simulation error: {str(e)}")
            
            # Start MITM handler in background
            mitm_thread = threading.Thread(target=handle_mitm_connection)
            mitm_thread.daemon = True
            mitm_thread.start()
            
            # Wait for connection or timeout
            mitm_thread.join(timeout=10)
            proxy_socket.close()
            
        except Exception as e:
            print(f"[-] MITM simulation failed: {str(e)}")
        
        print(f"[+] MITM Attack Results:")
        print(f"    Target: {mitm_results['target']}")
        print(f"    Attack Success: {mitm_results['attack_success']}")
        print(f"    Encryption Detected: {mitm_results['encryption_detected']}")
        print(f"    Intercepted Packets: {len(mitm_results['intercepted_data'])}")
        
        return mitm_results
    
    def inject_packet(self, src_ip, dst_ip, payload="Test injection"):
        """Simulate packet injection attack"""
        print(f"[+] Simulating packet injection: {src_ip} -> {dst_ip}")
        
        try:
            # Create custom packet
            packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=80) / Raw(load=payload)
            
            # Calculate and verify checksums
            del packet[IP].chksum
            del packet[TCP].chksum
            packet = IP(bytes(packet))  # Recalculate checksums
            
            print(f"[+] Injected packet details:")
            print(f"    Source: {packet[IP].src}")
            print(f"    Destination: {packet[IP].dst}")
            print(f"    Payload: {payload}")
            print(f"    IP Checksum: {packet[IP].chksum}")
            print(f"    TCP Checksum: {packet[TCP].chksum}")
            
            # In a real scenario, this would be sent to the network
            # send(packet)  # Commented out for safety
            
            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'payload': payload,
                'packet_size': len(packet),
                'timestamp': datetime.now().isoformat(),
                'success': True
            }
            
        except Exception as e:
            print(f"[-] Packet injection failed: {str(e)}")
            return None
    
    def test_encryption_strength(self, file_path):
        """Test if encrypted file transfer is secure against analysis"""
        print(f"[+] Testing encryption strength for file: {file_path}")
        
        try:
            # Read file and encrypt it
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            # Encrypt with AES
            key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_CBC)
            encrypted_data = cipher.encrypt(original_data.ljust((len(original_data) + 15) // 16 * 16, b'\x00'))
            
            # Analyze original vs encrypted
            original_entropy = self.calculate_entropy(original_data)
            encrypted_entropy = self.calculate_entropy(encrypted_data)
            
            results = {
                'file': file_path,
                'original_size': len(original_data),
                'encrypted_size': len(encrypted_data),
                'original_entropy': original_entropy,
                'encrypted_entropy': encrypted_entropy,
                'encryption_effective': encrypted_entropy > original_entropy + 1,
                'timestamp': datetime.now().isoformat()
            }
            
            print(f"[+] Encryption Analysis:")
            print(f"    Original Entropy: {original_entropy:.2f}")
            print(f"    Encrypted Entropy: {encrypted_entropy:.2f}")
            print(f"    Encryption Effective: {results['encryption_effective']}")
            
            return results
            
        except Exception as e:
            print(f"[-] Encryption test failed: {str(e)}")
            return None
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)
        
        return entropy
    
    def generate_security_report(self, output_file='security_analysis_report.json'):
        """Generate comprehensive security report"""
        print(f"[+] Generating security report: {output_file}")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'packet_analysis': self.analysis_results,
            'total_captured_packets': len(self.captured_packets),
            'security_recommendations': [
                "Always use encrypted protocols (HTTPS, SFTP, etc.)",
                "Implement certificate pinning to prevent MITM attacks",
                "Monitor network traffic for suspicious patterns",
                "Use strong encryption algorithms (AES-256, RSA-2048+)",
                "Regularly update security protocols and certificates"
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Security report saved successfully")
        return report

class IntrusionDetectionSystem:
    """Simple IDS for detecting suspicious network activity"""
    
    def __init__(self):
        self.alerts = []
        self.monitoring = False
        
    def start_monitoring(self, interface=None, duration=60):
        """Start intrusion detection monitoring"""
        print(f"[+] Starting IDS monitoring for {duration} seconds...")
        
        self.monitoring = True
        
        def monitor_traffic():
            try:
                def process_packet(packet):
                    if not self.monitoring:
                        return
                    
                    # Check for suspicious patterns
                    self.check_port_scan(packet)
                    self.check_dos_attempt(packet)
                    self.check_suspicious_payload(packet)
                
                sniff(iface=interface, prn=process_packet, timeout=duration)
                
            except Exception as e:
                print(f"[-] IDS monitoring error: {str(e)}")
        
        monitor_thread = threading.Thread(target=monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return monitor_thread
    
    def check_port_scan(self, packet):
        """Detect potential port scanning"""
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
            # Simple port scan detection (multiple SYN to different ports)
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            # In a real IDS, this would track connection attempts over time
            if dst_port in [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]:
                self.create_alert("Port Scan Detected", f"SYN scan from {src_ip} to port {dst_port}")
    
    def check_dos_attempt(self, packet):
        """Detect potential DoS attempts"""
        # Simple DoS detection based on packet rate
        # In a real IDS, this would track packets per second from each IP
        pass
    
    def check_suspicious_payload(self, packet):
        """Check for suspicious payload content"""
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore').lower()
            
            suspicious_patterns = [
                'union select', 'drop table', '<script>', 'javascript:',
                'passwd', '/etc/shadow', 'cmd.exe', 'powershell'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in payload:
                    self.create_alert("Suspicious Payload", 
                                    f"Pattern '{pattern}' detected from {packet[IP].src}")
    
    def create_alert(self, alert_type, description):
        """Create security alert"""
        alert = {
            'type': alert_type,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'severity': 'medium'
        }
        
        self.alerts.append(alert)
        print(f"[!] SECURITY ALERT: {alert_type} - {description}")
    
    def stop_monitoring(self):
        """Stop IDS monitoring"""
        self.monitoring = False
        print("[+] IDS monitoring stopped")
    
    def get_alerts(self):
        """Get all security alerts"""
        return self.alerts

def run_security_analysis():
    """Run comprehensive security analysis"""
    analyzer = SecurityAnalyzer()
    ids = IntrusionDetectionSystem()
    
    print("=" * 60)
    print("SECURITY ANALYSIS AND ATTACK SIMULATION")
    print("=" * 60)
    
    # Start packet capture
    capture_thread = analyzer.start_packet_capture(duration=15)
    
    # Start IDS monitoring
    ids_thread = ids.start_monitoring(duration=15)
    
    # Wait for monitoring to complete
    time.sleep(16)
    
    # Analyze captured packets
    analyzer.analyze_captured_packets()
    
    # Simulate MITM attack
    mitm_results = analyzer.simulate_mitm_attack('127.0.0.1', 80)
    
    # Simulate packet injection
    injection_results = analyzer.inject_packet('192.168.1.100', '192.168.1.1')
    
    # Stop monitoring
    ids.stop_monitoring()
    
    # Generate security report
    analyzer.generate_security_report()
    
    # Display IDS alerts
    alerts = ids.get_alerts()
    print(f"\n[+] IDS Alerts: {len(alerts)}")
    for alert in alerts:
        print(f"    {alert['timestamp']}: {alert['type']} - {alert['description']}")
    
    return analyzer, ids

if __name__ == "__main__":
    import math
    
    run_security_analysis() 