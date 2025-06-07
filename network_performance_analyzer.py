#!/usr/bin/env python3
"""
Network Performance Analyzer
Measures latency, bandwidth, packet loss and network conditions
"""

import subprocess
import time
import threading
import socket
import struct
import json
import statistics
from datetime import datetime
import matplotlib.pyplot as plt
from scapy.all import *

class NetworkPerformanceAnalyzer:
    """Analyzes network performance metrics"""
    
    def __init__(self):
        self.results = {
            'latency_tests': [],
            'bandwidth_tests': [],
            'packet_loss_tests': [],
            'conditions': []
        }
        
    def measure_latency(self, target_host, count=10):
        """Measure network latency using ping"""
        print(f"[+] Measuring latency to {target_host}...")
        
        latencies = []
        
        for i in range(count):
            try:
                # Send ping using subprocess
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['ping', '-n', '1', target_host], 
                                          capture_output=True, text=True)
                    output = result.stdout
                    
                    # Parse ping result
                    if 'time=' in output:
                        time_str = output.split('time=')[1].split('ms')[0]
                        latency = float(time_str)
                        latencies.append(latency)
                        print(f"  Ping {i+1}: {latency} ms")
                else:  # Linux/Mac
                    result = subprocess.run(['ping', '-c', '1', target_host], 
                                          capture_output=True, text=True)
                    output = result.stdout
                    
                    if 'time=' in output:
                        time_str = output.split('time=')[1].split(' ms')[0]
                        latency = float(time_str)
                        latencies.append(latency)
                        print(f"  Ping {i+1}: {latency} ms")
                        
            except Exception as e:
                print(f"  Ping {i+1}: Failed - {str(e)}")
            
            time.sleep(0.1)
        
        if latencies:
            avg_latency = statistics.mean(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            jitter = statistics.stdev(latencies) if len(latencies) > 1 else 0
            
            result = {
                'target': target_host,
                'timestamp': datetime.now().isoformat(),
                'average_latency': avg_latency,
                'min_latency': min_latency,
                'max_latency': max_latency,
                'jitter': jitter,
                'packet_count': len(latencies),
                'success_rate': len(latencies) / count * 100
            }
            
            self.results['latency_tests'].append(result)
            
            print(f"[+] Latency Results for {target_host}:")
            print(f"    Average: {avg_latency:.2f} ms")
            print(f"    Min: {min_latency:.2f} ms")
            print(f"    Max: {max_latency:.2f} ms")
            print(f"    Jitter: {jitter:.2f} ms")
            print(f"    Success Rate: {result['success_rate']:.1f}%")
            
            return result
        else:
            print(f"[-] No successful pings to {target_host}")
            return None
    
    def measure_bandwidth_simple(self, target_host, port=8889, data_size=1024*1024):
        """Simple bandwidth measurement by sending data"""
        print(f"[+] Measuring bandwidth to {target_host}:{port}...")
        
        try:
            # Create test data
            test_data = b'A' * data_size
            
            # Connect and send data
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_host, port))
            
            connect_time = time.time()
            sock.send(test_data)
            send_time = time.time()
            
            response = sock.recv(1024)
            end_time = time.time()
            
            sock.close()
            
            # Calculate metrics
            total_time = end_time - start_time
            send_duration = send_time - connect_time
            bandwidth_mbps = (data_size * 8) / (send_duration * 1024 * 1024)
            
            result = {
                'target': f"{target_host}:{port}",
                'timestamp': datetime.now().isoformat(),
                'data_size_bytes': data_size,
                'total_time_seconds': total_time,
                'send_time_seconds': send_duration,
                'bandwidth_mbps': bandwidth_mbps,
                'throughput_kbps': (data_size / send_duration) / 1024
            }
            
            self.results['bandwidth_tests'].append(result)
            
            print(f"[+] Bandwidth Results:")
            print(f"    Data Size: {data_size / 1024:.1f} KB")
            print(f"    Send Time: {send_duration:.3f} seconds")
            print(f"    Bandwidth: {bandwidth_mbps:.2f} Mbps")
            print(f"    Throughput: {result['throughput_kbps']:.2f} KB/s")
            
            return result
            
        except Exception as e:
            print(f"[-] Bandwidth test failed: {str(e)}")
            return None
    
    def simulate_packet_loss(self, target_host, loss_rate=0.1, count=50):
        """Simulate and measure packet loss"""
        print(f"[+] Simulating packet loss to {target_host} (rate: {loss_rate*100}%)...")
        
        sent_packets = 0
        received_packets = 0
        lost_packets = []
        
        for i in range(count):
            try:
                # Simulate random packet loss
                if random.random() < loss_rate:
                    lost_packets.append(i)
                    sent_packets += 1
                    continue
                
                # Send actual ping
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', target_host], 
                                          capture_output=True, text=True)
                else:  # Linux/Mac
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', target_host], 
                                          capture_output=True, text=True)
                
                sent_packets += 1
                
                if result.returncode == 0:
                    received_packets += 1
                else:
                    lost_packets.append(i)
                    
            except Exception as e:
                sent_packets += 1
                lost_packets.append(i)
        
        actual_loss_rate = len(lost_packets) / sent_packets if sent_packets > 0 else 0
        
        result = {
            'target': target_host,
            'timestamp': datetime.now().isoformat(),
            'expected_loss_rate': loss_rate,
            'actual_loss_rate': actual_loss_rate,
            'sent_packets': sent_packets,
            'received_packets': received_packets,
            'lost_packets': len(lost_packets),
            'lost_packet_ids': lost_packets
        }
        
        self.results['packet_loss_tests'].append(result)
        
        print(f"[+] Packet Loss Results:")
        print(f"    Sent: {sent_packets} packets")
        print(f"    Received: {received_packets} packets")
        print(f"    Lost: {len(lost_packets)} packets")
        print(f"    Loss Rate: {actual_loss_rate*100:.1f}%")
        
        return result
    
    def analyze_network_conditions(self):
        """Analyze different network conditions"""
        print("[+] Analyzing network conditions...")
        
        conditions = ['localhost', '8.8.8.8', '1.1.1.1']  # Local, Google DNS, Cloudflare DNS
        
        for condition in conditions:
            print(f"\n[+] Testing condition: {condition}")
            
            latency_result = self.measure_latency(condition, count=5)
            
            condition_data = {
                'condition': condition,
                'timestamp': datetime.now().isoformat(),
                'latency_result': latency_result
            }
            
            self.results['conditions'].append(condition_data)
    
    def generate_performance_report(self, output_file='network_performance_report.json'):
        """Generate comprehensive performance report"""
        print(f"[+] Generating performance report: {output_file}")
        
        # Add summary statistics
        summary = {
            'test_count': {
                'latency_tests': len(self.results['latency_tests']),
                'bandwidth_tests': len(self.results['bandwidth_tests']),
                'packet_loss_tests': len(self.results['packet_loss_tests']),
                'condition_tests': len(self.results['conditions'])
            },
            'generated_at': datetime.now().isoformat()
        }
        
        report = {
            'summary': summary,
            'results': self.results
        }
        
        # Save to JSON file
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved successfully")
        return report
    
    def plot_latency_results(self):
        """Plot latency test results"""
        if not self.results['latency_tests']:
            print("[-] No latency test results to plot")
            return
        
        targets = []
        avg_latencies = []
        jitters = []
        
        for test in self.results['latency_tests']:
            targets.append(test['target'])
            avg_latencies.append(test['average_latency'])
            jitters.append(test['jitter'])
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
        
        # Average latency plot
        ax1.bar(targets, avg_latencies, color='skyblue', alpha=0.7)
        ax1.set_ylabel('Average Latency (ms)')
        ax1.set_title('Network Latency by Target')
        ax1.tick_params(axis='x', rotation=45)
        
        # Jitter plot
        ax2.bar(targets, jitters, color='lightcoral', alpha=0.7)
        ax2.set_ylabel('Jitter (ms)')
        ax2.set_xlabel('Target Host')
        ax2.set_title('Network Jitter by Target')
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('network_latency_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("[+] Latency analysis plot saved as 'network_latency_analysis.png'")

class TrafficControlSimulator:
    """Simulate network conditions using traffic control"""
    
    def __init__(self):
        self.active_rules = []
    
    def simulate_latency(self, interface='eth0', delay='100ms'):
        """Add artificial latency to network interface"""
        if os.name != 'nt':  # Linux only
            try:
                cmd = f"tc qdisc add dev {interface} root netem delay {delay}"
                subprocess.run(cmd.split(), check=True)
                self.active_rules.append(('latency', interface, delay))
                print(f"[+] Added {delay} latency to {interface}")
            except Exception as e:
                print(f"[-] Failed to add latency: {str(e)}")
        else:
            print("[-] Traffic control simulation not available on Windows")
    
    def simulate_packet_loss(self, interface='eth0', loss_rate='5%'):
        """Add packet loss to network interface"""
        if os.name != 'nt':  # Linux only
            try:
                cmd = f"tc qdisc add dev {interface} root netem loss {loss_rate}"
                subprocess.run(cmd.split(), check=True)
                self.active_rules.append(('loss', interface, loss_rate))
                print(f"[+] Added {loss_rate} packet loss to {interface}")
            except Exception as e:
                print(f"[-] Failed to add packet loss: {str(e)}")
        else:
            print("[-] Traffic control simulation not available on Windows")
    
    def clear_rules(self, interface='eth0'):
        """Clear all traffic control rules"""
        if os.name != 'nt':  # Linux only
            try:
                cmd = f"tc qdisc del dev {interface} root"
                subprocess.run(cmd.split(), check=True)
                self.active_rules = []
                print(f"[+] Cleared traffic control rules for {interface}")
            except Exception as e:
                print(f"[-] Failed to clear rules: {str(e)}")

def run_performance_tests():
    """Run comprehensive network performance tests"""
    analyzer = NetworkPerformanceAnalyzer()
    
    print("=" * 60)
    print("NETWORK PERFORMANCE ANALYSIS")
    print("=" * 60)
    
    # Test different targets
    test_targets = ['127.0.0.1', '8.8.8.8', '1.1.1.1']
    
    for target in test_targets:
        print(f"\n{'='*40}")
        print(f"Testing target: {target}")
        print(f"{'='*40}")
        
        # Latency test
        analyzer.measure_latency(target, count=10)
        
        # Packet loss simulation
        analyzer.simulate_packet_loss(target, loss_rate=0.05, count=20)
        
        time.sleep(1)
    
    # Generate report
    analyzer.generate_performance_report()
    
    # Plot results
    try:
        analyzer.plot_latency_results()
    except Exception as e:
        print(f"[-] Could not generate plots: {str(e)}")
    
    return analyzer

if __name__ == "__main__":
    import random
    import os
    
    run_performance_tests() 