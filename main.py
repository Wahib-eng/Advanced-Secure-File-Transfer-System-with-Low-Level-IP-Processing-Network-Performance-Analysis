#!/usr/bin/env python3
"""
Main Coordinator Script for Advanced Secure File Transfer System
Bilgisayar Ağları Dönem Projesi

This script coordinates all modules of the secure file transfer system
including encryption, network analysis, and security testing.
"""

import os
import sys
import argparse
import time
from datetime import datetime

def print_banner():
    """Print project banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                Advanced Secure File Transfer System                          ║
║                    Bilgisayar Ağları Dönem Projesi                          ║
║                                                                              ║
║  ✓ AES/RSA Encryption & Authentication                                      ║
║  ✓ Low-Level IP Header Processing                                           ║
║  ✓ Network Performance Analysis                                             ║
║  ✓ Security Analysis & Attack Simulation                                    ║
║  ✓ Graphical User Interface                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = {
        'scapy': 'scapy',
        'pycryptodome': 'Crypto',
        'matplotlib': 'matplotlib',
        'tkinter': 'tkinter'
    }
    
    missing_packages = []
    
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"✓ {package_name} - OK")
        except ImportError:
            print(f"✗ {package_name} - Missing")
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"\n[-] Missing packages: {', '.join(missing_packages)}")
        print("    Please install them using: pip install " + " ".join(missing_packages))
        return False
    
    print("[+] All dependencies satisfied!")
    return True

def create_test_files():
    """Create test files for demonstration"""
    test_files = [
        ('test_document.txt', 'This is a test document for secure file transfer.\n' * 50),
        ('test_config.json', '{"server": "localhost", "port": 8888, "encryption": "AES-256"}')
    ]
    
    print("[+] Creating test files...")
    for filename, content in test_files:
        if not os.path.exists(filename):
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"    Created: {filename}")
        else:
            print(f"    Exists: {filename}")
    
    # Create binary test file separately
    if not os.path.exists('test_image.bin'):
        with open('test_image.bin', 'wb') as f:
            # Create a simple binary file
            f.write(b'PNG\x89' + b'A' * 1000)
        print(f"    Created: test_image.bin")
    else:
        print(f"    Exists: test_image.bin")

def run_gui_mode():
    """Run GUI application"""
    print("[+] Starting GUI application...")
    try:
        from gui_application import main
        main()
    except ImportError as e:
        print(f"[-] Failed to import GUI module: {e}")
    except Exception as e:
        print(f"[-] GUI error: {e}")

def run_server_mode(host='localhost', port=8888):
    """Run server mode"""
    print(f"[+] Starting server on {host}:{port}...")
    try:
        from secure_file_transfer import FileTransferServer
        server = FileTransferServer(host, port)
        server.start_server()
    except KeyboardInterrupt:
        print("\n[+] Server stopped by user")
    except Exception as e:
        print(f"[-] Server error: {e}")

def run_client_mode(file_path, host='localhost', port=8888):
    """Run client mode"""
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return
    
    print(f"[+] Sending file '{file_path}' to {host}:{port}...")
    try:
        from secure_file_transfer import FileTransferClient
        client = FileTransferClient(host, port)
        client.send_file(file_path)
    except Exception as e:
        print(f"[-] Client error: {e}")

def run_performance_analysis():
    """Run network performance analysis"""
    print("[+] Running network performance analysis...")
    try:
        from network_performance_analyzer import run_performance_tests
        analyzer = run_performance_tests()
        print("[+] Performance analysis completed successfully!")
        return analyzer
    except Exception as e:
        print(f"[-] Performance analysis error: {e}")
        return None

def run_security_analysis():
    """Run security analysis"""
    print("[+] Running security analysis...")
    try:
        from security_analyzer import run_security_analysis
        analyzer, ids = run_security_analysis()
        print("[+] Security analysis completed successfully!")
        return analyzer, ids
    except Exception as e:
        print(f"[-] Security analysis error: {e}")
        return None, None

def run_comprehensive_demo():
    """Run comprehensive demonstration of all features"""
    print("\n" + "="*80)
    print("COMPREHENSIVE SYSTEM DEMONSTRATION")
    print("="*80)
    
    # Create test files
    create_test_files()
    
    # Run performance analysis
    print("\n[1/3] Network Performance Analysis")
    print("-" * 40)
    perf_analyzer = run_performance_analysis()
    
    # Run security analysis  
    print("\n[2/3] Security Analysis")
    print("-" * 40)
    sec_analyzer, ids = run_security_analysis()
    
    # Generate comprehensive report
    print("\n[3/3] Generating Comprehensive Report")
    print("-" * 40)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"comprehensive_demo_report_{timestamp}.txt"
    
    with open(report_file, 'w') as f:
        f.write("ADVANCED SECURE FILE TRANSFER SYSTEM\n")
        f.write("Comprehensive Demonstration Report\n")
        f.write("="*50 + "\n\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        
        f.write("SYSTEM COMPONENTS:\n")
        f.write("- Secure File Transfer with AES/RSA encryption\n")
        f.write("- Low-level IP header processing\n")
        f.write("- Network performance monitoring\n")
        f.write("- Security analysis and attack simulation\n")
        f.write("- Graphical user interface\n\n")
        
        f.write("DEMONSTRATION RESULTS:\n")
        if perf_analyzer:
            f.write("✓ Network performance analysis completed\n")
        if sec_analyzer:
            f.write("✓ Security analysis completed\n")
        
        f.write("\nFor detailed results, see JSON reports.\n")
    
    print(f"[+] Comprehensive report saved: {report_file}")
    print("\n[+] Demonstration completed successfully!")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Advanced Secure File Transfer System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --gui                           # Start GUI application
  python main.py --server                       # Start server
  python main.py --client test_document.txt     # Send file to server
  python main.py --performance                  # Run performance analysis
  python main.py --security                     # Run security analysis
  python main.py --demo                         # Run comprehensive demo
        """
    )
    
    parser.add_argument('--gui', action='store_true', help='Start GUI application')
    parser.add_argument('--server', action='store_true', help='Start file transfer server')
    parser.add_argument('--client', type=str, help='Send file as client (specify file path)')
    parser.add_argument('--host', type=str, default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8888, help='Server port (default: 8888)')
    parser.add_argument('--performance', action='store_true', help='Run network performance analysis')
    parser.add_argument('--security', action='store_true', help='Run security analysis')
    parser.add_argument('--demo', action='store_true', help='Run comprehensive demonstration')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check dependencies if requested
    if args.check_deps:
        check_dependencies()
        return
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Check dependencies before running anything
    if not check_dependencies():
        print("\n[-] Please install missing dependencies before proceeding.")
        return
    
    try:
        if args.gui:
            run_gui_mode()
        elif args.server:
            run_server_mode(args.host, args.port)
        elif args.client:
            run_client_mode(args.client, args.host, args.port)
        elif args.performance:
            run_performance_analysis()
        elif args.security:
            run_security_analysis()
        elif args.demo:
            run_comprehensive_demo()
        else:
            print("[-] Please specify a mode. Use --help for options.")
            
    except KeyboardInterrupt:
        print("\n[+] Operation cancelled by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    main() 
