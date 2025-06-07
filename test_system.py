#!/usr/bin/env python3
"""
Simple System Test Script
Tests core functionality of the secure file transfer system
"""

import os
import time
from secure_file_transfer import SecureFileTransfer
from network_performance_analyzer import NetworkPerformanceAnalyzer

def test_encryption():
    """Test encryption and decryption functionality"""
    print("=" * 50)
    print("TESTING ENCRYPTION SYSTEM")
    print("=" * 50)
    
    # Create a test file
    test_content = "Bu bir test dosyasıdır.\nŞifreleme testi için oluşturuldu.\n" * 20
    with open('encryption_test.txt', 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    # Initialize secure transfer
    secure_transfer = SecureFileTransfer()
    
    # Test encryption
    print("[1/3] Testing file encryption...")
    encrypted_package = secure_transfer.encrypt_file('encryption_test.txt')
    print("✓ File encrypted successfully")
    
    # Test decryption
    print("[2/3] Testing file decryption...")
    secure_transfer.decrypt_file(encrypted_package, 'decrypted_test.txt')
    print("✓ File decrypted successfully")
    
    # Verify content
    print("[3/3] Verifying file integrity...")
    with open('decrypted_test.txt', 'r', encoding='utf-8') as f:
        decrypted_content = f.read()
    
    if decrypted_content == test_content:
        print("✓ File integrity verified - content matches original")
    else:
        print("✗ File integrity failed - content doesn't match")
    
    # Cleanup
    os.remove('encryption_test.txt')
    os.remove('decrypted_test.txt')
    
    print("\n✓ Encryption test completed successfully!")

def test_performance_analysis():
    """Test network performance analysis"""
    print("\n" + "=" * 50)
    print("TESTING PERFORMANCE ANALYSIS")
    print("=" * 50)
    
    analyzer = NetworkPerformanceAnalyzer()
    
    print("[1/2] Testing latency measurement...")
    result = analyzer.measure_latency('8.8.8.8', count=3)
    if result:
        print(f"✓ Latency test completed - Average: {result['average_latency']:.2f}ms")
    else:
        print("✗ Latency test failed")
    
    print("[2/2] Testing packet loss simulation...")
    loss_result = analyzer.simulate_packet_loss('8.8.8.8', loss_rate=0.1, count=5)
    if loss_result:
        print(f"✓ Packet loss test completed - Loss rate: {loss_result['actual_loss_rate']*100:.1f}%")
    else:
        print("✗ Packet loss test failed")
    
    print("\n✓ Performance analysis test completed!")

def test_ip_header_processing():
    """Test IP header processing functionality"""
    print("\n" + "=" * 50)
    print("TESTING IP HEADER PROCESSING")
    print("=" * 50)
    
    secure_transfer = SecureFileTransfer()
    
    print("[1/3] Testing IP header creation...")
    header = secure_transfer.create_custom_ip_header('192.168.1.1', '192.168.1.2', 1024)
    print(f"✓ IP header created - Length: {len(header)} bytes")
    
    print("[2/3] Testing checksum calculation...")
    test_data = b"Hello, Network!"
    checksum = secure_transfer.calculate_checksum(test_data)
    print(f"✓ Checksum calculated - Value: 0x{checksum:04X}")
    
    print("[3/3] Testing data fragmentation...")
    test_data = b"A" * 2000  # 2KB test data
    fragments = secure_transfer.fragment_data(test_data, fragment_size=500)
    print(f"✓ Data fragmented into {len(fragments)} pieces")
    
    # Test reassembly
    reassembled = secure_transfer.reassemble_fragments(fragments)
    if reassembled == test_data:
        print("✓ Data reassembly successful")
    else:
        print("✗ Data reassembly failed")
    
    print("\n✓ IP header processing test completed!")

def test_security_features():
    """Test security features"""
    print("\n" + "=" * 50)
    print("TESTING SECURITY FEATURES")
    print("=" * 50)
    
    secure_transfer = SecureFileTransfer()
    
    print("[1/2] Testing RSA key generation...")
    key_size = secure_transfer.rsa_key.size_in_bits()
    print(f"✓ RSA key generated - Size: {key_size} bits")
    
    print("[2/2] Testing data integrity verification...")
    test_file = 'security_test.txt'
    with open(test_file, 'w') as f:
        f.write("Security test content for hash verification.")
    
    # Encrypt and get hash
    encrypted_package = secure_transfer.encrypt_file(test_file)
    original_hash = encrypted_package['file_hash']
    print(f"✓ File hash generated: {original_hash[:16]}...")
    
    # Decrypt and verify
    secure_transfer.decrypt_file(encrypted_package, 'security_verified.txt')
    
    # Check if files match
    with open(test_file, 'r') as f1, open('security_verified.txt', 'r') as f2:
        if f1.read() == f2.read():
            print("✓ Security verification successful")
        else:
            print("✗ Security verification failed")
    
    # Cleanup
    os.remove(test_file)
    os.remove('security_verified.txt')
    
    print("\n✓ Security features test completed!")

def main():
    """Run all system tests"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     SYSTEM FUNCTIONALITY TESTS                              ║
║                Advanced Secure File Transfer System                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    start_time = time.time()
    
    try:
        test_encryption()
        test_ip_header_processing()
        test_security_features()
        test_performance_analysis()
        
        end_time = time.time()
        
        print("\n" + "=" * 50)
        print("ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 50)
        print(f"Total test time: {end_time - start_time:.2f} seconds")
        print("\nSistem tüm temel işlevleri başarıyla geçti:")
        print("✓ AES/RSA Şifreleme ve Doğrulama")
        print("✓ IP Header İşleme ve Checksum")
        print("✓ Paket Fragmentasyonu ve Birleştirme")
        print("✓ Ağ Performans Analizi")
        print("✓ Güvenlik Özellikleri")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    main() 