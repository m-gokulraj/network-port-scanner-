import socket
import threading
import time
import sys
import os
from datetime import datetime
from collections import defaultdict
import json

class AdvancedPortScanner:
    """
    Advanced Port Scanner with Cybersecurity Features
    Includes banner grabbing, OS detection, service enumeration, and detailed reporting
    """
    
    def __init__(self, target, start_port=1, end_port=1024, timeout=1, threads=50):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_threads = threads
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.lock = threading.Lock()
        self.banner_info = {}
        self.scan_start_time = None
        self.scan_end_time = None
        self.total_ports = end_port - start_port + 1
        self.scanned_ports = 0
        
    def resolve_hostname(self):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"\n[+] Target '{self.target}' resolved to: {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Could not resolve hostname '{self.target}'")
            return None
    
    def grab_banner(self, host, port):
        """Attempt to grab service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            try:
                banner = sock.recv(1024).decode().strip()
                if banner:
                    return banner[:100]  # Limit to 100 chars
            except:
                pass
            
            sock.close()
        except:
            pass
        return None
    
    def get_service_name(self, port):
        """Get service name for a port"""
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"
    
    def detect_os_hints(self, open_ports):
        """Detect OS hints based on open ports"""
        hints = []
        
        if 445 in open_ports or 139 in open_ports:
            hints.append("Windows (SMB ports open)")
        if 22 in open_ports and 23 not in open_ports:
            hints.append("Likely Unix/Linux (SSH open, no Telnet)")
        if 3389 in open_ports:
            hints.append("Windows (RDP port open)")
        if 111 in open_ports and 2049 in open_ports:
            hints.append("Unix/Linux (NFS/RPC ports open)")
        
        return hints if hints else ["OS Detection: Inconclusive"]
    
    def scan_port(self, port, host):
        """Scan a single port with detailed analysis"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            with self.lock:
                self.scanned_ports += 1
                progress = (self.scanned_ports / self.total_ports) * 100
                sys.stdout.write(f'\r[*] Progress: {progress:.1f}% ({self.scanned_ports}/{self.total_ports})')
                sys.stdout.flush()
            
            if result == 0:
                service = self.get_service_name(port)
                
                # Attempt banner grabbing
                banner = self.grab_banner(host, port)
                
                with self.lock:
                    self.open_ports.append(port)
                    if banner:
                        self.banner_info[port] = banner
                    print(f"\n[+] Port {port:5d} OPEN    | Service: {service:15s} | ", end="")
                    if banner:
                        print(f"Banner: {banner[:40]}")
                    else:
                        print()
            else:
                with self.lock:
                    self.closed_ports.append(port)
            
            sock.close()
            
        except socket.timeout:
            with self.lock:
                self.filtered_ports.append(port)
        except Exception as e:
            with self.lock:
                self.filtered_ports.append(port)
    
    def scan_common_vulnerabilities(self):
        """Check for common port misconfigurations"""
        vulnerabilities = []
        open_port_set = set(self.open_ports)
        
        # Check for dangerous service combinations
        if 23 in open_port_set:
            vulnerabilities.append("[!] TELNET (port 23) - Unencrypted, use SSH instead")
        
        if 21 in open_port_set:
            vulnerabilities.append("[!] FTP (port 21) - Unencrypted, use SFTP/SCP instead")
        
        if 445 in open_port_set or 139 in open_port_set:
            vulnerabilities.append("[!] SMB (ports 139/445) - Verify access controls")
        
        if 3306 in open_port_set:
            vulnerabilities.append("[!] MySQL (port 3306) - Should not be exposed to internet")
        
        if 5432 in open_port_set:
            vulnerabilities.append("[!] PostgreSQL (port 5432) - Should not be exposed to internet")
        
        if 27017 in open_port_set or 27018 in open_port_set:
            vulnerabilities.append("[!] MongoDB (ports 27017-27018) - Often misconfigured, no auth")
        
        if 6379 in open_port_set:
            vulnerabilities.append("[!] Redis (port 6379) - No authentication by default")
        
        if 5900 in open_port_set:
            vulnerabilities.append("[!] VNC (port 5900) - Weak encryption, consider SSH tunneling")
        
        if 3389 in open_port_set:
            vulnerabilities.append("[!] RDP (port 3389) - Exposed to internet - HIGH RISK")
        
        if 9200 in open_port_set or 9300 in open_port_set:
            vulnerabilities.append("[!] Elasticsearch (9200/9300) - No auth, potential RCE")
        
        if 8080 in open_port_set or 8000 in open_port_set or 8888 in open_port_set:
            vulnerabilities.append("[*] Alternative HTTP ports open - Check for development services")
        
        return vulnerabilities
    
    def perform_scan(self):
        """Main scanning function with threading"""
        print(f"\n{'='*80}")
        print(f"{'ADVANCED CYBERSECURITY PORT SCANNER':^80}")
        print(f"{'='*80}")
        
        print(f"\n[*] Target: {self.target}")
        print(f"[*] Port Range: {self.start_port} - {self.end_port}")
        print(f"[*] Total Ports: {self.total_ports}")
        print(f"[*] Threads: {self.max_threads}")
        print(f"[*] Timeout: {self.timeout} seconds")
        
        self.scan_start_time = datetime.now()
        print(f"[*] Scan Started: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"\n{'-'*80}")
        print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<20} {'DETAILS'}")
        print(f"{'-'*80}\n")
        
        # Create and start threads
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            while threading.active_count() >= self.max_threads + 1:
                time.sleep(0.1)
            
            thread = threading.Thread(
                target=self.scan_port,
                args=(port, self.target),
                daemon=True
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        self.scan_end_time = datetime.now()
        print(f"\n\n{'-'*80}\n")
    
    def generate_report(self):
        """Generate comprehensive security report"""
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        print(f"\n{'='*80}")
        print(f"{'SCAN REPORT':^80}")
        print(f"{'='*80}\n")
        
        print(f"[*] Scan Duration: {duration:.2f} seconds")
        print(f"[*] Ports Scanned: {self.scanned_ports}")
        
        print(f"\n[+] OPEN PORTS: {len(self.open_ports)}")
        if self.open_ports:
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"    Port {port:5d} - {service}")
                if port in self.banner_info:
                    print(f"             Banner: {self.banner_info[port]}")
        
        print(f"\n[*] CLOSED PORTS: {len(self.closed_ports)}")
        print(f"[*] FILTERED PORTS: {len(self.filtered_ports)}")
        
        # OS Detection
        print(f"\n[*] OS DETECTION HINTS:")
        for hint in self.detect_os_hints(set(self.open_ports)):
            print(f"    {hint}")
        
        # Vulnerability Check
        print(f"\n[!] SECURITY ASSESSMENT:")
        vulns = self.scan_common_vulnerabilities()
        if vulns:
            for vuln in vulns:
                print(f"    {vuln}")
        else:
            print(f"    [+] No obvious misconfigurations detected")
        
        # Statistics
        print(f"\n[*] SCAN STATISTICS:")
        print(f"    Total Ports Analyzed: {self.total_ports}")
        print(f"    Open Ports: {len(self.open_ports)} ({(len(self.open_ports)/self.total_ports)*100:.1f}%)")
        print(f"    Closed Ports: {len(self.closed_ports)} ({(len(self.closed_ports)/self.total_ports)*100:.1f}%)")
        print(f"    Filtered Ports: {len(self.filtered_ports)} ({(len(self.filtered_ports)/self.total_ports)*100:.1f}%)")
        print(f"    Scan Speed: {self.total_ports/duration:.1f} ports/second")
        
        print(f"\n[*] Scan Completed: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{'='*80}\n")
    
    def export_report(self, filename="scan_report.json"):
        """Export scan results to JSON"""
        report = {
            "target": self.target,
            "scan_start": self.scan_start_time.isoformat(),
            "scan_end": self.scan_end_time.isoformat(),
            "duration_seconds": (self.scan_end_time - self.scan_start_time).total_seconds(),
            "open_ports": sorted(self.open_ports),
            "closed_ports": len(self.closed_ports),
            "filtered_ports": len(self.filtered_ports),
            "banner_info": self.banner_info,
            "services": {port: self.get_service_name(port) for port in self.open_ports},
            "os_hints": self.detect_os_hints(set(self.open_ports)),
            "vulnerabilities": self.scan_common_vulnerabilities()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"[+] Report exported to: {filename}\n")
        except Exception as e:
            print(f"[-] Error exporting report: {e}\n")

def main():
    print(f"\n{'='*80}")
    print(f"{'ADVANCED CYBERSECURITY PORT SCANNER v2.0':^80}")
    print(f"{'='*80}")
    
    try:
        target = input("\n[?] Enter target IP or hostname: ").strip()
        
        if not target:
            print("[-] No target provided. Exiting.")
            return
        
        start_port_input = input("[?] Enter start port (default 1): ").strip()
        start_port = int(start_port_input) if start_port_input else 1
        
        end_port_input = input("[?] Enter end port (default 1024): ").strip()
        end_port = int(end_port_input) if end_port_input else 1024
        
        threads_input = input("[?] Enter number of threads (default 50): ").strip()
        threads = int(threads_input) if threads_input else 50
        
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print("[-] Invalid port range. Using default (1-1024)")
            start_port, end_port = 1, 1024
        
        if threads < 1 or threads > 500:
            print("[-] Invalid thread count. Using default (50)")
            threads = 50
        
        print("\n[!] DISCLAIMER: Only scan networks you own or have permission to scan!")
        print("[!] Unauthorized port scanning may be illegal.\n")
        
        scanner = AdvancedPortScanner(target, start_port, end_port, threads=threads)
        scanner.perform_scan()
        scanner.generate_report()
        
        export_choice = input("[?] Export report to JSON? (y/n): ").strip().lower()
        if export_choice == 'y':
            scanner.export_report()
    
    except ValueError:
        print("[-] Invalid input. Please enter valid numbers.")
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
