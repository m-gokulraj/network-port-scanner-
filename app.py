"""
PORT SCANNER WEB APPLICATION - FLASK BACKEND
Advanced Cybersecurity Port Scanner with Web Interface
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import socket
import threading
import time
from datetime import datetime
import json

app = Flask(__name__)
CORS(app)

# Global variable to track scan status
scan_results = {
    "status": "idle",
    "progress": 0,
    "open_ports": [],
    "closed_ports": 0,
    "filtered_ports": 0,
    "scan_start": None,
    "scan_end": None,
    "target": None,
    "banner_info": {},
    "vulnerabilities": [],
    "os_hints": []
}

class WebPortScanner:
    """Port Scanner for Web Interface"""
    
    def __init__(self, target, start_port, end_port, threads=50):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = threads
        self.open_ports = []
        self.closed_ports = 0
        self.filtered_ports = 0
        self.lock = threading.Lock()
        self.banner_info = {}
        self.total_ports = end_port - start_port + 1
        self.scanned_ports = 0
    
    def grab_banner(self, host, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner[:50] if banner else None
        except:
            return None
    
    def get_service_name(self, port):
        """Get service for port"""
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"
    
    def check_vulnerabilities(self):
        """Check for common vulnerabilities"""
        vulns = []
        open_set = set(self.open_ports)
        
        if 23 in open_set:
            vulns.append("⚠️ TELNET (23) - Unencrypted, use SSH")
        if 21 in open_set:
            vulns.append("⚠️ FTP (21) - Unencrypted, use SFTP")
        if 3306 in open_set:
            vulns.append("🔴 MySQL (3306) - Don't expose to internet")
        if 5432 in open_set:
            vulns.append("🔴 PostgreSQL (5432) - Don't expose to internet")
        if 27017 in open_set:
            vulns.append("🔴 MongoDB (27017) - Enable authentication")
        if 6379 in open_set:
            vulns.append("🔴 Redis (6379) - Enable password")
        if 3389 in open_set:
            vulns.append("🔴 RDP (3389) - CRITICAL - Restrict access")
        
        return vulns
    
    def detect_os(self):
        """Detect OS hints"""
        hints = []
        open_set = set(self.open_ports)
        
        if 445 in open_set or 139 in open_set:
            hints.append("Windows (SMB ports)")
        if 22 in open_set and 23 not in open_set:
            hints.append("Linux/Unix (SSH)")
        if 3389 in open_set:
            hints.append("Windows (RDP)")
        
        return hints if hints else ["OS Detection: Unable to determine"]
    
    def scan_port(self, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            
            with self.lock:
                self.scanned_ports += 1
                progress = (self.scanned_ports / self.total_ports) * 100
                scan_results["progress"] = round(progress, 1)
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(self.target, port)
                
                with self.lock:
                    self.open_ports.append(port)
                    if banner:
                        self.banner_info[port] = banner
                    scan_results["open_ports"] = sorted(self.open_ports)
                    scan_results["banner_info"] = self.banner_info
            else:
                with self.lock:
                    self.closed_ports += 1
            
            sock.close()
        except:
            with self.lock:
                self.filtered_ports += 1
    
    def start_scan(self):
        """Start scanning"""
        threads = []
        scan_results["status"] = "scanning"
        scan_results["scan_start"] = datetime.now().isoformat()
        
        for port in range(self.start_port, self.end_port + 1):
            while threading.active_count() > self.max_threads + 1:
                time.sleep(0.01)
            
            thread = threading.Thread(target=self.scan_port, args=(port,), daemon=True)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        scan_results["status"] = "completed"
        scan_results["scan_end"] = datetime.now().isoformat()
        scan_results["closed_ports"] = self.closed_ports
        scan_results["filtered_ports"] = self.filtered_ports
        scan_results["vulnerabilities"] = self.check_vulnerabilities()
        scan_results["os_hints"] = self.detect_os()

@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target', '')
    start_port = int(data.get('start_port', 1))
    end_port = int(data.get('end_port', 1024))
    threads = int(data.get('threads', 50))
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    # Reset results
    global scan_results
    scan_results = {
        "status": "scanning",
        "progress": 0,
        "open_ports": [],
        "closed_ports": 0,
        "filtered_ports": 0,
        "scan_start": datetime.now().isoformat(),
        "scan_end": None,
        "target": target,
        "banner_info": {},
        "vulnerabilities": [],
        "os_hints": []
    }
    
    # Start scan in background thread
    scanner = WebPortScanner(target, start_port, end_port, threads)
    scan_thread = threading.Thread(target=scanner.start_scan, daemon=True)
    scan_thread.start()
    
    return jsonify({"status": "scan started"})

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current scan status"""
    return jsonify(scan_results)

@app.route('/api/export', methods=['GET'])
def export_results():
    """Export results as JSON"""
    return jsonify(scan_results)

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
