import sys
import socket
import requests
import concurrent.futures
import time
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTableWidget, 
                             QTableWidgetItem, QVBoxLayout, QWidget, 
                             QPushButton, QHBoxLayout, QHeaderView, 
                             QTextEdit, QLineEdit, QLabel, QDialog, QListWidget)
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, get_working_ifaces, DNSQR, Raw

class SnifferThread(QThread):
    packet_captured = pyqtSignal(str, str, str, str, str, str, str, str, str, str)
    alert_triggered = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self._is_running = True
        self.ip_cache = {}
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        self.flood_tracker = {}
        self.scan_tracker = {}
        self.alerted_ips = set()

    def get_active_interface_name(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            for iface in get_working_ifaces():
                if iface.ip == local_ip:
                    return iface.name
        except Exception:
            pass
        return None

    def resolve_ip_background(self, ip):
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=2.0).json()
            self.ip_cache[ip] = res.get("country", "Unknown")
        except:
            self.ip_cache[ip] = "Unknown"

    def get_geo(self, ip):
        if ip.startswith(("192.168.", "10.", "172.", "127.", "255.")):
            return "Local Network"
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        self.ip_cache[ip] = "Resolving..."
        self.executor.submit(self.resolve_ip_background, ip)
        return "Resolving..."

    def run(self):
        self._is_running = True
        active_iface = self.get_active_interface_name()
        if active_iface:
            sniff(iface=active_iface, prn=self.process_packet, stop_filter=self.should_stop, store=0)
        else:
            sniff(prn=self.process_packet, stop_filter=self.should_stop, store=0)

    def process_packet(self, packet):
        if IP in packet:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            mac_src = packet[Ether].src if Ether in packet else "N/A"
            src = packet[IP].src
            dst = packet[IP].dst
            ttl = str(packet[IP].ttl)
            country = self.get_geo(dst)
            
            proto = "OTHER"
            payload_info = ""
            sport, dport = None, None
            
            if TCP in packet:
                proto = "TCP"
                sport, dport = packet[TCP].sport, packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport, dport = packet[UDP].sport, packet[UDP].dport
            elif ICMP in packet:
                proto = "ICMP"
                
            if packet.haslayer(DNSQR):
                try:
                    payload_info = packet[DNSQR].qname.decode('utf-8')
                except Exception:
                    payload_info = str(packet[DNSQR].qname)
            elif packet.haslayer(Raw):
                try:
                    raw_bytes = packet[Raw].load
                    clean_text = "".join(chr(b) for b in raw_bytes if 32 <= b <= 126)
                    if len(clean_text) > 3:
                        payload_info = clean_text[:50] + "..." if len(clean_text) > 50 else clean_text
                except Exception:
                    pass
                
            current_time = time.time()
            sec_str = timestamp.split('.')[0]

            if src not in self.flood_tracker:
                self.flood_tracker[src] = {'sec': sec_str, 'count': 1, 'alerted': False}
            else:
                if self.flood_tracker[src]['sec'] == sec_str:
                    self.flood_tracker[src]['count'] += 1
                else:
                    self.flood_tracker[src] = {'sec': sec_str, 'count': 1, 'alerted': False}

            if self.flood_tracker[src]['count'] > 2000 and not self.flood_tracker[src]['alerted']:
                self.alert_triggered.emit(timestamp, "CRITICAL", f"Traffic Anomaly: Possible DoS Attack from {src}")
                self.flood_tracker[src]['alerted'] = True

            if dport is not None:
                if dport in [4444, 6667] or sport in [4444, 6667]:
                    if dst not in self.alerted_ips:
                        self.alert_triggered.emit(timestamp, "CRITICAL", f"Malicious Port {dport}/{sport} detected with {dst}")
                        self.alerted_ips.add(dst)
                
                if dport in [21, 23]:
                    if dst not in self.alerted_ips:
                        self.alert_triggered.emit(timestamp, "WARNING", f"Insecure Protocol (Port {dport}) used with {dst}")
                        self.alerted_ips.add(dst)

                if src not in self.scan_tracker:
                    self.scan_tracker[src] = {'time': current_time, 'ports': {dport}, 'alerted': False}
                else:
                    if current_time - self.scan_tracker[src]['time'] < 2.0:
                        self.scan_tracker[src]['ports'].add(dport)
                    else:
                        self.scan_tracker[src] = {'time': current_time, 'ports': {dport}, 'alerted': False}
                
                if len(self.scan_tracker[src]['ports']) > 15 and not self.scan_tracker[src]['alerted']:
                    self.alert_triggered.emit(timestamp, "CRITICAL", f"Port Scan Detected from {src}")
                    self.scan_tracker[src]['alerted'] = True

            suspicious_countries = ["Russia", "China", "North Korea"]
            if country in suspicious_countries and dst not in self.alerted_ips:
                self.alert_triggered.emit(timestamp, "WARNING", f"Connection to {country} ({dst})")
                self.alerted_ips.add(dst)

            threat_keywords = ["password=", "login", "admin", "select * from", "union select"]
            if any(keyword in payload_info.lower() for keyword in threat_keywords):
                self.alert_triggered.emit(timestamp, "CRITICAL", f"Unencrypted sensitive data to {dst} | {payload_info}")

            length = str(len(packet))
            details = packet.show(dump=True)
            self.packet_captured.emit(timestamp, mac_src, src, dst, country, proto, length, ttl, payload_info, details)

    def should_stop(self, packet):
        return not self._is_running

    def stop(self):
        self._is_running = False

class PylemetryGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pylemetry - Advanced Network Analyzer")
        self.resize(1200, 750)
        
        self.setStyleSheet("""
            QMainWindow { background-color: #121212; }
            QWidget { background-color: #121212; color: #ffffff; font-family: 'Segoe UI', Arial; }
            QPushButton { background-color: #1e1e1e; border: 1px solid #333333; padding: 6px; border-radius: 4px; min-width: 100px; }
            QPushButton:hover { background-color: #2a2a2a; border-color: #444444; }
            QPushButton:disabled { background-color: #111111; color: #555555; border-color: #222222; }
            QTableWidget { background-color: #1e1e1e; border: 1px solid #333333; gridline-color: #2a2a2a; selection-background-color: #333333; }
            QHeaderView::section { background-color: #252525; color: #ffffff; padding: 4px; border: 1px solid #333333; }
            QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: 'Consolas', monospace; border: 1px solid #333333; }
            QLineEdit { background-color: #1e1e1e; border: 1px solid #333333; padding: 5px; border-radius: 4px; color: #ffffff; }
        """)

        self.thread = SnifferThread()
        self.thread.packet_captured.connect(self.update_table)
        self.thread.alert_triggered.connect(self.log_alert)
        self.packet_details_list = []
        self.alerts_log = []
        
        self.total_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        
        self.MAX_ROWS = 2000

        layout = QVBoxLayout()
        top_layout = QHBoxLayout()

        self.btn_start = QPushButton("Start Capture")
        self.btn_stop = QPushButton("Stop Capture")
        self.btn_stop.setEnabled(False)
        self.btn_start.clicked.connect(self.start_sniffing)
        self.btn_stop.clicked.connect(self.stop_sniffing)

        self.btn_alerts = QPushButton("Alerts: 0")
        self.btn_alerts.setStyleSheet("background-color: #1e1e1e; color: #aaaaaa;")
        self.btn_alerts.clicked.connect(self.show_alerts_dialog)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter by Domain, Country, IP...")
        self.search_bar.textChanged.connect(self.filter_table)

        top_layout.addWidget(self.btn_start)
        top_layout.addWidget(self.btn_stop)
        top_layout.addSpacing(20)
        top_layout.addWidget(self.search_bar)
        top_layout.addSpacing(20)
        top_layout.addWidget(self.btn_alerts)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["Time", "MAC Source", "Source IP", "Dest IP", "Country", "Protocol", "Length", "TTL", "DPI Payload"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self.display_packet_details)

        self.details_box = QTextEdit()
        self.details_box.setReadOnly(True)
        self.details_box.setPlaceholderText("Select a packet to view raw metrics...")

        self.stats_label = QLabel("Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0")
        self.stats_label.setStyleSheet("color: #aaaaaa; font-weight: bold; padding: 5px;")

        layout.addLayout(top_layout)
        layout.addWidget(self.table, 3)
        layout.addWidget(self.details_box, 2)
        layout.addWidget(self.stats_label)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def start_sniffing(self):
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.table.setRowCount(0)
        self.packet_details_list.clear()
        self.alerts_log.clear()
        self.thread.flood_tracker.clear()
        self.thread.scan_tracker.clear()
        self.thread.alerted_ips.clear()
        self.update_alert_button()
        self.details_box.clear()
        self.total_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        self.update_stats_label()
        self.thread.start()

    def stop_sniffing(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.thread.stop()
        self.thread.wait()

    def log_alert(self, timestamp, level, message):
        self.alerts_log.append(f"[{timestamp}] {level}: {message}")
        self.update_alert_button()

    def update_alert_button(self):
        count = len(self.alerts_log)
        self.btn_alerts.setText(f"Alerts: {count}")
        if count > 0:
            self.btn_alerts.setStyleSheet("background-color: #aa0000; color: #ffffff; font-weight: bold; border: 1px solid #ff5555;")
        else:
            self.btn_alerts.setStyleSheet("background-color: #1e1e1e; color: #aaaaaa; border: 1px solid #333333;")

    def show_alerts_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Security Alerts Log")
        dialog.resize(750, 400)
        dialog.setStyleSheet("""
            QDialog { background-color: #121212; color: #ffffff; }
            QListWidget { background-color: #1e1e1e; color: #ff5555; font-family: 'Consolas', monospace; padding: 10px; border: 1px solid #333333; }
        """)
        layout = QVBoxLayout()
        list_widget = QListWidget()
        
        if not self.alerts_log:
            list_widget.addItem("No threats detected.")
            list_widget.setStyleSheet("color: #aaaaaa;")
        else:
            list_widget.addItems(self.alerts_log)
            
        layout.addWidget(list_widget)
        dialog.setLayout(layout)
        dialog.exec()

    def update_table(self, timestamp, mac_src, src, dst, country, proto, length, ttl, payload_info, details):
        self.total_count += 1
        if proto == "TCP":
            self.tcp_count += 1
        elif proto == "UDP":
            self.udp_count += 1
        elif proto == "ICMP":
            self.icmp_count += 1
        else:
            self.other_count += 1
        self.update_stats_label()

        if self.table.rowCount() >= self.MAX_ROWS:
            self.table.removeRow(0)
            if self.packet_details_list:
                self.packet_details_list.pop(0)

        row = self.table.rowCount()
        self.table.insertRow(row)
        
        items = [
            QTableWidgetItem(timestamp),
            QTableWidgetItem(mac_src),
            QTableWidgetItem(src),
            QTableWidgetItem(dst),
            QTableWidgetItem(country),
            QTableWidgetItem(proto),
            QTableWidgetItem(length),
            QTableWidgetItem(ttl),
            QTableWidgetItem(payload_info)
        ]
        
        for col, item in enumerate(items):
            self.table.setItem(row, col, item)
        
        self.packet_details_list.append(details)
        
        search_text = self.search_bar.text().lower()
        if search_text:
            match = any(search_text in val.lower() for val in [timestamp, mac_src, src, dst, country, proto, length, ttl, payload_info])
            self.table.setRowHidden(row, not match)
            
        if not self.search_bar.text():
            self.table.scrollToBottom()

    def display_packet_details(self):
        selected_rows = self.table.selectedItems()
        if selected_rows:
            row_index = selected_rows[0].row()
            if row_index < len(self.packet_details_list):
                self.details_box.setText(self.packet_details_list[row_index])

    def filter_table(self):
        search_text = self.search_bar.text().lower()
        for row in range(self.table.rowCount()):
            match = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and search_text in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(row, not match)

    def update_stats_label(self):
        self.stats_label.setText(
            f"Total Packets: {self.total_count}  |  TCP: {self.tcp_count}  |  UDP: {self.udp_count}  |  ICMP: {self.icmp_count}  |  Other: {self.other_count}"
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PylemetryGUI()
    window.show()
    sys.exit(app.exec())