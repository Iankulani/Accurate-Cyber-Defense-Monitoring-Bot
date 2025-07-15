import os
import sys
import socket
import subprocess
import time
import threading
import requests
import json
import datetime
from collections import deque
import dns.resolver
import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP
import logging
from typing import Dict, List, Optional, Tuple

# Constants
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"
VERSION = "1.0.0"
MAX_LOG_ENTRIES = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot{}/sendMessage"

# Configuration
config = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "monitoring_interval": 5,
    "thresholds": {
        "dos": 100,  # packets per second
        "ddos": 500,  # packets per second from multiple sources
        "port_scan": 10,  # ports per minute
        "http_flood": 100,  # requests per minute
        "https_flood": 100  # requests per minute
    }
}

# Global variables
monitored_ips = {}
activity_log = deque(maxlen=MAX_LOG_ENTRIES)
is_monitoring = False
monitoring_thread = None
command_history = []

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format=f'{GREEN}%(asctime)s{RESET} - {GREEN}%(levelname)s{RESET} - %(message)s',
    handlers=[
        logging.FileHandler('cyber_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self):
        self.packet_counts = {}
        self.port_scan_counts = {}
        self.http_counts = {}
        self.https_counts = {}
        self.last_reset = datetime.datetime.now()
    
    def reset_counts(self):
        current_time = datetime.datetime.now()
        if (current_time - self.last_reset).seconds >= 60:
            self.packet_counts = {}
            self.port_scan_counts = {}
            self.http_counts = {}
            self.https_counts = {}
            self.last_reset = current_time
    
    def analyze_packet(self, packet):
        self.reset_counts()
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Count packets per source IP
            if src_ip not in self.packet_counts:
                self.packet_counts[src_ip] = 0
            self.packet_counts[src_ip] += 1
            
            # Detect port scanning
            if TCP in packet:
                dst_port = packet[TCP].dport
                if src_ip not in self.port_scan_counts:
                    self.port_scan_counts[src_ip] = set()
                self.port_scan_counts[src_ip].add(dst_port)
                
                # Detect HTTP/HTTPS floods
                if dst_port == 80:
                    if src_ip not in self.http_counts:
                        self.http_counts[src_ip] = 0
                    self.http_counts[src_ip] += 1
                elif dst_port == 443:
                    if src_ip not in self.https_counts:
                        self.https_counts[src_ip] = 0
                    self.https_counts[src_ip] += 1
    
    def get_threats(self, ip_address: str) -> List[str]:
        threats = []
        
        # Check for DoS
        if ip_address in self.packet_counts and self.packet_counts[ip_address] > config["thresholds"]["dos"]:
            threats.append(f"Potential DoS attack from {ip_address} ({self.packet_counts[ip_address]} packets/sec)")
        
        # Check for DDoS (multiple sources sending high packet counts)
        high_packet_sources = [ip for ip, count in self.packet_counts.items() if count > config["thresholds"]["dos"]]
        if len(high_packet_sources) > config["thresholds"]["ddos"]:
            threats.append(f"Potential DDoS attack from multiple sources ({len(high_packet_sources)} sources)")
        
        # Check for port scanning
        if ip_address in self.port_scan_counts and len(self.port_scan_counts[ip_address]) > config["thresholds"]["port_scan"]:
            threats.append(f"Potential port scanning from {ip_address} ({len(self.port_scan_counts[ip_address])} ports scanned)")
        
        # Check for HTTP flood
        if ip_address in self.http_counts and self.http_counts[ip_address] > config["thresholds"]["http_flood"]:
            threats.append(f"Potential HTTP flood from {ip_address} ({self.http_counts[ip_address]} requests/min)")
        
        # Check for HTTPS flood
        if ip_address in self.https_counts and self.https_counts[ip_address] > config["thresholds"]["https_flood"]:
            threats.append(f"Potential HTTPS flood from {ip_address} ({self.https_counts[ip_address]} requests/min)")
        
        return threats

class TelegramBot:
    @staticmethod
    def send_message(message: str):
        if not config["telegram_token"] or not config["telegram_chat_id"]:
            logger.warning("Telegram token or chat ID not configured")
            return
        
        url = TELEGRAM_API_URL.format(config["telegram_token"])
        payload = {
            "chat_id": config["telegram_chat_id"],
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            response = requests.post(url, json=payload)
            if response.status_code != 200:
                logger.error(f"Failed to send Telegram message: {response.text}")
        except Exception as e:
            logger.error(f"Error sending Telegram message: {str(e)}")

def print_banner():
    print(f"""{GREEN}{BOLD}
      
  ____            _   
 | __ )  ___   __| |_ 
 |  _ \ / _ \ / _` | |
 | |_) | (_) | (_| | |
 |____/ \___/ \__,_|_|
                                                                            
  {RESET}Version: {VERSION}
  Type 'help' for available commands
    """)
def print_help():
    print(f"""{GREEN}{BOLD}
Available Commands:
  help                  - Show this help message
  exit                  - Exit the program
  ping <ip>             - Ping an IP address
  tracert <ip>          - Trace route to an IP address
  nslookup <ip/domain>  - Perform DNS lookup
  netstat               - Show network statistics
  start monitoring <ip> - Start monitoring an IP address for threats
  stop monitoring <ip>  - Stop monitoring an IP address
  view logs             - View activity logs
  view monitored        - View currently monitored IPs
  view threats          - View detected threats
  config telegram <token> <chat_id> - Configure Telegram bot
  send <message>        - Send a message to Telegram bot
    {RESET}""")

def execute_command(command: str):
    command_history.append(command)
    parts = command.lower().split()
    
    if not parts:
        return
    
    cmd = parts[0]
    
    try:
        if cmd == "help":
            print_help()
        elif cmd == "exit":
            sys.exit(0)
        elif cmd == "ping" and len(parts) > 1:
            ping_ip(parts[1])
        elif cmd == "tracert" and len(parts) > 1:
            trace_route(parts[1])
        elif cmd == "nslookup" and len(parts) > 1:
            dns_lookup(parts[1])
        elif cmd == "netstat":
            show_netstat()
        elif cmd == "start" and len(parts) > 2 and parts[1] == "monitoring":
            start_monitoring(parts[2])
        elif cmd == "stop" and len(parts) > 2 and parts[1] == "monitoring":
            stop_monitoring(parts[2])
        elif cmd == "view":
            if len(parts) > 1:
                if parts[1] == "logs":
                    view_logs()
                elif parts[1] == "monitored":
                    view_monitored_ips()
                elif parts[1] == "threats":
                    view_threats()
        elif cmd == "config" and len(parts) > 2 and parts[1] == "telegram":
            if len(parts) > 3:
                config_telegram(parts[2], parts[3])
            else:
                print(f"{GREEN}Usage: config telegram <token> <chat_id>{RESET}")
        elif cmd == "send" and len(parts) > 1:
            TelegramBot.send_message(" ".join(parts[1:]))
        else:
            print(f"{GREEN}Unknown command. Type 'help' for available commands.{RESET}")
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")

def ping_ip(ip_address: str):
    try:
        param = "-n" if os.name == "nt" else "-c"
        command = ["ping", param, "4", ip_address]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"{GREEN}{output}{RESET}")
        log_activity(f"Ping executed for {ip_address}")
        TelegramBot.send_message(f"Ping results for {ip_address}:\n{output}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ping failed: {e.output}")
        TelegramBot.send_message(f"Ping failed for {ip_address}: {e.output}")

def trace_route(ip_address: str):
    try:
        param = "-d" if os.name == "nt" else ""
        command = ["tracert", param, ip_address] if os.name == "nt" else ["traceroute", ip_address]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"{GREEN}{output}{RESET}")
        log_activity(f"Traceroute executed for {ip_address}")
        TelegramBot.send_message(f"Traceroute results for {ip_address}:\n{output}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Traceroute failed: {e.output}")
        TelegramBot.send_message(f"Traceroute failed for {ip_address}: {e.output}")

def dns_lookup(target: str):
    try:
        if os.name == "nt":
            command = ["nslookup", target]
        else:
            command = ["dig", target]
        
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"{GREEN}{output}{RESET}")
        log_activity(f"DNS lookup executed for {target}")
        TelegramBot.send_message(f"DNS lookup results for {target}:\n{output}")
    except subprocess.CalledProcessError as e:
        logger.error(f"DNS lookup failed: {e.output}")
        TelegramBot.send_message(f"DNS lookup failed for {target}: {e.output}")

def show_netstat():
    try:
        command = ["netstat", "-ano"] if os.name == "nt" else ["netstat", "-tulnp"]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"{GREEN}{output}{RESET}")
        log_activity("Netstat executed")
        TelegramBot.send_message(f"Netstat results:\n{output}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Netstat failed: {e.output}")
        TelegramBot.send_message(f"Netstat failed: {e.output}")

def start_monitoring(ip_address: str):
    global is_monitoring, monitoring_thread
    
    if ip_address in monitored_ips:
        print(f"{GREEN}Already monitoring {ip_address}{RESET}")
        return
    
    monitored_ips[ip_address] = {
        "start_time": datetime.datetime.now(),
        "threats": [],
        "packet_count": 0,
        "monitor": NetworkMonitor()
    }
    
    print(f"{GREEN}Started monitoring {ip_address}{RESET}")
    log_activity(f"Started monitoring {ip_address}")
    TelegramBot.send_message(f"Started monitoring {ip_address}")
    
    if not is_monitoring:
        is_monitoring = True
        monitoring_thread = threading.Thread(target=monitor_network)
        monitoring_thread.daemon = True
        monitoring_thread.start()

def stop_monitoring(ip_address: str):
    global is_monitoring
    
    if ip_address in monitored_ips:
        del monitored_ips[ip_address]
        print(f"{GREEN}Stopped monitoring {ip_address}{RESET}")
        log_activity(f"Stopped monitoring {ip_address}")
        TelegramBot.send_message(f"Stopped monitoring {ip_address}")
        
        if not monitored_ips:
            is_monitoring = False
    else:
        print(f"{GREEN}Not currently monitoring {ip_address}{RESET}")

def monitor_network():
    while is_monitoring:
        for ip_address, data in monitored_ips.items():
            try:
                # Simulate packet capture and analysis (in a real tool, this would use actual packet capture)
                monitor = data["monitor"]
                
                # Simulate some network activity
                packet = IP(src="192.168.1.100", dst=ip_address)/TCP(dport=80)
                monitor.analyze_packet(packet)
                
                # Check for threats
                threats = monitor.get_threats(ip_address)
                if threats:
                    data["threats"].extend(threats)
                    for threat in threats:
                        logger.warning(threat)
                        TelegramBot.send_message(f"🚨 ALERT: {threat}")
                
                time.sleep(config["monitoring_interval"])
            except Exception as e:
                logger.error(f"Error monitoring {ip_address}: {str(e)}")

def view_logs():
    print(f"{GREEN}{BOLD}Activity Logs:{RESET}")
    for log in activity_log:
        print(f"{GREEN}{log}{RESET}")

def view_monitored_ips():
    print(f"{GREEN}{BOLD}Monitored IPs:{RESET}")
    for ip, data in monitored_ips.items():
        duration = datetime.datetime.now() - data["start_time"]
        print(f"{GREEN}{ip} - Monitoring for {duration}{RESET}")

def view_threats():
    print(f"{GREEN}{BOLD}Detected Threats:{RESET}")
    for ip, data in monitored_ips.items():
        if data["threats"]:
            print(f"{GREEN}{ip}:{RESET}")
            for threat in data["threats"]:
                print(f"  {GREEN}{threat}{RESET}")
        else:
            print(f"{GREEN}{ip}: No threats detected{RESET}")

def config_telegram(token: str, chat_id: str):
    config["telegram_token"] = token
    config["telegram_chat_id"] = chat_id
    print(f"{GREEN}Telegram bot configured{RESET}")
    log_activity("Telegram bot configured")
    TelegramBot.send_message("Accurate Cyber Defense Bot Security Monitor is now connected to Telegram!")

def log_activity(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    activity_log.append(log_entry)
    logger.info(message)

def main():
    print_banner()
    
    while True:
        try:
            command = input(f"{GREEN}cybermon>{RESET} ").strip()
            if command:
                execute_command(command)
        except KeyboardInterrupt:
            print("\nUse 'exit' command to quit the program")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    # Check for admin privileges
    if os.name == "nt":
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0
    
    if not is_admin:
        print(f"{GREEN}Warning: Running without administrator privileges may limit functionality{RESET}")
    
    main()