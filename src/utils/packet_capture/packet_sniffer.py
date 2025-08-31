"""
Packet Sniffer Module for IDS/IPS System
Captures and preprocesses network packets for analysis
"""

import threading
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from queue import Queue, Empty
import socket
import struct

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

@dataclass
class PacketInfo:
    """Data class to store packet information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    flags: Optional[str]
    payload_size: int
    raw_packet: Optional[bytes] = None

class PacketSniffer:
    """
    High-performance packet sniffer with filtering and preprocessing capabilities
    """
    
    def __init__(self, interface: str = None, filter_expression: str = None):
        """
        Initialize the packet sniffer
        
        Args:
            interface: Network interface to monitor (None for all interfaces)
            filter_expression: BPF filter expression for packet filtering
        """
        self.interface = interface
        self.filter_expression = filter_expression
        self.is_running = False
        self.packet_queue = Queue(maxsize=10000)
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
            'start_time': None,
            'bytes_captured': 0
        }
        self.callbacks: List[Callable[[PacketInfo], None]] = []
        self.logger = logging.getLogger(__name__)
        
        # Threading
        self.capture_thread = None
        self.processing_thread = None
        self.stop_event = threading.Event()
        
        # Configuration
        self.config = {
            'max_packet_size': 65535,
            'capture_timeout': 1,
            'enable_raw_capture': False,
            'protocols_to_capture': ['TCP', 'UDP', 'ICMP', 'ARP'],
            'port_ranges': None,  # [(start, end), ...] or None for all ports
            'ip_whitelist': None,  # [ip1, ip2, ...] or None for all IPs
            'ip_blacklist': None   # [ip1, ip2, ...] or None
        }
    
    def add_callback(self, callback: Callable[[PacketInfo], None]):
        """Add a callback function to process captured packets"""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[PacketInfo], None]):
        """Remove a callback function"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def configure(self, **kwargs):
        """Update configuration parameters"""
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value
                self.logger.info(f"Configuration updated: {key} = {value}")
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from a captured packet"""
        try:
            timestamp = time.time()
            
            # Initialize default values
            src_ip = dst_ip = "Unknown"
            src_port = dst_port = None
            protocol = "Unknown"
            flags = None
            packet_size = len(packet)
            payload_size = 0
            
            # Extract Ethernet layer info
            if packet.haslayer(Ether):
                eth_layer = packet[Ether]
            
            # Extract IP layer info
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                payload_size = len(ip_layer.payload) if ip_layer.payload else 0
                
                # Extract transport layer info
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"
                    flags = self._get_tcp_flags(tcp_layer.flags)
                    
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                    
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    protocol = "ICMP"
                    
            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                protocol = "ARP"
            
            # Apply filtering
            if not self._should_capture_packet(src_ip, dst_ip, src_port, dst_port, protocol):
                return None
            
            # Create packet info object
            packet_info = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                flags=flags,
                payload_size=payload_size,
                raw_packet=bytes(packet) if self.config['enable_raw_capture'] else None
            )
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _get_tcp_flags(self, flags: int) -> str:
        """Convert TCP flags integer to string representation"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        if flags & 0x40: flag_names.append("ECE")
        if flags & 0x80: flag_names.append("CWR")
        return "|".join(flag_names)
    
    def _should_capture_packet(self, src_ip: str, dst_ip: str, src_port: Optional[int], 
                              dst_port: Optional[int], protocol: str) -> bool:
        """Determine if a packet should be captured based on configuration"""
        
        # Protocol filtering
        if protocol not in self.config['protocols_to_capture']:
            return False
        
        # IP whitelist filtering
        if self.config['ip_whitelist']:
            if src_ip not in self.config['ip_whitelist'] and dst_ip not in self.config['ip_whitelist']:
                return False
        
        # IP blacklist filtering
        if self.config['ip_blacklist']:
            if src_ip in self.config['ip_blacklist'] or dst_ip in self.config['ip_blacklist']:
                return False
        
        # Port range filtering
        if self.config['port_ranges'] and (src_port or dst_port):
            port_in_range = False
            for start, end in self.config['port_ranges']:
                if ((src_port and start <= src_port <= end) or 
                    (dst_port and start <= dst_port <= end)):
                    port_in_range = True
                    break
            if not port_in_range:
                return False
        
        return True
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.stats['packets_captured'] += 1
                self.stats['bytes_captured'] += packet_info.packet_size
                
                # Add to processing queue
                try:
                    self.packet_queue.put_nowait(packet_info)
                except:
                    self.stats['packets_dropped'] += 1
                    self.logger.warning("Packet queue full, dropping packet")
                    
        except Exception as e:
            self.logger.error(f"Error in packet handler: {e}")
    
    def _processing_worker(self):
        """Worker thread for processing captured packets"""
        while not self.stop_event.is_set():
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1)
                
                # Process packet through callbacks
                for callback in self.callbacks:
                    try:
                        callback(packet_info)
                    except Exception as e:
                        self.logger.error(f"Error in callback: {e}")
                
                self.stats['packets_processed'] += 1
                self.packet_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in processing worker: {e}")
    
    def start(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet capture")
        
        if self.is_running:
            self.logger.warning("Packet sniffer is already running")
            return
        
        self.logger.info(f"Starting packet capture on interface: {self.interface or 'all'}")
        self.logger.info(f"Filter expression: {self.filter_expression or 'none'}")
        
        self.is_running = True
        self.stop_event.clear()
        self.stats['start_time'] = time.time()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._processing_worker, daemon=True)
        self.processing_thread.start()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
        self.capture_thread.start()
        
        self.logger.info("Packet sniffer started successfully")
    
    def _capture_worker(self):
        """Worker thread for packet capture"""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_expression,
                prn=self._packet_handler,
                stop_filter=lambda x: self.stop_event.is_set(),
                timeout=self.config['capture_timeout']
            )
        except Exception as e:
            self.logger.error(f"Error in capture worker: {e}")
            self.is_running = False
    
    def stop(self):
        """Stop packet capture"""
        if not self.is_running:
            self.logger.warning("Packet sniffer is not running")
            return
        
        self.logger.info("Stopping packet capture...")
        self.stop_event.set()
        self.is_running = False
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5)
        
        self.logger.info("Packet sniffer stopped")
    
    def get_stats(self) -> Dict:
        """Get capture statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['runtime'] = time.time() - stats['start_time']
            if stats['runtime'] > 0:
                stats['packets_per_second'] = stats['packets_captured'] / stats['runtime']
                stats['bytes_per_second'] = stats['bytes_captured'] / stats['runtime']
        return stats
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def packet_callback(packet_info: PacketInfo):
        """Example callback function"""
        print(f"Captured: {packet_info.src_ip}:{packet_info.src_port} -> "
              f"{packet_info.dst_ip}:{packet_info.dst_port} ({packet_info.protocol})")
    
    # Create and configure sniffer
    sniffer = PacketSniffer(interface=None, filter_expression="tcp or udp")
    sniffer.configure(
        protocols_to_capture=['TCP', 'UDP', 'ICMP'],
        max_packet_size=1500
    )
    
    # Add callback
    sniffer.add_callback(packet_callback)
    
    try:
        # Start capture
        sniffer.start()
        
        # Run for 30 seconds
        time.sleep(30)
        
        # Stop capture
        sniffer.stop()
        
        # Print statistics
        stats = sniffer.get_stats()
        print(f"Capture Statistics: {json.dumps(stats, indent=2)}")
        
    except KeyboardInterrupt:
        print("Stopping capture...")
        sniffer.stop()
    except Exception as e:
        print(f"Error: {e}")
        sniffer.stop()

