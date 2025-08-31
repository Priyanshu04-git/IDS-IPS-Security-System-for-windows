"""
IP Blocker Module for IDS/IPS System
Provides active prevention capabilities by blocking malicious IP addresses
"""

import os
import time
import json
import logging
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import platform

@dataclass
class BlockRule:
    """Data class representing an IP blocking rule"""
    ip_address: str
    reason: str
    severity: str
    timestamp: float
    duration: Optional[int] = None  # seconds, None for permanent
    rule_id: Optional[str] = None
    blocked_by: str = "IDS/IPS"
    additional_info: Dict = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}
        if self.rule_id is None:
            self.rule_id = f"ids_ips_{int(self.timestamp)}_{hash(self.ip_address) % 10000}"

@dataclass
class BlockResult:
    """Data class representing the result of a blocking operation"""
    success: bool
    ip_address: str
    rule_id: str
    message: str
    timestamp: float
    method: str  # iptables, netsh, etc.

class IPBlocker:
    """Main IP blocking engine with support for multiple platforms"""
    
    def __init__(self, config_file: str = "ip_blocker_config.json"):
        self.config_file = Path(config_file)
        self.logger = logging.getLogger(__name__)
        self.platform = platform.system().lower()
        
        # Active blocking rules
        self.active_rules: Dict[str, BlockRule] = {}
        self.blocked_ips: Set[str] = set()
        
        # Configuration
        self.config = {
            'max_rules': 10000,
            'default_block_duration': 3600,  # 1 hour
            'whitelist': ['127.0.0.1', '::1'],
            'enable_automatic_unblock': True,
            'backup_method': 'hosts_file',  # fallback if iptables/netsh fails
            'log_all_operations': True,
            'dry_run_mode': False,  # for testing
            'chain_name': 'IDS_IPS_BLOCK',  # iptables chain name
            'rule_prefix': 'IDS_IPS'  # prefix for rule comments
        }
        
        # Statistics
        self.stats = {
            'total_blocks': 0,
            'total_unblocks': 0,
            'active_blocks': 0,
            'failed_operations': 0,
            'start_time': time.time()
        }
        
        # Threading
        self._lock = threading.RLock()
        self.cleanup_thread = None
        self.stop_event = threading.Event()
        
        # Load configuration
        self.load_config()
        
        # Initialize platform-specific components
        self._initialize_platform()
        
        # Start cleanup thread
        self.start_cleanup_thread()
    
    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                self.config.update(loaded_config)
                self.logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Error loading configuration: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Saved configuration to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
    
    def _initialize_platform(self):
        """Initialize platform-specific components"""
        if self.platform == 'linux':
            self._initialize_iptables()
        elif self.platform == 'windows':
            self._initialize_netsh()
        else:
            self.logger.warning(f"Platform {self.platform} not fully supported, using fallback methods")
    
    def _initialize_iptables(self):
        """Initialize iptables for Linux systems"""
        try:
            # Check if iptables is available
            result = subprocess.run(['which', 'iptables'], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error("iptables not found on system")
                return False
            
            # Create custom chain if it doesn't exist
            chain_name = self.config['chain_name']
            
            # Check if chain exists
            result = subprocess.run(
                ['iptables', '-L', chain_name, '-n'],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                # Create the chain
                subprocess.run(['iptables', '-N', chain_name], check=True)
                self.logger.info(f"Created iptables chain: {chain_name}")
                
                # Insert rule to jump to our chain from INPUT
                subprocess.run([
                    'iptables', '-I', 'INPUT', '-j', chain_name
                ], check=True)
                self.logger.info(f"Added jump rule to {chain_name}")
            
            self.logger.info("iptables initialized successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error initializing iptables: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error initializing iptables: {e}")
            return False
    
    def _initialize_netsh(self):
        """Initialize netsh for Windows systems"""
        try:
            # Check if running as administrator
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.logger.error("Administrator privileges required for Windows firewall operations")
                return False
            
            # Test netsh availability
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles'],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                self.logger.error("netsh advfirewall not available")
                return False
            
            self.logger.info("netsh initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing netsh: {e}")
            return False
    
    def block_ip(self, ip_address: str, reason: str, severity: str = "MEDIUM", 
                 duration: Optional[int] = None) -> BlockResult:
        """Block an IP address"""
        
        with self._lock:
            timestamp = time.time()
            
            # Validate IP address
            if not self._is_valid_ip(ip_address):
                return BlockResult(
                    success=False,
                    ip_address=ip_address,
                    rule_id="",
                    message=f"Invalid IP address: {ip_address}",
                    timestamp=timestamp,
                    method="validation"
                )
            
            # Check whitelist
            if ip_address in self.config['whitelist']:
                return BlockResult(
                    success=False,
                    ip_address=ip_address,
                    rule_id="",
                    message=f"IP address {ip_address} is whitelisted",
                    timestamp=timestamp,
                    method="whitelist"
                )
            
            # Check if already blocked
            if ip_address in self.blocked_ips:
                existing_rule = None
                for rule in self.active_rules.values():
                    if rule.ip_address == ip_address:
                        existing_rule = rule
                        break
                
                if existing_rule:
                    return BlockResult(
                        success=False,  # Changed to False to indicate no new action taken
                        ip_address=ip_address,
                        rule_id=existing_rule.rule_id,
                        message=f"IP address {ip_address} already blocked",
                        timestamp=timestamp,
                        method="existing"
                    )
            
            # Check rule limit
            if len(self.active_rules) >= self.config['max_rules']:
                self.logger.warning("Maximum number of blocking rules reached")
                return BlockResult(
                    success=False,
                    ip_address=ip_address,
                    rule_id="",
                    message="Maximum number of blocking rules reached",
                    timestamp=timestamp,
                    method="limit"
                )
            
            # Create blocking rule
            if duration is None:
                duration = self.config['default_block_duration']
            
            rule = BlockRule(
                ip_address=ip_address,
                reason=reason,
                severity=severity,
                timestamp=timestamp,
                duration=duration
            )
            
            # Apply the block
            success, method, message = self._apply_block(rule)
            
            if success:
                self.active_rules[rule.rule_id] = rule
                self.blocked_ips.add(ip_address)
                self.stats['total_blocks'] += 1
                self.stats['active_blocks'] += 1
                
                self.logger.info(f"Blocked IP {ip_address}: {reason} (Rule ID: {rule.rule_id})")
            else:
                self.stats['failed_operations'] += 1
                self.logger.error(f"Failed to block IP {ip_address}: {message}")
            
            return BlockResult(
                success=success,
                ip_address=ip_address,
                rule_id=rule.rule_id,
                message=message,
                timestamp=timestamp,
                method=method
            )
    
    def unblock_ip(self, ip_address: str) -> BlockResult:
        """Unblock an IP address"""
        
        with self._lock:
            timestamp = time.time()
            
            # Find the rule for this IP
            rule_to_remove = None
            for rule_id, rule in self.active_rules.items():
                if rule.ip_address == ip_address:
                    rule_to_remove = rule
                    break
            
            if not rule_to_remove:
                return BlockResult(
                    success=False,
                    ip_address=ip_address,
                    rule_id="",
                    message=f"IP address {ip_address} is not currently blocked",
                    timestamp=timestamp,
                    method="not_found"
                )
            
            # Remove the block
            success, method, message = self._remove_block(rule_to_remove)
            
            if success:
                del self.active_rules[rule_to_remove.rule_id]
                self.blocked_ips.discard(ip_address)
                self.stats['total_unblocks'] += 1
                self.stats['active_blocks'] -= 1
                
                self.logger.info(f"Unblocked IP {ip_address} (Rule ID: {rule_to_remove.rule_id})")
            else:
                self.stats['failed_operations'] += 1
                self.logger.error(f"Failed to unblock IP {ip_address}: {message}")
            
            return BlockResult(
                success=success,
                ip_address=ip_address,
                rule_id=rule_to_remove.rule_id,
                message=message,
                timestamp=timestamp,
                method=method
            )
    
    def _apply_block(self, rule: BlockRule) -> Tuple[bool, str, str]:
        """Apply a blocking rule using platform-specific method"""
        
        if self.config['dry_run_mode']:
            return True, "dry_run", f"Dry run: would block {rule.ip_address}"
        
        # Try platform-specific method first
        if self.platform == 'linux':
            success, message = self._apply_iptables_block(rule)
            if success:
                return True, "iptables", message
        elif self.platform == 'windows':
            success, message = self._apply_netsh_block(rule)
            if success:
                return True, "netsh", message
        
        # Fallback to hosts file method
        if self.config['backup_method'] == 'hosts_file':
            success, message = self._apply_hosts_block(rule)
            if success:
                return True, "hosts_file", message
        
        return False, "failed", "All blocking methods failed"
    
    def _remove_block(self, rule: BlockRule) -> Tuple[bool, str, str]:
        """Remove a blocking rule using platform-specific method"""
        
        if self.config['dry_run_mode']:
            return True, "dry_run", f"Dry run: would unblock {rule.ip_address}"
        
        # Try platform-specific method first
        if self.platform == 'linux':
            success, message = self._remove_iptables_block(rule)
            if success:
                return True, "iptables", message
        elif self.platform == 'windows':
            success, message = self._remove_netsh_block(rule)
            if success:
                return True, "netsh", message
        
        # Fallback to hosts file method
        if self.config['backup_method'] == 'hosts_file':
            success, message = self._remove_hosts_block(rule)
            if success:
                return True, "hosts_file", message
        
        return False, "failed", "All unblocking methods failed"
    
    def _apply_iptables_block(self, rule: BlockRule) -> Tuple[bool, str]:
        """Apply block using iptables (Linux)"""
        try:
            chain_name = self.config['chain_name']
            comment = f"{self.config['rule_prefix']}_{rule.rule_id}"
            
            # Add DROP rule
            cmd = [
                'iptables', '-A', chain_name,
                '-s', rule.ip_address,
                '-j', 'DROP',
                '-m', 'comment', '--comment', comment
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True, f"iptables rule added for {rule.ip_address}"
            
        except subprocess.CalledProcessError as e:
            return False, f"iptables error: {e.stderr}"
        except Exception as e:
            return False, f"iptables error: {str(e)}"
    
    def _remove_iptables_block(self, rule: BlockRule) -> Tuple[bool, str]:
        """Remove block using iptables (Linux)"""
        try:
            chain_name = self.config['chain_name']
            comment = f"{self.config['rule_prefix']}_{rule.rule_id}"
            
            # Find and delete the rule
            cmd = [
                'iptables', '-D', chain_name,
                '-s', rule.ip_address,
                '-j', 'DROP',
                '-m', 'comment', '--comment', comment
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True, f"iptables rule removed for {rule.ip_address}"
            
        except subprocess.CalledProcessError as e:
            return False, f"iptables error: {e.stderr}"
        except Exception as e:
            return False, f"iptables error: {str(e)}"
    
    def _apply_netsh_block(self, rule: BlockRule) -> Tuple[bool, str]:
        """Apply block using netsh (Windows)"""
        try:
            rule_name = f"{self.config['rule_prefix']}_{rule.rule_id}"
            
            # Add firewall rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={rule.ip_address}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True, f"Windows firewall rule added for {rule.ip_address}"
            
        except subprocess.CalledProcessError as e:
            return False, f"netsh error: {e.stderr}"
        except Exception as e:
            return False, f"netsh error: {str(e)}"
    
    def _remove_netsh_block(self, rule: BlockRule) -> Tuple[bool, str]:
        """Remove block using netsh (Windows)"""
        try:
            rule_name = f"{self.config['rule_prefix']}_{rule.rule_id}"
            
            # Delete firewall rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True, f"Windows firewall rule removed for {rule.ip_address}"
            
        except subprocess.CalledProcessError as e:
            return False, f"netsh error: {e.stderr}"
        except Exception as e:
            return False, f"netsh error: {str(e)}"
    
    def _apply_hosts_block(self, rule: BlockRule) -> Tuple[bool, str]:
        """Apply block using hosts file (fallback method)"""
        try:
            hosts_file = self._get_hosts_file_path()
            
            # Read current hosts file
            with open(hosts_file, 'r') as f:
                content = f.read()
            
            # Add blocking entry
            block_entry = f"0.0.0.0 {rule.ip_address} # {self.config['rule_prefix']}_{rule.rule_id}\n"
            
            # Append if not already present
            if block_entry.strip() not in content:
                with open(hosts_file, 'a') as f:
                    f.write(block_entry)
            
            return True, f"hosts file entry added for {rule.ip_address}"
            
        except Exception as e:
            return False, f"hosts file error: {str(e)}"
    
    def _remove_hosts_block(self, rule: BlockRule) -> Tuple[bool, str]:
        """Remove block using hosts file (fallback method)"""
        try:
            hosts_file = self._get_hosts_file_path()
            
            # Read current hosts file
            with open(hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Remove blocking entry
            rule_comment = f"{self.config['rule_prefix']}_{rule.rule_id}"
            filtered_lines = [
                line for line in lines 
                if rule_comment not in line or rule.ip_address not in line
            ]
            
            # Write back
            with open(hosts_file, 'w') as f:
                f.writelines(filtered_lines)
            
            return True, f"hosts file entry removed for {rule.ip_address}"
            
        except Exception as e:
            return False, f"hosts file error: {str(e)}"
    
    def _get_hosts_file_path(self) -> str:
        """Get the path to the hosts file for the current platform"""
        if self.platform == 'windows':
            return r"C:\Windows\System32\drivers\etc\hosts"
        else:
            return "/etc/hosts"
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def start_cleanup_thread(self):
        """Start the cleanup thread for expired rules"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            return
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        self.logger.info("Cleanup thread started")
    
    def stop_cleanup_thread(self):
        """Stop the cleanup thread"""
        self.stop_event.set()
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        self.logger.info("Cleanup thread stopped")
    
    def _cleanup_worker(self):
        """Background worker to clean up expired rules"""
        while not self.stop_event.is_set():
            try:
                current_time = time.time()
                expired_rules = []
                
                with self._lock:
                    for rule_id, rule in self.active_rules.items():
                        if (rule.duration and 
                            current_time - rule.timestamp > rule.duration):
                            expired_rules.append(rule)
                
                # Remove expired rules
                for rule in expired_rules:
                    if self.config['enable_automatic_unblock']:
                        result = self.unblock_ip(rule.ip_address)
                        if result.success:
                            self.logger.info(f"Automatically unblocked expired rule: {rule.ip_address}")
                        else:
                            self.logger.error(f"Failed to automatically unblock: {rule.ip_address}")
                
                # Sleep for 60 seconds before next cleanup
                self.stop_event.wait(60)
                
            except Exception as e:
                self.logger.error(f"Error in cleanup worker: {e}")
                self.stop_event.wait(60)
    
    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        with self._lock:
            blocked_list = []
            for rule in self.active_rules.values():
                rule_dict = asdict(rule)
                rule_dict['time_remaining'] = None
                
                if rule.duration:
                    elapsed = time.time() - rule.timestamp
                    remaining = rule.duration - elapsed
                    rule_dict['time_remaining'] = max(0, remaining)
                
                blocked_list.append(rule_dict)
            
            return blocked_list
    
    def clear_all_blocks(self) -> Dict[str, int]:
        """Clear all active blocks"""
        with self._lock:
            results = {'success': 0, 'failed': 0}
            
            # Get list of IPs to unblock
            ips_to_unblock = list(self.blocked_ips)
            
            for ip in ips_to_unblock:
                result = self.unblock_ip(ip)
                if result.success:
                    results['success'] += 1
                else:
                    results['failed'] += 1
            
            return results
    
    def get_stats(self) -> Dict:
        """Get blocking statistics"""
        with self._lock:
            stats = self.stats.copy()
            stats['active_blocks'] = len(self.active_rules)
            stats['runtime'] = time.time() - stats['start_time']
            return stats
    
    def export_rules(self, filename: str) -> bool:
        """Export active rules to JSON file"""
        try:
            with self._lock:
                rules_data = {
                    'export_timestamp': time.time(),
                    'rules': [asdict(rule) for rule in self.active_rules.values()]
                }
            
            with open(filename, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            self.logger.info(f"Exported {len(self.active_rules)} rules to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting rules: {e}")
            return False
    
    def import_rules(self, filename: str) -> Dict[str, int]:
        """Import rules from JSON file"""
        try:
            with open(filename, 'r') as f:
                rules_data = json.load(f)
            
            results = {'success': 0, 'failed': 0, 'skipped': 0}
            
            for rule_dict in rules_data.get('rules', []):
                rule = BlockRule(**rule_dict)
                
                # Check if IP is already blocked
                if rule.ip_address in self.blocked_ips:
                    results['skipped'] += 1
                    continue
                
                # Apply the block
                block_result = self.block_ip(
                    rule.ip_address,
                    rule.reason,
                    rule.severity,
                    rule.duration
                )
                
                if block_result.success:
                    results['success'] += 1
                else:
                    results['failed'] += 1
            
            self.logger.info(f"Imported rules: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error importing rules: {e}")
            return {'success': 0, 'failed': 0, 'skipped': 0}

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create IP blocker (in dry run mode for testing)
    blocker = IPBlocker()
    blocker.config['dry_run_mode'] = True
    
    # Test blocking operations
    print("Testing IP blocking operations...")
    
    # Block some test IPs
    test_ips = [
        ("192.168.1.100", "Port scanning detected", "HIGH"),
        ("10.0.0.50", "Brute force attack", "CRITICAL"),
        ("172.16.1.200", "Malware communication", "HIGH")
    ]
    
    for ip, reason, severity in test_ips:
        result = blocker.block_ip(ip, reason, severity, duration=300)
        print(f"Block {ip}: {'SUCCESS' if result.success else 'FAILED'} - {result.message}")
    
    # Show blocked IPs
    print("\nCurrently blocked IPs:")
    blocked_ips = blocker.get_blocked_ips()
    for rule in blocked_ips:
        print(f"  {rule['ip_address']} - {rule['reason']} (Severity: {rule['severity']})")
    
    # Test unblocking
    print("\nTesting unblock operation...")
    result = blocker.unblock_ip("192.168.1.100")
    print(f"Unblock: {'SUCCESS' if result.success else 'FAILED'} - {result.message}")
    
    # Show statistics
    print("\nBlocking Statistics:")
    stats = blocker.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test export/import
    print("\nTesting export/import...")
    blocker.export_rules("test_rules.json")
    
    # Clear all blocks and import them back
    clear_results = blocker.clear_all_blocks()
    print(f"Cleared blocks: {clear_results}")
    
    import_results = blocker.import_rules("test_rules.json")
    print(f"Import results: {import_results}")
    
    # Stop cleanup thread
    blocker.stop_cleanup_thread()

