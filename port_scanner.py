import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
from typing import List, Dict, Optional, Tuple

class PortScanner:
    def __init__(self, max_threads: int = 100):
        self.max_threads = max_threads
        self.common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 27017: 'MongoDB'
        }

    def scan_port(self, target: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
        """Scan a single port on the target host"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.common_ports.get(port, 'unknown')
                    return {
                        'port': port,
                        'state': 'open',
                        'service': service
                    }
        except socket.gaierror:
            print(colored(f'Hostname {target} could not be resolved', 'red'))
        except socket.error:
            pass
        return None

    def scan_target(self, target: str, port_range: Tuple[int, int] = (1, 65535), 
                    timeout: float = 1.0) -> List[Dict]:
        """Scan a range of ports on the target host"""
        print(colored(f'\nStarting scan on host {target}', 'cyan'))
        start_time = time.time()
        open_ports = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            port_range_list = range(port_range[0], port_range[1] + 1)
            future_to_port = {
                executor.submit(self.scan_port, target, port, timeout): port 
                for port in port_range_list
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        self._print_port_info(result)
                except Exception as e:
                    print(colored(f'Error scanning port {port}: {str(e)}', 'red'))

        scan_time = time.time() - start_time
        self._print_summary(target, open_ports, scan_time)
        return open_ports

    def _print_port_info(self, port_info: Dict):
        """Print information about an open port"""
        print(colored(f"Port {port_info['port']} is {port_info['state']} "
                      f"({port_info['service']})", 'green'))

    def _print_summary(self, target: str, open_ports: List[Dict], scan_time: float):
        """Print scan summary"""
        print(colored('\nScan Summary:', 'yellow'))
        print(colored(f'Target Host: {target}', 'yellow'))
        print(colored(f'Open Ports: {len(open_ports)}', 'yellow'))
        print(colored(f'Scan Duration: {scan_time:.2f} seconds', 'yellow'))

def main():
    scanner = PortScanner()
    target = input('Enter target host without http/https: ')

    try:
        start_port = int(input('Enter start port (default 1): ') or 1)
        end_port = int(input('Enter end port (default 65535): ') or 65535)
    except ValueError:
        print(colored('Invalid input. Please enter numeric values for ports.', 'red'))
        return

    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535) or start_port > end_port:
        print(colored('Invalid port range. Please enter ports must be between 1 and 65535, and start <= end.', 'red'))
        return

    scanner.scan_target(target, (start_port, end_port))

if __name__ == '__main__':
    main()
