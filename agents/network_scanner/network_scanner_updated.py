import dspy
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
import nmap

class NetworkScanSignature(dspy.Signature):
    """Analyze network scan results for security issues"""
    scan_results = dspy.InputField(desc="Network scan results with open ports and services")
    context = dspy.InputField(desc="Network context and expected services")
    
    security_issues = dspy.OutputField(desc="List of security issues found")
    risk_assessment = dspy.OutputField(desc="Overall risk assessment")
    exposed_services = dspy.OutputField(desc="Potentially dangerous exposed services")
    recommendations = dspy.OutputField(desc="Security recommendations")

class NetworkScannerAgent(BaseAgent):
    """Agent for network scanning and analysis"""
    
    def __init__(self, config: Dict[str, Any], redis_manager=None):
        super().__init__("NetworkScanner", config, redis_manager)
        self.analyzer = dspy.ChainOfThought(NetworkScanSignature)
        self.scanner = nmap.PortScanner()
        self.nmap_available = False
        self._check_nmap()
    
    def _check_nmap(self):
        """Check if nmap is available"""
        try:
            self.scanner.nmap_version()
            self.nmap_available = True
            self.log_activity(f"Nmap version {self.scanner.nmap_version()} is available")
        except Exception as e:
            self.nmap_available = False
            self.log_activity(f"Nmap not available: {str(e)}", "warning")
    
    def scan_host(self, target: str, scan_type: str = 'quick') -> Dict:
        """Perform network scan using python-nmap"""
        if not self.nmap_available:
            return self._mock_scan_results(target)
        
        try:
            self.log_activity(f"Scanning {target} with {scan_type} scan")
            
            # Define scan options
            if scan_type == 'quick':
                # Quick scan: top 100 ports with service detection
                arguments = '-F -sV'
            elif scan_type == 'thorough':
                # Thorough scan: common ports with OS detection
                arguments = '-sV -O -A -p 1-1000'
            elif scan_type == 'stealth':
                # Stealth SYN scan
                arguments = '-sS -sV -p 1-1000'
            else:
                arguments = '-F -sV'
            
            # Run the scan
            self.scanner.scan(target, arguments=arguments)
            
            # Parse results
            return self._parse_scan_results(target)
        
        except nmap.PortScannerError as e:
            self.log_activity(f"Nmap scan error: {str(e)}", "error")
            return self._mock_scan_results(target)
        except Exception as e:
            self.log_activity(f"Scan error: {str(e)}", "error")
            return self._mock_scan_results(target)
    
    def _parse_scan_results(self, target: str) -> Dict:
        """Parse python-nmap scan results"""
        results = {
            'open_ports': [],
            'total_open': 0,
            'host_state': 'unknown',
            'os_detection': None
        }
        
        if target not in self.scanner.all_hosts():
            return results
        
        host_info = self.scanner[target]
        results['host_state'] = host_info.state()
        
        # Get OS detection if available
        if 'osmatch' in host_info:
            os_matches = host_info['osmatch']
            if os_matches:
                results['os_detection'] = os_matches[0].get('name', 'Unknown')
        
        # Get open ports
        for proto in host_info.all_protocols():
            ports = host_info[proto].keys()
            for port in ports:
                port_info = host_info[proto][port]
                if port_info['state'] == 'open':
                    service_info = f"{port_info.get('name', 'unknown')}"
                    if port_info.get('product'):
                        service_info += f" {port_info['product']}"
                    if port_info.get('version'):
                        service_info += f" {port_info['version']}"
                    
                    results['open_ports'].append({
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': service_info,
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    })
        
        results['total_open'] = len(results['open_ports'])
        return results
    
    def _mock_scan_results(self, target: str) -> Dict:
        """Mock scan results for testing when nmap unavailable"""
        self.log_activity("Using mock scan data", "warning")
        return {
            'open_ports': [
                {'port': 22, 'protocol': 'tcp', 'service': 'ssh OpenSSH 8.9', 'product': 'OpenSSH', 'version': '8.9', 'state': 'open'},
                {'port': 80, 'protocol': 'tcp', 'service': 'http Apache 2.4.49', 'product': 'Apache', 'version': '2.4.49', 'state': 'open'},
                {'port': 443, 'protocol': 'tcp', 'service': 'https Apache 2.4.49', 'product': 'Apache', 'version': '2.4.49', 'state': 'open'},
                {'port': 3306, 'protocol': 'tcp', 'service': 'mysql MySQL 8.0', 'product': 'MySQL', 'version': '8.0', 'state': 'open'},
                {'port': 8080, 'protocol': 'tcp', 'service': 'http-proxy', 'product': 'Unknown', 'version': '', 'state': 'open'}
            ],
            'total_open': 5,
            'host_state': 'up',
            'os_detection': 'Linux 3.x',
            'mock': True
        }
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan network and analyze results"""
        self.log_activity("Starting network scan")
        
        try:
            target = input_data.get('target', '127.0.0.1')
            scan_type = input_data.get('scan_type', 'quick')
            context = input_data.get('context', 'Security audit')
            
            # Perform scan
            scan_results = self.scan_host(target, scan_type)
            
            if 'error' in scan_results:
                return {
                    'agent': self.agent_name,
                    'status': 'error',
                    'error': scan_results['error']
                }
            
            # Format results for analysis
            scan_summary = self._format_scan_results(scan_results)
            
            # Analyze with DSPy
            result = self.analyzer(
                scan_results=scan_summary,
                context=context
            )
            
            return {
                'agent': self.agent_name,
                'target': target,
                'host_state': scan_results.get('host_state', 'unknown'),
                'os_detection': scan_results.get('os_detection'),
                'open_ports': scan_results.get('open_ports', []),
                'total_open': scan_results.get('total_open', 0),
                'security_issues': result.security_issues,
                'risk_assessment': result.risk_assessment,
                'exposed_services': result.exposed_services,
                'recommendations': result.recommendations,
                'is_mock': scan_results.get('mock', False),
                'status': 'success'
            }
        
        except Exception as e:
            self.log_activity(f"Error in network scan: {str(e)}", "error")
            return {
                'agent': self.agent_name,
                'status': 'error',
                'error': str(e)
            }
    
    def _format_scan_results(self, results: Dict) -> str:
        """Format scan results for LLM"""
        ports = results.get('open_ports', [])
        
        formatted = f"Network Scan Results for target:\n"
        formatted += f"Host State: {results.get('host_state', 'unknown')}\n"
        
        if results.get('os_detection'):
            formatted += f"OS Detection: {results['os_detection']}\n"
        
        formatted += f"Open Ports: {results.get('total_open', 0)}\n\n"
        
        for p in ports:
            formatted += f"• Port {p['port']}/{p['protocol']} - {p['service']}\n"
            if p.get('product'):
                formatted += f"  Product: {p['product']} {p.get('version', '')}\n"
        
        return formatted