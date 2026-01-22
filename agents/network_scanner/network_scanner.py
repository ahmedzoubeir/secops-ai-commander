import dspy
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
import subprocess
import json
import re

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
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("NetworkScanner", config)
        self.analyzer = dspy.ChainOfThought(NetworkScanSignature)
        self._check_nmap()
    
    def _check_nmap(self):
        """Check if nmap is available"""
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
            self.nmap_available = True
            self.log_activity("Nmap is available")
        except:
            self.nmap_available = False
            self.log_activity("Nmap not available, using mock data", "warning")
    
    def scan_host(self, target: str, scan_type: str = 'quick') -> Dict:
        """Perform network scan"""
        if not self.nmap_available:
            return self._mock_scan_results(target)
        
        try:
            # Quick scan: top 100 ports
            if scan_type == 'quick':
                cmd = ['nmap', '-F', '-sV', target]
            # Full scan: all ports
            else:
                cmd = ['nmap', '-p-', '-sV', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_output(result.stdout)
        
        except subprocess.TimeoutExpired:
            self.log_activity("Scan timeout", "error")
            return {'error': 'Scan timeout'}
        except Exception as e:
            self.log_activity(f"Scan error: {str(e)}", "error")
            return self._mock_scan_results(target)
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse nmap output"""
        ports = []
        
        # Extract open ports
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                match = re.search(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.*)', line)
                if match:
                    port, protocol, state, service = match.groups()
                    if state == 'open':
                        ports.append({
                            'port': int(port),
                            'protocol': protocol,
                            'service': service.strip()
                        })
        
        return {
            'open_ports': ports,
            'total_open': len(ports)
        }
    
    def _mock_scan_results(self, target: str) -> Dict:
        """Mock scan results for testing"""
        return {
            'open_ports': [
                {'port': 22, 'protocol': 'tcp', 'service': 'ssh OpenSSH 8.9'},
                {'port': 80, 'protocol': 'tcp', 'service': 'http Apache 2.4.49'},
                {'port': 443, 'protocol': 'tcp', 'service': 'https Apache 2.4.49'},
                {'port': 3306, 'protocol': 'tcp', 'service': 'mysql MySQL 8.0'},
                {'port': 8080, 'protocol': 'tcp', 'service': 'http-proxy'}
            ],
            'total_open': 5,
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
        
        formatted = f"Network Scan Results - {results.get('total_open', 0)} open ports found:\n\n"
        
        for p in ports:
            formatted += f"• Port {p['port']}/{p['protocol']} - {p['service']}\n"
        
        return formatted