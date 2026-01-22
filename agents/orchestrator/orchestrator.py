import dspy
from agents.base_agent import BaseAgent
from agents.log_analyzer.log_analyzer import LogAnalyzerAgent
from agents.threat_intel.threat_intel_agent import ThreatIntelAgent
from agents.vuln_scanner.cve_scanner import CVEScannerAgent
from agents.network_scanner.network_scanner_updated import NetworkScannerAgent
from agents.incident_response.incident_responder import IncidentResponderAgent
from dspy_modules.signatures import OrchestratorSignature
from typing import Dict, Any, List

class OrchestratorAgent(BaseAgent):
    """Main orchestrator coordinating all security agents"""
    
    """def __init__(self, config: Dict[str, Any]):
        super().__init__("Orchestrator", config)
        self.coordinator = dspy.ChainOfThought(OrchestratorSignature)
        
        # Initialize all agents
        self.log_analyzer = LogAnalyzerAgent(config.get('log_analyzer', {}))
        self.threat_intel = ThreatIntelAgent(config.get('threat_intel', {}))
        self.cve_scanner = CVEScannerAgent(config.get('cve_scanner', {}))
        self.network_scanner = NetworkScannerAgent(config.get('network_scanner', {}))
        self.incident_responder = IncidentResponderAgent(config.get('incident_responder', {}))
        
        self.log_activity("Orchestrator initialized with 5 agents")"""
    def __init__(self, config: Dict[str, Any], redis_manager=None):
        super().__init__("Orchestrator", config, redis_manager)
        self.coordinator = dspy.ChainOfThought(OrchestratorSignature)
        
        # Initialize all agents WITH Redis
        self.log_analyzer = LogAnalyzerAgent(config.get('log_analyzer', {}), redis_manager)
        self.threat_intel = ThreatIntelAgent(config.get('threat_intel', {}), redis_manager)
        self.cve_scanner = CVEScannerAgent(config.get('cve_scanner', {}), redis_manager)
        self.network_scanner = NetworkScannerAgent(config.get('network_scanner', {}), redis_manager)
        self.incident_responder = IncidentResponderAgent(config.get('incident_responder', {}), redis_manager)
        
        self.log_activity("Orchestrator initialized with 5 agents + Redis")
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main orchestration logic"""
        request_type = input_data.get('request_type', 'full_analysis')
        data = input_data.get('data', {})
        
        self.log_activity(f"Processing {request_type} request")
        
        try:
            if request_type == 'log_analysis':
                return self._handle_log_analysis(data)
            elif request_type == 'threat_intel':
                return self._handle_threat_intel(data)
            elif request_type == 'cve_scan':
                return self._handle_cve_scan(data)
            elif request_type == 'network_scan':
                return self._handle_network_scan(data)
            elif request_type == 'incident_response':
                return self._handle_incident_response(data)
            elif request_type == 'full_analysis':
                return self._handle_full_analysis(data)
            else:
                return {
                    'status': 'error',
                    'error': f'Unknown request type: {request_type}'
                }
        except Exception as e:
            self.log_activity(f"Orchestration error: {str(e)}", "error")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _handle_log_analysis(self, data: Dict) -> Dict:
        result = self.log_analyzer.process(data)
        return {
            'request_type': 'log_analysis',
            'results': {'log_analysis': result},
            'status': 'success'
        }
    
    def _handle_threat_intel(self, data: Dict) -> Dict:
        result = self.threat_intel.process(data)
        return {
            'request_type': 'threat_intel',
            'results': {'threat_intel': result},
            'status': 'success'
        }
    
    def _handle_cve_scan(self, data: Dict) -> Dict:
        result = self.cve_scanner.process(data)
        return {
            'request_type': 'cve_scan',
            'results': {'cve_scan': result},
            'status': 'success'
        }
    
    def _handle_network_scan(self, data: Dict) -> Dict:
        result = self.network_scanner.process(data)
        return {
            'request_type': 'network_scan',
            'results': {'network_scan': result},
            'status': 'success'
        }
    
    def _handle_incident_response(self, data: Dict) -> Dict:
        result = self.incident_responder.process(data)
        return {
            'request_type': 'incident_response',
            'results': {'incident_response': result},
            'status': 'success'
        }
    
    def _handle_full_analysis(self, data: Dict) -> Dict:
        """Handle full multi-agent analysis"""
        self.log_activity("Running full multi-agent analysis")
        
        results = {}
        
        # 1. Log Analysis (if log provided)
        if data.get('log_entry'):
            results['log_analysis'] = self.log_analyzer.process({
                'log_entry': data.get('log_entry', ''),
                'context': data.get('context', '')
            })
        
        # 2. Network Scan (if target provided)
        if data.get('target'):
            results['network_scan'] = self.network_scanner.process({
                'target': data.get('target'),
                'scan_type': data.get('scan_type', 'quick')
            })
        
        # 3. CVE Scan (if service provided)
        if data.get('service'):
            results['cve_scan'] = self.cve_scanner.process({
                'service': data.get('service', ''),
                'version': data.get('version', ''),
                'keywords': data.get('keywords', [])
            })
        
        # 4. Threat Intel (if threat detected)
        if results.get('log_analysis', {}).get('threat_detected') == 'true':
            log_result = results['log_analysis']
            results['threat_intel'] = self.threat_intel.process({
                'threat_description': log_result.get('description', ''),
                'indicators': [log_result.get('threat_type', '')]
            })
        
        # 5. Incident Response (if critical)
        if any(r.get('severity') in ['critical', 'high'] for r in results.values() if isinstance(r, dict)):
            results['incident_response'] = self.incident_responder.process({
                'incident_data': str(results),
                'threat_context': str(results.get('threat_intel', {})),
                'system_state': data.get('context', 'Production')
            })
        
        # Synthesize
        agent_results = self._format_all_results(results)
        synthesis = self.coordinator(
            request_type='full_analysis',
            input_data=str(data),
            agent_results=agent_results
        )
        
        return {
            'request_type': 'full_analysis',
            'results': {
                **results,
                'synthesis': {
                    'priority': synthesis.priority,
                    'summary': synthesis.summary,
                    'recommended_workflow': synthesis.recommended_workflow,
                    'alerts_needed': synthesis.alerts_needed
                }
            },
            'status': 'success'
        }
    
    def _format_all_results(self, results: Dict) -> str:
        """Format all agent results"""
        formatted = "Multi-Agent Analysis Results:\n\n"
        
        for agent_name, result in results.items():
            if isinstance(result, dict) and result.get('status') == 'success':
                formatted += f"{agent_name.upper()}:\n"
                formatted += f"{str(result)[:300]}...\n\n"
        
        return formatted