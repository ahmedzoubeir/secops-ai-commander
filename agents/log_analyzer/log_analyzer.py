import dspy
from agents.base_agent import BaseAgent
from dspy_modules.signatures import LogAnalysisSignature
from typing import Dict, Any

class LogAnalyzerAgent(BaseAgent):
    """Agent specialized in analyzing security logs"""
    
    def __init__(self, config: Dict[str, Any], redis_manager=None):
        super().__init__("LogAnalyzer", config, redis_manager)
        self.analyzer = dspy.ChainOfThought(LogAnalysisSignature)
        
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security logs for threats
        
        Args:
            input_data: {
                'log_entry': str,
                'context': str (optional)
            }
        """
        self.log_activity("Processing log entry")
        
        try:
            log_entry = input_data.get('log_entry', '')
            context = input_data.get('context', 'Standard security monitoring')
            
            # Run DSPy analysis
            result = self.analyzer(
                log_entry=log_entry,
                context=context
            )
            
            response = {
                'agent': self.agent_name,
                'threat_detected': result.threat_detected,
                'severity': result.severity,
                'threat_type': result.threat_type,
                'description': result.description,
                'recommended_action': result.recommended_action,
                'status': 'success'
            }
            
            self.log_activity(f"Analysis complete - Severity: {result.severity}")
            return response
            
        except Exception as e:
            self.log_activity(f"Error processing log: {str(e)}", "error")
            return {
                'agent': self.agent_name,
                'status': 'error',
                'error': str(e)
            }