import dspy
from agents.base_agent import BaseAgent
from typing import Dict, Any
from datetime import datetime

class IncidentResponseSignature(dspy.Signature):
    """Provide incident response recommendations"""
    incident_data = dspy.InputField(desc="Incident details and context")
    threat_context = dspy.InputField(desc="Related threat intelligence")
    system_state = dspy.InputField(desc="Current system state")
    
    severity = dspy.OutputField(desc="Incident severity: critical/high/medium/low")
    incident_type = dspy.OutputField(desc="Type of security incident")
    containment_actions = dspy.OutputField(desc="Immediate containment steps")
    investigation_steps = dspy.OutputField(desc="Investigation procedures")
    recovery_plan = dspy.OutputField(desc="Recovery and remediation plan")
    estimated_impact = dspy.OutputField(desc="Business impact assessment")

class IncidentResponderAgent(BaseAgent):
    """Agent for security incident response"""
    
    def __init__(self, config: Dict[str, Any], redis_manager=None):
        super().__init__("IncidentResponder", config, redis_manager)
        self.responder = dspy.ChainOfThought(IncidentResponseSignature)
        
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Provide incident response guidance"""
        self.log_activity("Processing incident response request")
        
        try:
            incident_data = input_data.get('incident_data', '')
            threat_context = input_data.get('threat_context', 'Unknown threat')
            system_state = input_data.get('system_state', 'Production system')
            
            # Analyze with DSPy
            result = self.responder(
                incident_data=incident_data,
                threat_context=threat_context,
                system_state=system_state
            )
            
            response = {
                'agent': self.agent_name,
                'timestamp': datetime.now().isoformat(),
                'severity': result.severity,
                'incident_type': result.incident_type,
                'containment_actions': result.containment_actions,
                'investigation_steps': result.investigation_steps,
                'recovery_plan': result.recovery_plan,
                'estimated_impact': result.estimated_impact,
                'status': 'success'
            }
            
            self.log_activity(f"Incident triage complete - Severity: {result.severity}")
            return response
        
        except Exception as e:
            self.log_activity(f"Error in incident response: {str(e)}", "error")
            return {
                'agent': self.agent_name,
                'status': 'error',
                'error': str(e)
            }