import dspy

class LogAnalysisSignature(dspy.Signature):
    """Analyze security logs and detect threats"""
    log_entry = dspy.InputField(desc="Security log entry to analyze")
    context = dspy.InputField(desc="Additional context about the system")
    
    threat_detected = dspy.OutputField(desc="Boolean: true if threat detected, false otherwise")
    severity = dspy.OutputField(desc="Severity level: critical, high, medium, low, info")
    threat_type = dspy.OutputField(desc="Type of threat: intrusion, malware, anomaly, policy_violation, none")
    description = dspy.OutputField(desc="Detailed description of findings")
    recommended_action = dspy.OutputField(desc="Recommended security action")

class CVEMatchSignature(dspy.Signature):
    """Match services/software to known CVEs"""
    service_info = dspy.InputField(desc="Service name and version information")
    cve_data = dspy.InputField(desc="Relevant CVE information from database")
    
    vulnerabilities_found = dspy.OutputField(desc="List of applicable CVEs with CVSS scores")
    risk_assessment = dspy.OutputField(desc="Overall risk assessment")
    remediation_priority = dspy.OutputField(desc="Priority level: immediate, high, medium, low")
    remediation_steps = dspy.OutputField(desc="Specific steps to remediate vulnerabilities")

class IncidentTriageSignature(dspy.Signature):
    """Triage security incidents and recommend response"""
    incident_data = dspy.InputField(desc="Security incident information")
    threat_context = dspy.InputField(desc="Related threat intelligence")
    
    incident_severity = dspy.OutputField(desc="Incident severity: critical, high, medium, low")
    incident_type = dspy.OutputField(desc="Classification of incident")
    containment_actions = dspy.OutputField(desc="Immediate containment actions")
    investigation_steps = dspy.OutputField(desc="Investigation procedures")
    estimated_impact = dspy.OutputField(desc="Potential business impact")

class OrchestratorSignature(dspy.Signature):
    """Orchestrate multi-agent security operations"""
    request_type = dspy.InputField(desc="Type of security request: log_analysis, vuln_scan, incident_response")
    input_data = dspy.InputField(desc="Input data for the request")
    agent_results = dspy.InputField(desc="Results from specialized agents")
    
    priority = dspy.OutputField(desc="Overall priority: critical, high, medium, low")
    summary = dspy.OutputField(desc="Executive summary of findings")
    recommended_workflow = dspy.OutputField(desc="Recommended next steps and workflow")
    alerts_needed = dspy.OutputField(desc="List of alerts that should be generated")

class ThreatIntelSignature(dspy.Signature):
    """Map security events to MITRE ATT&CK framework"""
    threat_description = dspy.InputField(desc="Description of the threat or attack pattern")
    mitre_techniques = dspy.InputField(desc="Relevant MITRE ATT&CK techniques")
    
    matched_tactics = dspy.OutputField(desc="MITRE ATT&CK tactics identified")
    matched_techniques = dspy.OutputField(desc="Specific techniques with IDs")
    threat_actor_groups = dspy.OutputField(desc="Potential threat actor groups")
    attack_chain = dspy.OutputField(desc="Likely attack chain/kill chain stages")
    mitigation_strategies = dspy.OutputField(desc="MITRE-recommended mitigations")


class CVEScanSignature(dspy.Signature):
    """Match services to CVE vulnerabilities"""
    service_info = dspy.InputField(desc="Service name and version")
    cve_database = dspy.InputField(desc="Relevant CVE entries")
    
    vulnerabilities = dspy.OutputField(desc="List of CVEs with severity scores")
    risk_level = dspy.OutputField(desc="Overall risk: critical/high/medium/low")
    remediation = dspy.OutputField(desc="Recommended fixes and patches")
    priority_actions = dspy.OutputField(desc="Immediate actions to take")

class NetworkScanSignature(dspy.Signature):
    """Analyze network scan results for security issues"""
    scan_results = dspy.InputField(desc="Network scan results with open ports and services")
    context = dspy.InputField(desc="Network context and expected services")
    
    security_issues = dspy.OutputField(desc="List of security issues found")
    risk_assessment = dspy.OutputField(desc="Overall risk assessment")
    exposed_services = dspy.OutputField(desc="Potentially dangerous exposed services")
    recommendations = dspy.OutputField(desc="Security recommendations")

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