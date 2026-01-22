import dspy
from agents.base_agent import BaseAgent
from typing import Dict, Any, List
import pandas as pd
import requests
import json

class ThreatIntelSignature(dspy.Signature):
    """Map security events to MITRE ATT&CK framework"""
    threat_description = dspy.InputField(desc="Description of the threat or attack pattern")
    mitre_techniques = dspy.InputField(desc="Relevant MITRE ATT&CK techniques")
    
    matched_tactics = dspy.OutputField(desc="MITRE ATT&CK tactics identified")
    matched_techniques = dspy.OutputField(desc="Specific techniques with IDs")
    threat_actor_groups = dspy.OutputField(desc="Potential threat actor groups")
    attack_chain = dspy.OutputField(desc="Likely attack chain/kill chain stages")
    mitigation_strategies = dspy.OutputField(desc="MITRE-recommended mitigations")

class ThreatIntelAgent(BaseAgent):
    """Agent for threat intelligence using MITRE ATT&CK"""
    
    def __init__(self, config: Dict[str, Any], redis_manager=None):
        super().__init__("ThreatIntel", config, redis_manager)
        self.analyzer = dspy.ChainOfThought(ThreatIntelSignature)
        self.attack_github_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        self._load_mitre_data()
        #self._check_mitre_data()
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK data from official source"""
        try:
            # Try official GitHub source first
            self.log_activity("Attempting to load from MITRE GitHub...")
            response = requests.get(self.attack_github_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                self._parse_attack_data(data)
                self.log_activity(f"Loaded {len(self.techniques)} techniques from MITRE GitHub")
                return
            else:
                raise Exception(f"GitHub API returned {response.status_code}")
                
        except Exception as e:
            self.log_activity(f"Could not load from GitHub: {str(e)}", "warning")
            self._load_static_mitre_data()
    
    def _parse_attack_data(self, data: Dict):
        """Parse official MITRE ATT&CK STIX data"""
        self.techniques = []
        self.groups = []
        self.software = []
        
        for obj in data.get('objects', []):
            obj_type = obj.get('type', '')
            
            # Parse techniques
            if obj_type == 'attack-pattern':
                technique_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break
                
                if technique_id:
                    # Get tactics
                    tactics = []
                    for phase in obj.get('kill_chain_phases', []):
                        tactics.append(phase.get('phase_name', '').replace('-', ' ').title())
                    
                    self.techniques.append({
                        'technique_id': technique_id,
                        'technique': obj.get('name', ''),
                        'tactic': ', '.join(tactics) if tactics else 'Unknown',
                        'description': obj.get('description', '')[:300]
                    })
            
            # Parse groups
            elif obj_type == 'intrusion-set':
                group_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        group_id = ref.get('external_id')
                        break
                
                if group_id:
                    self.groups.append({
                        'group': obj.get('name', ''),
                        'group_id': group_id,
                        'description': obj.get('description', '')[:200]
                    })
        
        self.techniques_df = pd.DataFrame(self.techniques)
        self.groups_df = pd.DataFrame(self.groups)
    
    def _load_static_mitre_data(self):
        """Fallback: Use expanded static MITRE data"""
        self.log_activity("Using static MITRE data")
        
        self.techniques = [
            {
                'technique_id': 'T1078',
                'technique': 'Valid Accounts',
                'tactic': 'Defense Evasion, Persistence, Privilege Escalation, Initial Access',
                'description': 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.'
            },
            {
                'technique_id': 'T1110',
                'technique': 'Brute Force',
                'tactic': 'Credential Access',
                'description': 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.'
            },
            {
                'technique_id': 'T1110.001',
                'technique': 'Brute Force: Password Guessing',
                'tactic': 'Credential Access',
                'description': 'Adversaries may use password guessing to gain access to accounts without knowledge of a valid password.'
            },
            {
                'technique_id': 'T1110.003',
                'technique': 'Brute Force: Password Spraying',
                'tactic': 'Credential Access',
                'description': 'Adversaries may use password spraying to gain access to accounts by trying a single common password against many accounts.'
            },
            {
                'technique_id': 'T1021.004',
                'technique': 'Remote Services: SSH',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH).'
            },
            {
                'technique_id': 'T1059',
                'technique': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.'
            },
            {
                'technique_id': 'T1071',
                'technique': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using application layer protocols to avoid detection/network filtering.'
            },
            {
                'technique_id': 'T1190',
                'technique': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.'
            },
            {
                'technique_id': 'T1566',
                'technique': 'Phishing',
                'tactic': 'Initial Access',
                'description': 'Adversaries may send phishing messages to gain access to victim systems.'
            },
            {
                'technique_id': 'T1486',
                'technique': 'Data Encrypted for Impact',
                'tactic': 'Impact',
                'description': 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability.'
            },
            {
                'technique_id': 'T1595',
                'technique': 'Active Scanning',
                'tactic': 'Reconnaissance',
                'description': 'Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.'
            },
            {
                'technique_id': 'T1133',
                'technique': 'External Remote Services',
                'tactic': 'Persistence, Initial Access',
                'description': 'Adversaries may leverage external-facing remote services to gain initial access or persistence.'
            }
        ]
        
        self.groups = [
            {'group': 'APT28', 'group_id': 'G0007', 'description': 'Russian military intelligence cyber espionage group'},
            {'group': 'APT29', 'group_id': 'G0016', 'description': 'Russian intelligence cyber espionage group'},
            {'group': 'Lazarus Group', 'group_id': 'G0032', 'description': 'North Korean state-sponsored threat group'},
            {'group': 'APT41', 'group_id': 'G0096', 'description': 'Chinese state-sponsored group conducting espionage and financially-motivated operations'}
        ]
        
        self.techniques_df = pd.DataFrame(self.techniques)
        self.groups_df = pd.DataFrame(self.groups)
    
    def search_techniques(self, keywords: List[str]) -> List[Dict]:
        """Search MITRE techniques by keywords"""
        if self.techniques_df.empty:
            return []
        
        results = []
        for keyword in keywords:
            keyword_lower = keyword.lower()
            matches = self.techniques_df[
                self.techniques_df['technique'].str.lower().str.contains(keyword_lower, na=False) |
                self.techniques_df['description'].str.lower().str.contains(keyword_lower, na=False)
            ]
            results.extend(matches.to_dict('records'))
        
        # Remove duplicates
        seen = set()
        unique_results = []
        for r in results:
            tid = r.get('technique_id')
            if tid not in seen:
                seen.add(tid)
                unique_results.append(r)
        
        return unique_results[:10]
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat and map to MITRE ATT&CK"""
        self.log_activity("Processing threat intelligence request")
        
        try:
            threat_desc = input_data.get('threat_description', '')
            indicators = input_data.get('indicators', [])
            
            # Search for relevant MITRE techniques
            relevant_techniques = self.search_techniques(indicators) if indicators else []
            
            # Format techniques for LLM
            mitre_context = self._format_mitre_context(relevant_techniques)
            
            # Analyze with DSPy
            result = self.analyzer(
                threat_description=threat_desc,
                mitre_techniques=mitre_context
            )
            
            response = {
                'agent': self.agent_name,
                'matched_tactics': result.matched_tactics,
                'matched_techniques': result.matched_techniques,
                'threat_actor_groups': result.threat_actor_groups,
                'attack_chain': result.attack_chain,
                'mitigation_strategies': result.mitigation_strategies,
                'mitre_techniques_found': relevant_techniques[:5],
                'status': 'success'
            }
            
            self.log_activity("Threat intelligence analysis complete")
            return response
            
        except Exception as e:
            self.log_activity(f"Error in threat analysis: {str(e)}", "error")
            return {
                'agent': self.agent_name,
                'status': 'error',
                'error': str(e)
            }
    
    def _format_mitre_context(self, techniques: List[Dict]) -> str:
        """Format MITRE techniques for LLM consumption"""
        if not techniques:
            return "No specific MITRE techniques found in database."
        
        context = "Relevant MITRE ATT&CK Techniques:\n"
        for tech in techniques[:5]:
            context += f"- {tech.get('technique_id', 'N/A')}: {tech.get('technique', 'N/A')}\n"
            context += f"  Tactic: {tech.get('tactic', 'N/A')}\n"
            context += f"  Description: {tech.get('description', 'N/A')[:200]}...\n\n"
        
        return context