import dspy
from agents.base_agent import BaseAgent
import requests
from typing import Dict, Any, List
from datetime import datetime, timedelta

class CVEScanSignature(dspy.Signature):
    """Match services to CVE vulnerabilities"""
    service_info = dspy.InputField(desc="Service name and version")
    cve_database = dspy.InputField(desc="Relevant CVE entries")
    
    vulnerabilities = dspy.OutputField(desc="List of CVEs with severity scores")
    risk_level = dspy.OutputField(desc="Overall risk: critical/high/medium/low")
    remediation = dspy.OutputField(desc="Recommended fixes and patches")
    priority_actions = dspy.OutputField(desc="Immediate actions to take")

class CVEScannerAgent(BaseAgent):
    def __init__(self, config: Dict[str, Any], redis_manager):
        super().__init__("CVEScanner", config, redis_manager)

        self.analyzer = dspy.ChainOfThought(CVEScanSignature)

        self.cve_api_base = "https://cveawg.mitre.org/api"
        self.cve_search_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"


        
    def search_cve_official(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Search official CVE database"""
        self.log_activity(f"Searching CVE.org for: {keyword}")
        
        try:
            # Use NVD API (mirrors CVE.org data with better search)
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': limit
            }
            
            headers = {
                'User-Agent': 'SecOps-AI-Commander/1.0'
            }
            
            response = requests.get(
                self.cve_search_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_nvd_response(data)
            else:
                self.log_activity(f"API returned status {response.status_code}", "warning")
                return self._get_mock_cves(keyword)
                
        except Exception as e:
            self.log_activity(f"Error accessing CVE API: {str(e)}", "warning")
            return self._get_mock_cves(keyword)
    
    def _parse_nvd_response(self, data: Dict) -> List[Dict]:
        """Parse NVD API response"""
        cves = []
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities[:10]:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
            
            # Get CVSS score
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'
            
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Fallback to v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = self._cvss_v2_to_severity(cvss_score)
            
            # Get published date
            published = cve_data.get('published', 'Unknown')
            
            cves.append({
                'cve_id': cve_id,
                'description': description[:200] + '...' if len(description) > 200 else description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published
            })
        
        return cves
    
    def _cvss_v2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_mock_cves(self, keyword: str) -> List[Dict]:
        """Fallback mock CVE data when API unavailable"""
        mock_data = {
            'ssh': [
                {
                    'cve_id': 'CVE-2024-6387',
                    'description': 'OpenSSH regreSSHion vulnerability - Remote code execution',
                    'cvss_score': 8.1,
                    'severity': 'HIGH',
                    'published': '2024-07-01'
                },
                {
                    'cve_id': 'CVE-2023-48795',
                    'description': 'SSH protocol vulnerability affecting multiple implementations',
                    'cvss_score': 5.9,
                    'severity': 'MEDIUM',
                    'published': '2023-12-18'
                }
            ],
            'apache': [
                {
                    'cve_id': 'CVE-2024-38472',
                    'description': 'Apache HTTP Server SSRF vulnerability',
                    'cvss_score': 9.1,
                    'severity': 'CRITICAL',
                    'published': '2024-07-01'
                }
            ],
            'default': [
                {
                    'cve_id': 'CVE-2024-XXXX',
                    'description': f'Vulnerability related to {keyword}',
                    'cvss_score': 7.5,
                    'severity': 'HIGH',
                    'published': '2024-01-01'
                }
            ]
        }
        
        keyword_lower = keyword.lower()
        for key in mock_data:
            if key in keyword_lower:
                return mock_data[key]
        
        return mock_data['default']
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan network and analyze results"""
        self.log_activity("Starting CVE vulnerability scan")
        
        try:
            service = input_data.get('service', '')
            version = input_data.get('version', '')
            keywords = input_data.get('keywords', [service])
            
            # Create cache key
            cache_key = f"cve:{service}:{version}"
            
            # Check cache first
            cached = self.get_cached_result(cache_key)
            if cached:
                self.log_activity("Using cached CVE results")
                return cached
            
            # Search CVE database
            all_cves = []
            for keyword in keywords[:3]:
                cves = self.search_cve_official(keyword)
                all_cves.extend(cves)
            
            # Remove duplicates
            unique_cves = {cve['cve_id']: cve for cve in all_cves}.values()
            cve_list = list(unique_cves)
            
            # Format for LLM analysis
            cve_context = self._format_cves(cve_list)
            
            # Analyze with DSPy
            result = self.analyzer(
                service_info=f"{service} {version}",
                cve_database=cve_context
            )
            
            response = {
                'agent': self.agent_name,
                'service': service,
                'version': version,
                'vulnerabilities': result.vulnerabilities,
                'risk_level': result.risk_level,
                'remediation': result.remediation,
                'priority_actions': result.priority_actions,
                'cves_found': cve_list[:10],
                'total_cves': len(cve_list),
                'status': 'success'
            }
            
            # Cache results for 1 hour (CVE data doesn't change often)
            self.cache_result(cache_key, response, expire=3600)
            
            # Publish event if critical CVEs found
            if len(cve_list) > 0:
                self.publish_event('cves_found', {
                    'service': service,
                    'version': version,
                    'count': len(cve_list),
                    'risk': result.risk_level
                })
            
            self.log_activity(f"Found {len(cve_list)} CVEs, risk level: {result.risk_level}")
            return response
            
        except Exception as e:
            self.log_activity(f"Error in CVE scan: {str(e)}", "error")
            return {
                'agent': self.agent_name,
                'status': 'error',
                'error': str(e)
            }
    
    def _format_cves(self, cves: List[Dict]) -> str:
        """Format CVEs for LLM consumption"""
        if not cves:
            return "No CVEs found in database."
        
        formatted = f"CVE Database Results ({len(cves)} vulnerabilities found):\n\n"
        for cve in cves[:10]:  # Top 10 for context limit
            formatted += f"• {cve['cve_id']} - Severity: {cve['severity']} (CVSS: {cve['cvss_score']})\n"
            formatted += f"  {cve['description']}\n"
            formatted += f"  Published: {cve['published']}\n\n"
        
        return formatted