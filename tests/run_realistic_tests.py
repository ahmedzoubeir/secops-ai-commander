import sys
import os
# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import AGENT_CONFIG
from agents.orchestrator.orchestrator import OrchestratorAgent
from tests.test_data import TEST_SCENARIOS, VULNERABLE_SOFTWARE
import json

def run_scenario_tests():
    print("🎯 Running Realistic Security Scenarios\n")
    print("="*70)
    
    orchestrator = OrchestratorAgent({
        'log_analyzer': AGENT_CONFIG['log_analyzer'],
        'threat_intel': AGENT_CONFIG['threat_intel'],
        'cve_scanner': AGENT_CONFIG['cve_scanner'],
        'network_scanner': AGENT_CONFIG['network_scanner'],
        'incident_responder': AGENT_CONFIG['incident_responder']
    })
    
    passed = 0
    failed = 0
    
    for scenario_name, scenario_data in TEST_SCENARIOS.items():
        print(f"\n📋 Scenario: {scenario_name.upper()}")
        print("-"*70)
        
        result = orchestrator.process({
            'request_type': 'full_analysis',
            'data': scenario_data
        })
        
        if result['status'] == 'success':
            results = result['results']
            
            # Check log analysis
            if 'log_analysis' in results:
                log = results['log_analysis']
                print(f"✓ Threat Detected: {log.get('threat_detected')}")
                print(f"✓ Severity: {log.get('severity')}")
                print(f"✓ Type: {log.get('threat_type')}")
                
                # Validate against expected
                expected_sev = scenario_data.get('expected_severity')
                if expected_sev and log.get('severity') == expected_sev:
                    print(f"✅ Severity matches expected: {expected_sev}")
                    passed += 1
                elif expected_sev:
                    print(f"⚠️  Expected {expected_sev}, got {log.get('severity')}")
                    failed += 1
            
            # Check CVE results
            if 'cve_scan' in results:
                cve = results['cve_scan']
                print(f"✓ CVEs Found: {cve.get('total_cves', 0)}")
                if cve.get('total_cves', 0) > 0:
                    print(f"✓ Risk Level: {cve.get('risk_level')}")
                    top_cve = cve.get('cves_found', [{}])[0]
                    print(f"✓ Top CVE: {top_cve.get('cve_id')} (CVSS: {top_cve.get('cvss_score')})")
            
            # Check MITRE mapping
            if 'threat_intel' in results:
                ti = results['threat_intel']
                techniques = ti.get('mitre_techniques_found', [])
                if techniques:
                    print(f"✓ MITRE Techniques: {len(techniques)}")
                    for tech in techniques[:2]:
                        print(f"  - {tech.get('technique_id')}: {tech.get('technique')}")
            
            # Check incident response
            if 'incident_response' in results:
                ir = results['incident_response']
                print(f"✓ Incident Severity: {ir.get('severity')}")
                print(f"✓ Response Type: {ir.get('incident_type')}")
        else:
            print(f"❌ Scenario failed: {result.get('error')}")
            failed += 1
        
        print("="*70)
    
    print(f"\n📊 Test Summary:")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    total = passed + failed
    if total > 0:
        print(f"📈 Success Rate: {(passed/total*100):.1f}%")

if __name__ == "__main__":
    run_scenario_tests()