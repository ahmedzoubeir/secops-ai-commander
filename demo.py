import time
from config import AGENT_CONFIG, redis_manager
from agents.orchestrator.orchestrator import OrchestratorAgent
from database.db_manager import DatabaseManager
import json

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}\n")

def print_section(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}▶ {text}{Colors.END}")

def print_result(label, value, color=Colors.GREEN):
    print(f"{Colors.BOLD}{label}:{Colors.END} {color}{value}{Colors.END}")

def demo():
    print_header("🛡️ SecOps AI Commander - Live Demo")
    
    print(f"{Colors.BOLD}Welcome to SecOps AI Commander!{Colors.END}")
    print("This demo showcases our multi-agent AI security platform.\n")
    
    time.sleep(2)
    
    # Initialize
    print_section("Initializing System...")
    orchestrator = OrchestratorAgent({
        'log_analyzer': AGENT_CONFIG['log_analyzer'],
        'threat_intel': AGENT_CONFIG['threat_intel'],
        'cve_scanner': AGENT_CONFIG['cve_scanner'],
        'network_scanner': AGENT_CONFIG['network_scanner'],
        'incident_responder': AGENT_CONFIG['incident_responder']
    }, redis_manager=redis_manager)
    
    db = DatabaseManager()
    
    print(f"{Colors.GREEN}✓ Orchestrator initialized with 5 AI agents{Colors.END}")
    print(f"{Colors.GREEN}✓ Redis cache connected{Colors.END}")
    print(f"{Colors.GREEN}✓ MySQL database connected{Colors.END}")
    
    time.sleep(2)
    
    # Demo 1: SSH Brute Force Attack
    print_header("SCENARIO 1: SSH Brute Force Attack Detection")
    
    print_section("Simulating real security log from production server...")
    scenario1 = {
        'request_type': 'full_analysis',
        'data': {
            'log_entry': '2025-01-20 14:23:45 sshd[5234]: Failed password for root from 185.220.101.42 port 52314 ssh2 (15 attempts in 60 seconds)',
            'context': 'Production web server - AWS EC2',
            'service': 'OpenSSH',
            'version': '7.4'
        }
    }
    
    print(f"\n{Colors.YELLOW}Log Entry:{Colors.END}")
    print(f"  {scenario1['data']['log_entry']}")
    
    time.sleep(2)
    
    print_section("Analyzing with AI agents...")
    result1 = orchestrator.process(scenario1)
    
    if result1['status'] == 'success':
        # Log Analysis Results
        log = result1['results']['log_analysis']
        print_section("🔍 Log Analysis Results")
        print_result("  Threat Detected", log.get('threat_detected'), Colors.RED if log.get('threat_detected') == 'true' else Colors.GREEN)
        print_result("  Severity", log.get('severity'), Colors.RED)
        print_result("  Threat Type", log.get('threat_type'), Colors.YELLOW)
        print(f"\n  {Colors.BOLD}Description:{Colors.END}")
        print(f"  {log.get('description', '')[:200]}...")
        
        time.sleep(2)
        
        # Threat Intelligence
        if 'threat_intel' in result1['results']:
            ti = result1['results']['threat_intel']
            print_section("🎯 MITRE ATT&CK Mapping")
            techniques = ti.get('mitre_techniques_found', [])
            print_result("  Techniques Found", len(techniques), Colors.CYAN)
            for tech in techniques[:3]:
                print(f"    • {Colors.BOLD}{tech.get('technique_id')}{Colors.END}: {tech.get('technique')}")
        
        time.sleep(2)
        
        # CVE Results
        if 'cve_scan' in result1['results']:
            cve = result1['results']['cve_scan']
            print_section("🔐 Vulnerability Scan Results")
            print_result("  CVEs Found", cve.get('total_cves', 0), Colors.RED if cve.get('total_cves', 0) > 0 else Colors.GREEN)
            print_result("  Risk Level", cve.get('risk_level', 'N/A'), Colors.YELLOW)
        
        time.sleep(2)
        
        # Incident Response
        if 'incident_response' in result1['results']:
            ir = result1['results']['incident_response']
            print_section("📋 Incident Response Recommendations")
            print_result("  Severity", ir.get('severity', 'N/A'), Colors.RED)
            print(f"\n  {Colors.BOLD}Containment Actions:{Colors.END}")
            print(f"  {str(ir.get('containment_actions', ''))[:200]}...")
        
        # Store in database
        db.store_analysis(result1['results'].get('log_analysis', {}))
        print(f"\n{Colors.GREEN}✓ Analysis stored in database{Colors.END}")
    
    time.sleep(3)
    
    # Demo 2: Ransomware Detection
    print_header("SCENARIO 2: Ransomware Detection")
    
    print_section("Simulating ransomware activity...")
    scenario2 = {
        'request_type': 'log_analysis',
        'data': {
            'log_entry': 'WARNING: Multiple files encrypted with .locked extension. Process encrypt.exe detected. Ransom note created: README_DECRYPT.txt',
            'context': 'File server - Windows Server 2019'
        }
    }
    
    print(f"\n{Colors.YELLOW}Log Entry:{Colors.END}")
    print(f"  {scenario2['data']['log_entry']}")
    
    time.sleep(2)
    
    print_section("Analyzing...")
    result2 = orchestrator.process(scenario2)
    
    if result2['status'] == 'success':
        log = result2['results']['log_analysis']
        print_section("🔍 Analysis Results")
        print_result("  Threat Type", log.get('threat_type'), Colors.RED)
        print_result("  Severity", log.get('severity'), Colors.RED)
        print(f"\n  {Colors.BOLD}Recommended Action:{Colors.END}")
        print(f"  {log.get('recommended_action', '')[:200]}...")
        
        db.store_analysis(log)
    
    time.sleep(3)
    
    # Demo 3: Network Scan
    print_header("SCENARIO 3: Network Security Scan")
    
    print_section("Scanning localhost for open ports...")
    scenario3 = {
        'request_type': 'network_scan',
        'data': {
            'target': '127.0.0.1',
            'scan_type': 'quick'
        }
    }
    
    time.sleep(2)
    
    result3 = orchestrator.process(scenario3)
    
    if result3['status'] == 'success':
        net = result3['results']['network_scan']
        print_section("🌐 Network Scan Results")
        print_result("  Host State", net.get('host_state', 'unknown'), Colors.GREEN)
        print_result("  Open Ports", net.get('total_open', 0), Colors.YELLOW)
        
        print(f"\n  {Colors.BOLD}Discovered Services:{Colors.END}")
        for port in net.get('open_ports', [])[:5]:
            print(f"    • Port {Colors.BOLD}{port['port']}/{port['protocol']}{Colors.END}: {port['service']}")
        
        print(f"\n  {Colors.BOLD}Risk Assessment:{Colors.END}")
        print(f"  {net.get('risk_assessment', '')[:150]}...")
    
    time.sleep(3)
    
    # Database Statistics
    print_header("📊 System Statistics")
    
    stats = db.get_statistics()
    print_section("Database Summary")
    print_result("  Total Analyses", stats.get('total_analyses', 0), Colors.CYAN)
    print_result("  Threats Detected", stats.get('total_threats', 0), Colors.YELLOW)
    print_result("  Vulnerabilities", stats.get('total_vulnerabilities', 0), Colors.RED)
    print_result("  Open Incidents", stats.get('open_incidents', 0), Colors.YELLOW)
    
    time.sleep(2)
    
    # Finale
    print_header("✅ Demo Complete!")
    
    print(f"""
{Colors.BOLD}SecOps AI Commander Features Demonstrated:{Colors.END}

{Colors.GREEN}✓{Colors.END} Real-time log analysis with AI
{Colors.GREEN}✓{Colors.END} MITRE ATT&CK threat intelligence mapping
{Colors.GREEN}✓{Colors.END} Automated CVE vulnerability scanning
{Colors.GREEN}✓{Colors.END} Network security assessment
{Colors.GREEN}✓{Colors.END} Incident response recommendations
{Colors.GREEN}✓{Colors.END} Multi-agent coordination
{Colors.GREEN}✓{Colors.END} Database persistence
{Colors.GREEN}✓{Colors.END} Redis caching


{Colors.BOLD}Built with:{Colors.END} DSPy, Groq, FastAPI, MITRE ATT&CK, Redis, MySQL
    """)

if __name__ == "__main__":
    demo()