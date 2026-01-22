# demo1.py
import time
from config import AGENT_CONFIG, redis_manager
from agents.orchestrator.orchestrator import OrchestratorAgent
from database.db_manager import DatabaseManager
import random

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
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text.center(80)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.END}\n")

def print_section(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}▶ {text}{Colors.END}")

def print_result(label, value, color=Colors.GREEN):
    print(f"{Colors.BOLD}{label}:{Colors.END} {color}{value}{Colors.END}")

def demo():
    print_header("🛡️ SecOps AI Commander - Advanced Demo 1")
    
    print(f"{Colors.BOLD}Welcome!{Colors.END} This demo highlights multi-step attacks and AI responses.\n")
    time.sleep(2)
    
    # Initialize Orchestrator & DB
    print_section("Initializing System and Agents...")
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
    
    ##########################
    # SCENARIO 1: Brute Force → Privilege Escalation
    ##########################
    print_header("SCENARIO 1: Multi-Stage SSH Attack")
    
    logs = [
        "Failed password for root from 185.220.101.42 port 52314 ssh2 (15 attempts in 60s)",
        "Failed password for admin from 185.220.101.42 port 52315 ssh2 (12 attempts in 45s)",
        "User 'root' successfully logged in from 185.220.101.42"
    ]
    
    for log_entry in logs:
        print_section(f"Simulating log: {log_entry[:50]}...")
        scenario = {'request_type': 'full_analysis', 'data': {
            'log_entry': log_entry,
            'context': 'Production Linux server - AWS EC2',
            'service': 'OpenSSH',
            'version': '7.4'
        }}
        result = orchestrator.process(scenario)
        
        if result['status'] == 'success':
            log = result['results']['log_analysis']
            print_result("Threat Detected", log.get('threat_detected'), Colors.RED if log.get('threat_detected')=='true' else Colors.GREEN)
            print_result("Severity", log.get('severity'), Colors.RED)
            print_result("Threat Type", log.get('threat_type'), Colors.YELLOW)
            print(f"\n  {Colors.BOLD}Description:{Colors.END}")
            print(f"  {log.get('description', '')[:150]}...\n")
            
            # MITRE ATT&CK mapping
            if 'threat_intel' in result['results']:
                ti = result['results']['threat_intel']
                techniques = ti.get('mitre_techniques_found', [])
                if techniques:
                    print_section("🎯 MITRE ATT&CK Mapping")
                    print_result("Techniques Found", len(techniques), Colors.CYAN)
                    for tech in techniques[:4]:
                        print(f"  • {Colors.BOLD}{tech.get('technique_id')}{Colors.END}: {tech.get('technique')}")
            
            db.store_analysis(log)
        time.sleep(2)
    
    ##########################
    # SCENARIO 2: Ransomware + Lateral Movement
    ##########################
    print_header("SCENARIO 2: Ransomware with Lateral Movement")
    
    logs = [
        "WARNING: Multiple files encrypted with .locked extension. Process encrypt.exe detected. Ransom note created: README_DECRYPT.txt",
        "Suspicious SMB connection from 192.168.1.105 to 192.168.1.110",
        "Process powershell.exe executed with encoded commands on host 192.168.1.110"
    ]
    
    for log_entry in logs:
        print_section(f"Analyzing log: {log_entry[:50]}...")
        scenario = {'request_type': 'log_analysis', 'data': {
            'log_entry': log_entry,
            'context': 'Windows file server & internal network'
        }}
        result = orchestrator.process(scenario)
        
        if result['status'] == 'success':
            log = result['results']['log_analysis']
            print_result("Threat Type", log.get('threat_type'), Colors.RED)
            print_result("Severity", log.get('severity'), Colors.RED)
            print(f"\n  {Colors.BOLD}Recommended Action:{Colors.END}")
            print(f"  {log.get('recommended_action', '')[:150]}...\n")
            db.store_analysis(log)
        time.sleep(2)
    
    ##########################
    # SCENARIO 3: Network Scan + Exploit Detection
    ##########################
    print_header("SCENARIO 3: Network Security Scan with CVE Analysis")
    
    targets = ["127.0.0.1", "192.168.1.50"]
    for target in targets:
        print_section(f"Scanning {target} for open ports & vulnerabilities...")
        scenario = {'request_type': 'network_scan', 'data': {'target': target, 'scan_type': 'quick'}}
        result = orchestrator.process(scenario)
        
        if result['status'] == 'success':
            net = result['results']['network_scan']
            print_result("Host State", net.get('host_state', 'unknown'), Colors.GREEN)
            print_result("Open Ports", net.get('total_open', 0), Colors.YELLOW)
            for port in net.get('open_ports', [])[:5]:
                print(f"  • Port {Colors.BOLD}{port['port']}/{port['protocol']}{Colors.END}: {port['service']}")
            
            if 'cve_scan' in net:
                cve = net['cve_scan']
                print_section("🔐 CVE Vulnerabilities Found")
                print_result("Total CVEs", cve.get('total_cves', 0), Colors.RED if cve.get('total_cves', 0) > 0 else Colors.GREEN)
            
            print(f"\n  {Colors.BOLD}Risk Assessment:{Colors.END}")
            print(f"  {net.get('risk_assessment', '')[:150]}...\n")
        time.sleep(2)
    
    ##########################
    # Final System Stats
    ##########################
    print_header("📊 System Statistics")
    
    stats = db.get_statistics()
    print_section("Database Summary")
    print_result("Total Analyses", stats.get('total_analyses', 0), Colors.CYAN)
    print_result("Threats Detected", stats.get('total_threats', 0), Colors.YELLOW)
    print_result("Vulnerabilities", stats.get('total_vulnerabilities', 0), Colors.RED)
    print_result("Open Incidents", stats.get('open_incidents', 0), Colors.YELLOW)
    
    time.sleep(2)
    print_header("✅ Demo Complete!")
    
    print(f"""
{Colors.BOLD}SecOps AI Commander Features Demonstrated:{Colors.END}

{Colors.GREEN}✓{Colors.END} Multi-stage attack detection
{Colors.GREEN}✓{Colors.END} Real-time log analysis with AI
{Colors.GREEN}✓{Colors.END} MITRE ATT&CK mapping & recommendations
{Colors.GREEN}✓{Colors.END} CVE vulnerability scanning
{Colors.GREEN}✓{Colors.END} Network security assessment
{Colors.GREEN}✓{Colors.END} Incident response planning
{Colors.GREEN}✓{Colors.END} Database persistence & stats
{Colors.GREEN}✓{Colors.END} Redis caching

Built with: DSPy, Groq, FastAPI, MITRE ATT&CK, Redis, MySQL
    """)

if __name__ == "__main__":
    demo()
