import logging
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from database.models import Analysis, Threat, Vulnerability, Incident, AgentMetrics, get_db

logger = logging.getLogger(__name__)

from sqlalchemy import text

class DatabaseManager:
    def __init__(self):
        self.db_available = True
        try:
            db = next(get_db())
            db.execute(text("SELECT 1"))  # <-- wrap SQL in text()
            db.close()
            logger.info("✅ Connected to MySQL database")
        except Exception as e:
            logger.warning(f"⚠️  Database not available: {str(e)}")
            self.db_available = False

    
    def store_analysis(self, analysis_data: Dict) -> Optional[int]:
        """Store analysis result in database"""
        if not self.db_available:
            return None
        
        try:
            db = next(get_db())
            
            analysis = Analysis(
                analysis_type=analysis_data.get('request_type', 'unknown'),
                input_data=analysis_data.get('data', {}),
                agent_name=analysis_data.get('agent_name'),
                status=analysis_data.get('status', 'unknown'),
                severity=analysis_data.get('severity'),
                threat_detected=analysis_data.get('threat_detected') == 'true',
                threat_type=analysis_data.get('threat_type'),
                full_results=analysis_data,
                processing_time=analysis_data.get('processing_time', 0),
                cached=analysis_data.get('cached', False)
            )
            
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
            
            analysis_id = analysis.id
            logger.info(f"📊 Stored analysis #{analysis_id}")
            
            db.close()
            return analysis_id
            
        except Exception as e:
            logger.error(f"❌ Error storing analysis: {str(e)}")
            return None
    
    def store_threat(self, threat_data: Dict, analysis_id: Optional[int] = None) -> Optional[int]:
        """Store detected threat"""
        if not self.db_available:
            return None
        
        try:
            db = next(get_db())
            
            threat = Threat(
                threat_type=threat_data.get('threat_type', 'unknown'),
                severity=threat_data.get('severity', 'unknown'),
                source_ip=threat_data.get('source_ip'),
                target=threat_data.get('target'),
                description=threat_data.get('description'),
                mitre_techniques=threat_data.get('mitre_techniques', []),
                recommended_actions=threat_data.get('recommended_actions'),
                analysis_id=analysis_id
            )
            
            db.add(threat)
            db.commit()
            db.refresh(threat)
            
            threat_id = threat.id
            logger.info(f"🚨 Stored threat #{threat_id}")
            
            db.close()
            return threat_id
            
        except Exception as e:
            logger.error(f"❌ Error storing threat: {str(e)}")
            return None
    
    def store_vulnerabilities(self, cves: List[Dict], analysis_id: Optional[int] = None) -> int:
        """Store CVE vulnerabilities"""
        if not self.db_available or not cves:
            return 0
        
        try:
            db = next(get_db())
            count = 0
            
            for cve_data in cves:
                vuln = Vulnerability(
                    cve_id=cve_data.get('cve_id'),
                    service=cve_data.get('service'),
                    version=cve_data.get('version'),
                    cvss_score=cve_data.get('cvss_score', 0.0),
                    severity=cve_data.get('severity', 'UNKNOWN'),
                    description=cve_data.get('description'),
                    remediation=cve_data.get('remediation'),
                    analysis_id=analysis_id
                )
                db.add(vuln)
                count += 1
            
            db.commit()
            logger.info(f"🔐 Stored {count} vulnerabilities")
            
            db.close()
            return count
            
        except Exception as e:
            logger.error(f"❌ Error storing vulnerabilities: {str(e)}")
            return 0
    
    def store_incident(self, incident_data: Dict, analysis_id: Optional[int] = None) -> Optional[int]:
        """Store security incident"""
        if not self.db_available:
            return None
        
        try:
            db = next(get_db())
            
            incident = Incident(
                incident_type=incident_data.get('incident_type', 'unknown'),
                severity=incident_data.get('severity', 'unknown'),
                status='open',
                description=incident_data.get('description'),
                containment_actions=incident_data.get('containment_actions'),
                investigation_steps=incident_data.get('investigation_steps'),
                recovery_plan=incident_data.get('recovery_plan'),
                analysis_id=analysis_id
            )
            
            db.add(incident)
            db.commit()
            db.refresh(incident)
            
            incident_id = incident.id
            logger.info(f"📋 Stored incident #{incident_id}")
            
            db.close()
            return incident_id
            
        except Exception as e:
            logger.error(f"❌ Error storing incident: {str(e)}")
            return None
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """Get recent analyses"""
        if not self.db_available:
            return []
        
        try:
            db = next(get_db())
            analyses = db.query(Analysis).order_by(Analysis.timestamp.desc()).limit(limit).all()
            
            results = []
            for a in analyses:
                results.append({
                    'id': a.id,
                    'type': a.analysis_type,
                    'timestamp': a.timestamp.isoformat(),
                    'severity': a.severity,
                    'threat_detected': a.threat_detected,
                    'agent': a.agent_name
                })
            
            db.close()
            return results
            
        except Exception as e:
            logger.error(f"❌ Error getting analyses: {str(e)}")
            return []
    
    def get_threats_by_severity(self, severity: str, limit: int = 10) -> List[Dict]:
        """Get threats by severity level"""
        if not self.db_available:
            return []
        
        try:
            db = next(get_db())
            threats = db.query(Threat).filter(
                Threat.severity == severity
            ).order_by(Threat.timestamp.desc()).limit(limit).all()
            
            results = []
            for t in threats:
                results.append({
                    'id': t.id,
                    'type': t.threat_type,
                    'timestamp': t.timestamp.isoformat(),
                    'source_ip': t.source_ip,
                    'description': t.description
                })
            
            db.close()
            return results
            
        except Exception as e:
            logger.error(f"❌ Error getting threats: {str(e)}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get security statistics"""
        if not self.db_available:
            return {}
        
        try:
            db = next(get_db())
            
            stats = {
                'total_analyses': db.query(Analysis).count(),
                'total_threats': db.query(Threat).count(),
                'total_vulnerabilities': db.query(Vulnerability).count(),
                'open_incidents': db.query(Incident).filter(Incident.status == 'open').count(),
                'critical_threats': db.query(Threat).filter(Threat.severity == 'critical').count()
            }
            
            db.close()
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error getting statistics: {str(e)}")
            return {}