from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, Float, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

Base = declarative_base()

class Analysis(Base):
    """Store all security analysis results"""
    __tablename__ = 'analyses'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_type = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    input_data = Column(JSON)
    agent_name = Column(String(50))
    status = Column(String(20))
    severity = Column(String(20))
    threat_detected = Column(Boolean, default=False)
    threat_type = Column(String(50))
    full_results = Column(JSON)
    processing_time = Column(Float)
    cached = Column(Boolean, default=False)

class Threat(Base):
    """Store detected threats"""
    __tablename__ = 'threats'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    threat_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    source_ip = Column(String(45))
    target = Column(String(255))
    description = Column(Text)
    mitre_techniques = Column(JSON)
    recommended_actions = Column(Text)
    analysis_id = Column(Integer)

class Vulnerability(Base):
    """Store CVE vulnerabilities found"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    cve_id = Column(String(50), nullable=False)
    service = Column(String(100))
    version = Column(String(50))
    cvss_score = Column(Float)
    severity = Column(String(20))
    description = Column(Text)
    remediation = Column(Text)
    analysis_id = Column(Integer)

class Incident(Base):
    """Store security incidents"""
    __tablename__ = 'incidents'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    incident_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default='open')
    description = Column(Text)
    containment_actions = Column(Text)
    investigation_steps = Column(Text)
    recovery_plan = Column(Text)
    analysis_id = Column(Integer)

class AgentMetrics(Base):
    """Track agent performance metrics"""
    __tablename__ = 'agent_metrics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    agent_name = Column(String(50), nullable=False)
    operation = Column(String(50))
    processing_time = Column(Float)
    status = Column(String(20))
    error_message = Column(Text)

# Database connection - MYSQL
DATABASE_URL = 'mysql+pymysql://secops:secops123@localhost:3306/secops_db?charset=utf8mb4'

engine = create_engine(
    DATABASE_URL, 
    echo=False,
    pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initialize database tables"""
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
        print(f"📁 Database: secops_db (MySQL)")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()