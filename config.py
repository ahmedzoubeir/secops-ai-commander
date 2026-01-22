import dspy
import os
from dotenv import load_dotenv

load_dotenv()

# Groq LLM setup - Updated DSPy syntax
groq_api_key = os.getenv('GROQ_API_KEY')

groq_llm = dspy.LM(
    model='groq/llama-3.3-70b-versatile',
    api_key=groq_api_key
)

dspy.configure(lm=groq_llm)

# Agent configuration
AGENT_CONFIG = {
    'log_analyzer': {
        'model': 'groq/llama-3.3-70b-versatile',
        'max_tokens': 2048
    },
    'cve_scanner': {
        'model': 'groq/llama-3.3-70b-versatile',
        'max_tokens': 2048
    },
    'threat_intel': {
        'model': 'groq/llama-3.3-70b-versatile',
        'max_tokens': 3072
    },
    'network_scanner': {  # ADD
        'model': 'groq/llama-3.3-70b-versatile',
        'max_tokens': 2048
    },
    'incident_responder': {  # ADD
        'model': 'groq/llama-3.3-70b-versatile',
        'max_tokens': 3072
    },
    'orchestrator': {
        'model': 'groq/llama-3.3-70b-versatile',
        'max_tokens': 3072
    }
}
from integrations.redis_manager import RedisManager

# Redis setup (after Groq setup)
REDIS_CONFIG = {
    'host': os.getenv('REDIS_HOST', 'localhost'),
    'port': int(os.getenv('REDIS_PORT', 6379)),
    'db': int(os.getenv('REDIS_DB', 0))
}

# Initialize Redis manager (gracefully degrades if unavailable)
redis_manager = RedisManager(**REDIS_CONFIG)