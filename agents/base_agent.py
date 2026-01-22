import dspy
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Base class for all security agents"""
    
    def __init__(self, agent_name: str, config: Dict[str, Any], redis_manager=None):
        self.agent_name = agent_name
        self.config = config
        self.logger = logging.getLogger(f"Agent.{agent_name}")
        self.redis = redis_manager  # Redis manager for caching/messaging
        
    @abstractmethod
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main processing method each agent must implement"""
        pass
    
    def log_activity(self, message: str, level: str = "info"):
        """Log agent activity"""
        if level == "info":
            self.logger.info(f"[{self.agent_name}] {message}")
        elif level == "error":
            self.logger.error(f"[{self.agent_name}] {message}")
        elif level == "warning":
            self.logger.warning(f"[{self.agent_name}] {message}")
    
    def retry_on_rate_limit(self, func, *args, **kwargs):
        """Retry function on rate limit"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if 'rate_limit' in str(e).lower() and attempt < max_retries - 1:
                    wait_time = 5 * (attempt + 1)
                    self.log_activity(f"Rate limit hit, waiting {wait_time}s...", "warning")
                    time.sleep(wait_time)
                else:
                    raise e
    
    # ============= REDIS HELPERS =============
    
    def cache_result(self, cache_key: str, result: Any, expire: int = 3600):
        """Cache agent result"""
        if self.redis and self.redis.is_available():
            self.redis.cache_set(f"{self.agent_name}:{cache_key}", result, expire)
            self.log_activity(f"Cached result: {cache_key}")
    
    def get_cached_result(self, cache_key: str) -> Optional[Any]:
        """Get cached result"""
        if self.redis and self.redis.is_available():
            result = self.redis.cache_get(f"{self.agent_name}:{cache_key}")
            if result:
                self.log_activity(f"Using cached result: {cache_key}")
            return result
        return None
    
    def publish_event(self, event_type: str, data: Dict):
        """Publish event to other agents"""
        if self.redis and self.redis.is_available():
            event = {
                'agent': self.agent_name,
                'type': event_type,
                'data': data,
                'timestamp': time.time()
            }
            self.redis.publish_event(f"agent:{self.agent_name}", event)
            self.log_activity(f"Published event: {event_type}")
    
    def update_state(self, state: Dict):
        """Update agent state in Redis"""
        if self.redis and self.redis.is_available():
            self.redis.set_agent_state(self.agent_name, state)