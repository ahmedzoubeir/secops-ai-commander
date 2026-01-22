import redis
import json
import logging
from typing import Any, Dict, Optional, List

logger = logging.getLogger(__name__)

class RedisManager:
    """Manage Redis connections and operations for agent communication"""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0):
        self.host = host
        self.port = port
        self.db = db
        self.redis_client = None
        self.pubsub = None
        self._connect()
    
    def _connect(self):
        """Connect to Redis server"""
        try:
            self.redis_client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Test connection
            self.redis_client.ping()
            logger.info(f"✅ Connected to Redis at {self.host}:{self.port}")
        except redis.ConnectionError as e:
            logger.warning(f"⚠️  Redis not available: {str(e)}. Operating without cache.")
            self.redis_client = None
    
    def is_available(self) -> bool:
        """Check if Redis is available"""
        if not self.redis_client:
            return False
        try:
            self.redis_client.ping()
            return True
        except:
            return False
    
    # ============= CACHING =============
    
    def cache_set(self, key: str, value: Any, expire: int = 3600) -> bool:
        """Cache a value with expiration (default 1 hour)"""
        if not self.is_available():
            return False
        
        try:
            serialized = json.dumps(value)
            self.redis_client.setex(key, expire, serialized)
            logger.debug(f"📦 Cached: {key} (expires in {expire}s)")
            return True
        except Exception as e:
            logger.error(f"❌ Cache set error: {str(e)}")
            return False
    
    def cache_get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        if not self.is_available():
            return None
        
        try:
            value = self.redis_client.get(key)
            if value:
                logger.debug(f"✅ Cache hit: {key}")
                return json.loads(value)
            logger.debug(f"❌ Cache miss: {key}")
            return None
        except Exception as e:
            logger.error(f"❌ Cache get error: {str(e)}")
            return None
    
    def cache_delete(self, key: str) -> bool:
        """Delete cached value"""
        if not self.is_available():
            return False
        
        try:
            self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"❌ Cache delete error: {str(e)}")
            return False
    
    # ============= TASK QUEUE =============
    
    def queue_task(self, queue_name: str, task_data: Dict) -> bool:
        """Add task to queue"""
        if not self.is_available():
            return False
        
        try:
            serialized = json.dumps(task_data)
            self.redis_client.lpush(queue_name, serialized)
            logger.info(f"📝 Task queued to {queue_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Queue task error: {str(e)}")
            return False
    
    def dequeue_task(self, queue_name: str, timeout: int = 0) -> Optional[Dict]:
        """Get task from queue (blocking if timeout > 0)"""
        if not self.is_available():
            return None
        
        try:
            if timeout > 0:
                result = self.redis_client.brpop(queue_name, timeout=timeout)
                if result:
                    _, task_data = result
                    return json.loads(task_data)
            else:
                task_data = self.redis_client.rpop(queue_name)
                if task_data:
                    return json.loads(task_data)
            return None
        except Exception as e:
            logger.error(f"❌ Dequeue task error: {str(e)}")
            return None
    
    def queue_size(self, queue_name: str) -> int:
        """Get queue size"""
        if not self.is_available():
            return 0
        
        try:
            return self.redis_client.llen(queue_name)
        except:
            return 0
    
    # ============= PUB/SUB =============
    
    def publish_event(self, channel: str, message: Dict) -> bool:
        """Publish event to channel"""
        if not self.is_available():
            return False
        
        try:
            serialized = json.dumps(message)
            self.redis_client.publish(channel, serialized)
            logger.debug(f"📢 Published to {channel}")
            return True
        except Exception as e:
            logger.error(f"❌ Publish error: {str(e)}")
            return False
    
    def subscribe(self, channels: List[str]):
        """Subscribe to channels"""
        if not self.is_available():
            return None
        
        try:
            self.pubsub = self.redis_client.pubsub()
            self.pubsub.subscribe(channels)
            logger.info(f"🔔 Subscribed to {channels}")
            return self.pubsub
        except Exception as e:
            logger.error(f"❌ Subscribe error: {str(e)}")
            return None
    
    # ============= AGENT STATE =============
    
    def set_agent_state(self, agent_name: str, state: Dict) -> bool:
        """Store agent state"""
        key = f"agent:state:{agent_name}"
        return self.cache_set(key, state, expire=300)  # 5 min expiry
    
    def get_agent_state(self, agent_name: str) -> Optional[Dict]:
        """Get agent state"""
        key = f"agent:state:{agent_name}"
        return self.cache_get(key)
    
    def close(self):
        """Close Redis connection"""
        if self.redis_client:
            self.redis_client.close()
            logger.info("🔌 Redis connection closed")