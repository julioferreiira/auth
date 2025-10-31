
import redis
from config import REDIS_URL

_redis = None

def get_redis():
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _redis
