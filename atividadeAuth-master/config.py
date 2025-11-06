
import os
from cryptography.fernet import Fernet

FERNET_KEY = os.environ.get("FERNET_KEY") or Fernet.generate_key().decode()

TOKEN_TTL = int(os.environ.get("TOKEN_TTL", 3600))   
RESET_TTL = int(os.environ.get("RESET_TTL", 900))   


RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", 5))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))


LOGIN_BLOCK_SECONDS = int(os.environ.get("LOGIN_BLOCK_SECONDS", 600))  
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", 3))

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
