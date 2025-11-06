from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_connection
import psycopg2.extras
import time
import uuid
from cryptography.fernet import Fernet, InvalidToken
from cache import get_redis
import config

import hashlib
import hmac
import secrets

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


fernet = Fernet(config.FERNET_KEY.encode())

redis = get_redis()


def generate_token(user_id: int) -> str:
    """Gera token simétrico (Fernet) contendo user_id:issued_at"""
    payload = f"{user_id}:{int(time.time())}".encode()
    return fernet.encrypt(payload).decode()

def decrypt_token(token: str):
    """Decripta token e verifica TTL manualmente. Retorna (user_id, issued_at) ou (None, None)."""
    try:
        data = fernet.decrypt(token.encode()).decode()
        user_id_str, issued_at_str = data.split(":")
        issued_at = int(issued_at_str)
        if (int(time.time()) - issued_at) > config.TOKEN_TTL:
            return None, None
        return int(user_id_str), issued_at
    except (InvalidToken, Exception):
        return None, None


def rate_limit_zset(key: str, max_requests: int, window_seconds: int):
    """
    Retorna tuple (allowed:bool, remaining:int, ttl:int)
    Implementa sliding-window com sorted set usando timestamp em ms.
    """
    now_ms = int(time.time() * 1000)
    window_ms = window_seconds * 1000
    zkey = f"rl:{key}"

   
    pipe = redis.pipeline()
   
    pipe.zremrangebyscore(zkey, 0, now_ms - window_ms)
    
    member = str(uuid.uuid4())
    pipe.zadd(zkey, {member: now_ms})
   
    pipe.zcard(zkey)
    
    pipe.expire(zkey, window_seconds + 5)
    removed, added, count, _ = pipe.execute()

    allowed = int(count) <= max_requests
    remaining = max_requests - int(count) if allowed else 0
    ttl = redis.ttl(zkey)
    return allowed, remaining, ttl


def throttle_ip(ip: str, max_requests: int, window_seconds: int):
    """
    Simples throttle por IP com INCR+EXPIRE.
    Retorna (allowed, remaining, ttl)
    """
    key = f"throttle:ip:{ip}"
    current = redis.incr(key)
    if current == 1:
        redis.expire(key, window_seconds)
    remaining = max(0, max_requests - int(current))
    ttl = redis.ttl(key)
    return (int(current) <= max_requests, remaining, ttl)


def create_reset_token_for_user(user_id: int):
    """
    Gera token seguro para reset:
    - cria token aleatório (enviado por e-mail ao usuário)
    - armazena apenas HASH(token) no Redis (pwreset:<hash> -> user_id)
    - retorna token (cru) para ser enviado por e-mail
    """
    token = secrets.token_urlsafe(32)  
    hashed = hashlib.sha256(token.encode()).hexdigest()
    redis.setex(f"pwreset:{hashed}", config.RESET_TTL, user_id)
    return token

def verify_reset_token(token: str):
    """
    Verifica token de reset: compara hash do token e retorna user_id se válido.
    """
    hashed = hashlib.sha256(token.encode()).hexdigest()
    key = f"pwreset:{hashed}"
    user_id = redis.get(key)
    if not user_id:
        return None
   
    redis.delete(key)
    return int(user_id)



@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json or {}
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not nome or not email or not senha:
        return jsonify({"error": "Preencha todos os campos."}), 400

    senha_hash = generate_password_hash(senha)

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (nome, email, senha) VALUES (%s, %s, %s)",
            (nome, email, senha_hash)
        )
        conn.commit()
        return jsonify({"message": "Usuário criado com sucesso!"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Erro ao criar usuário.", "details": str(e)}), 400
    finally:
        cursor.close()
        conn.close()


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({"error": "Email e senha são obrigatórios."}), 400

    a
