
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_connection
import psycopg2.extras
import time
import uuid
from cryptography.fernet import Fernet, InvalidToken
from cache import get_redis
import config

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

    agora = int(time.time())
    attempts_key = f"login_attempts:{email}"
    blocked_key = f"login_blocked:{email}"

    blocked_until = redis.get(blocked_key)
    if blocked_until:
        blocked_until = int(blocked_until)
        if agora < blocked_until:
            restante = blocked_until - agora
            return jsonify({"error": f"Conta bloqueada. Tente novamente em {restante} segundos."}), 403
        else:
            
            redis.delete(blocked_key)
            redis.delete(attempts_key)

   
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT id, nome, email, senha FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if user and check_password_hash(user['senha'], senha):
       
        redis.delete(attempts_key)
        token = generate_token(user['id'])
        return jsonify({
            "message": "Login bem-sucedido!",
            "token": token,
            "usuario": {"id": user['id'], "nome": user['nome'], "email": user['email']}
        }), 200
    else:
      
        attempts = redis.incr(attempts_key)
        redis.expire(attempts_key, config.LOGIN_BLOCK_SECONDS)
        if int(attempts) >= config.LOGIN_MAX_ATTEMPTS:
            redis.set(blocked_key, agora + config.LOGIN_BLOCK_SECONDS, ex=config.LOGIN_BLOCK_SECONDS)
            return jsonify({"error": "Muitas tentativas falhas. Conta bloqueada temporariamente."}), 403
        return jsonify({"error": "Credenciais inválidas.", "attempts": int(attempts)}), 401


@auth_bp.route('/recuperar-senha/request', methods=['POST'])
def request_password_reset():
    data = request.json or {}
    email = data.get('email')
    if not email:
        return jsonify({"error": "Informe o email."}), 400

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

   
    generic = {"message": "Se o email existir, você receberá instruções para resetar a senha."}
    if not user:
        return jsonify(generic), 200

    reset_token = str(uuid.uuid4())
    redis.setex(f"pwreset:{reset_token}", config.RESET_TTL, user['id'])

   
    return jsonify({
        "message": "Token gerado (em produção: enviado por email).",
        "reset_token": reset_token,
        "expires_in": config.RESET_TTL
    }), 200

@auth_bp.route('/recuperar-senha/confirm', methods=['POST'])
def confirm_password_reset():
    data = request.json or {}
    reset_token = data.get('reset_token')
    nova_senha = data.get('nova_senha')
    if not reset_token or not nova_senha:
        return jsonify({"error": "reset_token e nova_senha são obrigatórios."}), 400

    key = f"pwreset:{reset_token}"
    user_id = redis.get(key)
    if not user_id:
        return jsonify({"error": "Token inválido ou expirado."}), 400

   
    redis.delete(key)

    nova_hash = generate_password_hash(nova_senha)
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET senha = %s WHERE id = %s", (nova_hash, int(user_id)))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Erro ao atualizar senha."}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": "Senha atualizada com sucesso."}), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "Logout efetuado com sucesso."}), 200


def rate_limited(user_id: int):
    key = f"rate:me:{user_id}"
    window = config.RATE_LIMIT_WINDOW
    max_requests = config.RATE_LIMIT_MAX

    current = redis.incr(key)
    if current == 1:
        redis.expire(key, window)
    remaining = max(0, max_requests - int(current))
    ttl = redis.ttl(key)
    return (int(current) <= max_requests, remaining, ttl)

@auth_bp.route('/me', methods=['GET'])
def me():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({"error": "Token ausente."}), 401
    token = auth.split(" ", 1)[1]
    user_id, issued_at = decrypt_token(token)
    if not user_id:
        return jsonify({"error": "Token inválido ou expirado."}), 401

    allowed, remaining, ttl = rate_limited(user_id)
    if not allowed:
        return jsonify({"error": f"Rate limit atingido. Tente novamente em {ttl} segundos."}), 429

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT id, nome, email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404

    return jsonify({
        "id": user['id'],
        "nome": user['nome'],
        "email": user['email'],
        "rate_remaining": remaining
    }), 200
