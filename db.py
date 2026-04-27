import psycopg2
from psycopg2.pool import SimpleConnectionPool
from flask import g
import os

# ==============================
# CONFIG (use env em produção)
# ==============================

DB_CONFIG = {
    "host": "localhost",
    "database": "controlcam_db",
    "user": "devanderson",
    "password": "123456"
}

# ==============================
# POOL DE CONEXÕES
# ==============================

pool = SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    **DB_CONFIG
)


# ==============================
# CONEXÃO POR REQUEST (FLASK)
# ==============================

def get_db():
    if "db" not in g:
        g.db = pool.getconn()
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        pool.putconn(db)


# ==============================
# INIT DB (RODAR UMA VEZ)
# ==============================

def init_db():
    conn = pool.getconn()
    cursor = conn.cursor()

    # ==============================
    # EMPRESAS
    # ==============================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id SERIAL PRIMARY KEY,
            nome_empresa TEXT NOT NULL,
            token_api TEXT UNIQUE NOT NULL,
            criada_em TIMESTAMP DEFAULT NOW()
        );
    """)

    # ==============================
    # USUARIOS
    # ==============================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            tipo TEXT NOT NULL DEFAULT 'empresa'
        );
    """)

    # ==============================
    # CAMERAS
    # ==============================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cameras (
            id SERIAL PRIMARY KEY,
            nome_camera TEXT NOT NULL,
            ip_camera TEXT NOT NULL,
            caixa TEXT,
            rua1 TEXT,
            rua2 TEXT,
            mac TEXT,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            UNIQUE(ip_camera, empresa_id),
            UNIQUE(nome_camera, empresa_id)
        );
    """)

    # ==============================
    # AGENTES
    # ==============================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agentes (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            nome_maquina TEXT NOT NULL,
            ip_local TEXT,
            ultimo_heartbeat TIMESTAMP
        );
    """)

    # ==============================
    # COMANDOS (FILA)
    # ==============================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comandos (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            agente_id INTEGER NOT NULL REFERENCES agentes(id) ON DELETE CASCADE,
            tipo TEXT NOT NULL,
            alvo TEXT,
            status TEXT DEFAULT 'pendente',
            resultado TEXT,
            criado_em TIMESTAMP DEFAULT NOW(),
            executado_em TIMESTAMP
        );
    """)

    # ==============================
    # ÍNDICES (PERFORMANCE)
    # ==============================
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_comandos_status ON comandos(status);
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_comandos_agente ON comandos(agente_id);
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_agentes_empresa ON agentes(empresa_id);
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_cameras_empresa ON cameras(empresa_id);
    """)

    conn.commit()
    cursor.close()
    pool.putconn(conn)