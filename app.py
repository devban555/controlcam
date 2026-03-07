from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import subprocess
import re
import secrets
from flask import jsonify
import datetime
from psycopg2.extras import RealDictCursor
from flask import jsonify

token = secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = "controlcam_secret_key"

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("tipo") != "admin_global":
            return "Acesso negado", 403
        return f(*args, **kwargs)
    return decorated

# 🔐 LOGIN REQUIRED
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

import psycopg2
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "host": "localhost",
    "database": "controlcam_db",
    "user": "devanderson",
    "password": "123456"
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id SERIAL PRIMARY KEY,
            nome_empresa TEXT NOT NULL,
            token_api TEXT UNIQUE NOT NULL,
            criada_em TIMESTAMP DEFAULT NOW()
        );
    """)

    # USUARIOS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id),
            tipo TEXT NOT NULL DEFAULT 'empresa'
        );
    """)

    # CAMERAS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cameras (
            id SERIAL PRIMARY KEY,
            nome_camera TEXT NOT NULL,
            ip_camera TEXT NOT NULL,
            caixa TEXT,
            rua1 TEXT,
            rua2 TEXT,
            mac TEXT,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id),
            UNIQUE(ip_camera, empresa_id),
            UNIQUE(nome_camera, empresa_id)
        );
    """)

    # AGENTES
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agentes (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id),
            nome_maquina TEXT NOT NULL,
            ip_local TEXT,
            ultimo_heartbeat TIMESTAMP
        );
    """)

    # COMANDOS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comandos (
            id SERIAL PRIMARY KEY,
            empresa_id INTEGER NOT NULL REFERENCES empresas(id),
            agente_id INTEGER NOT NULL REFERENCES agentes(id),
            tipo TEXT NOT NULL,
            alvo TEXT,
            status TEXT DEFAULT 'pendente',
            resultado TEXT,
            criado_em TIMESTAMP,
            executado_em TIMESTAMP
        );
    """)

    conn.commit()
    cursor.close()
    conn.close()


init_db()

#------------------------------------------------------------------------
#-----Rotas do Admin Global

from werkzeug.security import generate_password_hash

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # empresas
    cursor.execute("""
        SELECT id, nome_empresa, token_api
        FROM empresas
        ORDER BY id DESC
    """)
    empresas = cursor.fetchall()

    # usuarios
    cursor.execute("""
        SELECT usuarios.id,
               usuarios.username,
               usuarios.empresa_id,
               empresas.nome_empresa
        FROM usuarios
        LEFT JOIN empresas
        ON usuarios.empresa_id = empresas.id
        ORDER BY usuarios.id DESC
    """)
    usuarios = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        empresas=empresas,
        usuarios=usuarios
    )


@app.route("/admin/criar_empresa", methods=["POST"])
@login_required
@admin_required
def criar_empresa():

    nome = request.form.get("nome_empresa")
    token = secrets.token_hex(32)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO empresas (nome_empresa, token_api, criada_em)
        VALUES (%s, %s, NOW())
    """, (nome, token))

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/excluir_empresa/<int:empresa_id>")
@login_required
@admin_required
def excluir_empresa(empresa_id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM empresas WHERE id = %s",
        (empresa_id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/criar_usuario", methods=["POST"])
@login_required
@admin_required
def criar_usuario():

    empresa_id = request.form.get("empresa_id")
    username = request.form.get("username")
    senha = generate_password_hash(request.form.get("senha"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO usuarios (empresa_id, username, senha, tipo)
        VALUES (%s, %s, %s, 'empresa')
    """, (empresa_id, username, senha))

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/agentes/<int:empresa_id>")
@login_required
@admin_required
def ver_agentes(empresa_id):

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("""
        SELECT *
        FROM agentes
        WHERE empresa_id = %s
        ORDER BY ultimo_heartbeat DESC
    """, (empresa_id,))

    agentes = cursor.fetchall()

    conn.close()

    return render_template(
        "admin_agentes.html",
        agentes=agentes
    )

@app.route("/alterar_empresa_usuario", methods=["POST"])
def alterar_empresa_usuario():

    usuario_id = request.form.get("usuario_id")
    empresa_id = request.form.get("empresa_id")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE usuarios
        SET empresa_id = %s
        WHERE id = %s
    """, (empresa_id, usuario_id))

    conn.commit()

    cursor.close()
    conn.close()

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/excluir_usuario/<int:usuario_id>")
@login_required
@admin_required
def excluir_usuario(usuario_id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM usuarios WHERE id = %s",
        (usuario_id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))
#------------------------------------------------------------------------

@app.route("/api/agent/heartbeat", methods=["POST"])
def agent_heartbeat():

    # aceitar token via header OU JSON
    data = request.get_json(silent=True)

    token = request.headers.get("Authorization")

    if not token and data and "token" in data:
        token = data["token"]

    if not token:
        return jsonify({"error": "Token ausente"}), 401

    conn = get_db()
    cursor = conn.cursor()

    # validar empresa
    cursor.execute(
        "SELECT id FROM empresas WHERE token_api = %s",
        (token,)
    )
    empresa = cursor.fetchone()

    if not empresa:
        cursor.close()
        conn.close()
        return jsonify({"error": "Token inválido"}), 403

    empresa_id = empresa[0]

    cursor.execute("""
        SELECT ultimo_heartbeat
        FROM agentes
        WHERE empresa_id = %s
        ORDER BY ultimo_heartbeat DESC
        LIMIT 1
    """, (empresa_id,))

    agente = cursor.fetchone()

    agente_status = "OFF"

    if agente:
        ultimo = agente[0]
        agora = datetime.datetime.now()

        if (agora - ultimo).total_seconds() < 30:
            agente_status = "ON"

    # usar JSON seguro
    nome_maquina = None
    ip_local = None

    if data:
        nome_maquina = data.get("nome_maquina")
        ip_local = data.get("ip_local")

    agora = datetime.datetime.now()

    # verificar se agente existe
    cursor.execute("""
        SELECT id FROM agentes
        WHERE empresa_id = %s AND nome_maquina = %s
    """, (empresa_id, nome_maquina))

    agente = cursor.fetchone()

    if agente:
        agente_id = agente[0]

        cursor.execute("""
            UPDATE agentes
            SET ultimo_heartbeat = %s, ip_local = %s
            WHERE id = %s
        """, (agora, ip_local, agente_id))

    else:
        cursor.execute("""
            INSERT INTO agentes (empresa_id, nome_maquina, ip_local, ultimo_heartbeat)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (empresa_id, nome_maquina, ip_local, agora))

        agente_id = cursor.fetchone()[0]

    # buscar comando pendente
    cursor.execute("""
        SELECT id, tipo, alvo
        FROM comandos
        WHERE agente_id = %s
          AND status = 'pendente'
        ORDER BY id ASC
        LIMIT 1
    """, (agente_id,))

    comando = cursor.fetchone()

    print("AGENTE_ID:", agente_id)
    print("COMANDO BRUTO:", comando)

    if comando:
        comando_id, tipo, alvo = comando

        cursor.execute("""
            UPDATE comandos
            SET status = 'enviado'
            WHERE id = %s
        """, (comando_id,))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            "status": "ok",
            "comando": {
                "id": comando_id,
                "tipo": tipo,
                "alvo": alvo
            }
        })

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "ok"})

@app.route("/api/agent/resultado", methods=["POST"])
def agent_resultado():

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token ausente"}), 401

    conn = get_db()
    cursor = conn.cursor()

    # validar empresa pelo token
    cursor.execute(
        "SELECT id FROM empresas WHERE token_api = %s",
        (token,)
    )
    empresa = cursor.fetchone()

    if not empresa:
        cursor.close()
        conn.close()
        return jsonify({"error": "Token inválido"}), 403

    empresa_id = empresa[0]

    comando_id = request.json.get("comando_id")
    resultado = request.json.get("resultado")
    agora = datetime.datetime.now()

    # garantir que comando pertence à empresa
    cursor.execute("""
        UPDATE comandos
        SET status = 'executado',
            resultado = %s,
            executado_em = %s
        WHERE id = %s
          AND empresa_id = %s
    """, (resultado, agora, comando_id, empresa_id))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "recebido"})

@app.route("/api/agent/ping", methods=["POST"])
def receber_ping():

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token ausente"}), 401

    conn = get_db()
    cursor = conn.cursor()

    # validar empresa
    cursor.execute(
        "SELECT id FROM empresas WHERE token_api = %s",
        (token,)
    )
    empresa = cursor.fetchone()

    if not empresa:
        cursor.close()
        conn.close()
        return jsonify({"error": "Token inválido"}), 403

    empresa_id = empresa[0]

    ip = request.json.get("ip")
    resultado = request.json.get("resultado")

    agora = datetime.datetime.now()

    # salvar como comando executado direto
    cursor.execute("""
        INSERT INTO comandos
        (empresa_id, agente_id, tipo, alvo, status, resultado, criado_em, executado_em)
        VALUES (
            %s,
            (SELECT id FROM agentes WHERE empresa_id = %s LIMIT 1),
            'ping',
            %s,
            'executado',
            %s,
            %s,
            %s
        )
    """, (empresa_id, empresa_id, ip, resultado, agora, agora))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "ok"})

@app.route("/registro", methods=["GET", "POST"])
def registro():

    if request.method == "POST":
        username = request.form.get("username")
        senha = request.form.get("senha")

        if not username or not senha:
            return "Preencha todos os campos"

        senha_hash = generate_password_hash(senha)

        conn = get_db()
        cursor = conn.cursor()

        # pegar primeira empresa (modo simples)
        cursor.execute("SELECT id FROM empresas LIMIT 1")
        empresa = cursor.fetchone()

        if not empresa:
            cursor.close()
            conn.close()
            return "Nenhuma empresa cadastrada"

        empresa_id = empresa[0]

        try:
            cursor.execute("""
                INSERT INTO usuarios (username, senha, empresa_id)
                VALUES (%s, %s, %s)
            """, (username, senha_hash, empresa_id))

            conn.commit()

        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            cursor.close()
            conn.close()
            return "Usuário já existe"

        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()
            return f"Erro ao criar usuário"

        cursor.close()
        conn.close()

        return redirect(url_for("admin_dashboard"))

    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username")
        senha = request.form.get("senha")

        if not username or not senha:
            return "Preencha todos os campos"

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, username, senha, empresa_id, tipo FROM usuarios WHERE username = %s",
            (username,)
        )
        usuario = cursor.fetchone()

        cursor.close()
        conn.close()

        if usuario and check_password_hash(usuario[2], senha):

            session["usuario_id"] = usuario[0]
            session["username"] = usuario[1]
            session["empresa_id"] = usuario[3]
            session["tipo"] = usuario[4]

            # 🔥 Redirecionamento inteligente
            if usuario[4] == "admin_global":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("index"))

        else:
            return "Login inválido"

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------
# ROTAS
# ---------------------------


@app.route("/")
@login_required
def index():

    conn = get_db()
    cursor = conn.cursor()

    # 🔎 Buscar empresa do usuário
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("logout"))

    empresa_id = usuario[0]

    # 🔎 STATUS DO AGENTE
    agente_status = "OFF"

    cursor.execute("""
        SELECT ultimo_heartbeat
        FROM agentes
        WHERE empresa_id = %s
        ORDER BY ultimo_heartbeat DESC
        LIMIT 1
    """, (empresa_id,))

    agente = cursor.fetchone()

    if agente and agente[0]:
        agora = datetime.datetime.now()
        delta = agora - agente[0]

        if delta.total_seconds() < 60:
            agente_status = "ON"

    # 🔎 Buscar câmeras da empresa
    cursor.execute("""
        SELECT id, nome_camera, ip_camera, caixa
        FROM cameras
        WHERE empresa_id = %s
    """, (empresa_id,))
    cameras = cursor.fetchall()

    lista_cameras = []
    agora = datetime.datetime.now()

    for cam in cameras:

        ip = cam[2]

        # 🔎 Buscar último comando executado
        cursor.execute("""
            SELECT resultado, executado_em
            FROM comandos
            WHERE alvo = %s
              AND empresa_id = %s
              AND status = 'executado'
            ORDER BY id DESC
            LIMIT 1
        """, (ip, empresa_id))

        comando = cursor.fetchone()

        status = "Sem teste"
        latencia = "-"

        # 🚨 se agente estiver OFF não confiar no último ping
        if agente_status == "OFF":

            status = "Desconhecido"
            latencia = "-"

        else:

            if comando:
                resultado_texto = comando[0]

                # compatível Windows e Linux
                if resultado_texto and "ttl=" in resultado_texto.lower():
                    status = "Online"

                    match = re.search(r'tempo[=<](\d+)', resultado_texto)
                    if match:
                        latencia = match.group(1) + " ms"

                else:
                    status = "Offline"

        # 🔎 Verificar comando ativo
        cursor.execute("""
            SELECT id FROM comandos
            WHERE alvo = %s
              AND empresa_id = %s
              AND status IN ('pendente', 'enviado')
            LIMIT 1
        """, (ip, empresa_id))

        comando_ativo = cursor.fetchone()

        # 🚀 Criar novo comando se necessário
        if not comando_ativo:

            cursor.execute("""
                SELECT id FROM agentes
                WHERE empresa_id = %s
                LIMIT 1
            """, (empresa_id,))
            agente = cursor.fetchone()

            if agente:
                agente_id = agente[0]

                cursor.execute("""
                    INSERT INTO comandos
                    (empresa_id, agente_id, tipo, alvo, criado_em)
                    VALUES (%s, %s, 'ping', %s, %s)
                """, (empresa_id, agente_id, ip, agora))

        lista_cameras.append({
            "id": cam[0],
            "nome": cam[1],
            "ip": ip,
            "caixa": cam[3],
            "status": status,
            "latencia": latencia
        })
        # 🔴 ORDENAR STATUS (OFFLINE PRIMEIRO)
        prioridade_status = {
            "Offline": 0,
            "Desconhecido": 1,
            "Sem teste": 2,
            "Online": 3
        }

        lista_cameras = sorted(
            lista_cameras,
            key=lambda c: prioridade_status.get(c["status"], 99)
        )

        conn.commit()
        cursor.close()
        conn.close()

        return render_template(
            "index.html",
            cameras=lista_cameras,
            agente_status=agente_status
        )

@app.route("/cadastro", methods=["GET", "POST"])
@login_required
def cadastro():

    if request.method == "POST":

        nome_camera = request.form.get("nome_camera")
        ip_camera = request.form.get("ip_camera")
        caixa = request.form.get("caixa")
        rua1 = request.form.get("rua1")
        rua2 = request.form.get("rua2")
        mac = request.form.get("mac")

        conn = get_db()
        cursor = conn.cursor()

        # 🔎 Buscar empresa do usuário logado
        cursor.execute(
            "SELECT empresa_id FROM usuarios WHERE id = %s",
            (session["usuario_id"],)
        )
        usuario = cursor.fetchone()

        if not usuario:
            cursor.close()
            conn.close()
            return redirect(url_for("logout"))

        empresa_id = usuario[0]

        try:
            cursor.execute("""
                INSERT INTO cameras
                (nome_camera, ip_camera, caixa, rua1, rua2, mac, empresa_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                nome_camera,
                ip_camera,
                caixa,
                rua1,
                rua2,
                mac,
                empresa_id
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()

            # Tratamento amigável de duplicidade
            if "duplicate key" in str(e):
                return "Já existe uma câmera com esse nome ou IP."

            return f"Erro ao salvar: {e}"

        cursor.close()
        conn.close()

        return redirect(url_for("index"))

    return render_template("cadastro.html")

# 🔎 PESQUISA
@app.route("/pesquisa", methods=["GET", "POST"])
@login_required
def pesquisa():

    resultados = []

    conn = get_db()
    cursor = conn.cursor()

    # empresa do usuário
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("logout"))

    empresa_id = usuario[0]

    if request.method == "POST":

        termo = request.form.get("termo")

        cursor.execute("""
            SELECT id, nome_camera, ip_camera, caixa, rua1, rua2
            FROM cameras
            WHERE empresa_id = %s
            AND (
                nome_camera ILIKE %s
                OR ip_camera ILIKE %s
                OR caixa ILIKE %s
                OR rua1 ILIKE %s
                OR rua2 ILIKE %s
            )
        """, (
            empresa_id,
            f"%{termo}%",
            f"%{termo}%",
            f"%{termo}%",
            f"%{termo}%",
            f"%{termo}%"
        ))

        resultados = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("pesquisa.html", resultados=resultados)

@app.route("/teste", methods=["GET", "POST"])
@login_required
def teste():

    conn = get_db()
    cursor = conn.cursor()

    # 🔎 Empresa do usuário
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("logout"))

    empresa_id = usuario[0]

    # 🔎 STATUS DO AGENTE
    agente_status = "OFF"

    cursor.execute("""
        SELECT ultimo_heartbeat
        FROM agentes
        WHERE empresa_id = %s
        ORDER BY ultimo_heartbeat DESC
        LIMIT 1
    """, (empresa_id,))

    agente = cursor.fetchone()

    if agente and agente[0]:
        agora = datetime.datetime.now()
        delta = agora - agente[0]

        if delta.total_seconds() < 60:
            agente_status = "ON"

    # 🔎 Listar caixas da empresa
    cursor.execute("""
        SELECT DISTINCT caixa
        FROM cameras
        WHERE caixa IS NOT NULL
          AND empresa_id = %s
    """, (empresa_id,))
    caixas = [row[0] for row in cursor.fetchall()]

    ips_solicitados = []
    resultados = []

    if request.method == "POST":

        tipo = request.form.get("tipo")

        # 🚨 se agente OFF não executar testes
        if agente_status == "OFF":

            if tipo == "ip":
                ip = request.form.get("ip_manual")
                if ip:
                    resultados.append(("Teste", ip, "Sem comunicação", "-"))

            elif tipo == "caixa":
                caixa = request.form.get("caixa")

                cursor.execute("""
                    SELECT ip_camera
                    FROM cameras
                    WHERE caixa = %s
                      AND empresa_id = %s
                """, (caixa, empresa_id))

                for row in cursor.fetchall():
                    resultados.append(("Teste", row[0], "Sem comunicação", "-"))

            elif tipo == "geral":

                cursor.execute("""
                    SELECT ip_camera
                    FROM cameras
                    WHERE empresa_id = %s
                """, (empresa_id,))

                for row in cursor.fetchall():
                    resultados.append(("Teste", row[0], "Sem comunicação", "-"))

            cursor.close()
            conn.close()

            return render_template("teste.html", caixas=caixas, resultados=resultados)

        # 🔎 Buscar agente da empresa
        cursor.execute(
            "SELECT id FROM agentes WHERE empresa_id = %s LIMIT 1",
            (empresa_id,)
        )
        agente = cursor.fetchone()

        if not agente:
            cursor.close()
            conn.close()
            return "Nenhum agente conectado"

        agente_id = agente[0]
        agora = datetime.datetime.now()

        # ---------------- TESTE POR IP ----------------
        if tipo == "ip":
            ip = request.form.get("ip_manual")
            if ip:
                ips_solicitados.append(ip)

        # ---------------- TESTE POR CAIXA ----------------
        elif tipo == "caixa":
            caixa = request.form.get("caixa")

            cursor.execute("""
                SELECT ip_camera
                FROM cameras
                WHERE caixa = %s
                  AND empresa_id = %s
            """, (caixa, empresa_id))

            ips_solicitados = [row[0] for row in cursor.fetchall()]

        # ---------------- TESTE GERAL ----------------
        elif tipo == "geral":

            cursor.execute("""
                SELECT ip_camera
                FROM cameras
                WHERE empresa_id = %s
            """, (empresa_id,))

            ips_solicitados = [row[0] for row in cursor.fetchall()]

        # 🚀 Criar comandos
        for ip in ips_solicitados:
            cursor.execute("""
                INSERT INTO comandos
                (empresa_id, agente_id, tipo, alvo, criado_em)
                VALUES (%s, %s, 'ping', %s, %s)
            """, (empresa_id, agente_id, ip, agora))

        conn.commit()

        # 🔎 Buscar últimos resultados
        for ip in ips_solicitados:

            cursor.execute("""
                SELECT resultado
                FROM comandos
                WHERE empresa_id = %s
                  AND alvo = %s
                  AND status = 'executado'
                ORDER BY id DESC
                LIMIT 1
            """, (empresa_id, ip))

            comando = cursor.fetchone()

            status = "Aguardando"
            latencia = "-"

            if comando and comando[0]:

                resultado_texto = comando[0]

                if "ttl=" in resultado_texto.lower():
                    status = "Online"
                    match = re.search(r'tempo[=<](\d+)', resultado_texto)
                    if match:
                        latencia = match.group(1) + " ms"
                else:
                    status = "Offline"

            resultados.append(("Teste", ip, status, latencia))

    cursor.close()
    conn.close()

    return render_template("teste.html", caixas=caixas, resultados=resultados)

@app.route("/alteracoes")
@login_required
def alteracoes():

    conn = get_db()
    cursor = conn.cursor()

    # Empresa do usuário
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("logout"))

    empresa_id = usuario[0]

    # Buscar somente câmeras da empresa
    cursor.execute("""
        SELECT id, nome_camera, ip_camera, caixa
        FROM cameras
        WHERE empresa_id = %s
        ORDER BY id DESC
    """, (empresa_id,))

    cameras = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("alteracoes.html", cameras=cameras)

@app.route("/editar/<int:id>", methods=["GET", "POST"])
@login_required
def editar(id):

    conn = get_db()
    cursor = conn.cursor()

    # Empresa do usuário
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("logout"))

    empresa_id = usuario[0]

    if request.method == "POST":

        nome_camera = request.form.get("nome_camera")
        ip_camera = request.form.get("ip_camera")
        caixa = request.form.get("caixa")
        rua1 = request.form.get("rua1")
        rua2 = request.form.get("rua2")
        mac = request.form.get("mac")

        try:
            cursor.execute("""
                UPDATE cameras
                SET nome_camera = %s,
                    ip_camera = %s,
                    caixa = %s,
                    rua1 = %s,
                    rua2 = %s,
                    mac = %s
                WHERE id = %s
                  AND empresa_id = %s
            """, (
                nome_camera,
                ip_camera,
                caixa,
                rua1,
                rua2,
                mac,
                id,
                empresa_id
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()
            return f"Erro ao atualizar: {e}"

        cursor.close()
        conn.close()
        return redirect(url_for("alteracoes"))

    # GET
    cursor.execute("""
        SELECT id, nome_camera, ip_camera, caixa, rua1, rua2, mac
        FROM cameras
        WHERE id = %s
          AND empresa_id = %s
    """, (id, empresa_id))

    camera = cursor.fetchone()

    cursor.close()
    conn.close()

    if not camera:
        return "Registro não encontrado"

    return render_template("editar.html", camera=camera)

@app.route("/apagar/<int:id>", methods=["POST"])
@login_required
def apagar(id):

    conn = get_db()
    cursor = conn.cursor()

    # Empresa do usuário
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("logout"))

    empresa_id = usuario[0]

    # Garantir que pertence à empresa
    cursor.execute("""
        DELETE FROM cameras
        WHERE id = %s
          AND empresa_id = %s
    """, (id, empresa_id))

    conn.commit()

    cursor.close()
    conn.close()

    return redirect(url_for("alteracoes"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)