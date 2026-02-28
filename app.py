from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import subprocess
import re
import secrets

token = secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = "controlcam_secret_key"

DATABASE = "banco.db"


# ---------------------------
# Criar banco
# ---------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ---------------- EMPRESAS ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS empresas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_empresa TEXT NOT NULL,
            token_api TEXT UNIQUE NOT NULL
        )
    """)

    # ---------------- USUARIOS ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            empresa_id INTEGER,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id)
        )
    """)

    # ---------------- CAMERAS ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cameras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_camera TEXT NOT NULL,
            ip_camera TEXT NOT NULL,
            caixa TEXT,
            rua1 TEXT,
            rua2 TEXT,
            mac TEXT,
            empresa_id INTEGER,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id)
        )
    """)

    conn.commit()
    conn.close()

init_db()

@app.route("/api/agent/ping", methods=["POST"])
def receber_ping():
    token = request.headers.get("Authorization")

    # validar token
    # salvar resultado no banco

    return {"status": "ok"}

#login e Registros
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/registro", methods=["GET", "POST"])
def registro():

    if request.method == "POST":
        username = request.form.get("username")
        senha = request.form.get("senha")

        senha_hash = generate_password_hash(senha)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO usuarios (username, senha) VALUES (?, ?)",
                (username, senha_hash)
            )
            conn.commit()
        except:
            conn.close()
            return "Usuário já existe"

        conn.close()
        return redirect(url_for("login"))

    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username")
        senha = request.form.get("senha")

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM usuarios WHERE username = ?",
            (username,)
        )
        usuario = cursor.fetchone()
        conn.close()

        if usuario and check_password_hash(usuario[2], senha):
            session["usuario_id"] = usuario[0]
            session["username"] = usuario[1]
            return redirect(url_for("index"))
        else:
            return "Login inválido"

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
# ---------------------------
# Função Ping
# ---------------------------
def testar_ping(ip):
    try:
        resultado = subprocess.run(
            ["ping", "-c", "3", ip],
            capture_output=True,
            text=True,
            timeout=3
        )

        if resultado.returncode == 0:
            match = re.search(r'time=(\d+\.?\d*)', resultado.stdout)
            latencia = match.group(1) + " ms" if match else "N/A"
            return "Online", latencia
        else:
            return "Offline", "-"

    except:
        return "Erro", "-"


# ---------------------------
# ROTAS
# ---------------------------

@app.route("/")
@login_required
def index():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome_camera, ip_camera, caixa FROM cameras")
    cameras = cursor.fetchall()
    conn.close()

    lista_cameras = []

    for cam in cameras:
        status, latencia = testar_ping(cam[2])
        lista_cameras.append({
            "id": cam[0],
            "nome": cam[1],
            "ip": cam[2],
            "caixa": cam[3],
            "status": status,
            "latencia": latencia
        })

    return render_template("index.html", cameras=lista_cameras)

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome_camera = request.form.get("nome_camera")
        ip_camera = request.form.get("ip_camera")
        caixa = request.form.get("caixa")
        rua1 = request.form.get("rua1")
        rua2 = request.form.get("rua2")
        mac = request.form.get("mac")

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO cameras
            (nome_camera, ip_camera, caixa, rua1, rua2, mac)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (nome_camera, ip_camera, caixa, rua1, rua2, mac))

        conn.commit()
        conn.close()

        return redirect(url_for("index"))

    return render_template("cadastro.html")


# 🔎 PESQUISA
@app.route("/pesquisa", methods=["GET", "POST"])
def pesquisa():
    resultados = []

    if request.method == "POST":
        termo = request.form.get("termo")

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM cameras
            WHERE nome_camera LIKE ?
            OR ip_camera LIKE ?
            OR caixa LIKE ?
        """, (f"%{termo}%", f"%{termo}%", f"%{termo}%"))

        resultados = cursor.fetchall()
        conn.close()

    return render_template("pesquisa.html", resultados=resultados)

@app.route("/teste", methods=["GET", "POST"])
def teste():
    resultados = []

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT caixa FROM cameras WHERE caixa IS NOT NULL")
    caixas = [row[0] for row in cursor.fetchall()]
    conn.close()

    if request.method == "POST":

        tipo = request.form.get("tipo")

        # ---------------- TESTE POR IP ----------------
        if tipo == "ip":
            ip = request.form.get("ip_manual")
            status, latencia = testar_ping(ip)
            resultados.append(("Manual", ip, status, latencia))

        # ---------------- TESTE POR CAIXA ----------------
        elif tipo == "caixa":
            caixa = request.form.get("caixa")

            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("SELECT nome_camera, ip_camera FROM cameras WHERE caixa = ?", (caixa,))
            cameras = cursor.fetchall()
            conn.close()

            for nome, ip in cameras:
                status, latencia = testar_ping(ip)
                resultados.append((nome, ip, status, latencia))

        # ---------------- TESTE GERAL ----------------
        elif tipo == "geral":

            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("SELECT nome_camera, ip_camera FROM cameras")
            cameras = cursor.fetchall()
            conn.close()

            for nome, ip in cameras:
                status, latencia = testar_ping(ip)
                resultados.append((nome, ip, status, latencia))

    return render_template("teste.html", caixas=caixas, resultados=resultados)

@app.route("/alteracoes")
def alteracoes():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cameras")
    cameras = cursor.fetchall()
    conn.close()

    return render_template("alteracoes.html", cameras=cameras)

@app.route("/editar/<int:id>", methods=["GET", "POST"])
def editar(id):

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    if request.method == "POST":
        nome_camera = request.form.get("nome_camera")
        ip_camera = request.form.get("ip_camera")
        caixa = request.form.get("caixa")
        rua1 = request.form.get("rua1")
        rua2 = request.form.get("rua2")
        mac = request.form.get("mac")

        cursor.execute("""
            UPDATE cameras
            SET nome_camera = ?, ip_camera = ?, caixa = ?, rua1 = ?, rua2 = ?, mac = ?
            WHERE id = ?
        """, (nome_camera, ip_camera, caixa, rua1, rua2, mac, id))

        conn.commit()
        conn.close()

        return redirect(url_for("alteracoes"))

    cursor.execute("SELECT * FROM cameras WHERE id = ?", (id,))
    camera = cursor.fetchone()
    conn.close()

    return render_template("editar.html", camera=camera)

if __name__ == "__main__":
    app.run(debug=True)