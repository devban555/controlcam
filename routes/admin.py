from flask import Blueprint, render_template, request, redirect, url_for
from db import get_db
from routes.auth import login_required, admin_required
from werkzeug.security import generate_password_hash
from psycopg2.extras import RealDictCursor
import secrets

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ==============================
# 🧑‍💼 DASHBOARD
# ==============================
@admin_bp.route("/")
@login_required
@admin_required
def admin_dashboard():
    """
    Renderiza o painel administrativo principal do sistema.

    Esta função é responsável por:
    - Garantir que o usuário esteja autenticado e seja administrador
    - Buscar todas as empresas cadastradas no banco de dados
    - Buscar todos os usuários e associar suas respectivas empresas
    - Enviar os dados para o template 'admin.html'

    Fluxo:
    1. Conecta ao banco de dados
    2. Consulta lista de empresas (ordenadas por ID decrescente)
    3. Consulta lista de usuários com JOIN nas empresas
    4. Fecha o cursor
    5. Renderiza a página com os dados

    Returns:
        Response: Página HTML do dashboard administrativo com listas de empresas e usuários

    Segurança:
        - Requer login (@login_required)
        - Requer permissão de administrador (@admin_required)
    """

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

    cursor.close()

    return render_template(
        "admin.html",
        empresas=empresas,
        usuarios=usuarios
    )

# ==============================
# 👤 CRIAR USUÁRIO
# ==============================
@admin_bp.route("/criar_usuario", methods=["POST"])
@login_required
@admin_required
def criar_usuario():
    """
    Cria um novo usuário vinculado a uma empresa no sistema.

    Esta função:
    - Recebe dados do formulário (empresa_id, username, senha)
    - Valida se os campos obrigatórios foram preenchidos
    - Criptografa a senha do usuário
    - Insere o novo usuário no banco de dados com tipo 'empresa'
    - Redireciona para o dashboard administrativo

    Fluxo:
    1. Captura dados do formulário via POST
    2. Valida campos obrigatórios
    3. Gera hash seguro da senha
    4. Insere usuário no banco
    5. Confirma transação (commit)
    6. Redireciona para o painel admin

    Args (form-data):
        empresa_id (str): ID da empresa vinculada
        username (str): Nome de usuário
        senha (str): Senha em texto puro (será criptografada)

    Returns:
        Response:
            - Redireciona para o dashboard em caso de sucesso
            - Retorna mensagem simples em caso de erro de validação

    Segurança:
        - Requer autenticação (@login_required)
        - Requer privilégio de administrador (@admin_required)
        - Senha armazenada com hash seguro (generate_password_hash)


    """

    empresa_id = request.form.get("empresa_id")
    username = request.form.get("username")
    senha_raw = request.form.get("senha")

    if not empresa_id or not username or not senha_raw:
        return "Dados inválidos"

    # Criptografia da senha antes de salvar
    senha = generate_password_hash(senha_raw)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO usuarios (empresa_id, username, senha, tipo)
        VALUES (%s, %s, %s, 'empresa')
    """, (empresa_id, username, senha))

    conn.commit()
    cursor.close()

    return redirect(url_for("admin.admin_dashboard"))


# ==============================
# ❌ EXCLUIR USUÁRIO
# ==============================
@admin_bp.route("/excluir_usuario/<int:usuario_id>")
@login_required
@admin_required
def excluir_usuario(usuario_id):
    """
    Remove um usuário do sistema com base no ID informado.

    Esta função:
    - Recebe o ID do usuário via parâmetro da URL
    - Executa a exclusão direta no banco de dados
    - Confirma a transação
    - Redireciona para o dashboard administrativo

    Fluxo:
    1. Recebe o usuario_id pela URL
    2. Conecta ao banco de dados
    3. Executa comando DELETE na tabela 'usuarios'
    4. Realiza commit da operação
    5. Fecha o cursor
    6. Redireciona para o painel admin

    Args:
        usuario_id (int): ID do usuário a ser removido

    Returns:
        Response: Redireciona para o dashboard administrativo após exclusão

    Segurança:
        - Requer autenticação (@login_required)
        - Requer privilégio de administrador (@admin_required)


    """

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM usuarios WHERE id = %s",
        (usuario_id,)
    )

    conn.commit()
    cursor.close()

    return redirect(url_for("admin.admin_dashboard"))


# ==============================
# 🏢 CRIAR EMPRESA
# ==============================
@admin_bp.route("/criar_empresa", methods=["POST"])
@login_required
@admin_required
def criar_empresa():
    """
    Cria uma nova empresa no sistema e gera automaticamente um token de API.

    Esta função:
    - Recebe o nome da empresa via formulário
    - Valida se o nome foi informado
    - Gera um token único e seguro para integração via API
    - Insere a empresa no banco de dados com data de criação
    - Redireciona para o dashboard administrativo

    Fluxo:
    1. Captura o nome da empresa via POST
    2. Valida se o campo foi preenchido
    3. Gera token seguro com secrets.token_hex
    4. Insere empresa no banco com timestamp atual
    5. Confirma transação (commit)
    6. Redireciona para o painel admin

    Args (form-data):
        nome_empresa (str): Nome da empresa a ser cadastrada

    Returns:
        Response:
            - Redireciona para o dashboard em caso de sucesso
            - Retorna mensagem simples em caso de erro de validação

    Segurança:
        - Requer autenticação (@login_required)
        - Requer privilégio de administrador (@admin_required)
        - Token gerado com alta entropia (secrets.token_hex)

    Token API:
        - Utilizado para autenticação de integrações externas
        - Deve ser mantido em sigilo
        - Gerado com 64 caracteres hexadecimais (32 bytes)


    """

    nome = request.form.get("nome_empresa")

    if not nome:
        return "Nome inválido"

    # Geração de token seguro para integração externa
    token = secrets.token_hex(32)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO empresas (nome_empresa, token_api, criada_em)
        VALUES (%s, %s, NOW())
    """, (nome, token))

    conn.commit()
    cursor.close()

    return redirect(url_for("admin.admin_dashboard"))


# ==============================
# ❌ EXCLUIR EMPRESA
# ==============================
@admin_bp.route("/excluir_empresa/<int:empresa_id>")
@login_required
@admin_required
def excluir_empresa(empresa_id):
    """
    Remove uma empresa do sistema com base no ID informado.

    Esta função:
    - Recebe o ID da empresa via parâmetro da URL
    - Executa a exclusão direta no banco de dados
    - Confirma a transação
    - Redireciona para o dashboard administrativo

    Fluxo:
    1. Recebe o empresa_id pela URL
    2. Conecta ao banco de dados
    3. Executa DELETE na tabela 'empresas'
    4. Realiza commit da operação
    5. Fecha o cursor
    6. Redireciona para o painel admin

    Args:
        empresa_id (int): ID da empresa a ser removida

    Returns:
        Response: Redireciona para o dashboard administrativo

    Segurança:
        - Requer autenticação (@login_required)
        - Requer privilégio de administrador (@admin_required)


    """

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM empresas WHERE id = %s",
        (empresa_id,)
    )

    conn.commit()
    cursor.close()

    return redirect(url_for("admin.admin_dashboard"))

@admin_bp.route("/admin/agentes/<int:empresa_id>")
@login_required
@admin_required
def ver_agentes(empresa_id):
    """
    Lista todos os agentes vinculados a uma empresa específica.

    Esta função:
    - Recebe o ID da empresa via URL
    - Consulta os agentes associados a essa empresa
    - Ordena os agentes pelo último heartbeat (atividade recente)
    - Renderiza a página administrativa de agentes

    Fluxo:
    1. Recebe o empresa_id pela URL
    2. Conecta ao banco de dados
    3. Consulta agentes da empresa
    4. Ordena por 'ultimo_heartbeat' (mais recentes primeiro)
    5. Fecha a conexão com o banco
    6. Renderiza template com os dados

    Args:
        empresa_id (int): ID da empresa

    Returns:
        Response: Página HTML com a lista de agentes da empresa

    Segurança:
        - Requer autenticação (@login_required)
        - Requer privilégio de administrador (@admin_required)

    Banco de Dados:
        - Tabela: agentes
        - Filtro: empresa_id
        - Ordenação: ultimo_heartbeat DESC


    """

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

@admin_bp.route("/alterar_empresa_usuario", methods=["POST"])
@login_required
@admin_required
def alterar_empresa_usuario():
    """
    Atualiza a empresa associada a um usuário no sistema.

    Esta função:
    - Recebe o ID do usuário e o novo ID da empresa via formulário
    - Atualiza o vínculo do usuário com a empresa no banco de dados
    - Persiste a alteração
    - Redireciona para o dashboard administrativo

    Fluxo:
    1. Captura usuario_id e empresa_id via POST
    2. Conecta ao banco de dados
    3. Executa UPDATE na tabela 'usuarios'
    4. Confirma a transação (commit)
    5. Fecha cursor e conexão
    6. Redireciona para o painel admin

    Args (form-data):
        usuario_id (str/int): ID do usuário a ser atualizado
        empresa_id (str/int): Novo ID da empresa

    Returns:
        Response: Redireciona para o dashboard administrativo

    Segurança:
        - Requer autenticação (@login_required)
        - Requer privilégio de administrador (@admin_required)

    Banco de Dados:
        - Tabela: usuarios
        - Campo atualizado: empresa_id


    """

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

    return redirect(url_for("admin.admin_dashboard"))