from flask import Blueprint, render_template, request, redirect, session, url_for
from functools import wraps
from db import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2

auth_bp = Blueprint("auth", __name__)


# ==============================
# 🔐 LOGIN REQUIRED
# ==============================
def login_required(f):
    """
    Decorator que garante que o usuário esteja autenticado antes de acessar uma rota.

    Esta função:
    - Verifica se existe uma sessão ativa do usuário
    - Impede acesso a rotas protegidas sem login
    - Redireciona para a página de login caso não autenticado

    Fluxo:
    1. Intercepta a chamada da rota decorada
    2. Verifica se 'usuario_id' existe na sessão
    3. Se não existir:
        - Redireciona para a rota de login ('auth.login')
    4. Se existir:
        - Executa a função original normalmente

    Args:
        f (function): Função (rota) que será protegida

    Returns:
        function: Função decorada com verificação de autenticação

    Sessão:
        - Utiliza 'session["usuario_id"]' como indicador de login ativo

    Segurança:
        - Bloqueia acesso não autenticado a rotas protegidas
        - Baseado em sessão (server-side)

    Observações:
        - Não valida tipo/permissão do usuário (apenas existência de login)
        - Deve ser combinado com outros decorators (ex: admin_required)

    Exemplo de uso:
        @app.route("/dashboard")
        @login_required
        def dashboard():
            ...

    Possíveis melhorias:
        - Implementar expiração de sessão
        - Verificar validade do usuário no banco
        - Adicionar suporte a JWT (para APIs)
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated_function

# ==============================
# 🛡️ ADMIN REQUIRED (ADICIONADO)
# ==============================
def admin_required(f):
    """
    Decorator que restringe o acesso apenas a usuários com perfil de administrador global.

    Esta função:
    - Verifica se o usuário está autenticado (sessão ativa)
    - Valida se o usuário possui permissão de administrador global
    - Bloqueia acesso caso não atenda aos requisitos

    Fluxo:
    1. Intercepta a chamada da rota decorada
    2. Verifica se 'usuario_id' existe na sessão
    3. Se não existir:
        - Redireciona para a página de login
    4. Verifica o tipo do usuário na sessão
    5. Se não for 'admin_global':
        - Retorna mensagem de "Acesso negado"
    6. Caso válido:
        - Executa a função original

    Args:
        f (function): Função (rota) que será protegida

    Returns:
        function: Função decorada com validação de permissão

    Sessão:
        - session["usuario_id"]: identifica usuário logado
        - session["tipo"]: define o nível de acesso

    Segurança:
        - Garante que apenas administradores globais acessem rotas críticas
        - Complementa o decorator @login_required

    Observações:
        - Depende da chave 'tipo' estar corretamente definida na sessão
        - Retorna mensagem simples em vez de página/JSON estruturado
        - Revalida login mesmo se usado junto com @login_required

    Exemplo de uso:
        @app.route("/admin")
        @login_required
        @admin_required
        def painel_admin():
            ...

    Possíveis melhorias:
        - Padronizar resposta de erro (HTML ou JSON)
        - Implementar múltiplos níveis de permissão (RBAC)
        - Validar tipo diretamente no banco (evitar confiar apenas na sessão)
        - Criar logs de tentativa de acesso negado
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "usuario_id" not in session:
            return redirect(url_for("auth.login"))

        if session.get("tipo") != "admin_global":
            return "Acesso negado"

        return f(*args, **kwargs)

    return decorated_function


# ==============================
# 🔑 LOGIN
# ==============================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Realiza a autenticação de usuários no sistema e inicia a sessão.

    Esta função:
    - Exibe a página de login (GET)
    - Processa credenciais enviadas pelo usuário (POST)
    - Valida usuário e senha no banco de dados
    - Cria sessão autenticada
    - Redireciona conforme o tipo de usuário

    Fluxo:
    1. Verifica método da requisição (GET ou POST)
    2. Se POST:
        a. Captura username e senha do formulário
        b. Valida campos obrigatórios
        c. Busca usuário no banco pelo username
        d. Verifica senha com hash seguro
        e. Se válido:
            - Cria sessão com dados do usuário
            - Redireciona conforme tipo:
                • admin_global → dashboard admin
                • outros → página principal
        f. Se inválido:
            - Retorna erro de login
    3. Se GET:
        - Renderiza página de login

    Args (form-data):
        username (str): Nome de usuário
        senha (str): Senha em texto puro

    Returns:
        Response:
            - Renderiza login.html (GET)
            - Redireciona após login bem-sucedido
            - Retorna mensagem simples em caso de erro

    Sessão:
        - session["usuario_id"]: ID do usuário
        - session["username"]: Nome do usuário
        - session["empresa_id"]: Empresa vinculada
        - session["tipo"]: Tipo de usuário (ex: admin_global)

    Segurança:
        - Senha verificada com hash seguro (check_password_hash)
        - Não armazena senha em texto puro
        - Sessão utilizada para autenticação persistente

    Banco de Dados:
        - Tabela: usuarios
        - Campos consultados:
            id, username, senha, empresa_id, tipo

    Observações:
        - Não diferencia mensagens de erro (segurança básica)
        - Não há limite de tentativas de login
        - Não valida usuário inativo/bloqueado

    Possíveis melhorias:
        - Implementar rate limit (bloqueio por tentativas)
        - Adicionar mensagens de erro amigáveis (flash)
        - Criar logout com invalidação de sessão
        - Implementar autenticação em dois fatores (2FA)
    """

    if request.method == "POST":
        username = request.form.get("username")
        senha = request.form.get("senha")

        if not username or not senha:
            return "Preencha todos os campos"

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, senha, empresa_id, tipo
            FROM usuarios
            WHERE username = %s
        """, (username,))

        usuario = cursor.fetchone()
        cursor.close()

        if usuario and check_password_hash(usuario[2], senha):

            # Criação da sessão do usuário
            session["usuario_id"] = usuario[0]
            session["username"] = usuario[1]
            session["empresa_id"] = usuario[3]
            session["tipo"] = usuario[4]

            # Redirecionamento baseado no tipo de usuário
            if usuario[4] == "admin_global":
                return redirect(url_for("admin.admin_dashboard"))
            else:
                return redirect(url_for("main.index"))

        return "Login inválido"

    return render_template("login.html")


# ==============================
# 🚪 LOGOUT
# ==============================
@auth_bp.route("/logout")
def logout():
    """
    Encerra a sessão do usuário autenticado e redireciona para a tela de login.

    Esta função:
    - Remove todos os dados da sessão ativa
    - Garante que o usuário seja deslogado do sistema
    - Redireciona para a página de login

    Fluxo:
    1. Limpa completamente a sessão do usuário (session.clear)
    2. Remove informações como:
        - usuario_id
        - username
        - empresa_id
        - tipo
    3. Redireciona para a rota de login

    Returns:
        Response: Redireciona para a página de login

    Segurança:
        - Invalida completamente a sessão atual
        - Evita reutilização de sessão (session hijacking)
        - Garante que rotas protegidas não possam mais ser acessadas

    Sessão:
        - Todos os dados armazenados em session são removidos

    Observações:
        - Não exige método POST (pode ser acessado via GET)
        - Não possui confirmação de logout
        - Não registra evento de logout

    Possíveis melhorias:
        - Exigir método POST (melhor prática de segurança)
        - Registrar log de logout (auditoria)
        - Implementar invalidação de sessão no servidor (caso use armazenamento externo)
    """

    session.clear()
    return redirect(url_for("auth.login"))

# ==============================
# 👤 REGISTRO
# ==============================
@auth_bp.route("/registro", methods=["GET", "POST"])
def registro():
    """
    Realiza o cadastro de novos usuários no sistema.

    Esta função:
    - Exibe a página de registro (GET)
    - Processa o cadastro de um novo usuário (POST)
    - Criptografa a senha antes de salvar
    - Associa automaticamente o usuário a uma empresa existente
    - Trata erros como usuário duplicado

    Fluxo:
    1. Verifica método da requisição (GET ou POST)
    2. Se POST:
        a. Captura username e senha do formulário
        b. Valida campos obrigatórios
        c. Gera hash seguro da senha
        d. Busca uma empresa existente no banco
        e. Se não houver empresa:
            - Retorna erro
        f. Insere novo usuário vinculado à empresa
        g. Trata erros:
            - Usuário duplicado (UniqueViolation)
            - Outros erros genéricos
        h. Redireciona para tela de login
    3. Se GET:
        - Renderiza página de registro

    Args (form-data):
        username (str): Nome de usuário
        senha (str): Senha em texto puro

    Returns:
        Response:
            - Renderiza registro.html (GET)
            - Redireciona para login após sucesso
            - Retorna mensagens de erro em caso de falha

    Segurança:
        - Senha armazenada com hash seguro (generate_password_hash)
        - Não armazena senha em texto puro

    Banco de Dados:
        - Tabela: usuarios
        - Associação automática com empresa existente
        - Restrição de unicidade no username (tratada via exceção)

    Observações:
        - Sempre vincula o usuário à primeira empresa encontrada (LIMIT 1)
        - Não permite cadastro se não houver empresa cadastrada
        - Não define explicitamente o tipo de usuário (tipo)

    Tratamento de erros:
        - UniqueViolation: usuário já existe
        - Exception genérica: erro inesperado no cadastro

    Possíveis melhorias:
        - Permitir seleção de empresa no cadastro
        - Definir tipo de usuário no momento do registro
        - Validar força da senha
        - Implementar confirmação de senha
        - Melhorar mensagens com flash()
    """

    if request.method == "POST":
        username = request.form.get("username")
        senha = request.form.get("senha")

        if not username or not senha:
            return "Preencha todos os campos"

        # Criptografia da senha
        senha_hash = generate_password_hash(senha)

        conn = get_db()
        cursor = conn.cursor()

        # Busca empresa existente para vincular usuário
        cursor.execute("SELECT id FROM empresas LIMIT 1")
        empresa = cursor.fetchone()

        if not empresa:
            cursor.close()
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
            return "Usuário já existe"

        except Exception as e:
            conn.rollback()
            cursor.close()
            return f"Erro ao criar usuário"

        cursor.close()

        return redirect(url_for("auth.login"))

    return render_template("registro.html")