from flask import (
    Blueprint,
    render_template,
    request,
    session,
    redirect,
    url_for,
    jsonify
)
from routes.auth import login_required
from db import get_db
import datetime
import re
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

main_bp = Blueprint("main", __name__)


# ==============================
# 🏠 INDEX
# ==============================
@main_bp.route("/")
@login_required
def index():
    """
        Renderiza o painel principal do sistema com status das câmeras e do agente.

        Esta função:
        - Identifica a empresa do usuário logado
        - Verifica o status do agente (online/offline)
        - Lista todas as câmeras da empresa
        - Consulta o último resultado de ping de cada câmera
        - Define status e latência das câmeras
        - Dispara novos comandos de ping automaticamente (se necessário)
        - Ordena as câmeras por prioridade de status
        - Renderiza o dashboard principal

        Fluxo:
        1. Obtém usuário logado via sessão
        2. Busca empresa vinculada ao usuário
        3. Verifica status do agente via último heartbeat:
            - < 60s → ON
            - ≥ 60s → OFF
        4. Busca todas as câmeras da empresa
        5. Para cada câmera:
            a. Busca último comando executado (ping)
            b. Interpreta resultado:
                - "ttl=" → Online
                - sem resposta → Offline
            c. Extrai latência via regex
            d. Evita flood de comandos (verifica pendentes)
            e. Cria novo comando de ping se necessário
        6. Monta lista estruturada de câmeras
        7. Ordena por prioridade:
            Offline → Desconhecido → Sem teste → Online
        8. Renderiza template com dados

        Returns:
            Response: Página HTML (index.html) com:
                - lista de câmeras
                - status do agente

        Sessão:
            - session["usuario_id"]: identifica usuário logado

        Banco de Dados:
            - usuarios → vínculo com empresa
            - agentes → status via heartbeat
            - cameras → lista de dispositivos
            - comandos → histórico e fila de execução

        Status de Câmeras:
            - Online: resposta válida com TTL
            - Offline: sem resposta válida
            - Sem teste: nenhum comando executado ainda
            - Desconhecido: agente offline

        Lógica de Monitoramento:
            - Sistema utiliza comandos 'ping' para verificar disponibilidade
            - Evita duplicidade com verificação de comandos pendentes
            - Execução é delegada ao agente

        Observações:
            - Usa parsing de texto do ping para determinar status
            - Latência extraída via regex
            - Apenas o último comando executado é considerado
            - Assume existência de pelo menos um agente

        Possíveis melhorias:
            - Suporte a múltiplos agentes por empresa
            - Cache de status para reduzir queries
            - Estruturar resultado do ping em JSON
            - Implementar timeout configurável
            - Melhorar performance (evitar múltiplas queries por câmera)
        """

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
        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    # ==============================
    # 🤖 STATUS AGENTE
    # ==============================
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
        if (agora - agente[0]).total_seconds() < 60:
            agente_status = "ON"

    # ==============================
    # 📷 CAMERAS
    # ==============================
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

        cursor.execute("""
            SELECT resultado
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

        if agente_status == "OFF":
            status = "Desconhecido"

        else:
            if comando and comando[0]:
                resultado_texto = comando[0]

                if "ttl=" in resultado_texto.lower():
                    status = "Online"
                    match = re.search(r'tempo[=<](\d+)', resultado_texto)
                    if match:
                        latencia = match.group(1) + " ms"
                else:
                    status = "Offline"

        # evitar flood de comandos
        cursor.execute("""
            SELECT id FROM comandos
            WHERE alvo = %s
              AND empresa_id = %s
              AND status IN ('pendente', 'enviado')
            LIMIT 1
        """, (ip, empresa_id))

        if not cursor.fetchone():

            cursor.execute("""
                SELECT id FROM agentes
                WHERE empresa_id = %s
                LIMIT 1
            """, (empresa_id,))

            agente = cursor.fetchone()

            if agente:
                cursor.execute("""
                    INSERT INTO comandos
                    (empresa_id, agente_id, tipo, alvo, criado_em)
                    VALUES (%s, %s, 'ping', %s, %s)
                """, (empresa_id, agente[0], ip, agora))

        lista_cameras.append({
            "id": cam[0],
            "nome": cam[1],
            "ip": ip,
            "caixa": cam[3],
            "status": status,
            "latencia": latencia
        })

    prioridade = {"Offline": 0, "Desconhecido": 1, "Sem teste": 2, "Online": 3}

    lista_cameras = sorted(lista_cameras, key=lambda c: prioridade.get(c["status"], 99))

    conn.commit()
    cursor.close()

    return render_template("index.html", cameras=lista_cameras, agente_status=agente_status)


# ==============================
# ➕ CADASTRO
# ==============================
@main_bp.route("/cadastro", methods=["GET", "POST"])
@login_required
def cadastro():
    """
        Realiza o cadastro de novas câmeras no sistema, vinculadas à empresa do usuário.

        Esta função:
        - Exibe o formulário de cadastro de câmeras (GET)
        - Processa o envio dos dados (POST)
        - Associa automaticamente a câmera à empresa do usuário logado
        - Persiste os dados no banco
        - Trata erros de duplicidade

        Fluxo:
        1. Verifica método da requisição (GET ou POST)
        2. Se POST:
            a. Obtém empresa do usuário logado via sessão
            b. Valida existência do usuário
            c. Captura dados do formulário
            d. Insere nova câmera no banco
            e. Trata erros:
                - Duplicidade (nome/IP)
                - Erros genéricos
            f. Redireciona para o dashboard
        3. Se GET:
            - Renderiza página de cadastro

        Campos (form-data):
            nome_camera (str): Nome identificador da câmera
            ip_camera (str): Endereço IP da câmera
            caixa (str): Identificação/local físico (ex: caixa/poste)
            rua1 (str): Endereço principal
            rua2 (str): Endereço complementar
            mac (str): Endereço MAC da câmera
            usuario (str): Usuário de acesso à câmera
            senha (str): Senha de acesso à câmera
            stream_path (str): Caminho do stream (ex: RTSP)

        Returns:
            Response:
                - Renderiza cadastro.html (GET)
                - Redireciona para index após sucesso
                - Retorna mensagem de erro em caso de falha

        Sessão:
            - session["usuario_id"]: identifica usuário logado
            - empresa_id obtido via consulta no banco

        Banco de Dados:
            - Tabela: cameras
            - Relacionamento: empresa_id

        Segurança:
            - Acesso restrito a usuários autenticados (@login_required)
            - Isolamento por empresa (multi-tenant)

        Observações:
            - Não valida campos obrigatórios individualmente
            - Não valida formato de IP/MAC
            - Armazena credenciais da câmera (usuario/senha)

        Tratamento de erros:
            - Duplicidade detectada via mensagem do banco ("duplicate key")
            - Rollback em falhas de inserção

        Possíveis melhorias:
            - Validar formato de IP e MAC
            - Criptografar senha da câmera (ou usar vault)
            - Validar campos obrigatórios
            - Melhorar mensagens com flash()
            - Criar validação de conectividade (teste RTSP)
        """
    if request.method == "POST":

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT empresa_id FROM usuarios WHERE id = %s",
            (session["usuario_id"],)
        )
        usuario = cursor.fetchone()

        if not usuario:
            cursor.close()
            return redirect(url_for("auth.logout"))

        empresa_id = usuario[0]

        try:
            cursor.execute("""
                INSERT INTO cameras
                (nome_camera, ip_camera, caixa, rua1, rua2, mac, usuario, senha, empresa_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                request.form.get("nome_camera"),
                request.form.get("ip_camera"),
                request.form.get("caixa"),
                request.form.get("rua1"),
                request.form.get("rua2"),
                request.form.get("mac"),
                request.form.get("usuario"),
                request.form.get("senha"),
                empresa_id
            ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            cursor.close()
            if "duplicate key" in str(e):
                return "Já existe uma câmera com esse nome ou IP."
            return f"Erro: {e}"

        cursor.close()
        return redirect(url_for("main.index"))

    return render_template("cadastro.html")


# ==============================
# 🔎 TESTE
# ==============================
@main_bp.route("/teste", methods=["GET", "POST"])
@login_required
def teste():
    """
        Realiza testes manuais de conectividade (ping) em câmeras e exibe resultados.

        Esta função:
        - Identifica a empresa do usuário logado
        - Verifica o status do agente (online/offline)
        - Lista caixas disponíveis para filtro
        - Permite executar testes de ping manualmente:
            • por IP
            • por caixa
            • geral (todas as câmeras)
        - Registra comandos no banco para execução pelo agente
        - Consulta e exibe resultados dos testes

        Fluxo:
        1. Obtém empresa do usuário via sessão
        2. Verifica status do agente via último heartbeat:
            - < 60s → ON
            - ≥ 60s → OFF
        3. Lista caixas distintas da empresa
        4. Se GET:
            - Exibe lista de câmeras sem testes (estado inicial)
        5. Se POST:
            a. Identifica tipo de teste (ip, caixa, geral)
            b. Se agente OFF:
                - Retorna resultado como "Sem comunicação"
            c. Se agente ON:
                - Obtém agente_id
                - Monta lista de IPs a testar
                - Insere comandos 'ping' no banco
                - Busca últimos resultados executados
                - Interpreta status e latência

        Tipos de teste:
            - ip: teste manual de um IP específico
            - caixa: testa todas as câmeras de uma caixa
            - geral: testa todas as câmeras da empresa

        Returns:
            Response: Página HTML (teste.html) contendo:
                - lista de caixas
                - resultados dos testes

        Sessão:
            - session["usuario_id"]: identifica usuário logado

        Banco de Dados:
            - usuarios → empresa do usuário
            - agentes → status via heartbeat
            - cameras → origem dos IPs
            - comandos → execução e resultados

        Status retornados:
            - Online: resposta com TTL
            - Offline: sem resposta válida
            - Aguardando: comando enviado, sem retorno ainda
            - Sem comunicação: agente offline

        Observações:
            - Permite execução manual de testes sob demanda
            - Não impede duplicidade de comandos (pode gerar múltiplos)
            - Usa parsing de texto para determinar status
            - Resultados são baseados no último comando executado

        Segurança:
            - Acesso restrito a usuários autenticados

        Possíveis melhorias:
            - Evitar duplicidade de comandos (controle de fila)
            - Retornar resultados em tempo real (polling/WebSocket)
            - Estruturar resultado como JSON
            - Adicionar timeout visual para testes pendentes
            - Paginar resultados para grande volume de câmeras
        """
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

    # =========================
    # 🔥 CORREÇÃO AQUI (GET)
    # =========================
    if request.method == "GET":

        cursor.execute("""
            SELECT nome_camera, ip_camera
            FROM cameras
            WHERE empresa_id = %s
        """, (empresa_id,))

        for row in cursor.fetchall():
            resultados.append((row[0], row[1], "Sem teste", "-"))

    # =========================
    # POST (SEU CÓDIGO ORIGINAL)
    # =========================
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


# ==============================
# 🔎 PESQUISA
# ==============================
@main_bp.route("/pesquisa", methods=["GET", "POST"])
@login_required
def pesquisa():
    """
        Realiza a busca de câmeras com base em um termo informado pelo usuário.

        Esta função:
        - Identifica a empresa do usuário logado
        - Recebe um termo de pesquisa via formulário
        - Busca câmeras relacionadas ao termo em múltiplos campos
        - Retorna os resultados para exibição

        Fluxo:
        1. Obtém empresa do usuário via sessão
        2. Se usuário não existir:
            - Redireciona para logout
        3. Se POST:
            a. Captura termo de pesquisa
            b. Executa consulta na tabela 'cameras'
            c. Aplica filtro em múltiplos campos:
                - nome_camera
                - ip_camera
                - caixa
                - rua1
                - rua2
            d. Utiliza ILIKE para busca case-insensitive
        4. Fecha conexão com banco
        5. Renderiza página com resultados

        Args (form-data):
            termo (str): Texto utilizado na busca

        Returns:
            Response: Página HTML (pesquisa.html) contendo:
                - lista de câmeras que correspondem ao termo
                - lista vazia caso não haja resultados

        Sessão:
            - session["usuario_id"]: identifica usuário logado
            - empresa_id obtido via banco

        Banco de Dados:
            - Tabela: cameras
            - Filtro por empresa_id (multi-tenant)
            - Busca com operador ILIKE (case-insensitive)

        Campos pesquisáveis:
            - nome_camera
            - ip_camera
            - caixa
            - rua1
            - rua2

        Observações:
            - Busca parcial (usa %termo%)
            - Não possui paginação (retorna todos os resultados)
            - Não trata termos vazios explicitamente

        Segurança:
            - Isolamento por empresa (empresa_id)
            - Protegido por autenticação (@login_required)

        Possíveis melhorias:
            - Adicionar paginação para grandes volumes
            - Implementar debounce (frontend)
            - Criar índice no banco para melhorar performance (ILIKE)
            - Destacar termos encontrados (highlight)
            - Permitir busca combinada (filtros avançados)
        """

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
        return redirect(url_for("auth.logout"))

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


# ==============================
# ⚙️ ALTERAÇÕES
# ==============================
@main_bp.route("/alteracoes")
@login_required
def alteracoes():
    """
       Exibe a lista de câmeras da empresa para visualização e possíveis alterações.

       Esta função:
       - Identifica a empresa do usuário logado
       - Busca todas as câmeras vinculadas à empresa
       - Retorna os dados para exibição em tela de configuração/edição

       Fluxo:
       1. Obtém usuário logado via sessão
       2. Busca empresa associada ao usuário
       3. Valida existência do usuário
       4. Consulta todas as câmeras da empresa
       5. Ordena por ID decrescente (mais recentes primeiro)
       6. Fecha conexão com banco
       7. Renderiza template com os dados

       Returns:
           Response: Página HTML (alteracoes.html) contendo:
               - lista de câmeras
               - dados completos para edição

       Sessão:
           - session["usuario_id"]: identifica usuário logado

       Banco de Dados:
           - usuarios → vínculo com empresa
           - cameras → dados das câmeras

       Campos retornados:
           - id
           - nome_camera
           - ip_camera
           - caixa
           - rua1
           - rua2
           - mac
           - usuario (credencial da câmera)
           - senha (credencial da câmera)

       Segurança:
           - Acesso restrito a usuários autenticados (@login_required)
           - Isolamento por empresa (multi-tenant)

       Observações:
           - Retorna credenciais das câmeras (sensível)
           - Não possui paginação (pode crescer com volume)
           - Função apenas de leitura (edição ocorre em outra rota)

       Possíveis melhorias:
           - Ocultar ou mascarar senha da câmera
           - Implementar paginação
           - Adicionar filtros (caixa, status, etc.)
           - Criar endpoint específico para edição
       """
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
        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    # Buscar somente câmeras da empresa
    cursor.execute("""
        SELECT 
            id,
            nome_camera,
            ip_camera,
            caixa,
            rua1,
            rua2,
            mac,
            usuario,
            senha
        FROM cameras
        WHERE empresa_id = %s
        ORDER BY id DESC
    """, (empresa_id,))

    cameras = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("alteracoes.html", cameras=cameras)


@main_bp.route("/editar/<int:id>", methods=["GET", "POST"])
@login_required
def editar(id):
    """
       Permite editar os dados de uma câmera específica pertencente à empresa do usuário.

       Esta função:
       - Identifica a empresa do usuário logado
       - Valida se a câmera pertence à empresa (isolamento multi-tenant)
       - Exibe os dados atuais da câmera (GET)
       - Atualiza os dados da câmera no banco (POST)

       Fluxo:
       1. Obtém empresa do usuário via sessão
       2. Valida existência do usuário
       3. Se POST:
           a. Captura dados do formulário
           b. Executa UPDATE na tabela 'cameras'
           c. Garante que a câmera pertence à empresa
           d. Confirma transação (commit)
           e. Redireciona para tela de alterações
       4. Se GET:
           a. Busca dados da câmera pelo ID
           b. Valida vínculo com empresa
           c. Renderiza formulário preenchido

       Args:
           id (int): ID da câmera a ser editada

       Campos editáveis (form-data):
           nome_camera (str)
           ip_camera (str)
           caixa (str)
           rua1 (str)
           rua2 (str)
           mac (str)
           usuario (str): credencial da câmera
           senha (str): credencial da câmera

       Returns:
           Response:
               - Renderiza editar.html com dados da câmera (GET)
               - Redireciona para alteracoes após sucesso (POST)
               - Retorna erro em caso de falha

       Sessão:
           - session["usuario_id"]: identifica usuário logado

       Banco de Dados:
           - Tabela: cameras
           - Condição de segurança:
               WHERE id = %s AND empresa_id = %s

       Segurança:
           - Acesso restrito a usuários autenticados (@login_required)
           - Isolamento por empresa (evita acesso a dados de outras empresas)

       Observações:
           - Atualiza diretamente todos os campos (overwrite completo)
           - Não valida campos individualmente
           - Permite alteração de credenciais da câmera

       Tratamento de erros:
           - Rollback em caso de falha no UPDATE
           - Retorna mensagem com erro

       Possíveis melhorias:
           - Validar formato de IP/MAC
           - Criptografar senha da câmera
           - Detectar alterações (evitar update desnecessário)
           - Adicionar confirmação de edição
           - Implementar histórico de alterações (audit log)
       """
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
        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    if request.method == "POST":

        nome_camera = request.form.get("nome_camera")
        ip_camera = request.form.get("ip_camera")
        caixa = request.form.get("caixa")
        rua1 = request.form.get("rua1")
        rua2 = request.form.get("rua2")
        mac = request.form.get("mac")

        usuario_cam = request.form.get("usuario")
        senha_cam = request.form.get("senha")

        try:
            cursor.execute("""
                UPDATE cameras
                SET nome_camera = %s,
                    ip_camera = %s,
                    caixa = %s,
                    rua1 = %s,
                    rua2 = %s,
                    mac = %s,
                    usuario = %s,
                    senha = %s
                WHERE id = %s
                  AND empresa_id = %s
            """, (
                nome_camera,
                ip_camera,
                caixa,
                rua1,
                rua2,
                mac,
                usuario_cam,
                senha_cam,
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
        return redirect(url_for("main.alteracoes"))

    # GET
    cursor.execute("""
        SELECT 
            id,
            nome_camera,
            ip_camera,
            caixa,
            rua1,
            rua2,
            mac,
            usuario,
            senha
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

@main_bp.route("/apagar/<int:id>", methods=["POST"])
@login_required
def apagar(id):
    """
       Remove uma câmera do sistema, garantindo que pertença à empresa do usuário.

       Esta função:
       - Identifica a empresa do usuário logado
       - Executa a exclusão da câmera pelo ID
       - Garante isolamento multi-tenant (empresa_id)
       - Redireciona para a tela de alterações após a remoção

       Fluxo:
       1. Obtém empresa do usuário via sessão
       2. Valida existência do usuário
       3. Executa DELETE na tabela 'cameras'
          com verificação de empresa_id
       4. Confirma a transação (commit)
       5. Fecha conexão com banco
       6. Redireciona para a página de alterações

       Args:
           id (int): ID da câmera a ser removida

       Returns:
           Response: Redireciona para a página 'alteracoes'

       Sessão:
           - session["usuario_id"]: identifica usuário logado

       Banco de Dados:
           - Tabela: cameras
           - Condição de segurança:
               WHERE id = %s AND empresa_id = %s

       Segurança:
           - Acesso restrito a usuários autenticados (@login_required)
           - Proteção multi-tenant (impede exclusão de outras empresas)
           - Método POST evita exclusão acidental via URL

       Observações:
           - Exclusão permanente (hard delete)
           - Não há confirmação adicional no backend
           - Não verifica existência antes de excluir

       Possíveis melhorias:
           - Implementar soft delete (campo ativo/deletado)
           - Adicionar confirmação no frontend
           - Criar log de auditoria (quem apagou, quando)
           - Verificar dependências antes da exclusão
       """

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
        return redirect(url_for("auth.logout"))

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

    return redirect(url_for("main.alteracoes"))

# ==============================
# 📊 RELATÓRIO
# ==============================
@main_bp.route("/relatorio")
@login_required
def relatorio():
    """
      Gera um relatório de câmeras offline da empresa do usuário.

      Esta função:
      - Identifica a empresa do usuário logado
      - Busca todas as câmeras da empresa
      - Verifica o último resultado de ping de cada câmera
      - Filtra apenas as câmeras que estão offline
      - Retorna os dados para exibição em relatório

      Fluxo:
      1. Obtém empresa do usuário via sessão
      2. Valida existência do usuário
      3. Busca todas as câmeras da empresa
      4. Para cada câmera:
          a. Consulta último comando executado (ping)
          b. Analisa resultado:
              - Contém "ttl=" → Online
              - Caso contrário → Offline
          c. Se Offline:
              - Adiciona à lista do relatório
      5. Fecha conexão com banco
      6. Renderiza template com câmeras offline

      Returns:
          Response: Página HTML (relatorio.html) contendo:
              - lista de câmeras offline

      Sessão:
          - session["usuario_id"]: identifica usuário logado

      Banco de Dados:
          - usuarios → empresa do usuário
          - cameras → lista de dispositivos
          - comandos → histórico de execução (ping)

      Critério de Status:
          - Online: resultado contém "ttl="
          - Offline: ausência de resultado válido

      Observações:
          - Considera apenas o último comando executado
          - Não diferencia erro de rede vs timeout
          - Não inclui câmeras sem histórico (assumidas como offline)

      Segurança:
          - Acesso restrito a usuários autenticados (@login_required)
          - Isolamento por empresa (multi-tenant)

      Possíveis melhorias:
          - Incluir data/hora do último teste
          - Mostrar latência
          - Diferenciar tipos de falha (timeout, host down, etc.)
          - Exportar relatório (CSV/PDF)
          - Adicionar filtros (caixa, região, etc.)
      """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    cursor.execute("""
        SELECT id, nome_camera, ip_camera, caixa
        FROM cameras
        WHERE empresa_id = %s
    """, (empresa_id,))

    cameras = cursor.fetchall()

    lista_offline = []

    for cam in cameras:

        ip = cam[2]

        cursor.execute("""
            SELECT resultado
            FROM comandos
            WHERE alvo = %s
              AND empresa_id = %s
              AND status = 'executado'
            ORDER BY id DESC
            LIMIT 1
        """, (ip, empresa_id))

        comando = cursor.fetchone()

        status = "Offline"

        if comando:
            resultado = comando[0]

            if resultado and "ttl=" in resultado.lower():
                status = "Online"

        if status == "Offline":

            lista_offline.append({
                "nome": cam[1],
                "ip": ip,
                "caixa": cam[3]
            })

    cursor.close()
    conn.close()

    return render_template(
        "relatorio.html",
        cameras=lista_offline
    )


# ==============================
# 📄 RELATÓRIO PDF
# ==============================
@main_bp.route("/relatorio/pdf")
@login_required
def relatorio_pdf():
    """
        Gera um relatório em PDF contendo as câmeras offline da empresa do usuário.

        Esta função:
        - Identifica a empresa do usuário logado
        - Busca todas as câmeras da empresa
        - Analisa o último resultado de ping de cada câmera
        - Filtra apenas câmeras offline
        - Gera um arquivo PDF com os dados formatados
        - Retorna o PDF para download

        Fluxo:
        1. Obtém empresa do usuário via sessão
        2. Valida existência do usuário
        3. Busca todas as câmeras da empresa
        4. Para cada câmera:
            a. Consulta último comando executado (ping)
            b. Determina status (Online/Offline)
            c. Adiciona à lista se estiver offline
        5. Gera PDF:
            - Título
            - Data/hora de geração
            - Total de câmeras offline
            - Tabela com dados
        6. Trata quebra de página automaticamente
        7. Retorna arquivo PDF como download

        Returns:
            Response:
                - Arquivo PDF para download (application/pdf)

        Sessão:
            - session["usuario_id"]: identifica usuário logado

        Banco de Dados:
            - usuarios → empresa do usuário
            - cameras → dispositivos
            - comandos → histórico de execução

        Conteúdo do PDF:
            - Título do relatório
            - Data de geração
            - Quantidade total de câmeras offline
            - Lista contendo:
                • Nome
                • IP
                • Caixa
                • Status

        Biblioteca:
            - reportlab (canvas) para geração do PDF
            - io.BytesIO para buffer em memória

        Observações:
            - Considera apenas o último comando executado
            - Todas as câmeras sem resposta válida são consideradas offline
            - PDF gerado em memória (não salva em disco)

        Layout:
            - Paginação automática quando atinge limite vertical
            - Cabeçalho repetido em novas páginas

        Segurança:
            - Acesso restrito a usuários autenticados (@login_required)
            - Isolamento por empresa (multi-tenant)

        Possíveis melhorias:
            - Adicionar logo da empresa no PDF
            - Incluir latência e horário do último teste
            - Permitir exportação por filtro (caixa/região)
            - Gerar PDF com tabela estilizada (cores/bordas)
            - Cachear relatório para reduzir carga
        """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()
        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    cursor.execute("""
        SELECT id, nome_camera, ip_camera, caixa
        FROM cameras
        WHERE empresa_id = %s
    """, (empresa_id,))
    cameras = cursor.fetchall()

    lista_offline = []

    for cam in cameras:

        ip = cam[2]

        cursor.execute("""
            SELECT resultado
            FROM comandos
            WHERE alvo = %s
              AND empresa_id = %s
              AND status = 'executado'
            ORDER BY id DESC
            LIMIT 1
        """, (ip, empresa_id))

        comando = cursor.fetchone()

        status = "Offline"

        if comando:
            resultado = comando[0]

            if resultado and "ttl=" in resultado.lower():
                status = "Online"

        if status == "Offline":

            lista_offline.append({
                "nome": cam[1],
                "ip": ip,
                "caixa": cam[3]
            })

    cursor.close()
    conn.close()

    # -------- GERAR PDF --------

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=A4)

    largura, altura = A4

    y = altura - 40

    # Título
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(40, y, "Relatório de Câmeras Offline")

    y -= 25

    # Data
    pdf.setFont("Helvetica", 10)
    data = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    pdf.drawString(40, y, f"Gerado em: {data}")

    y -= 20

    # Total
    pdf.drawString(40, y, f"Total de câmeras offline: {len(lista_offline)}")

    y -= 30

    # Cabeçalho
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(40, y, "Nome")
    pdf.drawString(250, y, "IP")
    pdf.drawString(380, y, "Caixa")
    pdf.drawString(460, y, "Status")

    y -= 15
    pdf.setFont("Helvetica", 10)

    for cam in lista_offline:

        if y < 50:
            pdf.showPage()
            y = altura - 40

            pdf.setFont("Helvetica-Bold", 11)
            pdf.drawString(40, y, "Nome")
            pdf.drawString(250, y, "IP")
            pdf.drawString(380, y, "Caixa")
            pdf.drawString(460, y, "Status")

            y -= 20
            pdf.setFont("Helvetica", 10)

        pdf.drawString(40, y, cam["nome"])
        pdf.drawString(250, y, cam["ip"])
        pdf.drawString(380, y, str(cam["caixa"]))
        pdf.drawString(460, y, "Offline")

        y -= 18

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="relatorio_cameras_offline.pdf",
        mimetype="application/pdf"
    )

@main_bp.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()
    cursor = conn.cursor()

    condominios = []

    # Buscar todos os condomínios/empresas
    cursor.execute("""
        SELECT id, nome_empresa
        FROM empresas
        ORDER BY nome_empresa
    """)

    empresas = cursor.fetchall()

    agora = datetime.datetime.now()

    for empresa in empresas:

        empresa_id = empresa[0]
        nome_empresa = empresa[1]

        # Buscar dispositivos do condomínio
        cursor.execute("""
            SELECT status, ping_ativo, latencia
            FROM dispositivos
            WHERE empresa_id = %s
        """, (empresa_id,))

        dispositivos = cursor.fetchall()

        total = len(dispositivos)

        online = sum(
            1 for d in dispositivos
            if d[0] == "online"
        )

        offline = total - online

        avisos = sum(
            1 for d in dispositivos
            if d[0] in ("atencao", "atenção", "offline")
        )

        latencias_validas = [
            d[2] for d in dispositivos
            if d[2] is not None
        ]

        ping_medio = round(
            sum(latencias_validas) / len(latencias_validas)
        ) if latencias_validas else 0

        if total > 0:
            saude = round((online / total) * 100)
        else:
            saude = 0

        # Buscar status do Agent
        cursor.execute("""
            SELECT ultimo_heartbeat
            FROM agentes
            WHERE empresa_id = %s
            ORDER BY ultimo_heartbeat DESC
            LIMIT 1
        """, (empresa_id,))

        agente = cursor.fetchone()

        agent_status = "OFF"

        if agente and agente[0]:
            if (agora - agente[0]).total_seconds() < 60:
                agent_status = "ON"

        # Definir estado geral do condomínio
        if agent_status == "OFF":
            estado = "CRÍTICO"
        elif saude >= 90:
            estado = "SAUDÁVEL"
        elif saude >= 70:
            estado = "ATENÇÃO"
        else:
            estado = "CRÍTICO"

        # Definir visual do card
        if estado == "CRÍTICO":
            cor = "#ef4444"
            chip = "chip-danger"
            borda = "border-red-500/35"
            glow = "shadow-[0_0_24px_rgba(239,68,68,.10)]"

        elif estado == "ATENÇÃO":
            cor = "#f59e0b"
            chip = "chip-warn"
            borda = "border-amber-500/35"
            glow = "shadow-[0_0_24px_rgba(245,158,11,.10)]"

        else:
            cor = "#10b981"
            chip = "chip-ok"
            borda = "border-slate-800/80"
            glow = ""

        condominios.append({
            "id": empresa_id,

            "nome": nome_empresa,

            # O HTML espera "status"
            "status": estado,

            "saude": saude,

            # Visual do card
            "cor": cor,
            "chip": chip,
            "borda": borda,
            "glow": glow,

            # Métricas
            "dispositivos": total,
            "online": online,
            "offline": offline,

            # Agent
            "agent": "ONLINE" if agent_status == "ON" else "OFFLINE",

            # Por enquanto fixo
            "link": "ONLINE" if agent_status == "ON" else "OFFLINE",

            # Ping
            "latencia": f"{ping_medio}ms",

            # Texto do alerta
            "alerta": (
                "Sem alertas ativos"
                if avisos == 0
                else f"{avisos} dispositivo(s) em atenção"
            )
        })

    cursor.close()
    conn.close()

    print(condominios)

    return render_template(
        "dashboard.html",
        condominios=condominios
    )


@main_bp.route("/cadastro-dispositivo", methods=["GET", "POST"])
@login_required
def cadastro_dispositivo():

    if request.method == "POST":

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT empresa_id FROM usuarios WHERE id = %s",
            (session["usuario_id"],)
        )

        usuario = cursor.fetchone()

        if not usuario:

            cursor.close()
            conn.close()

            return redirect(url_for("auth.logout"))

        empresa_id = usuario[0]

        try:

            cursor.execute("""

                INSERT INTO dispositivos (

                    empresa_id,

                    nome,
                    categoria,

                    fabricante,
                    modelo,

                    ip,
                    mac,
                    hostname,

                    usuario,
                    senha,

                    ssh_ativo,
                    snmp_ativo,
                    api_ativa,

                    community_snmp,

                    porta_http,
                    porta_https,
                    porta_rtsp,
                    porta_ssh,

                    status,
                    localizacao,
                    observacao

                )

                VALUES (

                    %s,

                    %s,
                    %s,

                    %s,
                    %s,

                    %s,
                    %s,
                    %s,

                    %s,
                    %s,

                    %s,
                    %s,
                    %s,

                    %s,

                    %s,
                    %s,
                    %s,
                    %s,

                    %s,
                    %s,
                    %s

                )

                ON CONFLICT (ip)

                DO UPDATE SET

                    nome = EXCLUDED.nome,
                    categoria = EXCLUDED.categoria,

                    fabricante = EXCLUDED.fabricante,
                    modelo = EXCLUDED.modelo,

                    mac = EXCLUDED.mac,
                    hostname = EXCLUDED.hostname,

                    usuario = EXCLUDED.usuario,
                    senha = EXCLUDED.senha,

                    ssh_ativo = EXCLUDED.ssh_ativo,
                    snmp_ativo = EXCLUDED.snmp_ativo,
                    api_ativa = EXCLUDED.api_ativa,

                    community_snmp = EXCLUDED.community_snmp,

                    porta_http = EXCLUDED.porta_http,
                    porta_https = EXCLUDED.porta_https,
                    porta_rtsp = EXCLUDED.porta_rtsp,
                    porta_ssh = EXCLUDED.porta_ssh,

                    status = EXCLUDED.status,
                    localizacao = EXCLUDED.localizacao,
                    observacao = EXCLUDED.observacao

                RETURNING id

            """, (

                empresa_id,

                request.form.get("nome"),
                request.form.get("categoria") or "rede",

                request.form.get("fabricante"),
                request.form.get("modelo"),

                request.form.get("ip"),
                request.form.get("mac"),
                request.form.get("hostname"),

                request.form.get("usuario"),
                request.form.get("senha"),

                True if request.form.get("ssh_ativo") else False,
                True if request.form.get("snmp_ativo") else False,
                True if request.form.get("api_ativa") else False,

                request.form.get("community_snmp"),

                int(request.form.get("porta_http") or 80),
                int(request.form.get("porta_https") or 443),
                int(request.form.get("porta_rtsp") or 554),
                int(request.form.get("porta_ssh") or 22),

                request.form.get("status") or "online",
                request.form.get("localizacao"),
                request.form.get("observacao")

            ))

            dispositivo_id = cursor.fetchone()[0]

            conn.commit()

        except Exception as e:

            conn.rollback()

            cursor.close()
            conn.close()

            return f"Erro ao cadastrar dispositivo: {e}"

        cursor.close()
        conn.close()

        return redirect(url_for("main.dispositivos"))

    return render_template("cadastro_dispositivo.html")

@main_bp.route("/discovery")
@login_required
def discovery():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""

        UPDATE dispositivos

        SET

            ping_ativo = FALSE,
            status = 'offline'

        WHERE

            ultimo_ping IS NULL

            OR

            ultimo_ping < NOW() - INTERVAL '120 seconds'

    """)

    conn.commit()

    # ==========================================
    # EMPRESA DO USUÁRIO
    # ==========================================

    cursor.execute(
        """
        SELECT empresa_id, tipo
        FROM usuarios
        WHERE id = %s
        """,
        (session["usuario_id"],)
    )

    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()

        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]
    tipo_usuario = usuario[1]

    empresa_id_url = request.args.get("empresa_id", type=int)

    # Admin Global pode visualizar qualquer condomínio
    if tipo_usuario == "admin_global" and empresa_id_url:

        cursor.execute("""
            SELECT id
            FROM empresas
            WHERE id = %s
        """, (empresa_id_url,))

        empresa_existe = cursor.fetchone()

        if empresa_existe:
            empresa_id = empresa_id_url

    # ==========================================
    # NOME DA EMPRESA
    # ==========================================

    cursor.execute("""

        SELECT nome_empresa

        FROM empresas

        WHERE id = %s

    """, (empresa_id,))

    empresa = cursor.fetchone()

    nome_empresa = empresa[0] if empresa else "Empresa"

    # ==========================================
    # STATUS DO AGENT
    # ==========================================

    agente_status = "OFF"
    ultimo_heartbeat = None

    cursor.execute("""

        SELECT ultimo_heartbeat

        FROM agentes

        WHERE empresa_id = %s

        ORDER BY ultimo_heartbeat DESC

        LIMIT 1

    """, (empresa_id,))

    agente = cursor.fetchone()

    if agente and agente[0]:

        ultimo_heartbeat = agente[0]

        agora = datetime.datetime.now()

        if (agora - agente[0]).total_seconds() < 60:

            agente_status = "ON"

    # ==========================================
    # INVENTÁRIO
    # ==========================================

    cursor.execute("""

        SELECT

            id,
            ip,
            mac,
            hostname,

            ssh,
            snmp,
            http,
            https,
            rtsp,

            ping_ativo,
            latencia,

            ultima_descoberta

        FROM inventario_dispositivos
            
        WHERE empresa_id = %s
         AND vinculado = FALSE
         
        ORDER BY ultima_descoberta DESC

    """, (empresa_id,))

    rows = cursor.fetchall()

    agora = datetime.datetime.now()

    dispositivos = []

    for d in rows:

        ultima_descoberta = d[11]

        status_descoberta = "offline"

        if ultima_descoberta:

            idade = (agora - ultima_descoberta).total_seconds()

            if idade <= 120:

                status_descoberta = "online"

            elif idade <= 600:

                status_descoberta = "atencao"

        dispositivos.append({

            "id": d[0],
            "ip": d[1],
            "mac": d[2],
            "hostname": d[3],

            "ssh": d[4],
            "snmp": d[5],
            "http": d[6],
            "https": d[7],
            "rtsp": d[8],

            "ping_ativo": d[9],
            "latencia": d[10],

            "ultima_descoberta": d[11],

            "status_descoberta": status_descoberta

        })

    cursor.close()
    conn.close()

    print(f"Discovery carregou {len(dispositivos)} dispositivos")

    return render_template(

        "discovery.html",

        dispositivos=dispositivos,

        agente_status=agente_status,
        ultimo_heartbeat=ultimo_heartbeat,

        nome_empresa=nome_empresa

    )


@main_bp.route("/dispositivos/adicionar", methods=["POST"])
@login_required
def adicionar_dispositivo():

    data = request.get_json()

    inventario_id = data.get("inventario_id")

    conn = get_db()
    cursor = conn.cursor()

    try:

        # =========================
        # BUSCAR INVENTÁRIO
        # =========================
        cursor.execute("""

            SELECT

                empresa_id,

                ip,
                mac,
                hostname,

                ssh,
                snmp,
                http,
                https,
                rtsp,

                ping_ativo,
                latencia

            FROM inventario_dispositivos

            WHERE id = %s

        """, (inventario_id,))

        d = cursor.fetchone()

        if not d:

            cursor.close()
            conn.close()

            return jsonify({

                "erro": "Dispositivo não encontrado no inventário"

            }), 404

        empresa_id = d[0]

        ip = d[1]
        mac = d[2]
        hostname = d[3]

        ssh = d[4]
        snmp = d[5]

        ping_ativo = d[9]
        latencia = d[10]

        # =========================
        # INSERT / UPDATE
        # =========================
        cursor.execute("""

            INSERT INTO dispositivos (

                empresa_id,

                nome,
                categoria,

                ip,
                mac,
                hostname,

                ssh_ativo,
                snmp_ativo,

                ping_ativo,
                latencia,

                status,
                origem,

                inventario_id

            )

            VALUES (

                %s,

                %s,
                %s,

                %s,
                %s,
                %s,

                %s,
                %s,

                %s,
                %s,

                %s,
                %s,

                %s

            )

            ON CONFLICT (ip)

            DO UPDATE SET

                empresa_id = EXCLUDED.empresa_id,

                nome = EXCLUDED.nome,

                mac = EXCLUDED.mac,
                hostname = EXCLUDED.hostname,

                ssh_ativo = EXCLUDED.ssh_ativo,
                snmp_ativo = EXCLUDED.snmp_ativo,

                ping_ativo = EXCLUDED.ping_ativo,
                latencia = EXCLUDED.latencia,

                status = EXCLUDED.status,
                origem = EXCLUDED.origem,

                inventario_id = EXCLUDED.inventario_id

            RETURNING id

        """, (

            empresa_id,

            hostname or ip,
            "rede",

            ip,
            mac,
            hostname,

            ssh,
            snmp,

            ping_ativo,
            latencia,

            "online",
            "discovery",

            inventario_id

        ))

        dispositivo_id = cursor.fetchone()[0]

        # =========================
        # MARCAR VINCULADO
        # =========================
        cursor.execute("""

            UPDATE inventario_dispositivos

            SET vinculado = TRUE

            WHERE id = %s

        """, (inventario_id,))

        conn.commit()

    except Exception as e:

        conn.rollback()

        cursor.close()
        conn.close()

        return jsonify({

            "erro": f"Erro interno no banco de dados: {str(e)}"

        }), 500

    cursor.close()
    conn.close()

    return jsonify({

        "status": "ok",
        "dispositivo_id": dispositivo_id

    })


@main_bp.route("/dispositivos")
@login_required
def dispositivos():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""

        UPDATE dispositivos

        SET

            ping_ativo = FALSE,
            status = 'offline'

        WHERE

            ultimo_ping IS NULL

            OR

            ultimo_ping < NOW() - INTERVAL '120 seconds'

    """)

    conn.commit()

    cursor.execute(
        """
        SELECT empresa_id, tipo
        FROM usuarios
        WHERE id = %s
        """,
        (session["usuario_id"],)
    )

    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()

        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]
    tipo_usuario = usuario[1]

    empresa_id_url = request.args.get("empresa_id", type=int)

    # Admin Global pode visualizar qualquer condomínio
    if tipo_usuario == "admin_global" and empresa_id_url:

        cursor.execute("""
            SELECT id
            FROM empresas
            WHERE id = %s
        """, (empresa_id_url,))

        empresa_existe = cursor.fetchone()

        if empresa_existe:
            empresa_id = empresa_id_url

    # ==========================
    # NOME DA EMPRESA
    # ==========================

    cursor.execute("""

        SELECT nome_empresa

        FROM empresas

        WHERE id = %s

    """, (empresa_id,))

    empresa = cursor.fetchone()

    nome_empresa = empresa[0] if empresa else "Empresa"

    # ==========================
    # STATUS DO AGENTE
    # ==========================

    agente_status = "OFF"

    ultimo_heartbeat = None

    cursor.execute("""

        SELECT ultimo_heartbeat

        FROM agentes

        WHERE empresa_id = %s

        ORDER BY ultimo_heartbeat DESC

        LIMIT 1

    """, (empresa_id,))

    agente = cursor.fetchone()

    if agente and agente[0]:

        ultimo_heartbeat = agente[0]

        agora = datetime.datetime.now()

        if (agora - agente[0]).total_seconds() < 60:

            agente_status = "ON"

    # ==========================
    # DISPOSITIVOS
    # ==========================

    cursor.execute("""

        SELECT

            id,
            nome,
            categoria,

            fabricante,
            modelo,

            ip,
            mac,
            hostname,

            status,

            ssh_ativo,
            snmp_ativo,
            api_ativa,

            porta_http,
            porta_https,
            porta_rtsp,
            porta_ssh,

            ping_ativo,
            latencia

        FROM dispositivos

        WHERE empresa_id = %s

        ORDER BY categoria, nome

    """, (empresa_id,))

    rows = cursor.fetchall()

    dispositivos = []

    for d in rows:

        dispositivos.append({

            "id": d[0],

            "nome": d[1],
            "categoria": d[2],

            "fabricante": d[3],
            "modelo": d[4],

            "ip": d[5],
            "mac": d[6],
            "hostname": d[7],

            "status": d[8],

            "ssh": d[9],
            "snmp": d[10],
            "api": d[11],

            "porta_http": d[12],
            "porta_https": d[13],
            "porta_rtsp": d[14],
            "porta_ssh": d[15],

            "ping_ativo": d[16],
            "latencia": d[17]

        })

    cursor.close()
    conn.close()

    total_dispositivos = len(dispositivos)

    online = sum(
        1 for d in dispositivos
        if d["status"] == "online"
    )

    if total_dispositivos > 0:

        saude_rede = round(
            (online / total_dispositivos) * 100
        )

    else:

        saude_rede = 0

    if saude_rede >= 90:

        saude_cor = "verde"

    elif saude_rede >= 70:

        saude_cor = "amarelo"

    else:

        saude_cor = "vermelho"

    return render_template(

        "dispositivos.html",

        dispositivos=dispositivos,
        agente_status=agente_status,
        ultimo_heartbeat=ultimo_heartbeat,
        nome_empresa = nome_empresa,
        saude_rede=saude_rede,
        saude_cor=saude_cor,
        empresa_id=empresa_id

    )

@main_bp.route(
    "/dispositivos/<int:id>/editar",
    methods=["GET", "POST"]
)

@login_required
def editar_dispositivo(id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )

    usuario = cursor.fetchone()

    if not usuario:

        cursor.close()
        conn.close()

        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    # ==========================================
    # SALVAR ALTERAÇÕES
    # ==========================================

    if request.method == "POST":

        try:

            cursor.execute("""

                UPDATE dispositivos

                SET

                    nome = %s,
                    categoria = %s,
                    tipo_dispositivo = %s,

                    fabricante = %s,
                    modelo = %s,

                    ip = %s,
                    hostname = %s,
                    mac = %s,

                    localizacao = %s,
                    endereco_fisico = %s

                WHERE id = %s
                  AND empresa_id = %s

            """, (

                request.form.get("nome"),
                request.form.get("categoria"),
                request.form.get("tipo_dispositivo"),

                request.form.get("fabricante"),
                request.form.get("modelo"),

                request.form.get("ip"),
                request.form.get("hostname"),
                request.form.get("mac"),

                request.form.get("localizacao"),
                request.form.get("endereco_fisico"),

                id,
                empresa_id

            ))

            conn.commit()

            return redirect(url_for("main.dispositivos"))

        except Exception as e:

            conn.rollback()

            return f"Erro ao salvar dispositivo: {e}"

    # ==========================================
    # CARREGAR DISPOSITIVO
    # ==========================================

    cursor.execute("""

        SELECT *

        FROM dispositivos

        WHERE id = %s
          AND empresa_id = %s

    """, (id, empresa_id))

    colunas = [desc[0] for desc in cursor.description]

    row = cursor.fetchone()

    dispositivo = dict(zip(colunas, row)) if row else None

    cursor.close()
    conn.close()

    if not dispositivo:
        return "Dispositivo não encontrado"

    return render_template(

        "editar_dispositivo.html",

        dispositivo=dispositivo

    )

@main_bp.route(
    "/dispositivos/<int:id>/excluir",
    methods=["POST"]
)
@login_required
def excluir_dispositivo(id):

    conn = get_db()
    cursor = conn.cursor()

    try:

        cursor.execute(
            "SELECT empresa_id FROM usuarios WHERE id = %s",
            (session["usuario_id"],)
        )

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for("auth.logout"))

        empresa_id = usuario[0]

        cursor.execute("""

            DELETE FROM dispositivos

            WHERE id = %s
              AND empresa_id = %s

        """, (id, empresa_id))

        conn.commit()

    except Exception as e:

        conn.rollback()

        return f"Erro ao excluir dispositivo: {e}"

    finally:

        cursor.close()
        conn.close()

    return redirect(url_for("main.dispositivos"))

@main_bp.route("/add-dispositivo", methods=["GET", "POST"])
@login_required
def add_dispositivo():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )

    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conn.close()

        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    ip = request.form.get("ip")

    if ip:

        cursor.execute(
            "SELECT id FROM dispositivos WHERE ip = %s",
            (ip,)
        )

        if cursor.fetchone():
            cursor.close()
            conn.close()

            return "Já existe um dispositivo cadastrado com este IP."

        try:

            cursor.execute("""

                INSERT INTO dispositivos (

                    empresa_id,

                    nome,
                    categoria,
                    tipo_dispositivo,

                    fabricante,
                    modelo,

                    ip,
                    hostname,
                    mac,

                    localizacao,
                    endereco_fisico,

                    usuario_web,
                    senha_web,

                    usuario_ssh,
                    senha_ssh,

                    usuario_onvif,
                    senha_onvif,

                    community_snmp,

                    porta_http,
                    porta_https,
                    porta_rtsp,
                    porta_ssh,

                    ssh_ativo,
                    snmp_ativo,
                    api_ativa,

                    observacoes,

                    origem,

                    status,
                    ping_ativo,
                    latencia

                )

                VALUES (

                    %s,

                    %s,
                    %s,
                    %s,

                    %s,
                    %s,

                    %s,
                    %s,
                    %s,

                    %s,
                    %s,

                    %s,
                    %s,

                    %s,
                    %s,

                    %s,
                    %s,

                    %s,

                    %s,
                    %s,
                    %s,
                    %s,

                    %s,
                    %s,
                    %s,

                    %s,

                    'manual',

                    'offline',
                    FALSE,
                    0

                )

            """, (

                empresa_id,

                request.form.get("nome"),
                request.form.get("categoria"),
                request.form.get("tipo_dispositivo"),

                request.form.get("fabricante"),
                request.form.get("modelo"),

                request.form.get("ip"),
                request.form.get("hostname"),
                request.form.get("mac"),

                request.form.get("localizacao"),
                request.form.get("endereco_fisico"),

                request.form.get("usuario_web"),
                request.form.get("senha_web"),

                request.form.get("usuario_ssh"),
                request.form.get("senha_ssh"),

                request.form.get("usuario_onvif"),
                request.form.get("senha_onvif"),

                request.form.get("community_snmp"),

                request.form.get("porta_http") or 80,
                request.form.get("porta_https") or 443,
                request.form.get("porta_rtsp") or 554,
                request.form.get("porta_ssh") or 22,

                bool(request.form.get("ssh_ativo")),
                bool(request.form.get("snmp_ativo")),
                bool(request.form.get("api_ativa")),

                request.form.get("observacoes")

            ))

            conn.commit()

            return redirect(url_for("main.dispositivos"))

        except Exception as e:

            conn.rollback()

            return f"Erro ao cadastrar dispositivo: {e}"

    cursor.close()
    conn.close()

    return render_template(
        "add_dispositivo.html"
    )

@main_bp.route("/dispositivo/<int:id>")
@login_required
def detalhe_dispositivo(id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )

    usuario = cursor.fetchone()

    if not usuario:

        cursor.close()
        conn.close()

        return redirect(url_for("auth.logout"))

    empresa_id = usuario[0]

    cursor.execute("""

        SELECT *

        FROM dispositivos

        WHERE id = %s
        AND empresa_id = %s

    """, (id, empresa_id))

    dispositivo = cursor.fetchone()

    if not dispositivo:

        cursor.close()
        conn.close()

        return "Dispositivo não encontrado"

    colunas = [desc[0] for desc in cursor.description]

    dispositivo = dict(zip(colunas, dispositivo))

    cursor.close()
    conn.close()

    return render_template(
        "detalhe_dispositivo.html",
        dispositivo=dispositivo
    )