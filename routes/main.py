from flask import Blueprint, render_template, request, redirect, url_for, session, send_file
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
                (nome_camera, ip_camera, caixa, rua1, rua2, mac, usuario, senha, stream_path, empresa_id)
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
                request.form.get("stream_path"),
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
                OR ip_camera ILIKE %sy
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