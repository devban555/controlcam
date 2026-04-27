from flask import Blueprint, request, jsonify
from db import get_db
import datetime

agent_bp = Blueprint("agent", __name__, url_prefix="/api/agent")

# cache simples de frames (depois pode ir pra Redis)
frames_cache = {}


# ==============================
# 🔐 VALIDAR TOKEN
# ==============================
def validar_empresa(token, cursor):
    """
    Valida o token de API de uma empresa e retorna seus dados básicos.

    Esta função:
    - Recebe um token de autenticação enviado por um agente
    - Consulta o banco de dados para verificar se o token é válido
    - Retorna o ID da empresa associada ao token

    Fluxo:
    1. Recebe o token da requisição
    2. Executa consulta na tabela 'empresas'
    3. Verifica se existe correspondência com o token_api
    4. Retorna os dados da empresa (ou None se inválido)

    Args:
        token (str): Token de API da empresa
        cursor: Cursor ativo do banco de dados

    Returns:
        dict | None:
            - Dados da empresa (ex: {"id": 1}) se válido
            - None se o token não existir

    Segurança:
        - Utilizado como mecanismo de autenticação para agentes externos
        - O token deve ser secreto e único por empresa
        - Evita acesso não autorizado às rotas da API

    Banco de Dados:
        - Tabela: empresas
        - Campo: token_api

    
    """

    cursor.execute(
        "SELECT id FROM empresas WHERE token_api = %s",
        (token,)
    )
    return cursor.fetchone()


# ==============================
# 📡 PING
# ==============================
@agent_bp.route("/ping", methods=["POST"])
def receber_ping():
    """
    Recebe e registra o resultado de um comando de ping enviado por um agente.

    Esta função:
    - Autentica a requisição via token da empresa (header Authorization)
    - Recebe dados do agente (IP alvo e resultado do ping)
    - Registra a execução do comando no banco de dados
    - Retorna status de sucesso para o agente

    Fluxo:
    1. Obtém token do header Authorization
    2. Valida token da empresa
    3. Extrai dados JSON da requisição (ip, resultado)
    4. Obtém timestamp atual
    5. Insere registro na tabela 'comandos'
       - Tipo: 'ping'
       - Status: 'executado'
    6. Confirma a transação (commit)
    7. Retorna resposta JSON de sucesso

    Headers:
        Authorization (str): Token de API da empresa

    Body (JSON):
        ip (str): Endereço IP alvo do ping
        resultado (str): Resultado da execução (ex: sucesso, falha, latência)

    Returns:
        JSON:
            {"status": "ok"} em caso de sucesso

        Erros:
            401: Token ausente
            403: Token inválido

    Segurança:
        - Validação obrigatória de token por empresa
        - Impede envio de dados por agentes não autorizados

    Banco de Dados:
        - Tabela: comandos
        - Tipo: 'ping'
        - Status: 'executado'
        - agente_id obtido via subquery


    """

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token ausente"}), 401

    conn = get_db()
    cursor = conn.cursor()

    empresa = validar_empresa(token, cursor)

    if not empresa:
        cursor.close()
        return jsonify({"error": "Token inválido"}), 403

    empresa_id = empresa[0]

    data = request.get_json(silent=True) or {}

    ip = data.get("ip")
    resultado = data.get("resultado")

    agora = datetime.datetime.now()

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

    return jsonify({"status": "ok"})


# ==============================
# ❤️ HEARTBEAT + BUSCA COMANDO
# ==============================
@agent_bp.route("/heartbeat", methods=["POST"])
def agent_heartbeat():
    """
    Gerencia o heartbeat do agente e entrega comandos pendentes.

    Esta função é responsável por:
    - Autenticar o agente via token da empresa
    - Registrar/atualizar o estado do agente (heartbeat)
    - Criar automaticamente o agente caso não exista
    - Buscar comandos pendentes para execução
    - Retornar o próximo comando disponível ao agente

    Fluxo:
    1. Recebe dados JSON do agente
    2. Obtém token (header Authorization ou body)
    3. Valida token da empresa
    4. Identifica ou cria agente (nome_maquina)
    5. Atualiza último heartbeat e IP local
    6. Busca comando pendente para o agente
    7. Se existir:
        - Marca como "enviado"
        - Retorna comando ao agente
    8. Caso contrário:
        - Retorna status "ok" sem comando

    Headers:
        Authorization (str): Token de API da empresa (opcional se enviado no body)

    Body (JSON):
        token (str, opcional): Token da empresa
        nome_maquina (str): Identificador único do agente
        ip_local (str): IP local da máquina

    Returns:
        JSON:
            Caso exista comando:
            {
                "status": "ok",
                "comando": {
                    "id": int,
                    "tipo": str,
                    "alvo": str,
                    "resultado": str
                }
            }

            Caso não exista comando:
            {
                "status": "ok"
            }

        Erros:
            401: Token ausente
            403: Token inválido

    Segurança:
        - Autenticação via token por empresa
        - Isolamento de dados por empresa_id

    Banco de Dados:
        - Tabela: agentes (controle de estado)
        - Tabela: comandos (fila de execução)

    Comportamento do Agente:
        - O agente se registra automaticamente no primeiro heartbeat
        - Heartbeat atualiza presença (ultimo_heartbeat)
        - Recebe comandos pendentes de forma sequencial (fila)


    """

    data = request.get_json(silent=True) or {}

    token = request.headers.get("Authorization") or data.get("token")

    if not token:
        return jsonify({"error": "Token ausente"}), 401

    conn = get_db()
    cursor = conn.cursor()

    empresa = validar_empresa(token, cursor)

    if not empresa:
        cursor.close()
        return jsonify({"error": "Token inválido"}), 403

    empresa_id = empresa[0]

    nome_maquina = data.get("nome_maquina")
    ip_local = data.get("ip_local")
    agora = datetime.datetime.now()

    # ==============================
    # 🔍 VERIFICAR / CRIAR AGENTE
    # ==============================
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

    # ==============================
    # 📦 BUSCAR COMANDO
    # ==============================
    cursor.execute("""
        SELECT id, tipo, alvo, resultado
        FROM comandos
        WHERE agente_id = %s
          AND status = 'pendente'
        ORDER BY id ASC
        LIMIT 1
    """, (agente_id,))

    comando = cursor.fetchone()

    if comando:
        comando_id, tipo, alvo, resultado = comando

        cursor.execute("""
            UPDATE comandos
            SET status = 'enviado'
            WHERE id = %s
        """, (comando_id,))

        conn.commit()
        cursor.close()

        return jsonify({
            "status": "ok",
            "comando": {
                "id": comando_id,
                "tipo": tipo,
                "alvo": alvo,
                "resultado": resultado
            }
        })

    conn.commit()
    cursor.close()

    return jsonify({"status": "ok"})

# ==============================
# 📥 RESULTADO DO COMANDO
# ==============================
@agent_bp.route("/resultado", methods=["POST"])
def agent_resultado():
    """
    Recebe e registra o resultado da execução de um comando enviado ao agente.

    Esta função:
    - Autentica a requisição via token da empresa
    - Recebe o ID do comando executado e seu resultado
    - Atualiza o status do comando para 'executado'
    - Armazena o resultado e o timestamp da execução
    - Retorna confirmação de recebimento

    Fluxo:
    1. Obtém token do header Authorization
    2. Valida token da empresa
    3. Extrai dados JSON (comando_id, resultado)
    4. Atualiza o comando no banco:
        - status → 'executado'
        - resultado → conteúdo retornado pelo agente
        - executado_em → timestamp atual
    5. Confirma transação (commit)
    6. Retorna resposta de confirmação

    Headers:
        Authorization (str): Token de API da empresa

    Body (JSON):
        comando_id (int): ID do comando executado
        resultado (str): Resultado da execução (output, erro, etc.)

    Returns:
        JSON:
            {"status": "recebido"} em caso de sucesso

        Erros:
            401: Token ausente
            403: Token inválido

    Segurança:
        - Validação por token de empresa
        - Garante que o comando pertence à empresa (WHERE empresa_id)

    Banco de Dados:
        - Tabela: comandos
        - Campos atualizados:
            - status
            - resultado
            - executado_em


    """

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token ausente"}), 401

    conn = get_db()
    cursor = conn.cursor()

    empresa = validar_empresa(token, cursor)

    if not empresa:
        cursor.close()
        return jsonify({"error": "Token inválido"}), 403

    empresa_id = empresa[0]

    data = request.get_json(silent=True) or {}

    comando_id = data.get("comando_id")
    resultado = data.get("resultado")
    agora = datetime.datetime.now()

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

    return jsonify({"status": "recebido"})

# ==============================
# 🎥 STREAM
# ==============================
@agent_bp.route("/stream", methods=["POST"])
def receber_stream():
    """
    Recebe e armazena frames de vídeo enviados por agentes (câmeras).

    Esta função:
    - Recebe requisições contendo frames de vídeo (imagem)
    - Identifica a câmera pelo camera_id
    - Armazena o frame mais recente em cache (memória)
    - Retorna confirmação simples ao agente

    Fluxo:
    1. Obtém token do header Authorization
    2. Valida presença do token (não valida autenticidade)
    3. Recebe dados via multipart/form-data:
        - camera_id
        - frame (arquivo de imagem)
    4. Valida campos obrigatórios
    5. Lê o conteúdo do frame
    6. Armazena no cache em memória (frames_cache)
    7. Retorna "ok"

    Headers:
        Authorization (str): Token da empresa (obrigatório, mas não validado)

    Form-data:
        camera_id (str): Identificador da câmera
        frame (file): Imagem capturada (frame atual)

    Returns:
        str:
            "ok" → sucesso
            "erro" → token ausente (401)
            "dados inválidos" → campos faltando (400)

    Armazenamento:
        - Utiliza cache em memória (dict global: frames_cache)
        - Estrutura:
            frames_cache[camera_id] = bytes do frame

    Observações:
        - Apenas o último frame é mantido por câmera
        - Frames anteriores são sobrescritos
        - Não há persistência em disco ou banco
        - Não há validação do token (apenas presença)


    """

    token = request.headers.get("Authorization")

    if not token:
        return "erro", 401

    camera_id = request.form.get("camera_id")
    frame = request.files.get("frame")

    if not frame or not camera_id:
        return "dados inválidos", 400

    # Armazena o frame mais recente da câmera em memória
    frames_cache[camera_id] = frame.read()

    return "ok"