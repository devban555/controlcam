from flask import Blueprint, render_template, request, session, Response
from routes.auth import login_required
from db import get_db
from routes.agent import frames_cache
import datetime
import time

stream_bp = Blueprint("stream", __name__, url_prefix="/stream")


# ==============================
# 📡 STREAM DASHBOARD
# ==============================
@stream_bp.route("/")
@login_required
def stream():
    """
       Renderiza o dashboard de streaming de câmeras e envia comandos de captura ao agente.

       Esta função:
       - Identifica a empresa do usuário logado
       - Lista caixas disponíveis para filtro
       - Busca câmeras da empresa (com ou sem filtro por caixa)
       - Gera URLs RTSP para cada câmera
       - Envia comandos ao agente para captura de frames
       - Monta estrutura para exibição no frontend

       Fluxo:
       1. Obtém parâmetro opcional 'caixa' (filtro)
       2. Identifica empresa do usuário via sessão
       3. Busca caixas disponíveis (DISTINCT)
       4. Busca câmeras:
           - Filtradas por caixa (se informado)
           - Ou todas da empresa
       5. Busca agente ativo da empresa
       6. Para cada câmera:
           a. Normaliza dados (usuario, senha, stream_path)
           b. Gera identificador seguro (safe_nome)
           c. Monta URL RTSP
           d. Envia comando 'frame' para o agente
           e. Adiciona à lista de exibição
       7. Confirma transação (commit)
       8. Renderiza dashboard de stream

       Query Params:
           caixa (str, opcional): Filtra câmeras por agrupamento

       Returns:
           Response: Página HTML (stream.html) contendo:
               - lista de câmeras
               - filtros por caixa
               - status do agente

       Sessão:
           - session["usuario_id"]: identifica usuário logado

       Banco de Dados:
           - usuarios → empresa do usuário
           - cameras → dados das câmeras
           - agentes → agente ativo
           - comandos → envio de comandos de frame

       Comando enviado:
           tipo: 'frame'
           alvo: identificador da câmera (safe_nome)
           resultado: URL RTSP da câmera

       Estrutura de saída:
           cameras = [
               {
                   "nome": str,
                   "url": "/stream/video/<nome>",
                   "caixa": str
               }
           ]

       Observações:
           - Cada acesso ao dashboard gera novos comandos para o agente
           - Não há controle de duplicidade de comandos
           - Credenciais são usadas para montar RTSP dinamicamente
           - stream_path possui valor padrão se não definido

       Segurança:
           - Acesso restrito a usuários autenticados
           - Isolamento por empresa (multi-tenant)

       Possíveis melhorias:
           - Evitar envio repetido de comandos (debounce/cache)
           - Validar disponibilidade do agente antes de enviar comandos
           - Criptografar credenciais RTSP
           - Implementar controle de taxa (rate limit)
           - Suportar múltiplos agentes
       """
    caixa = request.args.get("caixa")

    conn = get_db()
    cursor = conn.cursor()

    # ==============================
    # 🏢 EMPRESA DO USUÁRIO
    # ==============================
    cursor.execute(
        "SELECT empresa_id FROM usuarios WHERE id = %s",
        (session["usuario_id"],)
    )

    result = cursor.fetchone()
    if not result:
        cursor.close()
        return "Usuário sem empresa"

    empresa_id = result[0]

    # ==============================
    # 📦 CAIXAS DISPONÍVEIS
    # ==============================
    cursor.execute("""
        SELECT DISTINCT caixa
        FROM cameras
        WHERE empresa_id = %s
        ORDER BY caixa
    """, (empresa_id,))

    caixas = [c[0] for c in cursor.fetchall() if c[0]]

    # ==============================
    # 📷 BUSCAR CÂMERAS
    # ==============================
    if caixa:
        cursor.execute("""
            SELECT nome_camera, ip_camera, usuario, senha, stream_path, caixa
            FROM cameras
            WHERE empresa_id = %s AND caixa = %s
            ORDER BY nome_camera
        """, (empresa_id, caixa))
    else:
        cursor.execute("""
            SELECT nome_camera, ip_camera, usuario, senha, stream_path, caixa
            FROM cameras
            WHERE empresa_id = %s
            ORDER BY nome_camera
        """, (empresa_id,))

    cameras_db = cursor.fetchall()

    # ==============================
    # 🤖 BUSCAR AGENTE
    # ==============================
    cursor.execute("""
        SELECT id
        FROM agentes
        WHERE empresa_id = %s
        ORDER BY ultimo_heartbeat DESC
        LIMIT 1
    """, (empresa_id,))

    agente = cursor.fetchone()
    agente_id = agente[0] if agente else None

    cameras = []
    agora = datetime.datetime.now()

    # ==============================
    # 🔁 PROCESSAR CAMERAS
    # ==============================
    for cam in cameras_db:

        nome, ip, usuario, senha, stream_path, caixa_cam = cam

        usuario = usuario or "admin"
        senha = senha or ""
        stream_path = stream_path or "/cam/realmonitor?channel=1&subtype=1"

        # ID seguro
        safe_nome = nome.replace(" ", "_")

        # RTSP
        rtsp = f"rtsp://{usuario}:{senha}@{ip}:554{stream_path}"

        # ==============================
        # 🚀 ENVIAR COMANDO AO AGENTE
        # ==============================
        if agente_id:
            cursor.execute("""
                INSERT INTO comandos
                (empresa_id, agente_id, tipo, alvo, resultado, criado_em)
                VALUES (%s, %s, 'frame', %s, %s, %s)
            """, (empresa_id, agente_id, safe_nome, rtsp, agora))

        cameras.append({
            "nome": safe_nome,
            "url": f"/stream/video/{safe_nome}",
            "caixa": caixa_cam
        })

    conn.commit()
    cursor.close()

    total = len(cameras)

    return render_template(
        "stream.html",
        cameras=cameras,
        caixas=caixas,
        caixa_selecionada=caixa,
        online=0,
        offline=0,
        total=total,
        agente=True if agente_id else False
    )


# ==============================
# 🎥 VIDEO STREAM
# ==============================
@stream_bp.route("/video/<camera_id>")
@login_required
def video(camera_id):
    """
      Fornece stream de vídeo em tempo real (MJPEG) para uma câmera específica.

      Esta função:
      - Recebe o identificador da câmera via URL
      - Recupera frames do cache em memória (frames_cache)
      - Gera um fluxo contínuo de imagens (MJPEG)
      - Retorna o stream para o navegador

      Fluxo:
      1. Recebe camera_id pela URL
      2. Inicia gerador contínuo (loop infinito)
      3. Busca frame mais recente no cache
      4. Se não houver frame:
          - Aguarda (sleep)
          - Continua loop
      5. Se houver frame:
          - Envia no formato multipart (MJPEG)
      6. Repete continuamente (stream ao vivo)

      Args:
          camera_id (str): Identificador único da câmera

      Returns:
          Response:
              - Stream contínuo no formato MJPEG
              - Content-Type: multipart/x-mixed-replace

      Formato do Stream:
          - Boundary: frame
          - Tipo: image/jpeg
          - Estrutura:
              --frame
              Content-Type: image/jpeg
              [dados binários]

      Fonte dos Dados:
          - frames_cache[camera_id]: último frame recebido do agente

      Observações:
          - Utiliza polling contínuo (loop infinito)
          - Sempre envia o último frame disponível
          - Não mantém histórico de frames

      Performance:
          - Delay de ~30ms entre frames (~33 FPS teórico)
          - Delay adicional quando não há frame disponível

      Segurança:
          - Acesso restrito a usuários autenticados (@login_required)
          - Não valida vínculo da câmera com empresa (pode ser melhorado)

      Limitações:
          - Cache em memória (não escalável)
          - Não suporta múltiplas instâncias (sem Redis)
          - Pode consumir CPU em loops intensivos

      Possíveis melhorias:
          - Validar se a câmera pertence à empresa do usuário
          - Usar Redis para cache distribuído
          - Implementar controle de FPS
          - Adicionar timeout para desconexão
          - Suportar WebSocket para melhor performance
      """
    def generate():
        while True:
            frame = frames_cache.get(camera_id)

            if not frame:
                time.sleep(0.05)
                continue

            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

            time.sleep(0.03)

    return Response(
        generate(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )