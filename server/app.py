"""AEGIS — site, painel do cliente e API do aplicativo desktop."""
from __future__ import annotations

import csv
import io
import json
import math
import os
import re
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, send_file, session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import security
from database import INSTANCE_DIR, db, generate_license_key, init_db, utcnow

BASE_DIR = Path(__file__).resolve().parent
DESKTOP_DIR = Path(os.environ.get("AEGIS_DESKTOP_DIR", BASE_DIR.parent / "desktop"))
APP_VERSION = "1.0.0"
TOKEN_MAX_AGE = 30 * 24 * 3600


def load_secret_key() -> str:
    env = os.environ.get("AEGIS_SECRET_KEY")
    if env:
        return env
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    key_file = INSTANCE_DIR / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("AEGIS_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    MAX_CONTENT_LENGTH=1024 * 1024,
    JSON_AS_ASCII=False,
)

login_limiter = security.RateLimiter()


def enable_proxy_fix(flask_app) -> None:
    """Atrás de um proxy (Render, Nginx…), confia nos cabeçalhos X-Forwarded-* para enxergar
    o IP, o host e o https reais. Só habilite quando realmente houver um proxy na frente."""
    flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, x_for=1, x_proto=1, x_host=1)


if os.environ.get("AEGIS_BEHIND_PROXY") == "1":
    enable_proxy_fix(app)

# --------------------------------------------------------------------------
# Planos
# --------------------------------------------------------------------------
PLANOS = {
    "essencial": {
        "nome": "Essencial", "preco": 0, "dispositivos": 1, "tempo_real": False,
        "historico": 5, "exportar": False, "suporte": "Comunidade",
        "resumo": "Para começar a se proteger, sem custo.",
        "destaques": ["Verificação rápida e personalizada", "Quarentena reversível",
                      "Atualização de assinaturas", "1 dispositivo"],
    },
    "plus": {
        "nome": "Plus", "preco": 1900, "dispositivos": 3, "tempo_real": True,
        "historico": 50, "exportar": False, "suporte": "E-mail",
        "resumo": "Proteção contínua para quem trabalha e estuda em casa.",
        "destaques": ["Tudo do Essencial", "Proteção em tempo real",
                      "Histórico completo no painel", "Até 3 dispositivos"],
    },
    "pro": {
        "nome": "Pro", "preco": 3900, "dispositivos": 10, "tempo_real": True,
        "historico": 50, "exportar": True, "suporte": "Prioritário",
        "resumo": "Para equipes pequenas e profissionais com vários equipamentos.",
        "destaques": ["Tudo do Plus", "Até 10 dispositivos",
                      "Exportação do histórico em CSV", "Suporte prioritário"],
    },
}
PLAN_ORDER = ["essencial", "plus", "pro"]
PAID_PLANS = ("plus", "pro")

# --------------------------------------------------------------------------
# Datas e filtros
# --------------------------------------------------------------------------
try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo("America/Sao_Paulo")
except Exception:                                   # sem tzdata (Windows)
    LOCAL_TZ = timezone(timedelta(hours=-3))


def parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@app.template_filter("brl")
def brl_filter(cents) -> str:
    cents = int(cents or 0)
    return f"R$ {cents // 100},{cents % 100:02d}"


@app.template_filter("datahora")
def datahora_filter(value) -> str:
    if not value:
        return "—"
    return parse_dt(value).astimezone(LOCAL_TZ).strftime("%d/%m/%Y %H:%M")


@app.template_filter("data")
def data_filter(value) -> str:
    if not value:
        return "—"
    return parse_dt(value).astimezone(LOCAL_TZ).strftime("%d/%m/%Y")


@app.template_filter("tipo_scan")
def tipo_scan_filter(value) -> str:
    return {"rapida": "Rápida", "personalizada": "Personalizada",
            "tempo_real": "Tempo real"}.get(value, value)


def days_left(expira_em):
    if not expira_em:
        return None
    seconds = (parse_dt(expira_em) - datetime.now(timezone.utc)).total_seconds()
    return max(0, math.ceil(seconds / 86400))


def refresh_plan(row, conn) -> dict:
    """Rebaixa para o plano Essencial se a assinatura venceu."""
    user = dict(row)
    exp = user.get("plano_expira_em")
    if user["plano"] != "essencial" and exp and parse_dt(exp) < datetime.now(timezone.utc):
        conn.execute("UPDATE users SET plano='essencial', plano_expira_em=NULL WHERE id=?",
                     (user["id"],))
        user["plano"], user["plano_expira_em"] = "essencial", None
    return user


# --------------------------------------------------------------------------
# Ciclo da requisição
# --------------------------------------------------------------------------
@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid:
        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            g.user = refresh_plan(row, conn) if row else None
        if g.user is None:
            session.clear()
    if request.method == "POST" and not request.path.startswith("/api/"):
        security.verify_csrf()


@app.context_processor
def inject_globals():
    user = g.get("user")
    return {
        "user": user,
        "PLANOS": PLANOS,
        "plano_atual": PLANOS[user["plano"]] if user else None,
        "csrf_token": security.csrf_token,
        "ano": datetime.now().year,
    }


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if request.path.startswith(("/sistema", "/comprar", "/download", "/login", "/cadastro")):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("Entre na sua conta para continuar.", "erro")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return fn(*args, **kwargs)
    return wrapper


def start_session(user_id: int) -> None:
    session.clear()
    session["user_id"] = user_id
    session.permanent = True


# --------------------------------------------------------------------------
# Páginas públicas
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/termos")
def termos():
    return render_template("legal.html", pagina="termos")


@app.route("/privacidade")
def privacidade():
    return render_template("legal.html", pagina="privacidade")


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if g.user:
        return redirect(url_for("sistema"))
    plano = request.values.get("plano", "")
    if plano not in PLANOS:
        plano = ""
    form = {"nome": "", "email": ""}

    if request.method == "POST":
        form["nome"] = request.form.get("nome", "").strip()
        form["email"] = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        aceite = request.form.get("aceite") == "on"

        erro = None
        if len(form["nome"]) < 3 or len(form["nome"]) > 80:
            erro = "Informe seu nome completo."
        elif not security.valid_email(form["email"]):
            erro = "Informe um e-mail válido."
        elif security.password_problem(senha):
            erro = security.password_problem(senha)
        elif not aceite:
            erro = "É preciso aceitar os Termos de Uso para criar a conta."

        if not erro:
            try:
                with db() as conn:
                    cur = conn.execute(
                        "INSERT INTO users (nome, email, senha_hash, license_key, criado_em) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (form["nome"], form["email"], generate_password_hash(senha),
                         generate_license_key(), utcnow()),
                    )
                    new_id = cur.lastrowid
            except Exception as exc:
                if "UNIQUE" in str(exc).upper():
                    erro = "Já existe uma conta com esse e-mail. Tente entrar."
                else:
                    raise
        if erro:
            flash(erro, "erro")
            return render_template("cadastro.html", plano=plano, form=form), 400

        start_session(new_id)
        flash("Conta criada! Bem-vindo ao AEGIS.", "ok")
        if plano in PAID_PLANS:
            return redirect(url_for("comprar", plano=plano))
        return redirect(url_for("download") if plano == "essencial" else url_for("sistema"))

    return render_template("cadastro.html", plano=plano, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = security.safe_next(request.values.get("next"))
    if g.user:
        return redirect(next_url or url_for("sistema"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        key = f"web:{request.remote_addr}:{email}"

        if login_limiter.is_blocked(key):
            flash("Muitas tentativas. Aguarde alguns minutos e tente de novo.", "erro")
            return render_template("login.html", next=next_url, email=email), 429

        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row and check_password_hash(row["senha_hash"], senha):
            login_limiter.reset(key)
            start_session(row["id"])
            return redirect(next_url or url_for("sistema"))

        login_limiter.fail(key)
        flash("E-mail ou senha incorretos.", "erro")
        return render_template("login.html", next=next_url, email=email), 401

    return render_template("login.html", next=next_url, email="")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# --------------------------------------------------------------------------
# Painel do cliente
# --------------------------------------------------------------------------
ABAS = ("geral", "dispositivos", "historico", "compras", "conta")


@app.route("/sistema")
@login_required
def sistema():
    aba = request.args.get("aba", "geral")
    if aba not in ABAS:
        aba = "geral"
    u = g.user
    plano = PLANOS[u["plano"]]
    with db() as conn:
        dispositivos = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY criado_em, id", (u["id"],)).fetchall()
        resumo = conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(arquivos),0) AS arquivos, "
            "COALESCE(SUM(ameacas),0) AS ameacas, MAX(criado_em) AS ultimo "
            "FROM scans WHERE user_id = ?", (u["id"],)).fetchone()
        scans = conn.execute(
            "SELECT s.*, d.nome AS dispositivo FROM scans s "
            "LEFT JOIN devices d ON d.id = s.device_row_id "
            "WHERE s.user_id = ? ORDER BY s.id DESC LIMIT ?",
            (u["id"], plano["historico"])).fetchall()
        deteccoes = conn.execute(
            "SELECT * FROM detections WHERE user_id = ? ORDER BY id DESC LIMIT 15",
            (u["id"],)).fetchall()
        compras = conn.execute(
            "SELECT * FROM compras WHERE user_id = ? ORDER BY id DESC", (u["id"],)).fetchall()
    return render_template(
        "sistema.html", aba=aba, abas=ABAS, plano=plano, dispositivos=dispositivos,
        resumo=resumo, scans=scans, deteccoes=deteccoes, compras=compras,
        dias=days_left(u["plano_expira_em"]),
    )


@app.post("/sistema/dispositivos/<int:device_row_id>/remover")
@login_required
def remover_dispositivo(device_row_id):
    with db() as conn:
        conn.execute("DELETE FROM devices WHERE id = ? AND user_id = ?",
                     (device_row_id, g.user["id"]))
    flash("Dispositivo removido. O aplicativo nele precisará entrar novamente.", "ok")
    return redirect(url_for("sistema", aba="dispositivos"))


@app.post("/sistema/licenca/regenerar")
@login_required
def regenerar_licenca():
    with db() as conn:
        conn.execute("UPDATE users SET license_key = ? WHERE id = ?",
                     (generate_license_key(), g.user["id"]))
    flash("Nova chave de licença gerada. A anterior deixou de funcionar.", "ok")
    return redirect(url_for("sistema"))


@app.post("/sistema/assinatura/cancelar")
@login_required
def cancelar_assinatura():
    if g.user["plano"] == "essencial":
        flash("Você já está no plano Essencial.", "erro")
    else:
        with db() as conn:
            conn.execute("UPDATE users SET plano='essencial', plano_expira_em=NULL WHERE id = ?",
                         (g.user["id"],))
        flash("Assinatura cancelada. Sua conta voltou ao plano Essencial.", "ok")
    return redirect(url_for("sistema"))


@app.post("/sistema/senha")
@login_required
def alterar_senha():
    atual = request.form.get("atual", "")
    nova = request.form.get("nova", "")
    confirma = request.form.get("confirma", "")
    with db() as conn:
        row = conn.execute("SELECT senha_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
        erro = None
        if not check_password_hash(row["senha_hash"], atual):
            erro = "A senha atual está incorreta."
        elif nova != confirma:
            erro = "A confirmação não confere com a nova senha."
        elif security.password_problem(nova):
            erro = security.password_problem(nova)
        if not erro:
            conn.execute("UPDATE users SET senha_hash = ? WHERE id = ?",
                         (generate_password_hash(nova), g.user["id"]))
    flash(erro or "Senha alterada com sucesso.", "erro" if erro else "ok")
    return redirect(url_for("sistema", aba="conta"))


@app.route("/sistema/historico.csv")
@login_required
def exportar_historico():
    if not PLANOS[g.user["plano"]]["exportar"]:
        flash("A exportação em CSV está disponível no plano Pro.", "erro")
        return redirect(url_for("sistema", aba="historico"))
    with db() as conn:
        rows = conn.execute(
            "SELECT s.criado_em, s.tipo, s.arquivos, s.ameacas, s.duracao, d.nome AS dispositivo "
            "FROM scans s LEFT JOIN devices d ON d.id = s.device_row_id "
            "WHERE s.user_id = ? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
    out = io.StringIO()
    writer = csv.writer(out, delimiter=";")
    writer.writerow(["data_utc", "tipo", "arquivos", "ameacas", "duracao_s", "dispositivo"])
    for r in rows:
        writer.writerow([r["criado_em"], r["tipo"], r["arquivos"], r["ameacas"],
                         r["duracao"], r["dispositivo"] or ""])
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=aegis-historico.csv"})


# --------------------------------------------------------------------------
# Compra (pagamento simulado)
# --------------------------------------------------------------------------
@app.route("/comprar/<plano>", methods=["GET", "POST"])
@login_required
def comprar(plano):
    if plano not in PAID_PLANS:
        return redirect(url_for("index") + "#planos")
    info = PLANOS[plano]
    u = g.user
    if PLAN_ORDER.index(u["plano"]) > PLAN_ORDER.index(plano):
        flash(f"Você já possui o plano {PLANOS[u['plano']]['nome']}, que é superior a este.", "erro")
        return redirect(url_for("sistema"))

    renovando = u["plano"] == plano
    form = {"nome": u["nome"]}

    if request.method == "POST":
        form["nome"] = request.form.get("nome", "").strip()
        numero = re.sub(r"\D", "", request.form.get("numero", ""))
        validade = request.form.get("validade", "")
        cvv = request.form.get("cvv", "").strip()

        erro = None
        if len(form["nome"]) < 3:
            erro = "Informe o nome impresso no cartão."
        elif not security.luhn_valid(numero):
            erro = "Número de cartão inválido."
        elif not security.card_expiry_valid(validade):
            erro = "Validade inválida ou cartão vencido."
        elif not re.fullmatch(r"\d{3,4}", cvv):
            erro = "CVV inválido."

        if erro:
            flash(erro, "erro")
            return render_template("comprar.html", plano=plano, info=info,
                                   renovando=renovando, form=form), 400

        now = datetime.now(timezone.utc)
        base = now
        if renovando and u["plano_expira_em"]:
            current = parse_dt(u["plano_expira_em"])
            if current > now:
                base = current
        expira = (base + timedelta(days=30)).isoformat(timespec="seconds")
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO compras (user_id, plano, valor_centavos, bandeira, cartao_final, "
                "status, criado_em, expira_em) VALUES (?, ?, ?, ?, ?, 'pago', ?, ?)",
                (u["id"], plano, info["preco"], security.card_brand(numero), numero[-4:],
                 utcnow(), expira))
            compra_id = cur.lastrowid
            conn.execute("UPDATE users SET plano = ?, plano_expira_em = ? WHERE id = ?",
                         (plano, expira, u["id"]))
        return redirect(url_for("comprar_sucesso", compra_id=compra_id))

    return render_template("comprar.html", plano=plano, info=info,
                           renovando=renovando, form=form)


@app.route("/comprar/sucesso/<int:compra_id>")
@login_required
def comprar_sucesso(compra_id):
    with db() as conn:
        compra = conn.execute("SELECT * FROM compras WHERE id = ? AND user_id = ?",
                              (compra_id, g.user["id"])).fetchone()
    if not compra:
        abort(404)
    return render_template("comprar_sucesso.html", compra=compra, info=PLANOS[compra["plano"]])


# --------------------------------------------------------------------------
# Download do aplicativo
# --------------------------------------------------------------------------
@app.route("/download")
@login_required
def download():
    return render_template("download.html", plano=PLANOS[g.user["plano"]])


def build_desktop_zip(server_url: str) -> io.BytesIO:
    skip_dirs = {"__pycache__", "tests", ".venv", "dist", "build", ".git"}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(DESKTOP_DIR.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(DESKTOP_DIR)
            if (any(part in skip_dirs for part in rel.parts)
                    or path.suffix == ".pyc" or rel.as_posix() == "config.json"):
                continue
            zf.write(path, f"aegis-antivirus/{rel.as_posix()}")
        zf.writestr("aegis-antivirus/config.json", json.dumps({"server_url": server_url}, indent=2))
    buf.seek(0)
    return buf


@app.route("/download/aegis-antivirus.zip")
@login_required
def download_zip():
    if not DESKTOP_DIR.is_dir():
        abort(404)
    server_url = os.environ.get("AEGIS_PUBLIC_URL") or request.host_url.rstrip("/")
    return send_file(build_desktop_zip(server_url), mimetype="application/zip",
                     as_attachment=True, download_name="aegis-antivirus.zip")


# --------------------------------------------------------------------------
# API do aplicativo desktop
# --------------------------------------------------------------------------
def api_error(message: str, status: int):
    return jsonify({"erro": message}), status


def token_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="aegis-app-token")


def user_payload(user: dict) -> dict:
    plano = PLANOS[user["plano"]]
    return {
        "nome": user["nome"], "email": user["email"], "plano": user["plano"],
        "plano_nome": plano["nome"], "expira_em": user["plano_expira_em"],
        "dispositivos": plano["dispositivos"], "tempo_real": plano["tempo_real"],
    }


def device_allowed(conn, user_id: int, device_row_id: int, limit: int) -> bool:
    rows = conn.execute("SELECT id FROM devices WHERE user_id = ? ORDER BY criado_em, id LIMIT ?",
                        (user_id, limit)).fetchall()
    return device_row_id in [r["id"] for r in rows]


def api_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return api_error("Token ausente.", 401)
        try:
            data = token_serializer().loads(header[7:], max_age=TOKEN_MAX_AGE)
        except SignatureExpired:
            return api_error("Sessão expirada. Entre novamente.", 401)
        except BadSignature:
            return api_error("Token inválido.", 401)
        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (data.get("uid"),)).fetchone()
            device = conn.execute("SELECT * FROM devices WHERE id = ? AND user_id = ?",
                                  (data.get("did"), data.get("uid"))).fetchone()
            if not row or not device:
                return api_error("Dispositivo não autorizado. Entre novamente.", 401)
            user = refresh_plan(row, conn)
            if not device_allowed(conn, user["id"], device["id"], PLANOS[user["plano"]]["dispositivos"]):
                return api_error("Este dispositivo excede o limite do seu plano.", 403)
            conn.execute("UPDATE devices SET ultimo_acesso = ? WHERE id = ?", (utcnow(), device["id"]))
        g.user, g.device = user, dict(device)
        return fn(*args, **kwargs)
    return wrapper


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True, "versao": APP_VERSION})


@app.post("/api/auth/login")
def api_login():
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", ""))
    if not re.fullmatch(r"[A-Za-z0-9\-]{8,64}", device_id):
        return api_error("Identificador do dispositivo inválido.", 400)
    device_name = (str(data.get("device_name", "")).strip() or "Computador")[:80]
    system = str(data.get("os", ""))[:80]
    license_key = str(data.get("license_key", "")).strip().upper()
    email = str(data.get("email", "")).strip().lower()

    limiter_key = f"api:{request.remote_addr}:{license_key or email}"
    if login_limiter.is_blocked(limiter_key):
        return api_error("Muitas tentativas. Aguarde alguns minutos.", 429)

    with db() as conn:
        row = None
        if license_key:
            row = conn.execute("SELECT * FROM users WHERE license_key = ?", (license_key,)).fetchone()
        elif email:
            cand = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if cand and check_password_hash(cand["senha_hash"], str(data.get("senha", ""))):
                row = cand
        if not row:
            login_limiter.fail(limiter_key)
            return api_error("Credenciais inválidas.", 401)
        login_limiter.reset(limiter_key)

        user = refresh_plan(row, conn)
        plano = PLANOS[user["plano"]]
        dev = conn.execute("SELECT * FROM devices WHERE user_id = ? AND device_id = ?",
                           (user["id"], device_id)).fetchone()
        if dev is None:
            count = conn.execute("SELECT COUNT(*) AS n FROM devices WHERE user_id = ?",
                                 (user["id"],)).fetchone()["n"]
            if count >= plano["dispositivos"]:
                return api_error(
                    f"O plano {plano['nome']} permite {plano['dispositivos']} dispositivo(s). "
                    "Remova um dispositivo no painel do site ou faça upgrade.", 403)
            dev_row_id = conn.execute(
                "INSERT INTO devices (user_id, device_id, nome, sistema, ultimo_acesso, criado_em) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user["id"], device_id, device_name, system, utcnow(), utcnow())).lastrowid
        else:
            dev_row_id = dev["id"]
            if not device_allowed(conn, user["id"], dev_row_id, plano["dispositivos"]):
                return api_error("Este dispositivo excede o limite do seu plano.", 403)
            conn.execute("UPDATE devices SET nome = ?, sistema = ?, ultimo_acesso = ? WHERE id = ?",
                         (device_name, system, utcnow(), dev_row_id))

    token = token_serializer().dumps({"uid": user["id"], "did": dev_row_id})
    return jsonify({"token": token, "user": user_payload(user)})


@app.get("/api/me")
@api_auth
def api_me():
    return jsonify({"user": user_payload(g.user)})


@app.get("/api/signatures")
@api_auth
def api_signatures():
    try:
        with open(BASE_DIR / "signatures.json", "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return api_error("Base de assinaturas indisponível.", 503)
    try:
        client_version = int(request.args.get("versao", 0))
    except ValueError:
        client_version = 0
    if client_version >= data.get("versao", 0):
        return jsonify({"versao": data["versao"], "atualizado": False})
    data["atualizado"] = True
    return jsonify(data)


def _clamp_int(value, high=10**9) -> int:
    try:
        return max(0, min(int(value), high))
    except (TypeError, ValueError):
        return 0


@app.post("/api/scans")
@api_auth
def api_scans():
    data = request.get_json(silent=True) or {}
    tipo = data.get("tipo") if data.get("tipo") in ("rapida", "personalizada", "tempo_real") else "personalizada"
    try:
        duracao = max(0.0, min(float(data.get("duracao", 0)), 10**6))
    except (TypeError, ValueError):
        duracao = 0.0
    deteccoes = data.get("deteccoes") if isinstance(data.get("deteccoes"), list) else []
    with db() as conn:
        scan_id = conn.execute(
            "INSERT INTO scans (user_id, device_row_id, tipo, arquivos, ameacas, duracao, criado_em) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (g.user["id"], g.device["id"], tipo, _clamp_int(data.get("arquivos")),
             _clamp_int(data.get("ameacas")), duracao, utcnow())).lastrowid
        for d in deteccoes[:100]:
            if not isinstance(d, dict):
                continue
            conn.execute(
                "INSERT INTO detections (scan_id, user_id, arquivo, ameaca, acao, criado_em) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, g.user["id"], str(d.get("arquivo", ""))[:260],
                 str(d.get("ameaca", ""))[:120], str(d.get("acao", ""))[:60], utcnow()))
    return jsonify({"ok": True, "id": scan_id})


# --------------------------------------------------------------------------
# Erros
# --------------------------------------------------------------------------
@app.errorhandler(400)
def err_400(_e):
    return render_template("erro.html", codigo=400, titulo="Solicitação inválida",
                           texto="Sua sessão pode ter expirado. Volte, recarregue a página e tente de novo."), 400


@app.errorhandler(404)
def err_404(_e):
    if request.path.startswith("/api/"):
        return api_error("Rota não encontrada.", 404)
    return render_template("erro.html", codigo=404, titulo="Página não encontrada",
                           texto="O endereço que você tentou abrir não existe."), 404


@app.errorhandler(413)
def err_413(_e):
    return render_template("erro.html", codigo=413, titulo="Conteúdo grande demais",
                           texto="O envio excede o limite permitido."), 413


@app.errorhandler(500)
def err_500(_e):
    if request.path.startswith("/api/"):
        return api_error("Erro interno do servidor.", 500)
    return render_template("erro.html", codigo=500, titulo="Algo deu errado",
                           texto="Tivemos um problema interno. Tente novamente em instantes."), 500


def seed_demo_user() -> None:
    """Cria uma conta de demonstração se AEGIS_DEMO_EMAIL e AEGIS_DEMO_PASSWORD estiverem definidos.
    Útil em hospedagem com disco efêmero (o banco é apagado a cada reinício)."""
    email = os.environ.get("AEGIS_DEMO_EMAIL", "").strip().lower()
    password = os.environ.get("AEGIS_DEMO_PASSWORD", "")
    if not email or not password:
        return
    plano = os.environ.get("AEGIS_DEMO_PLAN", "plus")
    if plano not in PLANOS:
        plano = "essencial"
    expira = None
    if plano != "essencial":
        expira = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds")
    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            return
        conn.execute(
            "INSERT INTO users (nome, email, senha_hash, plano, plano_expira_em, license_key, criado_em) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("Conta de Demonstração", email, generate_password_hash(password), plano, expira,
             generate_license_key(), utcnow()))


init_db()
seed_demo_user()

if __name__ == "__main__":
    # No Render (e similares) a porta vem na variável PORT e o app precisa escutar em 0.0.0.0.
    on_platform = bool(os.environ.get("PORT"))
    host = os.environ.get("AEGIS_HOST") or ("0.0.0.0" if on_platform else "127.0.0.1")
    port = int(os.environ.get("AEGIS_PORT") or os.environ.get("PORT") or 5000)
    if os.environ.get("AEGIS_DEBUG") == "1":
        app.run(host=host, port=port, debug=True)
    else:
        try:
            from waitress import serve
            print(f"AEGIS rodando em http://{host}:{port}  (Ctrl+C para parar)")
            serve(app, host=host, port=port, threads=8)
        except ImportError:
            app.run(host=host, port=port)
