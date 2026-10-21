#!/usr/bin/env python3
"""AEGIS Desktop — versão em linha de comando (usa o mesmo núcleo da interface gráfica).

Exemplos:
  python aegis_cli.py login --email voce@email.com
  python aegis_cli.py update
  python aegis_cli.py testfiles
  python aegis_cli.py scan --quick
  python aegis_cli.py scan C:\\Users\\voce\\Downloads
  python aegis_cli.py clamav status      (detecta; use "test" e "update" também)
  python aegis_cli.py quarantine list
  python aegis_cli.py realtime
"""
from __future__ import annotations

import argparse
import getpass
import sys
import time

import config
from api_client import ApiError
from controller import Controller

LABEL = {"malicious": "MALICIOSO", "suspicious": "SUSPEITO"}


def make_controller() -> Controller:
    last = {"t": 0.0}

    def emit(kind, payload=None):
        if kind == "progress":
            done, total, path = payload
            now = time.monotonic()
            if now - last["t"] > 0.5 and sys.stdout.isatty():
                last["t"] = now
                text = f"Preparando… {done} arquivos" if total == 0 else f"Verificando {done}/{total}"
                print(f"\r{text:<60}", end="", flush=True)
        elif kind == "result":
            print(f"\r{'':<60}\r[{LABEL.get(payload.verdict, payload.verdict)}] {payload.path}\n"
                  f"    ameaça: {payload.threat} | situação: {payload.action or 'pendente'}\n"
                  f"    motivos: {payload.reason_text}")
        elif kind == "rt_event":
            print(f"[TEMPO REAL] {LABEL.get(payload.verdict)} {payload.path} → {payload.action or 'pendente'}")
        elif kind == "phase":
            print(f"\r{'':<60}\rFase: {payload}" + (" (carregando a base, aguarde…)" if payload == "ClamAV" else ""))
        elif kind in ("info", "error"):
            print(payload, file=sys.stderr)

    return Controller(emit=emit)


def cmd_login(ctl, args):
    if args.license:
        user = ctl.login(license_key=args.license)
    else:
        email = args.email or input("E-mail: ")
        senha = args.senha or getpass.getpass("Senha: ")
        user = ctl.login(email=email, senha=senha)
    print(f"Conectado como {user['nome']} (plano {user['plano_nome']}).")
    return 0


def cmd_logout(ctl, _args):
    ctl.logout()
    print("Sessão encerrada.")
    return 0


def cmd_status(ctl, _args):
    user = ctl.user
    print(f"Servidor:      {ctl.settings.server_url}")
    print(f"Conta:         {user.get('nome', 'modo offline')} — plano {user.get('plano_nome', '-')}")
    print(f"Tempo real:    {'disponível' if ctl.can_realtime else 'indisponível'}")
    print(f"Assinaturas:   versão {ctl.signatures.version} ({ctl.signatures.total} regras)")
    ctl.detect_clam()
    print(f"ClamAV:        {ctl.clam_status.summary}"
          + ("" if ctl.settings.clamav_enabled else "  [desativado nos ajustes]"))
    print(f"Quarentena:    {len(ctl.quarantine.list())} item(ns)")
    print(f"Última verif.: {ctl.settings.last_scan or 'nunca'} {ctl.settings.last_scan_info}")
    return 0


def cmd_update(ctl, _args):
    changed = ctl.update_signatures()
    print("Assinaturas atualizadas." if changed else "Já está na versão mais recente.")
    print(f"Versão {ctl.signatures.version} — {ctl.signatures.total} regras.")
    return 0


def cmd_scan(ctl, args):
    ctl.settings.auto_quarantine = not args.no_quarantine
    if args.quick or not args.paths:
        kind, paths = "rapida", config.quick_scan_paths()
    else:
        kind, paths = "personalizada", args.paths
    print("Verificando:", ", ".join(paths))
    thread = ctl.start_scan(kind, paths)
    try:
        while thread.is_alive():
            thread.join(0.2)
    except KeyboardInterrupt:
        ctl.cancel_scan()
        thread.join()
    print("\nVerificação concluída.")
    print(ctl.settings.last_scan_info)
    # código 2 = ameaças encontradas (útil em scripts)
    return 2 if ctl.last_summary and ctl.last_summary.threats else 0


def cmd_clamav(ctl, args):
    action = args.action
    if action in ("on", "off"):
        ctl.set_clamav_enabled(action == "on")
        print("ClamAV " + ("ativado." if action == "on" else "desativado."))
        return 0
    if args.path:
        ctl.settings.clamscan_path = args.path
        ctl.settings.save()
    status = ctl.detect_clam()
    if action == "status":
        print(status.summary)
        return 0 if status.available else 1
    if action == "test":
        ok, msg = ctl.clam_self_test()
        print(msg)
        return 0 if ok else 1
    if action == "update":
        print("Atualizando a base de vírus (pode demorar)…")
        ok, msg = ctl.update_clam_database()
        print(msg)
        return 0 if ok else 1
    return 0


def cmd_quarantine(ctl, args):
    q = ctl.quarantine
    if args.action == "list":
        items = q.list()
        if not items:
            print("Quarentena vazia.")
        for e in items:
            print(f"{e['id']}  {e['data']}  {e['ameaca']:<22} {e['caminho']}")
    elif args.action == "restore":
        print("Restaurado em:", q.restore(args.id))
    elif args.action == "delete":
        q.delete(args.id)
        print("Excluído.")
    return 0


def cmd_realtime(ctl, _args):
    ctl.start_realtime()
    print("Proteção em tempo real ativa. Pressione Ctrl+C para sair.")
    for folder in ctl.settings.watch_folders:
        print(" •", folder)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ctl.watcher.stop()
        print("\nEncerrado.")
    return 0


def cmd_testfiles(ctl, args):
    for path in ctl.create_test_files(args.dir):
        print("Criado:", path)
    print("Agora execute: python aegis_cli.py scan", args.dir or "<pasta acima>")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="aegis_cli", description="AEGIS Desktop (linha de comando)")
    p.add_argument("--server", help="URL do servidor AEGIS (salva nas configurações)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("login", help="entrar na conta")
    s.add_argument("--email")
    s.add_argument("--senha")
    s.add_argument("--license", help="chave de licença (alternativa a e-mail/senha)")
    s.set_defaults(fn=cmd_login)

    sub.add_parser("logout", help="sair da conta").set_defaults(fn=cmd_logout)
    sub.add_parser("status", help="mostrar situação").set_defaults(fn=cmd_status)
    sub.add_parser("update", help="atualizar assinaturas").set_defaults(fn=cmd_update)

    s = sub.add_parser("scan", help="verificar arquivos/pastas")
    s.add_argument("paths", nargs="*")
    s.add_argument("--quick", action="store_true", help="verificação rápida (Downloads, Desktop, Temp)")
    s.add_argument("--no-quarantine", action="store_true", help="apenas relatar, sem isolar")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("clamav", help="integração com o ClamAV")
    s.add_argument("action", choices=["status", "test", "update", "on", "off"])
    s.add_argument("--path", help="caminho do clamscan (salvo nas configurações)")
    s.set_defaults(fn=cmd_clamav)

    s = sub.add_parser("quarantine", help="gerenciar a quarentena")
    s.add_argument("action", choices=["list", "restore", "delete"])
    s.add_argument("id", nargs="?")
    s.set_defaults(fn=cmd_quarantine)

    sub.add_parser("realtime", help="proteção em tempo real (Plus/Pro)").set_defaults(fn=cmd_realtime)

    s = sub.add_parser("testfiles", help="criar arquivos de teste inofensivos")
    s.add_argument("--dir")
    s.set_defaults(fn=cmd_testfiles)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    ctl = make_controller()
    if args.server:
        ctl.set_server_url(args.server)
    if args.cmd == "quarantine" and args.action in ("restore", "delete") and not args.id:
        print("Informe o ID do item.", file=sys.stderr)
        return 1
    try:
        return args.fn(ctl, args)
    except ApiError as exc:
        print(f"Erro: {exc.message}", file=sys.stderr)
        return 1
    except (PermissionError, ValueError, RuntimeError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
