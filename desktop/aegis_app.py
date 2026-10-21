"""AEGIS Desktop — interface gráfica (Tkinter).

Toda a lógica está em controller.py; aqui fica apenas a apresentação.
Execute com:  python aegis_app.py
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
import webbrowser
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # Linux sem o pacote do Tkinter
    sys.exit("Tkinter não encontrado. No Linux instale com: sudo apt install python3-tk\n"
             "Ou use a versão em linha de comando: python3 aegis_cli.py --help")

import config
from api_client import ApiError
from controller import Controller
from quarantine import QuarantineError

if sys.platform.startswith("win"):
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

BG, PANEL, PANEL2, LINE = "#0a0e1a", "#131b30", "#0e1424", "#232e4a"
CYAN, MAGENTA, GREEN, AMBER, RED = "#22d3ee", "#f472b6", "#34d399", "#fbbf24", "#fb7185"
TEXT, DIM = "#eef1f8", "#94a1c2"
ACTIVE_NAV = "#16304a"

if sys.platform.startswith("win"):
    FAMILY = "Segoe UI"
elif sys.platform == "darwin":
    FAMILY = "Helvetica Neue"
else:
    FAMILY = "DejaVu Sans"


def font(size=10, bold=False):
    return (FAMILY, size, "bold") if bold else (FAMILY, size)


def fmt_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return "—"


def short(path: str, limit: int = 70) -> str:
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


VERDICT_LABEL = {"malicious": "Malicioso", "suspicious": "Suspeito"}


def action_label(action: str) -> str:
    if not action:
        return "Pendente"
    if action == "quarentena":
        return "Em quarentena"
    return action[:40]


class App(tk.Tk):
    PAGES = [("dashboard", "Painel"), ("scan", "Verificar"), ("quarantine", "Quarentena"),
             ("protection", "Proteção"), ("settings", "Conta e ajustes")]

    def __init__(self):
        super().__init__()
        self.title("AEGIS — Next-Gen Security")
        self.geometry("1020x680")
        self.minsize(920, 620)
        self.configure(bg=BG)

        self.q: queue.Queue = queue.Queue()
        self.ctl = Controller(emit=lambda kind, payload=None: self.q.put((kind, payload)))
        self.results: dict = {}
        self.unresolved: set = set()
        self.main_ready = False
        self._indeterminate = False
        self.phase = ""
        self._icon = None
        self._logo = None

        self._load_images()
        self._setup_style()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        if self.ctl.logged_in:
            self.show_main()
            threading.Thread(target=self._startup_tasks, daemon=True).start()
        else:
            self.show_login()
        self.after(100, self._poll)

    # ------------------------------------------------------------------
    # Infraestrutura
    # ------------------------------------------------------------------
    def _load_images(self):
        try:
            self._icon = tk.PhotoImage(file=str(config.ASSETS_DIR / "logo-mark.png"))
            self.iconphoto(True, self._icon)
            self._logo = tk.PhotoImage(file=str(config.ASSETS_DIR / "logo-40.png"))
        except Exception:
            self._icon = self._logo = None

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background=PANEL2, fieldbackground=PANEL2, foreground=TEXT,
                        rowheight=28, borderwidth=0, font=font(9))
        style.configure("Treeview.Heading", background=PANEL, foreground=DIM, relief="flat",
                        font=font(9, True))
        style.map("Treeview", background=[("selected", "#1c3a4d")], foreground=[("selected", TEXT)])
        style.map("Treeview.Heading", background=[("active", PANEL)])
        style.configure("Aegis.Horizontal.TProgressbar", troughcolor=PANEL2, background=CYAN,
                        bordercolor=PANEL2, lightcolor=CYAN, darkcolor=CYAN, thickness=8)
        style.configure("Vertical.TScrollbar", background=PANEL, troughcolor=PANEL2,
                        arrowcolor=DIM, bordercolor=PANEL2)

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                handler = getattr(self, f"_on_{kind}", None)
                if handler:
                    try:
                        handler(payload)
                    except Exception:
                        traceback.print_exc()
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _clear(self):
        for child in self.winfo_children():
            child.destroy()
        self.main_ready = False

    def on_close(self):
        self.ctl.cancel_scan()
        if self.ctl.watcher:
            self.ctl.watcher.stop()      # mantém a preferência salva para a próxima abertura
        self.destroy()

    def notify(self, level: str, title: str, message: str):
        fn = {"info": messagebox.showinfo, "warning": messagebox.showwarning,
              "error": messagebox.showerror}[level]
        self.after(50, lambda: fn(title, message))

    # ------------------------------------------------------------------
    # Widgets auxiliares
    # ------------------------------------------------------------------
    def button(self, parent, text, command, kind="ghost"):
        palette = {
            "primary": (CYAN, "#04141c", "#67e8f9"),
            "ghost": (PANEL, TEXT, "#1b2642"),
            "danger": (PANEL, RED, "#2a1d2e"),
        }
        bg, fg, hover = palette[kind]
        btn = tk.Button(parent, text=text, command=command, bg=bg, fg=fg, activebackground=hover,
                        activeforeground=fg, disabledforeground=DIM, relief="flat", bd=0,
                        padx=16, pady=9, cursor="hand2", font=font(10, True))
        btn.bind("<Enter>", lambda _e: btn["state"] != "disabled" and btn.config(bg=hover))
        btn.bind("<Leave>", lambda _e: btn.config(bg=bg))
        return btn

    def entry(self, parent, variable, show=None, width=34):
        return tk.Entry(parent, textvariable=variable, show=show or "", width=width, bg=PANEL2,
                        fg=TEXT, insertbackground=TEXT, relief="flat", font=font(10),
                        highlightthickness=1, highlightbackground=LINE, highlightcolor=CYAN)

    def label(self, parent, text="", size=10, bold=False, color=TEXT, bg=None, **kw):
        return tk.Label(parent, text=text, fg=color, bg=bg or parent["bg"], font=font(size, bold),
                        anchor="w", **kw)

    def heading(self, parent, title, sub=""):
        self.label(parent, title, 20, True).pack(anchor="w")
        if sub:
            self.label(parent, sub, 10, color=DIM, wraplength=680, justify="left").pack(anchor="w", pady=(2, 14))

    def make_tree(self, parent, columns, height=10):
        frame = tk.Frame(parent, bg=PANEL2, highlightbackground=LINE, highlightthickness=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
                            height=height, selectmode="extended")
        for key, title, width, stretch in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, stretch=stretch, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        tree.tag_configure("malicious", foreground=MAGENTA)
        tree.tag_configure("suspicious", foreground=AMBER)
        return frame, tree

    # ------------------------------------------------------------------
    # Tela de login
    # ------------------------------------------------------------------
    def show_login(self):
        self._clear()
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)
        box = tk.Frame(outer, bg=PANEL, padx=38, pady=30, highlightbackground=LINE, highlightthickness=1)
        box.place(relx=0.5, rely=0.5, anchor="center")

        if self._icon:
            small = self._icon.subsample(2, 2)
            self._login_logo = small
            tk.Label(box, image=small, bg=PANEL).pack()
        self.label(box, "AEGIS", 22, True, bg=PANEL).pack()
        self.label(box, "Entre para ativar sua proteção", 10, color=DIM, bg=PANEL).pack(pady=(0, 16))

        self.mode_var = tk.StringVar(value="senha")
        modes = tk.Frame(box, bg=PANEL)
        modes.pack(fill="x", pady=(0, 10))
        for value, text in (("senha", "E-mail e senha"), ("key", "Chave de licença")):
            tk.Radiobutton(modes, text=text, value=value, variable=self.mode_var, command=self._login_mode,
                           bg=PANEL, fg=TEXT, selectcolor=PANEL2, activebackground=PANEL,
                           activeforeground=CYAN, font=font(9)).pack(side="left", padx=(0, 14))

        self.email_var, self.pass_var, self.key_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.server_var = tk.StringVar(value=self.ctl.settings.server_url)

        self.cred = tk.Frame(box, bg=PANEL)
        self.cred.pack(fill="x")
        self.f_pw = tk.Frame(self.cred, bg=PANEL)
        self.label(self.f_pw, "E-mail", 9, color=DIM, bg=PANEL).pack(anchor="w")
        self.entry(self.f_pw, self.email_var).pack(fill="x", ipady=6, pady=(2, 10))
        self.label(self.f_pw, "Senha", 9, color=DIM, bg=PANEL).pack(anchor="w")
        self.pass_entry = self.entry(self.f_pw, self.pass_var, show="•")
        self.pass_entry.pack(fill="x", ipady=6, pady=(2, 4))
        self.pass_entry.bind("<Return>", lambda _e: self._do_login())

        self.f_key = tk.Frame(self.cred, bg=PANEL)
        self.label(self.f_key, "Chave de licença (painel > Visão geral)", 9, color=DIM, bg=PANEL).pack(anchor="w")
        key_entry = self.entry(self.f_key, self.key_var)
        key_entry.pack(fill="x", ipady=6, pady=(2, 4))
        key_entry.bind("<Return>", lambda _e: self._do_login())
        self.f_pw.pack(fill="x")

        self.label(box, "Servidor", 9, color=DIM, bg=PANEL).pack(anchor="w", pady=(10, 0))
        self.entry(box, self.server_var).pack(fill="x", ipady=4, pady=(2, 8))

        self.login_msg = self.label(box, "", 9, color=RED, bg=PANEL, wraplength=320, justify="left")
        self.login_msg.pack(anchor="w", pady=(0, 8))

        self.btn_login = self.button(box, "Entrar", self._do_login, "primary")
        self.btn_login.pack(fill="x")
        self.button(box, "Criar conta no site", self._open_signup).pack(fill="x", pady=(8, 0))
        offline = tk.Label(box, text="Usar sem conta (somente verificação manual)", fg=DIM, bg=PANEL,
                           font=font(9), cursor="hand2")
        offline.pack(pady=(14, 0))
        offline.bind("<Button-1>", lambda _e: self._go_offline())

    def _login_mode(self):
        self.f_pw.pack_forget()
        self.f_key.pack_forget()
        (self.f_pw if self.mode_var.get() == "senha" else self.f_key).pack(fill="x")

    def _open_signup(self):
        self.ctl.set_server_url(self.server_var.get())
        webbrowser.open(self.ctl.settings.server_url + "/cadastro")

    def _go_offline(self):
        self.ctl.use_offline()
        self.show_main()

    def _do_login(self):
        self.ctl.set_server_url(self.server_var.get())
        mode = self.mode_var.get()
        email, senha, key = self.email_var.get().strip(), self.pass_var.get(), self.key_var.get().strip()
        if mode == "senha" and not (email and senha):
            self.login_msg.config(text="Informe e-mail e senha.")
            return
        if mode == "key" and not key:
            self.login_msg.config(text="Informe a chave de licença.")
            return
        self.btn_login.config(state="disabled", text="Entrando…")
        self.login_msg.config(text="Conectando… servidores gratuitos podem levar até 1 minuto para acordar.", fg=DIM)

        def work():
            try:
                self.ctl.login(email, senha, key if mode == "key" else "")
                self.q.put(("login_ok", None))
            except ApiError as exc:
                self.q.put(("login_error", exc.message))
            except Exception as exc:
                self.q.put(("login_error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def _on_login_ok(self, _):
        self.show_main()
        threading.Thread(target=self._startup_tasks, daemon=True).start()

    def _on_login_error(self, message):
        if hasattr(self, "btn_login") and not self.main_ready:
            try:
                self.btn_login.config(state="normal", text="Entrar")
                self.login_msg.config(text=message, fg=RED)
            except tk.TclError:
                pass

    def _startup_tasks(self):
        self.ctl.refresh_account()
        if not self.ctl.logged_in:
            return
        try:
            self.ctl.update_signatures()
        except ApiError:
            pass
        if self.ctl.settings.realtime and self.ctl.can_realtime:
            try:
                self.ctl.start_realtime()
            except (PermissionError, ValueError):
                pass

    # ------------------------------------------------------------------
    # Estrutura principal
    # ------------------------------------------------------------------
    def show_main(self):
        self._clear()
        root = tk.Frame(self, bg=BG)
        root.pack(fill="both", expand=True)

        side = tk.Frame(root, bg=PANEL2, width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        brand = tk.Frame(side, bg=PANEL2)
        brand.pack(fill="x", padx=18, pady=(22, 20))
        if self._logo:
            tk.Label(brand, image=self._logo, bg=PANEL2).pack(side="left", padx=(0, 10))
        self.label(brand, "AEGIS", 16, True, bg=PANEL2).pack(side="left")

        self.nav_buttons = {}
        for key, text in self.PAGES:
            btn = tk.Button(side, text=text, anchor="w", relief="flat", bd=0, padx=20, pady=10,
                            bg=PANEL2, fg=DIM, activebackground=ACTIVE_NAV, activeforeground=CYAN,
                            font=font(10, True), cursor="hand2", command=lambda k=key: self.go(k))
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = btn

        bottom = tk.Frame(side, bg=PANEL2)
        bottom.pack(side="bottom", fill="x", padx=18, pady=18)
        self.user_label = self.label(bottom, "", 9, color=DIM, bg=PANEL2, wraplength=170, justify="left")
        self.user_label.pack(anchor="w")

        right = tk.Frame(root, bg=BG)
        right.pack(side="right", fill="both", expand=True)
        self.statusbar = self.label(right, "", 9, color=DIM)
        self.statusbar.pack(side="bottom", fill="x", padx=28, pady=(0, 10))
        self.content = tk.Frame(right, bg=BG)
        self.content.pack(fill="both", expand=True)

        self.pages = {}
        self._build_dashboard()
        self._build_scan()
        self._build_quarantine()
        self._build_protection()
        self._build_settings()
        self.main_ready = True
        self._refresh_account_ui()
        self.go("dashboard")
        threading.Thread(target=self.ctl.detect_clam, daemon=True).start()

    def _new_page(self, name):
        page = tk.Frame(self.content, bg=BG, padx=30, pady=26)
        self.pages[name] = page
        return page

    def go(self, name):
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        for key, btn in self.nav_buttons.items():
            btn.config(bg=ACTIVE_NAV if key == name else PANEL2, fg=CYAN if key == name else DIM)
        if name == "dashboard":
            self._refresh_dashboard()
        elif name == "quarantine":
            self._refresh_quarantine()
        elif name == "protection":
            self._refresh_protection()

    def set_status(self, text, color=DIM):
        if self.main_ready:
            self.statusbar.config(text=text, fg=color)

    # ------------------------------------------------------------------
    # Painel
    # ------------------------------------------------------------------
    def _build_dashboard(self):
        page = self._new_page("dashboard")
        self.heading(page, "Painel", "Visão geral da proteção deste computador.")

        card = tk.Frame(page, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=24, pady=20)
        card.pack(fill="x")
        self.lbl_status = self.label(card, "Protegido", 20, True, color=GREEN, bg=PANEL)
        self.lbl_status.pack(anchor="w")
        self.lbl_status_sub = self.label(card, "", 10, color=DIM, bg=PANEL)
        self.lbl_status_sub.pack(anchor="w", pady=(2, 0))

        grid = tk.Frame(page, bg=BG)
        grid.pack(fill="x", pady=16)
        self.info = {}
        for i, (key, text) in enumerate([("plan", "Plano"), ("sigs", "Assinaturas AEGIS"), ("clam", "ClamAV"),
                                         ("last", "Última verificação"), ("quar", "Quarentena"),
                                         ("rt", "Tempo real"), ("srv", "Servidor")]):
            cell = tk.Frame(grid, bg=PANEL2, highlightbackground=LINE, highlightthickness=1, padx=14, pady=10)
            cell.grid(row=i // 3, column=i % 3, sticky="nsew", padx=(0, 10), pady=(0, 10))
            grid.columnconfigure(i % 3, weight=1)
            self.label(cell, text, 9, color=DIM, bg=PANEL2).pack(anchor="w")
            self.info[key] = self.label(cell, "—", 10, True, bg=PANEL2, wraplength=200, justify="left")
            self.info[key].pack(anchor="w")

        actions = tk.Frame(page, bg=BG)
        actions.pack(fill="x", pady=(6, 0))
        self.button(actions, "Verificação rápida", self.quick_scan, "primary").pack(side="left", padx=(0, 10))
        self.button(actions, "Verificar pasta…", self.scan_folder).pack(side="left", padx=(0, 10))
        self.button(actions, "Atualizar assinaturas", self.update_signatures).pack(side="left", padx=(0, 10))
        self.button(actions, "Criar arquivos de teste", self.create_tests).pack(side="left")

    def _refresh_dashboard(self):
        if not self.main_ready:
            return
        ctl, user = self.ctl, self.ctl.user
        plan = user.get("plano_nome") or "Offline (sem conta)"
        if user.get("expira_em"):
            plan += f" · até {fmt_time(user['expira_em'])[:10]}"
        self.info["plan"].config(text=plan)
        self.info["sigs"].config(text=f"versão {ctl.signatures.version} · {ctl.signatures.total} regras")
        last = ctl.settings.last_scan
        self.info["last"].config(text=f"{fmt_time(last)}\n{ctl.settings.last_scan_info}" if last else "Nunca")
        self.info["quar"].config(text=f"{len(ctl.quarantine.list())} item(ns)")
        if ctl.realtime_running:
            self.info["rt"].config(text="Ativa", fg=GREEN)
        elif ctl.can_realtime:
            self.info["rt"].config(text="Desativada", fg=AMBER)
        else:
            self.info["rt"].config(text="Indisponível no plano", fg=DIM)
        self.info["srv"].config(text=ctl.settings.server_url)
        if not ctl.settings.clamav_enabled:
            self.info["clam"].config(text="Desativado nos ajustes", fg=DIM)
        else:
            self.info["clam"].config(text=ctl.clam_status.summary, fg=GREEN if ctl.clam_active else DIM)

        if ctl.scanning:
            self.lbl_status.config(text="Verificando…", fg=CYAN)
            self.lbl_status_sub.config(text="Uma verificação está em andamento.")
        elif self.unresolved:
            self.lbl_status.config(text="Atenção", fg=MAGENTA)
            self.lbl_status_sub.config(text=f"{len(self.unresolved)} ameaça(s) aguardam uma ação na aba Verificar.")
        else:
            self.lbl_status.config(text="Protegido", fg=GREEN)
            self.lbl_status_sub.config(text="Nenhuma ameaça pendente.")

    def quick_scan(self):
        self.run_scan("rapida", config.quick_scan_paths())

    def scan_folder(self):
        folder = filedialog.askdirectory(title="Escolha a pasta para verificar")
        if folder:
            self.run_scan("personalizada", [folder])

    def update_signatures(self):
        def work():
            try:
                changed = self.ctl.update_signatures()
                msg = "Assinaturas atualizadas com sucesso." if changed else "Você já está com as assinaturas mais recentes."
                self.q.put(("notify", ("info", "Assinaturas", msg)))
            except ApiError as exc:
                self.q.put(("notify", ("warning", "Assinaturas", exc.message)))
        self.set_status("Atualizando assinaturas…", CYAN)
        threading.Thread(target=work, daemon=True).start()

    def create_tests(self):
        try:
            files = self.ctl.create_test_files()
        except OSError as exc:
            messagebox.showerror("Arquivos de teste", f"Não foi possível criar os arquivos: {exc}")
            return
        folder = os.path.dirname(files[0])
        again = messagebox.askyesno(
            "Arquivos de teste criados",
            f"Criados em:\n{folder}\n\n"
            "• eicar_test.txt — padrão inofensivo que todo antivírus reconhece\n"
            "• aegis_update_test.txt — só é detectado depois de atualizar as assinaturas\n\n"
            "Se o seu outro antivírus apagar esses arquivos, é normal.\n\nVerificar essa pasta agora?")
        if again:
            self.run_scan("personalizada", [folder])

    # ------------------------------------------------------------------
    # Verificação
    # ------------------------------------------------------------------
    def _build_scan(self):
        page = self._new_page("scan")
        self.heading(page, "Verificação", "Acompanhe o progresso e decida o que fazer com cada detecção.")

        top = tk.Frame(page, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=20, pady=16)
        top.pack(fill="x")
        self.scan_label = self.label(top, "Nenhuma verificação em andamento.", 10, bg=PANEL)
        self.scan_label.pack(anchor="w", pady=(0, 8))
        self.pbar = ttk.Progressbar(top, style="Aegis.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.pbar.pack(fill="x")
        row = tk.Frame(top, bg=PANEL)
        row.pack(fill="x", pady=(10, 0))
        self.scan_counts = self.label(row, "", 9, color=DIM, bg=PANEL)
        self.scan_counts.pack(side="left")
        self.btn_cancel = self.button(row, "Cancelar", self.cancel_scan, "danger")
        self.btn_cancel.pack(side="right")
        self.btn_cancel.config(state="disabled")

        frame, self.tree_scan = self.make_tree(page, [
            ("arquivo", "Arquivo", 430, True), ("veredito", "Resultado", 90, False),
            ("ameaca", "Ameaça", 150, False), ("acao", "Situação", 120, False)], height=11)
        frame.pack(fill="both", expand=True, pady=14)
        self.tree_scan.bind("<Double-1>", lambda _e: self.show_detail())

        actions = tk.Frame(page, bg=BG)
        actions.pack(fill="x")
        self.button(actions, "Quarentenar selecionados", self.quarantine_selected, "primary").pack(side="left", padx=(0, 10))
        self.button(actions, "Ignorar selecionados", self.ignore_selected).pack(side="left", padx=(0, 10))
        self.button(actions, "Ver detalhes", self.show_detail).pack(side="left")
        self.scan_threat_count = 0

    def run_scan(self, kind, paths):
        if self.ctl.scanning:
            messagebox.showinfo("Verificação", "Já existe uma verificação em andamento.")
            return
        for iid in self.tree_scan.get_children():
            self.tree_scan.delete(iid)
        self.results.clear()
        self.unresolved.clear()
        self.scan_threat_count = 0
        try:
            self.ctl.start_scan(kind, paths)
        except (ValueError, RuntimeError) as exc:
            messagebox.showwarning("Verificação", str(exc))
            return
        self.phase = ""
        self.btn_cancel.config(state="normal")
        self.scan_label.config(text="Preparando a verificação…")
        self.scan_counts.config(text="")
        self.pbar.config(mode="determinate", value=0)
        self._indeterminate = False
        self.go("scan")

    def cancel_scan(self):
        self.ctl.cancel_scan()
        self.scan_label.config(text="Cancelando…")

    def _selected(self):
        return [(iid, self.results[iid]) for iid in self.tree_scan.selection() if iid in self.results]

    def quarantine_selected(self):
        chosen = self._selected()
        if not chosen:
            messagebox.showinfo("Quarentena", "Selecione ao menos um item da lista.")
            return
        ok, errors = self.ctl.quarantine_results([r for _, r in chosen])
        for iid, res in chosen:
            self.tree_scan.item(iid, values=self._row_values(res))
            if res.action == "quarentena":
                self.unresolved.discard(res.path)
        msg = f"{ok} arquivo(s) movido(s) para a quarentena."
        if errors:
            msg += "\n\nFalhas:\n" + "\n".join(errors[:5])
        messagebox.showinfo("Quarentena", msg)
        self._refresh_dashboard()

    def ignore_selected(self):
        for iid, res in self._selected():
            res.action = "ignorado"
            self.unresolved.discard(res.path)
            self.tree_scan.item(iid, values=self._row_values(res))
        self._refresh_dashboard()

    def show_detail(self):
        chosen = self._selected()
        if not chosen:
            return
        res = chosen[0][1]
        text = (f"Arquivo: {res.path}\nAmeaça: {res.threat}\nDetectado por: {res.source}\nPontuação: {res.score}\n"
                f"SHA-256: {res.sha256}\n\nMotivos:\n• " + "\n• ".join(res.reasons or ["—"]))
        messagebox.showinfo("Detalhes da detecção", text)

    def _row_values(self, res):
        threat = f"{res.threat} (ClamAV)" if res.source == "ClamAV" else res.threat
        return (res.path, VERDICT_LABEL.get(res.verdict, res.verdict), threat, action_label(res.action))

    # eventos da verificação
    def _on_progress(self, payload):
        if not self.main_ready:
            return
        done, total, path = payload
        if total == 0:
            if not self._indeterminate:
                self.pbar.config(mode="indeterminate")
                self.pbar.start(12)
                self._indeterminate = True
            self.scan_label.config(text=f"Preparando… {done} arquivos encontrados")
            return
        if self._indeterminate:
            self.pbar.stop()
            self.pbar.config(mode="determinate")
            self._indeterminate = False
        self.pbar.config(maximum=total, value=done)
        prefix = f"{self.phase}: " if self.phase else ""
        self.scan_label.config(text=f"{prefix}verificando {done} de {total}: {short(path, 55)}")

    def _on_phase(self, name):
        if not self.main_ready:
            return
        self.phase = name
        if name == "ClamAV":
            self.scan_label.config(text="ClamAV: carregando a base de vírus… (pode levar alguns instantes)")
            self.pbar.config(mode="indeterminate")
            self.pbar.start(12)
            self._indeterminate = True

    def _on_result(self, res):
        if not self.main_ready:
            return
        iid = self.tree_scan.insert("", "end", values=self._row_values(res), tags=(res.verdict,))
        self.results[iid] = res
        self.scan_threat_count += 1
        if res.action != "quarentena":
            self.unresolved.add(res.path)
        self.scan_counts.config(text=f"{self.scan_threat_count} detecção(ões) até agora")

    def _on_scan_done(self, payload):
        if not self.main_ready:
            return
        if self._indeterminate:
            self.pbar.stop()
            self._indeterminate = False
        summary, duration = payload["summary"], payload["duration"]
        self.btn_cancel.config(state="disabled")
        self.pbar.config(mode="determinate")
        if not summary.cancelled:
            self.pbar.config(value=self.pbar["maximum"])
        state = "Cancelada" if summary.cancelled else "Concluída"
        self.scan_label.config(text=f"{state}: {summary.scanned} arquivos em {duration:.1f} s.")
        self.scan_counts.config(text=f"{summary.malicious} malicioso(s) · {summary.suspicious} suspeito(s) · "
                                     f"{summary.errors} sem acesso")
        self._refresh_dashboard()
        if summary.threats:
            quarantined = sum(1 for r in summary.results if r.action == "quarentena")
            pending = summary.threats - quarantined
            msg = f"{summary.threats} ameaça(s) encontrada(s)."
            if quarantined:
                msg += f"\n{quarantined} já foram isoladas na quarentena."
            if pending:
                msg += f"\n{pending} aguardam sua decisão na lista."
            self.notify("warning", "Verificação concluída", msg)
        elif not summary.cancelled:
            self.notify("info", "Verificação concluída", "Nenhuma ameaça encontrada.")

    # ------------------------------------------------------------------
    # Quarentena
    # ------------------------------------------------------------------
    def _build_quarantine(self):
        page = self._new_page("quarantine")
        self.heading(page, "Quarentena", "Arquivos isolados ficam codificados e não podem ser executados.")
        frame, self.tree_q = self.make_tree(page, [
            ("data", "Isolado em", 140, False), ("nome", "Arquivo", 200, False),
            ("ameaca", "Ameaça", 150, False), ("caminho", "Local original", 380, True)], height=14)
        frame.pack(fill="both", expand=True, pady=(0, 14))
        actions = tk.Frame(page, bg=BG)
        actions.pack(fill="x")
        self.button(actions, "Restaurar", self.restore_selected).pack(side="left", padx=(0, 10))
        self.button(actions, "Excluir definitivamente", self.delete_selected, "danger").pack(side="left", padx=(0, 10))
        self.button(actions, "Atualizar lista", self._refresh_quarantine).pack(side="left")

    def _refresh_quarantine(self):
        if not self.main_ready:
            return
        for iid in self.tree_q.get_children():
            self.tree_q.delete(iid)
        for e in self.ctl.quarantine.list():
            self.tree_q.insert("", "end", iid=e["id"],
                               values=(fmt_time(e["data"]), e["nome"], e["ameaca"], e["caminho"]))

    def restore_selected(self):
        ids = self.tree_q.selection()
        if not ids:
            messagebox.showinfo("Quarentena", "Selecione um item para restaurar.")
            return
        if not messagebox.askyesno("Restaurar", "Estes arquivos foram isolados por conterem possíveis ameaças.\n"
                                                "Restaurar mesmo assim? (Use apenas se for um falso positivo.)"):
            return
        for qid in ids:
            try:
                self.ctl.quarantine.restore(qid)
            except (QuarantineError, OSError) as exc:
                messagebox.showerror("Restaurar", str(exc))
        self._refresh_quarantine()
        self._refresh_dashboard()

    def delete_selected(self):
        ids = self.tree_q.selection()
        if not ids:
            messagebox.showinfo("Quarentena", "Selecione um item para excluir.")
            return
        if not messagebox.askyesno("Excluir", "Excluir definitivamente os itens selecionados? Não há como desfazer."):
            return
        for qid in ids:
            try:
                self.ctl.quarantine.delete(qid)
            except QuarantineError as exc:
                messagebox.showerror("Excluir", str(exc))
        self._refresh_quarantine()
        self._refresh_dashboard()

    # ------------------------------------------------------------------
    # Proteção em tempo real
    # ------------------------------------------------------------------
    def _build_protection(self):
        page = self._new_page("protection")
        self.heading(page, "Proteção em tempo real",
                     "Verifica automaticamente arquivos novos nas pastas monitoradas, assim que terminam de chegar.")

        card = tk.Frame(page, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=22, pady=18)
        card.pack(fill="x")
        self.rt_state = self.label(card, "", 14, True, bg=PANEL)
        self.rt_state.pack(anchor="w")
        self.rt_note = self.label(card, "", 9, color=DIM, bg=PANEL, wraplength=640, justify="left")
        self.rt_note.pack(anchor="w", pady=(2, 4))
        self.rt_clam_note = self.label(card, "", 9, color=DIM, bg=PANEL, wraplength=640, justify="left")
        self.rt_clam_note.pack(anchor="w", pady=(0, 10))
        row = tk.Frame(card, bg=PANEL)
        row.pack(fill="x")
        self.btn_rt = self.button(row, "Ativar", self.toggle_realtime, "primary")
        self.btn_rt.pack(side="left")
        self.btn_plans = self.button(row, "Ver planos", lambda: webbrowser.open(self.ctl.settings.server_url + "/#planos"))
        self.auto_var = tk.BooleanVar(value=self.ctl.settings.auto_quarantine)
        tk.Checkbutton(row, text="Isolar automaticamente ameaças confirmadas", variable=self.auto_var,
                       command=self._save_auto, bg=PANEL, fg=TEXT, selectcolor=PANEL2, activebackground=PANEL,
                       activeforeground=CYAN, font=font(9)).pack(side="right")

        lists = tk.Frame(page, bg=BG)
        lists.pack(fill="both", expand=True, pady=14)
        left = tk.Frame(lists, bg=BG)
        left.pack(side="left", fill="y", padx=(0, 16))
        self.label(left, "Pastas monitoradas", 10, True).pack(anchor="w", pady=(0, 6))
        self.folder_list = tk.Listbox(left, width=34, height=8, bg=PANEL2, fg=TEXT, relief="flat",
                                      highlightthickness=1, highlightbackground=LINE,
                                      selectbackground="#1c3a4d", font=font(9), exportselection=False)
        self.folder_list.pack(fill="x")
        btns = tk.Frame(left, bg=BG)
        btns.pack(fill="x", pady=8)
        self.button(btns, "Adicionar…", self.add_folder).pack(side="left", padx=(0, 8))
        self.button(btns, "Remover", self.remove_folder).pack(side="left")

        right = tk.Frame(lists, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self.label(right, "Eventos recentes", 10, True).pack(anchor="w", pady=(0, 6))
        frame, self.tree_rt = self.make_tree(right, [
            ("hora", "Hora", 120, False), ("arquivo", "Arquivo", 200, True),
            ("ameaca", "Ameaça", 130, False), ("acao", "Situação", 110, False)], height=8)
        frame.pack(fill="both", expand=True)

    def _refresh_protection(self):
        if not self.main_ready:
            return
        ctl = self.ctl
        self.folder_list.delete(0, "end")
        for folder in ctl.settings.watch_folders:
            self.folder_list.insert("end", folder)
        self.btn_plans.pack_forget()
        if ctl.clam_active and ctl.clam_status.mode == "clamd":
            self.rt_clam_note.config(text="O ClamAV (clamd) também participa da proteção em tempo real.")
        elif ctl.clam_active:
            self.rt_clam_note.config(text="O tempo real usa o motor do AEGIS. Para incluir o ClamAV nele, "
                                          "execute o clamd (modo daemon).")
        else:
            self.rt_clam_note.config(text="")
        if ctl.realtime_running:
            self.rt_state.config(text="Ativa", fg=GREEN)
            self.rt_note.config(text="As pastas abaixo estão sendo monitoradas.")
            self.btn_rt.config(text="Desativar", state="normal")
        elif ctl.can_realtime:
            self.rt_state.config(text="Desativada", fg=AMBER)
            self.rt_note.config(text="Ative para verificar arquivos novos automaticamente.")
            self.btn_rt.config(text="Ativar", state="normal")
        else:
            self.rt_state.config(text="Indisponível", fg=DIM)
            reason = ("Entre na sua conta para usar este recurso." if not ctl.logged_in else
                      "A proteção em tempo real está nos planos Plus e Pro.")
            self.rt_note.config(text=reason)
            self.btn_rt.config(text="Ativar", state="disabled")
            self.btn_plans.pack(side="left", padx=(10, 0))

    def toggle_realtime(self):
        try:
            if self.ctl.realtime_running:
                self.ctl.stop_realtime()
            else:
                self.ctl.start_realtime()
        except (PermissionError, ValueError) as exc:
            messagebox.showinfo("Tempo real", str(exc))
        self._refresh_protection()
        self._refresh_dashboard()

    def _save_auto(self):
        self.ctl.settings.auto_quarantine = bool(self.auto_var.get())
        self.ctl.settings.save()

    def add_folder(self):
        folder = filedialog.askdirectory(title="Pasta para monitorar")
        if folder and folder not in self.ctl.settings.watch_folders:
            self.ctl.settings.watch_folders.append(folder)
            self.ctl.settings.save()
            self._refresh_protection()
            if self.ctl.realtime_running:
                self.set_status("Reative a proteção para monitorar a nova pasta.", AMBER)

    def remove_folder(self):
        sel = self.folder_list.curselection()
        if sel:
            self.ctl.settings.watch_folders.pop(sel[0])
            self.ctl.settings.save()
            self._refresh_protection()

    def _on_rt_event(self, res):
        if not self.main_ready:
            return
        self.tree_rt.insert("", 0, values=(datetime.now().strftime("%d/%m %H:%M:%S"), res.name,
                                           res.threat, action_label(res.action)), tags=(res.verdict,))
        if res.action != "quarentena":
            self.unresolved.add(res.path)
        self._refresh_dashboard()
        self.bell()
        title = "Ameaça detectada" if res.verdict == "malicious" else "Arquivo suspeito"
        self.notify("warning", title, f"{res.name}\n{res.threat}\nSituação: {action_label(res.action)}")

    def _on_realtime(self, _running):
        self._refresh_protection()
        self._refresh_dashboard()

    # ------------------------------------------------------------------
    # Conta e ajustes
    # ------------------------------------------------------------------
    def _build_settings(self):
        page = self._new_page("settings")
        self.heading(page, "Conta e ajustes")

        card = tk.Frame(page, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=22, pady=18)
        card.pack(fill="x")
        self.acc_name = self.label(card, "", 14, True, bg=PANEL)
        self.acc_name.pack(anchor="w")
        self.acc_plan = self.label(card, "", 10, color=DIM, bg=PANEL)
        self.acc_plan.pack(anchor="w", pady=(2, 12))
        row = tk.Frame(card, bg=PANEL)
        row.pack(fill="x")
        self.button(row, "Abrir painel online", lambda: webbrowser.open(self.ctl.settings.server_url + "/sistema"),
                    "primary").pack(side="left", padx=(0, 10))
        self.btn_account = self.button(row, "Sair da conta", self.logout, "danger")
        self.btn_account.pack(side="left")

        srv = tk.Frame(page, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=22, pady=18)
        srv.pack(fill="x", pady=16)
        self.label(srv, "Servidor AEGIS", 10, True, bg=PANEL).pack(anchor="w")
        self.srv_var = tk.StringVar(value=self.ctl.settings.server_url)
        line = tk.Frame(srv, bg=PANEL)
        line.pack(fill="x", pady=(6, 0))
        self.entry(line, self.srv_var, width=44).pack(side="left", ipady=5)
        self.button(line, "Salvar", self.save_server).pack(side="left", padx=10)
        self.button(line, "Testar conexão", self.test_server).pack(side="left")

        cl = tk.Frame(page, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=22, pady=18)
        cl.pack(fill="x", pady=(0, 16))
        self.label(cl, "ClamAV (opcional, recomendado)", 10, True, bg=PANEL).pack(anchor="w")
        self.clam_status_lbl = self.label(cl, self.ctl.clam_status.summary, 9, color=DIM, bg=PANEL,
                                          wraplength=700, justify="left")
        self.clam_status_lbl.pack(anchor="w", pady=(2, 6))
        self.clam_var = tk.BooleanVar(value=self.ctl.settings.clamav_enabled)
        tk.Checkbutton(cl, text="Usar o ClamAV nas verificações", variable=self.clam_var,
                       command=self._toggle_clam, bg=PANEL, fg=TEXT, selectcolor=PANEL2,
                       activebackground=PANEL, activeforeground=CYAN, font=font(9)).pack(anchor="w")
        self.label(cl, "Caminho do clamscan (deixe vazio para detectar sozinho)", 9, color=DIM,
                   bg=PANEL).pack(anchor="w", pady=(8, 2))
        path_row = tk.Frame(cl, bg=PANEL)
        path_row.pack(fill="x")
        self.clam_path_var = tk.StringVar(value=self.ctl.settings.clamscan_path)
        self.entry(path_row, self.clam_path_var, width=48).pack(side="left", ipady=5)
        self.button(path_row, "Procurar…", self._clam_browse).pack(side="left", padx=8)
        self.button(path_row, "Salvar e detectar", self._clam_save_path).pack(side="left")
        btns = tk.Frame(cl, bg=PANEL)
        btns.pack(fill="x", pady=(10, 0))
        self.button(btns, "Detectar novamente", self._clam_detect).pack(side="left", padx=(0, 8))
        self.button(btns, "Testar ClamAV", self._clam_test).pack(side="left", padx=(0, 8))
        self.button(btns, "Atualizar base de vírus", self._clam_update).pack(side="left", padx=(0, 8))
        self.button(btns, "Guia de instalação", lambda: webbrowser.open("https://docs.clamav.net/")).pack(side="left")

        self.label(page, f"AEGIS Desktop {config.APP_VERSION}  ·  dados em {config.DATA_DIR}", 9, color=DIM).pack(anchor="w")

    def _refresh_account_ui(self):
        if not self.main_ready:
            return
        user = self.ctl.user
        if self.ctl.logged_in:
            self.user_label.config(text=f"{user.get('nome', '')}\nPlano {user.get('plano_nome', '')}")
            self.acc_name.config(text=user.get("nome", ""))
            self.acc_plan.config(text=f"{user.get('email', '')}  ·  Plano {user.get('plano_nome', '')}")
            self.btn_account.config(text="Sair da conta", command=self.logout)
        else:
            self.user_label.config(text="Modo offline\nsem conta")
            self.acc_name.config(text="Modo offline")
            self.acc_plan.config(text="Verificação manual com as assinaturas locais.")
            self.btn_account.config(text="Entrar na conta", command=self.show_login)

    def save_server(self):
        self.ctl.set_server_url(self.srv_var.get())
        self.srv_var.set(self.ctl.settings.server_url)
        self.set_status("Servidor salvo.", GREEN)

    def test_server(self):
        self.save_server()

        def work():
            try:
                self.ctl.client().health()
                self.q.put(("notify", ("info", "Conexão", "Servidor respondeu normalmente.")))
            except ApiError as exc:
                self.q.put(("notify", ("warning", "Conexão", exc.message)))
        threading.Thread(target=work, daemon=True).start()

    def logout(self):
        if messagebox.askyesno("Sair", "Sair da conta neste computador? A proteção em tempo real será desligada."):
            self.ctl.logout()

    # ClamAV
    def _run_bg(self, work):
        threading.Thread(target=work, daemon=True).start()

    def _toggle_clam(self):
        self.ctl.set_clamav_enabled(self.clam_var.get())
        self._refresh_dashboard()

    def _clam_browse(self):
        path = filedialog.askopenfilename(title="Escolha o executável clamscan")
        if path:
            self.clam_path_var.set(path)

    def _clam_save_path(self):
        path = self.clam_path_var.get()
        self.set_status("Detectando o ClamAV…", CYAN)
        self._run_bg(lambda: self.ctl.set_clamscan_path(path))

    def _clam_detect(self):
        self.set_status("Detectando o ClamAV…", CYAN)
        self._run_bg(self.ctl.detect_clam)

    def _clam_test(self):
        def work():
            ok, msg = self.ctl.clam_self_test()
            self.q.put(("notify", ("info" if ok else "warning", "Teste do ClamAV", msg)))
        self.set_status("Testando o ClamAV…", CYAN)
        self._run_bg(work)

    def _clam_update(self):
        def work():
            ok, msg = self.ctl.update_clam_database()
            self.q.put(("notify", ("info" if ok else "warning", "Base de vírus do ClamAV", msg)))
        self.set_status("Atualizando a base de vírus do ClamAV (pode demorar)…", CYAN)
        self._run_bg(work)

    def _on_clam(self, status):
        if not self.main_ready:
            return
        self.clam_status_lbl.config(text=status.summary, fg=GREEN if self.ctl.clam_active else DIM)
        self._refresh_dashboard()
        self._refresh_protection()
        self.set_status("", DIM)

    # eventos gerais
    def _on_account(self, _user):
        self._refresh_account_ui()
        self._refresh_dashboard()
        if self.main_ready:
            self._refresh_protection()

    def _on_signatures(self, info):
        self._refresh_dashboard()
        self.set_status(f"Assinaturas na versão {info['versao']} ({info['total']} regras).", GREEN)

    def _on_info(self, text):
        self.set_status(text, AMBER)

    def _on_error(self, text):
        self.set_status(text, RED)

    def _on_notify(self, payload):
        level, title, message = payload
        self.notify(level, title, message)

    def _on_logout(self, _):
        self.show_login()
        if hasattr(self, "login_msg"):
            self.login_msg.config(text="Você saiu da conta.", fg=DIM)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
