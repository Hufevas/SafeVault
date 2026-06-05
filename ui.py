import csv
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from crypto_utils import criar_verificacao, gerar_chave, gerar_salt, validar_senha
from database import Database

TIMEOUT_BLOQUEIO_MS = 5 * 60 * 1000


def centralizar(janela, largura, altura):
    janela.update_idletasks()
    x = (janela.winfo_screenwidth() // 2) - (largura // 2)
    y = (janela.winfo_screenheight() // 2) - (altura // 2)
    janela.geometry(f"{largura}x{altura}+{x}+{y}")


class DialogoSenhaMestra(tk.Toplevel):
    def __init__(
        self,
        pai,
        db: Database,
        titulo: str = "Confirmar senha mestra",
        mensagem: str = "Digite a senha mestra para continuar:",
    ):
        super().__init__(pai)
        self.db = db
        self.confirmado = False

        self.title(titulo)
        self.resizable(False, False)
        self.transient(pai)
        self.grab_set()

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=mensagem, wraplength=320).pack(anchor=tk.W, pady=(0, 12))
        ttk.Label(frame, text="Senha mestra").pack(anchor=tk.W)
        self.entry_senha = ttk.Entry(frame, show="*", width=36)
        self.entry_senha.pack(fill=tk.X, pady=(4, 16))
        self.entry_senha.bind("<Return>", lambda _: self._confirmar())
        self.entry_senha.focus()

        botoes = ttk.Frame(frame)
        botoes.pack(fill=tk.X)

        ttk.Button(botoes, text="Cancelar", command=self._cancelar).pack(
            side=tk.RIGHT, padx=(8, 0)
        )
        ttk.Button(botoes, text="Confirmar", command=self._confirmar).pack(side=tk.RIGHT)

        self.protocol("WM_DELETE_WINDOW", self._cancelar)
        centralizar(self, 380, 180)
        self.wait_window()

    def _confirmar(self):
        senha_mestra = self.entry_senha.get()
        if not senha_mestra:
            messagebox.showerror("Erro", "Digite a senha mestra", parent=self)
            return

        salt = self.db.obter_salt()
        cipher = gerar_chave(senha_mestra, salt)
        if validar_senha(cipher, self.db.obter_verificacao()):
            self.confirmado = True
            self.destroy()
        else:
            messagebox.showerror("Erro", "Senha mestra incorreta", parent=self)
            self.entry_senha.delete(0, tk.END)
            self.entry_senha.focus()

    def _cancelar(self):
        self.confirmado = False
        self.destroy()


class SafeVaultApp:
    def __init__(self):
        self.db = Database()
        self.cipher = None
        self.root = tk.Tk()
        self.root.withdraw()
        self.tela_atual = None
        self._mostrar_login()

    def _limpar_tela(self):
        if self.tela_atual is not None:
            self.tela_atual.destroy()
            self.tela_atual = None

    def _mostrar_login(self):
        self._limpar_tela()
        self.cipher = None
        self.root.deiconify()
        self.tela_atual = TelaLogin(self.root, self.db, self._mostrar_principal)
        centralizar(self.root, 380, 250)

    def _mostrar_principal(self, cipher):
        self._limpar_tela()
        self.cipher = cipher
        self.root.deiconify()
        self.tela_atual = TelaPrincipal(self.root, self.db, cipher, self._mostrar_login)
        self.root.minsize(820, 600)
        self.root.geometry("920x640")

    def executar(self):
        self.root.protocol("WM_DELETE_WINDOW", self._ao_fechar)
        self.root.mainloop()

    def _ao_fechar(self):
        self.db.fechar()
        self.root.destroy()


class TelaLogin(ttk.Frame):
    def __init__(self, root, db: Database, on_desbloquear):
        super().__init__(root, padding=24)
        self.db = db
        self.on_desbloquear = on_desbloquear
        self.pack(fill=tk.BOTH, expand=True)

        self._configurar_estilo()
        self._montar_interface()
        root.title("SafeVault — Login")
        root.resizable(False, False)

    def _configurar_estilo(self):
        estilo = ttk.Style()
        estilo.configure("TFrame", padding=4)
        estilo.configure("TButton", padding=6)
        estilo.configure("TLabel", padding=2)

    def _montar_interface(self):
        ttk.Label(self, text="🔐 SafeVault", font=("Segoe UI", 16, "bold")).pack(
            pady=(0, 4)
        )
        ttk.Label(
            self,
            text="Digite a senha mestra para desbloquear o cofre",
            font=("Segoe UI", 9),
        ).pack(pady=(0, 16))

        campo_frame = ttk.Frame(self)
        campo_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(campo_frame, text="Senha mestra").pack(anchor=tk.W)
        self.entry_senha = ttk.Entry(campo_frame, show="*", width=36)
        self.entry_senha.pack(fill=tk.X, pady=(4, 0))
        self.entry_senha.bind("<Return>", lambda _: self.desbloquear())
        self.entry_senha.focus()

        ttk.Button(self, text="Desbloquear Cofre", command=self.desbloquear).pack(
            fill=tk.X, pady=(8, 0)
        )

    def desbloquear(self):
        senha_mestra = self.entry_senha.get()
        if not senha_mestra:
            messagebox.showerror("Erro", "Digite a senha mestra")
            return

        if not self.db.cofre_configurado():
            salt = gerar_salt()
            cipher = gerar_chave(senha_mestra, salt)
            verificacao = criar_verificacao(cipher)
            self.db.inicializar_cofre(verificacao, salt)
            messagebox.showinfo("Sucesso", "Senha mestra criada!")
            self.on_desbloquear(cipher)
            return

        salt = self.db.obter_salt()
        cipher = gerar_chave(senha_mestra, salt)
        if validar_senha(cipher, self.db.obter_verificacao()):
            self.on_desbloquear(cipher)
        else:
            messagebox.showerror("Erro", "Senha mestra incorreta")


class TelaPrincipal(ttk.Frame):
    def __init__(self, root, db: Database, cipher, on_bloquear):
        super().__init__(root, padding=12)
        self.db = db
        self.cipher = cipher
        self.on_bloquear = on_bloquear
        self.credencial_selecionada = None
        self.ordenar_por = "id"
        self.ordem = "ASC"
        self._timer_bloqueio = None

        self.pack(fill=tk.BOTH, expand=True)
        root.title("SafeVault — Cofre")
        root.resizable(True, True)

        self._configurar_estilo()
        self._montar_interface()
        self.atualizar_lista()
        self._configurar_timeout()
        self._registrar_atividade()

    def _configurar_estilo(self):
        estilo = ttk.Style()
        estilo.configure("TFrame", padding=4)
        estilo.configure("TButton", padding=4)
        estilo.configure("TLabel", padding=2)
        estilo.configure("Header.TLabel", font=("Segoe UI", 11, "bold"))
        estilo.configure("Status.TLabel", font=("Segoe UI", 9), foreground="#2e7d32")

    def _montar_interface(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._montar_barra_superior()
        self._montar_formulario()
        self._montar_conteudo()
        self._montar_status()

    def _montar_barra_superior(self):
        barra = ttk.Frame(self)
        barra.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        ttk.Button(barra, text="Bloquear Cofre", command=self.bloquear_cofre).pack(
            side=tk.RIGHT
        )
        ttk.Button(barra, text="Exportar CSV", command=self.exportar_csv).pack(
            side=tk.RIGHT, padx=(0, 8)
        )
        ttk.Button(barra, text="Importar CSV", command=self.importar_csv).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

    def _montar_formulario(self):
        frame = ttk.LabelFrame(self, text="Credencial", padding=12)
        frame.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)
        frame.columnconfigure(5, weight=1)

        ttk.Label(frame, text="Site").grid(row=0, column=0, sticky=tk.W, padx=(0, 8))
        self.entry_site = ttk.Entry(frame)
        self.entry_site.grid(row=0, column=1, sticky="ew", padx=(0, 16))

        ttk.Label(frame, text="Usuário").grid(row=0, column=2, sticky=tk.W, padx=(0, 8))
        self.entry_usuario = ttk.Entry(frame)
        self.entry_usuario.grid(row=0, column=3, sticky="ew", padx=(0, 16))

        ttk.Label(frame, text="Senha").grid(row=0, column=4, sticky=tk.W, padx=(0, 8))
        self.entry_senha = ttk.Entry(frame)
        self.entry_senha.grid(row=0, column=5, sticky="ew")

        botoes = ttk.Frame(frame)
        botoes.grid(row=1, column=0, columnspan=6, sticky=tk.W, pady=(12, 0))

        ttk.Button(botoes, text="Gerar senha", command=self.gerar_senha).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(botoes, text="Salvar credencial", command=self.salvar).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(botoes, text="Atualizar credencial", command=self.atualizar).pack(
            side=tk.LEFT
        )

    def _montar_conteudo(self):
        painel = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        painel.grid(row=2, column=0, sticky="nsew")

        lista_frame = ttk.LabelFrame(painel, text="Credenciais", padding=8)
        painel.add(lista_frame, weight=3)

        tree_frame = ttk.Frame(lista_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        colunas = ("id", "site", "usuario")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=colunas,
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("id", text="ID", command=lambda: self._ordenar_por("id"))
        self.tree.heading("site", text="Site", command=lambda: self._ordenar_por("site"))
        self.tree.heading(
            "usuario", text="Usuário", command=lambda: self._ordenar_por("usuario")
        )
        self.tree.column("id", width=50, anchor=tk.CENTER, stretch=False)
        self.tree.column("site", width=200, anchor=tk.W)
        self.tree.column("usuario", width=200, anchor=tk.W)

        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._ao_selecionar)

        detalhes_frame = ttk.LabelFrame(painel, text="Detalhes", padding=12)
        painel.add(detalhes_frame, weight=2)

        self.label_site = self._campo_detalhe(detalhes_frame, "Site", 0)
        self.label_usuario = self._campo_detalhe(detalhes_frame, "Usuário", 1)
        self.label_senha = self._campo_detalhe(detalhes_frame, "Senha", 2)

        acoes = ttk.Frame(detalhes_frame)
        acoes.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(16, 0))

        ttk.Button(acoes, text="Copiar Usuário", command=self.copiar_usuario).pack(
            fill=tk.X, pady=(0, 6)
        )
        ttk.Button(acoes, text="Copiar Senha", command=self.copiar_senha).pack(
            fill=tk.X, pady=(0, 6)
        )
        ttk.Button(acoes, text="Excluir Credencial", command=self.excluir_credencial).pack(
            fill=tk.X
        )

    def _campo_detalhe(self, pai, rotulo, linha):
        ttk.Label(pai, text=rotulo, style="Header.TLabel").grid(
            row=linha, column=0, sticky=tk.W, pady=(0, 2)
        )
        campo = ttk.Entry(pai, state="readonly", width=32)
        campo.grid(row=linha, column=1, sticky="ew", pady=(0, 10))
        pai.columnconfigure(1, weight=1)
        return campo

    def _montar_status(self):
        self.status_label = ttk.Label(self, text="", style="Status.TLabel")
        self.status_label.grid(row=3, column=0, sticky=tk.W, pady=(8, 0))

    def _definir_campo_readonly(self, entry, valor):
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, valor)
        entry.config(state="readonly")

    def _mostrar_status(self, mensagem):
        self.status_label.config(text=mensagem)
        self.after(2500, lambda: self.status_label.config(text=""))

    def _configurar_timeout(self):
        self._reiniciar_timer_bloqueio()

    def _reiniciar_timer_bloqueio(self):
        if self._timer_bloqueio is not None:
            self.after_cancel(self._timer_bloqueio)
        self._timer_bloqueio = self.after(TIMEOUT_BLOQUEIO_MS, self._bloqueio_automatico)

    def _registrar_atividade(self):
        eventos = ("<KeyPress>", "<ButtonPress>", "<Motion>")

        def registrar(widget):
            for evento in eventos:
                widget.bind(evento, self._ao_atividade, add="+")
            for filho in widget.winfo_children():
                registrar(filho)

        registrar(self)

    def _ao_atividade(self, _event=None):
        if not self.winfo_exists():
            return
        self._reiniciar_timer_bloqueio()

    def _bloqueio_automatico(self):
        self.bloquear_cofre()

    def bloquear_cofre(self):
        self.cipher = None
        self.credencial_selecionada = None
        if self._timer_bloqueio is not None:
            self.after_cancel(self._timer_bloqueio)
            self._timer_bloqueio = None
        self.on_bloquear()

    def _ordenar_por(self, coluna):
        if self.ordenar_por == coluna:
            self.ordem = "DESC" if self.ordem == "ASC" else "ASC"
        else:
            self.ordenar_por = coluna
            self.ordem = "ASC"
        self.atualizar_lista()

    def gerar_senha(self):
        senha = secrets.token_urlsafe(12)
        self.entry_senha.delete(0, tk.END)
        self.entry_senha.insert(0, senha)

    def _limpar_formulario(self):
        self.entry_site.delete(0, tk.END)
        self.entry_usuario.delete(0, tk.END)
        self.entry_senha.delete(0, tk.END)

    def salvar(self):
        site = self.entry_site.get().strip()
        usuario = self.entry_usuario.get().strip()
        senha = self.entry_senha.get()

        if not site or not usuario or not senha:
            messagebox.showerror("Erro", "Preencha site, usuário e senha")
            return

        senha_cripto = self.cipher.encrypt(senha.encode())
        self.db.inserir_credencial(site, usuario, senha_cripto)
        self._limpar_formulario()
        self.atualizar_lista()
        self._mostrar_status("Credencial salva com sucesso")

    def atualizar(self):
        if not self.credencial_selecionada:
            messagebox.showerror("Erro", "Selecione uma credencial na lista")
            return

        site = self.entry_site.get().strip()
        usuario = self.entry_usuario.get().strip()
        senha = self.entry_senha.get()

        if not site or not usuario or not senha:
            messagebox.showerror("Erro", "Preencha site, usuário e senha")
            return

        senha_cripto = self.cipher.encrypt(senha.encode())
        self.db.atualizar_credencial(
            self.credencial_selecionada["id"],
            site,
            usuario,
            senha_cripto,
        )
        self._limpar_formulario()
        self.atualizar_lista()
        self._mostrar_status("Credencial atualizada com sucesso")

    def atualizar_lista(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        credenciais = self.db.listar_credenciais(
            ordenar_por=self.ordenar_por,
            ordem=self.ordem,
        )

        for cred_id, site, usuario in credenciais:
            self.tree.insert("", tk.END, iid=str(cred_id), values=(cred_id, site, usuario))

        self.credencial_selecionada = None
        self._limpar_detalhes()

    def _limpar_detalhes(self):
        for campo in (self.label_site, self.label_usuario, self.label_senha):
            self._definir_campo_readonly(campo, "")

    def _ao_selecionar(self, _event=None):
        selecao = self.tree.selection()
        if not selecao:
            return

        cred_id = int(selecao[0])
        resultado = self.db.obter_credencial(cred_id)
        if resultado is None:
            return

        site, usuario, senha_cripto = resultado
        senha = self.cipher.decrypt(senha_cripto).decode()

        self.credencial_selecionada = {
            "id": cred_id,
            "site": site,
            "usuario": usuario,
            "senha": senha,
        }

        self._definir_campo_readonly(self.label_site, site)
        self._definir_campo_readonly(self.label_usuario, usuario)
        self._definir_campo_readonly(self.label_senha, senha)

        self.entry_site.delete(0, tk.END)
        self.entry_site.insert(0, site)
        self.entry_usuario.delete(0, tk.END)
        self.entry_usuario.insert(0, usuario)
        self.entry_senha.delete(0, tk.END)
        self.entry_senha.insert(0, senha)

    def copiar_usuario(self):
        if not self.credencial_selecionada:
            self._mostrar_status("Selecione uma credencial na lista")
            return
        janela = self.winfo_toplevel()
        janela.clipboard_clear()
        janela.clipboard_append(self.credencial_selecionada["usuario"])
        self._mostrar_status("Usuário copiado para a área de transferência")

    def copiar_senha(self):
        if not self.credencial_selecionada:
            self._mostrar_status("Selecione uma credencial na lista")
            return
        janela = self.winfo_toplevel()
        janela.clipboard_clear()
        janela.clipboard_append(self.credencial_selecionada["senha"])
        self._mostrar_status("Senha copiada para a área de transferência")

    def excluir_credencial(self):
        if not self.credencial_selecionada:
            messagebox.showerror("Erro", "Selecione uma credencial na lista")
            return

        if not messagebox.askyesno(
            "Confirmar exclusão",
            "Tem certeza que deseja excluir esta credencial?",
        ):
            return

        self.db.excluir_credencial(self.credencial_selecionada["id"])
        self._limpar_formulario()
        self.atualizar_lista()
        self._mostrar_status("Credencial excluída com sucesso")

    def exportar_csv(self):
        dialogo = DialogoSenhaMestra(
            self.winfo_toplevel(),
            self.db,
            titulo="Exportar credenciais",
            mensagem=(
                "A exportação gera um arquivo com senhas em texto puro. "
                "Digite a senha mestra para autorizar esta ação:"
            ),
        )
        if not dialogo.confirmado:
            return

        caminho = filedialog.asksaveasfilename(
            title="Exportar credenciais",
            defaultextension=".csv",
            filetypes=[("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")],
        )
        if not caminho:
            return

        credenciais = self.db.listar_todas_credenciais()
        if not credenciais:
            messagebox.showwarning("Exportação", "Nenhuma credencial para exportar.")
            return

        try:
            exportadas = self._gerar_csv_exportacao(caminho, credenciais)
        except OSError as erro:
            messagebox.showerror("Erro", f"Não foi possível exportar o arquivo:\n{erro}")
            return

        self._mostrar_status(f"{exportadas} credencial(is) exportada(s) com sucesso")

    def _gerar_csv_exportacao(
        self,
        caminho: str,
        credenciais: list[tuple[int, str, str, bytes]],
    ) -> int:
        with open(caminho, "w", newline="", encoding="utf-8-sig") as arquivo:
            campos = ("name", "url", "username", "password")
            escritor = csv.DictWriter(arquivo, fieldnames=campos)
            escritor.writeheader()

            for _cred_id, site, usuario, senha_cripto in credenciais:
                senha = self.cipher.decrypt(senha_cripto).decode()
                escritor.writerow(
                    {
                        "name": site,
                        "url": site,
                        "username": usuario,
                        "password": senha,
                    }
                )

        return len(credenciais)

    def importar_csv(self):
        caminho = filedialog.askopenfilename(
            title="Importar credenciais",
            filetypes=[("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")],
        )
        if not caminho:
            return

        try:
            importadas = self._processar_csv(caminho)
        except (OSError, csv.Error, UnicodeDecodeError) as erro:
            messagebox.showerror("Erro", f"Não foi possível importar o arquivo:\n{erro}")
            return

        if importadas == 0:
            messagebox.showwarning(
                "Importação",
                "Nenhuma credencial válida encontrada no arquivo.",
            )
            return

        self.atualizar_lista()
        self._mostrar_status(f"{importadas} credencial(is) importada(s) com sucesso")

    def _processar_csv(self, caminho: str) -> int:
        importadas = 0

        with open(caminho, newline="", encoding="utf-8-sig") as arquivo:
            leitor = csv.DictReader(arquivo)
            if not leitor.fieldnames:
                return 0

            mapa = {nome.lower().strip(): nome for nome in leitor.fieldnames}

            for linha in leitor:
                site = self._valor_csv(linha, mapa, ("url", "website", "site", "origin"))
                usuario = self._valor_csv(
                    linha, mapa, ("username", "login", "user", "usuario")
                )
                senha = self._valor_csv(linha, mapa, ("password", "senha", "pass"))

                if not site:
                    site = self._valor_csv(linha, mapa, ("name", "title"))

                if not site or not usuario or not senha:
                    continue

                senha_cripto = self.cipher.encrypt(senha.encode())
                self.db.inserir_credencial(site.strip(), usuario.strip(), senha_cripto)
                importadas += 1

        return importadas

    @staticmethod
    def _valor_csv(linha: dict, mapa: dict, chaves: tuple[str, ...]) -> str:
        for chave in chaves:
            coluna = mapa.get(chave)
            if coluna and linha.get(coluna):
                return str(linha[coluna]).strip()
        return ""
