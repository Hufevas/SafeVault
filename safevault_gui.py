import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import sqlite3
import secrets
import os

# ===== CRIPTO =====
KEY_FILE = "chave.key"

def carregar_ou_criar_chave():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        key = Fernet.generate_key()
        open(KEY_FILE, "wb").write(key)
        return key

cipher = Fernet(carregar_ou_criar_chave())

# ===== BANCO =====
conn = sqlite3.connect("safevault.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS credenciais (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT,
    usuario TEXT,
    senha TEXT
)
""")

# ===== FUNÇÕES =====

def gerar_senha():
    senha = secrets.token_urlsafe(12)
    entry_senha.delete(0, tk.END)
    entry_senha.insert(0, senha)

def salvar():
    site = entry_site.get()
    usuario = entry_user.get()
    senha = entry_senha.get()

    senha_cripto = cipher.encrypt(senha.encode())

    cursor.execute(
        "INSERT INTO credenciais (site, usuario, senha) VALUES (?, ?, ?)",
        (site, usuario, senha_cripto)
    )
    conn.commit()

    messagebox.showinfo("Sucesso", "Senha salva!")

def listar():
    cursor.execute("SELECT id, site, usuario, senha FROM credenciais")
    dados = cursor.fetchall()

    texto = ""
    for id_, site, user, senha in dados:
        texto += f"[{id_}] {site} | {user} | {cipher.decrypt(senha).decode()}\n"

    messagebox.showinfo("Senhas", texto if texto else "Nenhuma senha")

    def remover():
    id_remover = entry_id.get()

    if not id_remover:
        messagebox.showerror("Erro", "Digite um ID válido")
        return

    cursor.execute("DELETE FROM credenciais WHERE id = ?", (id_remover,))
    conn.commit()

    messagebox.showinfo("Sucesso", "Senha removida com sucesso!")

# ===== INTERFACE =====

janela = tk.Tk()
janela.title("SafeVault")

tk.Label(janela, text="Site").pack()
entry_site = tk.Entry(janela)
entry_site.pack()

tk.Label(janela, text="Usuário").pack()
entry_user = tk.Entry(janela)
entry_user.pack()

tk.Label(janela, text="Senha").pack()
entry_senha = tk.Entry(janela)
entry_senha.pack()

tk.Label(janela, text="ID para remover").pack()
entry_id = tk.Entry(janela)
entry_id.pack()

tk.Button(janela, text="Gerar senha", command=gerar_senha).pack()
tk.Button(janela, text="Salvar", command=salvar).pack()
tk.Button(janela, text="Listar senhas", command=listar).pack()
tk.Button(janela, text="Remover senha", command=remover).pack()

janela.mainloop()