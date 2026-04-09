from cryptography.fernet import Fernet
import sqlite3
import secrets
import os

# =========================
# CONFIGURAÇÃO DA CHAVE
# =========================

KEY_FILE = "chave.key"

def carregar_ou_criar_chave():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

key = carregar_ou_criar_chave()
cipher = Fernet(key)

# =========================
# BANCO DE DADOS 
# =========================

conn = sqlite3.connect("safevault.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS credenciais (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    usuario TEXT NOT NULL,
    senha TEXT NOT NULL
)
""")
conn.commit()

# =========================
# FUNÇÕES
# =========================

def gerar_senha():
    return secrets.token_urlsafe(12)

def salvar_senha():
    site = input("Site: ")
    usuario = input("Usuário: ")
    senha = input("Senha (ou deixe vazio para gerar): ")

    if senha == "":
        senha = gerar_senha()
        print(f"Senha gerada: {senha}")

    senha_cripto = cipher.encrypt(senha.encode())

    cursor.execute(
        "INSERT INTO credenciais (site, usuario, senha) VALUES (?, ?, ?)",
        (site, usuario, senha_cripto)
    )
    conn.commit()
    print("✅ Senha salva com sucesso!\n")

def listar_senhas():
    cursor.execute("SELECT site, usuario, senha FROM credenciais")
    dados = cursor.fetchall()

    if not dados:
        print("⚠️ Nenhuma senha cadastrada.\n")
        return

    print("\n📂 Senhas armazenadas:")
    for site, usuario, senha in dados:
        senha_real = cipher.decrypt(senha).decode()
        print(f"🌐 {site} | 👤 {usuario} | 🔑 {senha_real}")
    print()

# =========================
# MENU
# =========================

def menu():
    while True:
        print("===== 🔐 SafeVault =====")
        print("1. Salvar nova senha")
        print("2. Listar senhas")
        print("3. Gerar senha segura")
        print("4. Sair")

        opcao = input("Escolha: ")

        if opcao == "1":
            salvar_senha()
        elif opcao == "2":
            listar_senhas()
        elif opcao == "3":
            print("Senha gerada:", gerar_senha(), "\n")
        elif opcao == "4":
            print("Saindo...")
            break
        else:
            print("Opção inválida!\n")

# =========================
# EXECUÇÃO
# =========================

if __name__ == "__main__":
    menu()