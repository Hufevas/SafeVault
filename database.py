import sqlite3

from crypto_utils import LEGACY_SALT

DB_PATH = "safevault.db"
COLUNAS_ORDENACAO = {"id", "site", "usuario"}


class Database:
    def __init__(self, path: str = DB_PATH):
        self.conn = sqlite3.connect(path)
        self._inicializar_schema()

    def _inicializar_schema(self):
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credenciais (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT,
                usuario TEXT,
                senha TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                verificacao BLOB,
                salt BLOB
            )
        """)

        colunas = {
            linha[1] for linha in cursor.execute("PRAGMA table_info(config)").fetchall()
        }
        if "salt" not in colunas:
            cursor.execute("ALTER TABLE config ADD COLUMN salt BLOB")

        self.conn.commit()

    def cofre_configurado(self) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM config WHERE id = 1")
        return cursor.fetchone()[0] > 0

    def obter_salt(self) -> bytes | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT salt FROM config WHERE id = 1")
        resultado = cursor.fetchone()
        if resultado is None:
            return None
        salt = resultado[0]
        if salt is None:
            return LEGACY_SALT
        return salt

    def obter_verificacao(self) -> bytes | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT verificacao FROM config WHERE id = 1")
        resultado = cursor.fetchone()
        if resultado is None:
            return None
        return resultado[0]

    def inicializar_cofre(self, verificacao: bytes, salt: bytes) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO config (id, verificacao, salt) VALUES (1, ?, ?)",
            (verificacao, salt),
        )
        self.conn.commit()

    def inserir_credencial(self, site: str, usuario: str, senha_cripto: bytes) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO credenciais (site, usuario, senha) VALUES (?, ?, ?)",
            (site, usuario, senha_cripto),
        )
        self.conn.commit()
        return cursor.lastrowid

    def listar_todas_credenciais(self) -> list[tuple[int, str, str, bytes]]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, site, usuario, senha FROM credenciais ORDER BY id"
        )
        return cursor.fetchall()

    def listar_credenciais(
        self,
        ordenar_por: str = "id",
        ordem: str = "ASC",
    ) -> list[tuple[int, str, str]]:
        if ordenar_por not in COLUNAS_ORDENACAO:
            ordenar_por = "id"
        ordem = "DESC" if ordem.upper() == "DESC" else "ASC"

        query = f"SELECT id, site, usuario FROM credenciais ORDER BY {ordenar_por} {ordem}"

        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()

    def obter_credencial(self, cred_id: int) -> tuple[str, str, bytes] | None:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT site, usuario, senha FROM credenciais WHERE id = ?",
            (cred_id,),
        )
        return cursor.fetchone()

    def atualizar_credencial(
        self,
        cred_id: int,
        site: str,
        usuario: str,
        senha_cripto: bytes,
    ) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE credenciais SET site = ?, usuario = ?, senha = ? WHERE id = ?",
            (site, usuario, senha_cripto, cred_id),
        )
        self.conn.commit()

    def excluir_credencial(self, cred_id: int) -> None:
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM credenciais WHERE id = ?", (cred_id,))
        self.conn.commit()

    def fechar(self) -> None:
        self.conn.close()
