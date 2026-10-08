#!/usr/bin/env python3
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
DB = DATA / "store.json"
LOCK = threading.Lock()

DEFAULT = {"credentials": [], "scripts": []}


def normalize_private_key(value):
    key = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if "\\n" in key and "\n" not in key:
        key = key.replace("\\n", "\n")
    return key + "\n" if key else ""


def validate_private_key(value):
    key = normalize_private_key(value)
    if not key:
        return "La clave privada está vacía"
    if (
        "BEGIN OPENSSH PRIVATE KEY" not in key
        and "BEGIN RSA PRIVATE KEY" not in key
        and "BEGIN EC PRIVATE KEY" not in key
    ):
        return "Pega una clave privada completa, incluyendo BEGIN y END PRIVATE KEY"
    if (
        "END OPENSSH PRIVATE KEY" not in key
        and "END RSA PRIVATE KEY" not in key
        and "END EC PRIVATE KEY" not in key
    ):
        return "La clave privada está incompleta: falta la línea END"
    return None


def load_db():
    with LOCK:
        if not DB.exists():
            save_db(DEFAULT)
        try:
            return json.loads(DB.read_text())
        except (OSError, json.JSONDecodeError):
            return DEFAULT.copy()


def save_db(db):
    tmp = DB.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(DB)


def public_credential(item):
    return {
        k: item.get(k, "")
        for k in ("id", "name", "host", "port", "username", "key_path")
    }


def public_script(item):
    return {
        k: item.get(k, "")
        for k in (
            "id",
            "name",
            "description",
            "content",
            "updated_at",
            "api_enabled",
            "api_token",
            "credential_id",
        )
    }


def validate_id(value):
    return bool(value and re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", value))


def is_enabled(value):
    return value in (True, 1, "1", "on", "true")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 2_000_000:
            raise ValueError("Payload demasiado grande")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/state":
            db = load_db()
            return self.send_json(
                {
                    "credentials": [public_credential(x) for x in db["credentials"]],
                    "scripts": [public_script(x) for x in db["scripts"]],
                }
            )
        if path == "/" or path == "/index.html":
            return self.serve_file(ROOT / "static" / "index.html", "text/html; charset=utf-8")
        if path == "/app.css":
            return self.serve_file(ROOT / "static" / "app.css", "text/css; charset=utf-8")
        if path == "/app.js":
            return self.serve_file(ROOT / "static" / "app.js", "text/javascript; charset=utf-8")
        if path == "/favicon.svg":
            return self.serve_file(ROOT / "static" / "favicon.svg", "image/svg+xml")
        self.send_json({"error": "No encontrado"}, 404)

    def serve_file(self, path, content_type):
        try:
            raw = path.read_bytes()
        except OSError:
            return self.send_json({"error": "Archivo no encontrado"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_json()
            if path == "/api/credentials":
                return self.create_credential(body)
            if path == "/api/scripts":
                return self.create_script(body)
            if path == "/api/run":
                return self.run_script(body)
            parts = path.split("/")
            if len(parts) == 4 and parts[1:3] == ["api", "trigger"] and parts[3]:
                return self.trigger_script(parts[3])
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": str(exc) or "JSON inválido"}, 400)
        except Exception as exc:
            return self.send_json({"error": f"Error interno: {exc}"}, 500)
        self.send_json({"error": "No encontrado"}, 404)

    def do_PUT(self):
        path = urlparse(self.path).path
        parts = path.split("/")
        if len(parts) != 4 or parts[1] != "api" or parts[3] == "":
            return self.send_json({"error": "Ruta inválida"}, 400)
        kind, item_id = parts[2], parts[3]
        if kind not in ("credentials", "scripts") or not validate_id(item_id):
            return self.send_json({"error": "Recurso inválido"}, 400)
        try:
            body = self.read_json()
            if kind == "credentials":
                return self.update_credential(item_id, body)
            return self.update_script(item_id, body)
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": str(exc) or "JSON inválido"}, 400)

    def do_DELETE(self):
        path = urlparse(self.path).path
        parts = path.split("/")
        if len(parts) != 4 or parts[1] != "api" or parts[3] == "":
            return self.send_json({"error": "Ruta inválida"}, 400)
        kind, item_id = parts[2], parts[3]
        if kind not in ("credentials", "scripts") or not validate_id(item_id):
            return self.send_json({"error": "Recurso inválido"}, 400)
        db = load_db()
        before = len(db[kind])
        db[kind] = [x for x in db[kind] if x["id"] != item_id]
        if len(db[kind]) == before:
            return self.send_json({"error": "No encontrado"}, 404)
        save_db(db)
        self.send_json({"ok": True})

    def create_credential(self, body):
        required = ("name", "host", "username")
        if any(not str(body.get(k, "")).strip() for k in required):
            return self.send_json({"error": "Completa nombre, host y usuario"}, 400)
        key_path = str(body.get("key_path", "")).strip()
        private_key = normalize_private_key(body.get("private_key", ""))
        if not key_path and not private_key:
            return self.send_json(
                {"error": "Indica una ruta o pega el contenido de la clave privada"},
                400,
            )
        if key_path and private_key:
            return self.send_json(
                {"error": "Usa una ruta o pega la clave privada, no ambas"}, 400
            )
        if private_key:
            key_error = validate_private_key(private_key)
            if key_error:
                return self.send_json({"error": key_error}, 400)
        db = load_db()
        item = {
            "id": uuid.uuid4().hex[:10],
            "name": str(body["name"]).strip(),
            "host": str(body["host"]).strip(),
            "port": int(body.get("port") or 22),
            "username": str(body["username"]).strip(),
            "key_path": os.path.expanduser(key_path),
            "private_key": private_key,
        }
        if not 1 <= item["port"] <= 65535:
            return self.send_json(
                {"error": "El puerto debe estar entre 1 y 65535"}, 400
            )
        db["credentials"].append(item)
        save_db(db)
        self.send_json(public_credential(item), 201)

    def update_credential(self, item_id, body):
        db = load_db()
        item = next((x for x in db["credentials"] if x["id"] == item_id), None)
        if not item:
            return self.send_json({"error": "Conexión no encontrada"}, 404)
        for field in ("name", "host", "username"):
            if not str(body.get(field, "")).strip():
                return self.send_json({"error": "Completa nombre, host y usuario"}, 400)
        key_path = str(body.get("key_path", "")).strip()
        private_key = normalize_private_key(body.get("private_key", ""))
        if key_path and private_key:
            return self.send_json(
                {"error": "Usa una ruta o pega la clave privada, no ambas"}, 400
            )
        item.update(
            {
                "name": str(body["name"]).strip(),
                "host": str(body["host"]).strip(),
                "port": int(body.get("port") or 22),
                "username": str(body["username"]).strip(),
            }
        )
        if not 1 <= item["port"] <= 65535:
            return self.send_json(
                {"error": "El puerto debe estar entre 1 y 65535"}, 400
            )
        if key_path:
            item["key_path"], item["private_key"] = os.path.expanduser(key_path), ""
        elif private_key:
            key_error = validate_private_key(private_key)
            if key_error:
                return self.send_json({"error": key_error}, 400)
            item["key_path"], item["private_key"] = "", private_key
        save_db(db)
        self.send_json(public_credential(item))

    def create_script(self, body):
        name, content = str(body.get("name", "")).strip(), str(body.get("content", ""))
        if not name or not content.strip():
            return self.send_json(
                {"error": "El script necesita nombre y contenido"}, 400
            )
        db = load_db()
        api_enabled = is_enabled(body.get("api_enabled"))
        credential_id = str(body.get("credential_id", "")).strip()
        if api_enabled and not any(x["id"] == credential_id for x in db["credentials"]):
            return self.send_json(
                {"error": "Selecciona una conexión SSH para activar la API"}, 400
            )
        item = {
            "id": uuid.uuid4().hex[:10],
            "name": name[:120],
            "description": str(body.get("description", "")).strip()[:240],
            "content": content,
            "api_enabled": api_enabled,
            "api_token": secrets.token_urlsafe(24) if api_enabled else "",
            "credential_id": credential_id if api_enabled else "",
            "updated_at": __import__("datetime")
            .datetime.now()
            .isoformat(timespec="minutes"),
        }
        db["scripts"].append(item)
        save_db(db)
        self.send_json(public_script(item), 201)

    def update_script(self, item_id, body):
        db = load_db()
        item = next((x for x in db["scripts"] if x["id"] == item_id), None)
        if not item:
            return self.send_json({"error": "Script no encontrado"}, 404)
        name, content = str(body.get("name", "")).strip(), str(body.get("content", ""))
        if not name or not content.strip():
            return self.send_json(
                {"error": "El script necesita nombre y contenido"}, 400
            )
        api_enabled = is_enabled(body.get("api_enabled"))
        credential_id = str(body.get("credential_id", "")).strip()
        if api_enabled and not any(x["id"] == credential_id for x in db["credentials"]):
            return self.send_json(
                {"error": "Selecciona una conexión SSH para activar la API"}, 400
            )
        item.update(
            {
                "name": name[:120],
                "description": str(body.get("description", "")).strip()[:240],
                "content": content,
                "api_enabled": api_enabled,
                "api_token": (item.get("api_token") or secrets.token_urlsafe(24))
                if api_enabled
                else "",
                "credential_id": credential_id if api_enabled else "",
                "updated_at": __import__("datetime")
                .datetime.now()
                .isoformat(timespec="minutes"),
            }
        )
        save_db(db)
        self.send_json(public_script(item))

    def trigger_script(self, token):
        db = load_db()
        script = next(
            (
                x
                for x in db["scripts"]
                if x.get("api_enabled")
                and secrets.compare_digest(x.get("api_token", ""), token)
            ),
            None,
        )
        if not script:
            return self.send_json({"error": "Endpoint no encontrado"}, 404)
        if not script.get("credential_id"):
            return self.send_json(
                {"error": "El script no tiene una conexión SSH configurada"}, 400
            )
        return self.run_script(
            {"script_id": script["id"], "credential_id": script["credential_id"]}
        )

    def run_script(self, body):
        db = load_db()
        credential = next(
            (x for x in db["credentials"] if x["id"] == body.get("credential_id")), None
        )
        script = next(
            (x for x in db["scripts"] if x["id"] == body.get("script_id")), None
        )
        if not credential or not script:
            return self.send_json(
                {"error": "Selecciona un script y una conexión válidos"}, 400
            )
        temporary_key = None
        if credential.get("private_key"):
            temporary_key = tempfile.NamedTemporaryFile(
                mode="w", prefix="sshrunner-key-", delete=False
            )
            temporary_key.write(credential["private_key"])
            temporary_key.close()
            os.chmod(temporary_key.name, 0o600)
            key = Path(temporary_key.name)
        else:
            key = Path(credential.get("key_path", "")).expanduser()
            if not key.is_file():
                return self.send_json(
                    {"error": f"No existe la clave privada: {key}"}, 400
                )
        remote = f"/tmp/sshrunner-{secrets.token_hex(8)}.sh"
        target = f"{credential['username']}@{credential['host']}"
        base = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-i",
            str(key),
            "-p",
            str(credential["port"]),
            target,
        ]
        try:
            copy = subprocess.run(
                base + [f"cat > {remote} && chmod 700 {remote}"],
                input=script["content"].encode(),
                capture_output=True,
                timeout=25,
            )
            if copy.returncode:
                error = copy.stderr.decode(errors="replace")
                if "error in libcrypto" in error:
                    error = "OpenSSH no puede leer la clave privada. Pégala completa y sin cambiar sus saltos de línea; no pegues la clave pública."
                return self.send_json(
                    {"error": error or "No se pudo copiar el script"}, 502
                )
            result = subprocess.run(
                base + [f"bash {remote}; code=$?; rm -f {remote}; exit $code"],
                capture_output=True,
                timeout=120,
            )
            self.send_json(
                {
                    "ok": result.returncode == 0,
                    "exit_code": result.returncode,
                    "stdout": result.stdout.decode(errors="replace"),
                    "stderr": result.stderr.decode(errors="replace"),
                }
            )
        except subprocess.TimeoutExpired:
            self.send_json(
                {"error": "La conexión o ejecución superó el tiempo límite"}, 504
            )
        finally:
            if temporary_key:
                try:
                    os.unlink(temporary_key.name)
                except OSError:
                    pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SSH Runner local web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    print(f"SSH Runner disponible en http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
