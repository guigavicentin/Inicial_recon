#!/usr/bin/env python3
"""
cve_base.py - Biblioteca base compartilhada para nginx_cve.py e apache_cve.py
Funções: curl, interactsh, logging, output consolidado
"""

import subprocess
import threading
import re
import json
import time
import shutil
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# CONFIGURAÇÕES GLOBAIS
# ──────────────────────────────────────────────
CURL_TIMEOUT         = 8    # segundos por requisição curl
INTERACTSH_WAIT      = 12   # segundos aguardando callback OOB
INTERACTSH_POLL      = 1    # intervalo de polling (segundos)
OUTPUT_FILE          = "cve_results.txt"   # arquivo consolidado de saída

# ──────────────────────────────────────────────
# CORES / LOG
# ──────────────────────────────────────────────
_log_lock = threading.Lock()

RESET  = "\033[0m"
RED    = "\033[1;31m"
GREEN  = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE   = "\033[1;34m"
CYAN   = "\033[1;36m"
BOLD   = "\033[1m"


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, level="INFO"):
    colors = {
        "INFO":  BLUE,
        "OK":    GREEN,
        "WARN":  YELLOW,
        "ERR":   RED,
        "VULN":  f"{RED}{BOLD}",
        "SAFE":  GREEN,
        "OOB":   CYAN,
    }
    c = colors.get(level, "")
    with _log_lock:
        print(f"{c}[{level}] {_ts()} {msg}{RESET}")


def log_vuln(cve, target, detail=""):
    with _log_lock:
        print(f"\n{RED}{BOLD}{'═'*60}")
        print(f"  !! VULNERÁVEL !! {cve}")
        print(f"  Alvo   : {target}")
        if detail:
            print(f"  Detalhe: {detail}")
        print(f"{'═'*60}{RESET}\n")


# ──────────────────────────────────────────────
# CURL
# ──────────────────────────────────────────────

def curl(
    url,
    method="GET",
    headers=None,
    data=None,
    path_as_is=False,
    insecure=True,
    timeout=None,
    extra_flags="",
):
    """
    Executa curl e retorna (status_code, headers_str, body_str, raw_cmd).
    """
    timeout = timeout or CURL_TIMEOUT
    headers = headers or {}

    parts = ["curl", "-sv", "--max-time", str(timeout)]
    if insecure:
        parts.append("-k")
    if path_as_is:
        parts.append("--path-as-is")
    if method != "GET":
        parts += ["-X", method]
    for k, v in headers.items():
        parts += ["-H", f"{k}: {v}"]
    if data:
        parts += ["--data-binary", data]
    if extra_flags:
        parts += extra_flags.split()
    parts.append(url)

    raw_cmd = " ".join(
        f'"{p}"' if " " in p else p for p in parts
    )
    log(f"$ {raw_cmd}")

    try:
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        # curl -sv: headers vão para stderr, body para stdout
        headers_raw = result.stderr
        body        = result.stdout

        # Extrai status code
        status = 0
        m = re.search(r"< HTTP/[\d.]+ (\d+)", headers_raw)
        if m:
            status = int(m.group(1))

        return status, headers_raw, body, raw_cmd

    except subprocess.TimeoutExpired:
        log(f"Timeout curl: {url}", "WARN")
        return 0, "", "", raw_cmd
    except Exception as e:
        log(f"Erro curl: {e}", "ERR")
        return 0, "", "", raw_cmd


def curl_header_value(headers_raw, header_name):
    """Extrai valor de um header da saída stderr do curl -sv."""
    m = re.search(
        rf"< {re.escape(header_name)}:\s*(.+)",
        headers_raw,
        re.IGNORECASE,
    )
    return m.group(1).strip() if m else ""


# ──────────────────────────────────────────────
# INTERACTSH
# ──────────────────────────────────────────────

class InteractshSession:
    """
    Gerencia uma sessão do interactsh-client.
    Captura callbacks OOB com timestamp preciso.
    """

    def __init__(self):
        self.domain   = None
        self.proc     = None
        self._hits    = []          # lista de dicts {ts, data}
        self._lock    = threading.Lock()
        self._reader  = None
        self._running = False

    def start(self):
        if not shutil.which("interactsh-client"):
            log("interactsh-client não encontrado — CVEs OOB serão puladas", "WARN")
            return False

        log("Iniciando interactsh-client...", "OOB")
        try:
            self.proc = subprocess.Popen(
                ["interactsh-client", "-json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Aguarda domínio aparecer no stderr
            deadline = time.time() + 15
            while time.time() < deadline:
                line = self.proc.stderr.readline()
                m = re.search(r"([a-z0-9]+\.oast\.\S+)", line)
                if m:
                    self.domain = m.group(1).strip()
                    log(f"Domínio interactsh: {self.domain}", "OOB")
                    break
                time.sleep(0.2)

            if not self.domain:
                log("Não foi possível obter domínio interactsh", "ERR")
                self.stop()
                return False

            # Thread leitora de callbacks
            self._running = True
            self._reader  = threading.Thread(
                target=self._read_hits, daemon=True
            )
            self._reader.start()
            return True

        except Exception as e:
            log(f"Erro ao iniciar interactsh: {e}", "ERR")
            return False

    def _read_hits(self):
        """Lê stdout do interactsh-client (JSON por linha)."""
        while self._running and self.proc:
            try:
                line = self.proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                received_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    data = {"raw": line}
                hit = {"ts": received_at, "data": data}
                with self._lock:
                    self._hits.append(hit)
                log(
                    f"[OOB HIT] {received_at} — "
                    f"proto={data.get('protocol','?')} "
                    f"from={data.get('remote-address','?')}",
                    "OOB",
                )
            except Exception:
                break

    def wait_for_hit(self, since_ts, timeout=None):
        """
        Aguarda um callback OOB após since_ts (float = time.time()).
        Retorna o hit dict ou None se timeout.
        """
        timeout  = timeout or INTERACTSH_WAIT
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                for hit in reversed(self._hits):
                    # Converte ts do hit para comparar
                    try:
                        hit_time = datetime.strptime(
                            hit["ts"], "%Y-%m-%d %H:%M:%S.%f"
                        ).timestamp()
                    except Exception:
                        continue
                    if hit_time >= since_ts:
                        return hit
            time.sleep(INTERACTSH_POLL)
        return None

    def stop(self):
        self._running = False
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                pass


# ──────────────────────────────────────────────
# RESULTADO / OUTPUT CONSOLIDADO
# ──────────────────────────────────────────────

class ResultCollector:
    """
    Coleta resultados de todos os CVEs e salva no arquivo consolidado.
    """

    def __init__(self, output_file=None):
        self.output_file = output_file or OUTPUT_FILE
        self._results    = []
        self._lock       = threading.Lock()

    def add(
        self,
        target,
        cve,
        status,            # "VULNERABLE" | "NOT_VULNERABLE" | "ERROR" | "SKIPPED"
        detail="",
        curl_repro="",     # curl para reprodução manual
        oob_hit=None,      # dict do hit interactsh se aplicável
    ):
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rec = {
            "ts":         ts,
            "target":     target,
            "cve":        cve,
            "status":     status,
            "detail":     detail,
            "curl_repro": curl_repro,
            "oob_hit":    oob_hit,
        }
        with self._lock:
            self._results.append(rec)

        # Log imediato
        if status == "VULNERABLE":
            log_vuln(cve, target, detail)
        elif status == "NOT_VULNERABLE":
            log(f"{cve} → {target} — não vulnerável", "SAFE")
        elif status == "ERROR":
            log(f"{cve} → {target} — erro: {detail}", "ERR")
        elif status == "SKIPPED":
            log(f"{cve} → {target} — pulado: {detail}", "WARN")

    def save(self):
        """Salva arquivo consolidado de resultados."""
        path = Path(self.output_file)
        lines = []
        lines.append("=" * 70)
        lines.append(f"  CVE SCAN RESULTS — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)
        lines.append("")

        # Agrupa por status
        vulns  = [r for r in self._results if r["status"] == "VULNERABLE"]
        others = [r for r in self._results if r["status"] != "VULNERABLE"]

        if vulns:
            lines.append("── VULNERÁVEIS ──────────────────────────────────────────────")
            for r in vulns:
                lines.append(f"\n[{r['ts']}] {r['cve']} — {r['target']}")
                if r["detail"]:
                    lines.append(f"  Detalhe : {r['detail']}")
                if r["oob_hit"]:
                    hit = r["oob_hit"]
                    lines.append(f"  OOB Hit : {hit['ts']}")
                    proto = hit["data"].get("protocol", "?")
                    src   = hit["data"].get("remote-address", "?")
                    lines.append(f"  Proto   : {proto}  |  From: {src}")
                if r["curl_repro"]:
                    lines.append(f"  Reproduzir manualmente:")
                    lines.append(f"    {r['curl_repro']}")
            lines.append("")

        lines.append("── DEMAIS RESULTADOS ────────────────────────────────────────")
        for r in others:
            symbol = {"NOT_VULNERABLE": "[-]", "ERROR": "[!]", "SKIPPED": "[~]"}.get(
                r["status"], "[?]"
            )
            lines.append(f"{symbol} [{r['ts']}] {r['cve']} — {r['target']} — {r['detail'] or r['status']}")

        lines.append("")
        lines.append("=" * 70)
        lines.append(f"  Total: {len(self._results)}  |  Vulneráveis: {len(vulns)}")
        lines.append("=" * 70)

        with self._lock:
            # Append ao arquivo (múltiplos hosts no mesmo arquivo)
            with open(path, "a") as f:
                f.write("\n".join(lines) + "\n\n")

        log(f"Resultados salvos em: {path}  ({len(vulns)} vulnerável(is) de {len(self._results)} testes)", "OK")
        return str(path)

    def summary(self):
        vulns = [r for r in self._results if r["status"] == "VULNERABLE"]
        return {
            "total":      len(self._results),
            "vulnerable": len(vulns),
            "vulns":      vulns,
        }
