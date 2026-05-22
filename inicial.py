#!/usr/bin/env python3
"""
recon.py - Reconhecimento automatizado de subdomínios
Ferramentas: chaos, github-subdomains, subfinder, assetfinder, nmap, httpx, shortscan
"""

import subprocess
import os
import sys
import re
import json
import shutil
import argparse
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────
# CONFIGURAÇÕES
# ──────────────────────────────────────────────
PORTS = "80,81,3000,3001,8443,10000,9000,9443,443,8080,8000,6885,4443,2075,2076,6443,3868,3366,9091,5900,8081,6000,8181,3306,5000,4000,5432,15672,9999,161,4044,7077"
HTTPX_THREADS      = 80
FINGERPRINT_THREADS = 20
CURL_TIMEOUT       = 5   # segundos

# ── Caminhos dos scripts CVE (preencha aqui) ──
NGINX_CVE_SCRIPT      = "/opt/scripts/nginx_cve.py"   # ex: "/opt/scripts/nginx_cve.py"
APACHE_CVE_SCRIPT     = "/opt/scripts/apache_cve.py"   # ex: "/opt/scripts/apache_cve.py"
OPENRESTY_CVE_SCRIPT  = "/opt/scripts/openresty_cve.py"   # ex: "/opt/scripts/openresty_cve.py"
HAPROXY_CVE_SCRIPT    = "/opt/scripts/haproxy_cve.py"   # ex: "/opt/scripts/haproxy_cve.py"

TOOLS_REQUIRED = ["subfinder", "assetfinder", "nmap", "httpx", "curl"]
TOOLS_OPTIONAL = ["chaos", "github-subdomains", "shortscan"]

# Palavras-chave que indicam Cloudflare / WAF / sem identificação clara
CLOUDFLARE_WAF_KEYWORDS = [
    "cloudflare", "cloudfront", "sucuri", "incapsula", "imperva",
    "akamai", "barracuda", "f5", "fastly", "waf", "firewall",
]

# Lock para log thread-safe
_log_lock = threading.Lock()


# ──────────────────────────────────────────────
# UTILIDADES
# ──────────────────────────────────────────────

def banner():
    print("""
\033[1;32m
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
  Subdomain Recon + Nmap + HTTPX + Fingerprint + CVE
""")


def log(msg, level="INFO"):
    colors = {
        "INFO": "\033[1;34m",
        "OK":   "\033[1;32m",
        "WARN": "\033[1;33m",
        "ERR":  "\033[1;31m",
    }
    reset = "\033[0m"
    c  = colors.get(level, "")
    ts = datetime.now().strftime("%H:%M:%S")
    with _log_lock:
        print(f"{c}[{level}] {ts} {msg}{reset}")


def run_cmd(cmd, output_file=None, timeout=300):
    """Executa comando e retorna stdout como string."""
    log(f"$ {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            log(f"stderr: {result.stderr[:300]}", "WARN")
        if output_file and out:
            Path(output_file).write_text(out + "\n")
        return out
    except subprocess.TimeoutExpired:
        log(f"Timeout ao executar: {cmd}", "WARN")
        return ""
    except Exception as e:
        log(f"Erro: {e}", "ERR")
        return ""


def tool_available(name):
    return shutil.which(name) is not None


def check_tools():
    missing_req = [t for t in TOOLS_REQUIRED if not tool_available(t)]
    missing_opt = [t for t in TOOLS_OPTIONAL if not tool_available(t)]

    if missing_req:
        log(f"Ferramentas obrigatórias não encontradas: {', '.join(missing_req)}", "ERR")
        log("Instale antes de continuar.", "ERR")
        sys.exit(1)

    if missing_opt:
        log(f"Ferramentas opcionais não encontradas (serão puladas): {', '.join(missing_opt)}", "WARN")

    log("Verificação de ferramentas OK", "OK")


def dedup_sort(lines):
    return sorted(set(l.strip().lower() for l in lines if l.strip()))


def write_lines(path, lines):
    Path(path).write_text("\n".join(lines) + "\n")
    log(f"Salvo: {path} ({len(lines)} entradas)", "OK")


# ──────────────────────────────────────────────
# COLETA DE SUBDOMÍNIOS
# ──────────────────────────────────────────────

def run_subfinder(domain, outdir):
    out = f"{outdir}/subfinder.txt"
    run_cmd(f"subfinder -d {domain} -silent -o {out}", timeout=180)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def run_assetfinder(domain, outdir):
    out = f"{outdir}/assetfinder.txt"
    run_cmd(f"assetfinder --subs-only {domain} > {out}", timeout=120)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def run_chaos(domain, outdir):
    if not tool_available("chaos"):
        return []
    chaos_key = os.environ.get("CHAOS_KEY", "")
    if not chaos_key:
        log("CHAOS_KEY não definido — pulando chaos", "WARN")
        return []
    out = f"{outdir}/chaos.txt"
    run_cmd(f"chaos -d {domain} -key {chaos_key} -silent -o {out}", timeout=120)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def run_github_subdomains(domain, outdir):
    if not tool_available("github-subdomains"):
        return []
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        log("GITHUB_TOKEN não definido — pulando github-subdomains", "WARN")
        return []
    out = f"{outdir}/github_subs.txt"
    run_cmd(f"github-subdomains -d {domain} -t {token} -o {out}", timeout=120)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def collect_subdomains(domain, outdir):
    log("=== COLETA DE SUBDOMÍNIOS ===")
    all_subs = []

    all_subs += run_subfinder(domain, outdir)
    log(f"subfinder: {len(all_subs)} até agora", "OK")

    tmp = run_assetfinder(domain, outdir)
    all_subs += tmp
    log(f"assetfinder: +{len(tmp)}", "OK")

    tmp = run_chaos(domain, outdir)
    all_subs += tmp
    log(f"chaos: +{len(tmp)}", "OK")

    tmp = run_github_subdomains(domain, outdir)
    all_subs += tmp
    log(f"github-subdomains: +{len(tmp)}", "OK")

    subs = dedup_sort([s for s in all_subs if domain in s])
    subs_file = f"{outdir}/subs_domain.txt"
    write_lines(subs_file, subs)
    log(f"Total de subdomínios únicos: {len(subs)}", "OK")
    return subs_file, subs


# ──────────────────────────────────────────────
# NMAP
# ──────────────────────────────────────────────

def run_nmap(subs_file, outdir):
    log("=== NMAP ===")
    nmap_out   = f"{outdir}/nmap_output.txt"
    nmap_gnmap = f"{outdir}/nmap_output.gnmap"

    cmd = (
        f"nmap -iL {subs_file} "
        f"-p {PORTS} "
        f"--open -T4 -n -sV "          # -sV para banner/version detection
        f"-oG {nmap_gnmap} "
        f"-oN {nmap_out} "
        f"--max-retries 2 "
        f"--host-timeout 60s"
    )
    run_cmd(cmd, timeout=1800)

    if not Path(nmap_gnmap).exists():
        log("Nmap não gerou saída grepable", "WARN")
        return {}, {}

    # Parse gnmap → {ip: [porta, ...]}
    results = {}
    for line in Path(nmap_gnmap).read_text().splitlines():
        if "Ports:" not in line:
            continue
        host_match  = re.search(r"Host:\s+(\S+)", line)
        ports_match = re.findall(r"(\d+)/open/tcp", line)
        if host_match and ports_match:
            ip = host_match.group(1)
            results.setdefault(ip, set()).update(ports_match)

    # Parse nmap normal output → {ip: server_banner}
    # Ex: "80/tcp  open  http    nginx 1.18.0"
    banners = {}
    nmap_text = Path(nmap_out).read_text() if Path(nmap_out).exists() else ""
    current_host = None
    for line in nmap_text.splitlines():
        host_line = re.match(r"Nmap scan report for (\S+)", line)
        if host_line:
            current_host = host_line.group(1)
            # remove possível "(ip)" do final
            current_host = re.sub(r"\s*\(.*\)", "", current_host).strip()
            continue
        if current_host:
            # Captura linhas como: 80/tcp open http nginx 1.18.0
            port_line = re.match(r"\s*(\d+)/tcp\s+open\s+\S+\s+(.*)", line)
            if port_line:
                service_info = port_line.group(2).strip().lower()
                if service_info and current_host not in banners:
                    banners[current_host] = service_info

    log(f"Nmap encontrou {len(results)} hosts com portas abertas", "OK")
    log(f"Nmap coletou {len(banners)} banners de serviço", "OK")
    return {k: sorted(v, key=int) for k, v in results.items()}, banners


# ──────────────────────────────────────────────
# HTTPX
# ──────────────────────────────────────────────

# Caminhos candidatos para o httpx do ProjectDiscovery
HTTPX_PD_CANDIDATES = [
    "/root/go/bin/httpx",
    "/home/ubuntu/go/bin/httpx",
    "/usr/local/go/bin/httpx",
]


def _find_pd_httpx():
    """
    Procura o binário httpx do ProjectDiscovery em:
    1. Caminhos conhecidos do Go
    2. PATH — mas verifica se aceita flag -l
    Retorna o path do binário ou None.
    """
    import shutil as _shutil

    # Tenta caminhos fixos do Go primeiro
    for candidate in HTTPX_PD_CANDIDATES:
        if Path(candidate).exists():
            try:
                r = subprocess.run(
                    [candidate, "-version"],
                    capture_output=True, text=True, timeout=5
                )
                out = (r.stdout + r.stderr).lower()
                if "no such option" not in out:
                    log(f"httpx ProjectDiscovery encontrado: {candidate}", "OK")
                    return candidate
            except Exception:
                continue

    # Tenta o httpx do PATH — verifica se é o PD
    httpx_in_path = _shutil.which("httpx")
    if httpx_in_path:
        try:
            r = subprocess.run(
                f'echo "" | {httpx_in_path} -l /dev/stdin -silent 2>&1 | head -1',
                shell=True, capture_output=True, text=True, timeout=8
            )
            out = (r.stdout + r.stderr).lower()
            if "no such option" not in out and "usage: httpx [options] url" not in out:
                log(f"httpx ProjectDiscovery encontrado no PATH: {httpx_in_path}", "OK")
                return httpx_in_path
        except Exception:
            pass

    return None


def run_httpx(subs_file, outdir):
    log("=== HTTPX ===")
    alive_file = f"{outdir}/alive.txt"
    alive_json = f"{outdir}/alive_json.txt"

    httpx_bin = _find_pd_httpx()
    if not httpx_bin:
        log("httpx ProjectDiscovery não encontrado", "ERR")
        log("Adicione ao PATH: export PATH=/root/go/bin:$PATH", "ERR")
        log("Ou instale: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "ERR")
        log("Pulando httpx — fingerprint usará fallback via ips_ativos_com_protocolo.txt", "WARN")
        return None, None

    cmd = (
        f"{httpx_bin} -l {subs_file} "
        f"-ports {PORTS} "
        f"-threads {HTTPX_THREADS} "
        f"-json "
        f"-o {alive_json}"
    )
    run_cmd(cmd, timeout=900)

    cmd2 = (
        f"{httpx_bin} -l {subs_file} "
        f"-ports {PORTS} "
        f"-threads {HTTPX_THREADS} "
        f"-o {alive_file}"
    )
    run_cmd(cmd2, timeout=900)

    return alive_file, alive_json


# ──────────────────────────────────────────────
# ALIVE DEDUP  (novo)
# ──────────────────────────────────────────────

def build_alive_dedup(alive_file, outdir):
    """
    Remove duplicatas http/https do alive.txt.
    Prefere https quando ambos existem para o mesmo host:porta.
    Salva em alive_dedup.txt.
    """
    if not Path(alive_file).exists():
        log("alive.txt não encontrado, pulando dedup", "WARN")
        return

    lines = [l.strip() for l in Path(alive_file).read_text().splitlines() if l.strip()]

    if not lines:
        log("alive.txt existe mas está vazio — pulando dedup", "WARN")
        return None

    # Normaliza: extrai (host, porta) sem protocolo
    seen   = {}   # (host, port) → url preferida (https > http)
    for url in lines:
        m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", url)
        if not m:
            continue
        scheme, host, port = m.group(1), m.group(2), m.group(3) or ("443" if m.group(1) == "https" else "80")
        key = (host, port)
        if key not in seen or scheme == "https":
            seen[key] = url

    dedup = sorted(seen.values())
    out   = f"{outdir}/alive_dedup.txt"
    write_lines(out, dedup)
    log(f"alive_dedup.txt: {len(lines)} → {len(dedup)} (removidas {len(lines)-len(dedup)} duplicatas)", "OK")
    return out


# ──────────────────────────────────────────────
# IPs ONLY  (novo)
# ──────────────────────────────────────────────

def build_ips_only(ip_port_file, outdir):
    """
    Extrai apenas os IPs de ips_ativos_portas.txt (sem porta).
    Salva em ips_only.txt.
    """
    if not Path(ip_port_file).exists():
        log("ips_ativos_portas.txt não encontrado, pulando ips_only", "WARN")
        return

    ips = set()
    for line in Path(ip_port_file).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        # Remove protocolo se houver
        clean = re.sub(r"^https?://", "", line)
        ip = clean.split(":")[0]
        if ip:
            ips.add(ip)

    out = f"{outdir}/ips_only.txt"
    if not ips:
        log("Nenhum IP extraído para ips_only.txt", "WARN")
        return None
    write_lines(out, sorted(ips))
    return out


# ──────────────────────────────────────────────
# FINGERPRINT DE SERVIDOR  (novo)
# ──────────────────────────────────────────────

def _classify_server(raw: str) -> str:
    """
    Classifica o valor bruto do header/banner em uma categoria.
    Retorna: 'nginx' | 'apache' | 'iis' | 'cloudflare_waf' | 'outro:<valor>'
    """
    val = raw.lower().strip()

    # Cloudflare / WAF primeiro (pode mascarar o servidor real)
    for kw in CLOUDFLARE_WAF_KEYWORDS:
        if kw in val:
            return "cloudflare_waf"

    if "openresty" in val:
        return "openresty"
    if "nginx" in val:
        return "nginx"
    if "apache" in val:
        return "apache"
    if "microsoft-iis" in val or "iis" in val:
        return "iis"
    if "haproxy" in val:
        return "haproxy"
    if val:
        return f"outro:{val}"
    return "desconhecido"


def _fingerprint_url(url: str, nmap_banners: dict) -> tuple[str, str]:
    """
    Tenta identificar o servidor de uma URL específica (IP:porta).
    Ordem: nmap banner → curl header Server → curl body de erro.
    Retorna (url, classificacao) — chave é a URL completa, não só o host.
    """
    m = re.match(r"https?://([^/:]+)", url)
    if not m:
        return url, "desconhecido"
    host = m.group(1)

    # 1. Banner do nmap (por host — nmap não distingue porta aqui)
    if host in nmap_banners:
        banner_val = nmap_banners[host]
        cls = _classify_server(banner_val)
        if cls not in ("desconhecido",):
            log(f"[fingerprint] {url} → {cls} (nmap banner)", "INFO")
            return url, cls

    # 2. curl header Server: desta URL específica (porta inclusa)
    try:
        result = subprocess.run(
            f"curl -sk -o /dev/null -D - --max-time {CURL_TIMEOUT} {url}",
            shell=True, capture_output=True, text=True, timeout=CURL_TIMEOUT + 2
        )
        for line in result.stdout.splitlines():
            if line.lower().startswith("server:"):
                server_val = line.split(":", 1)[1].strip()
                cls = _classify_server(server_val)
                if cls not in ("desconhecido",):
                    log(f"[fingerprint] {url} → {cls} (curl header)", "INFO")
                    return url, cls
    except Exception:
        pass

    # 3. curl body de erro nesta porta específica
    try:
        error_url = url.rstrip("/") + "/____recon_probe_404____"
        result = subprocess.run(
            f"curl -sk --max-time {CURL_TIMEOUT} {error_url}",
            shell=True, capture_output=True, text=True, timeout=CURL_TIMEOUT + 2
        )
        body = result.stdout.lower()
        if "openresty" in body:
            log(f"[fingerprint] {url} → openresty (curl body)", "INFO")
            return url, "openresty"
        if "nginx" in body:
            log(f"[fingerprint] {url} → nginx (curl body)", "INFO")
            return url, "nginx"
        if "apache" in body:
            log(f"[fingerprint] {url} → apache (curl body)", "INFO")
            return url, "apache"
        if "microsoft-iis" in body or "iis" in body:
            log(f"[fingerprint] {url} → iis (curl body)", "INFO")
            return url, "iis"
        if "haproxy" in body:
            log(f"[fingerprint] {url} → haproxy (curl body)", "INFO")
            return url, "haproxy"
        for kw in CLOUDFLARE_WAF_KEYWORDS:
            if kw in body:
                log(f"[fingerprint] {url} → cloudflare_waf (curl body)", "INFO")
                return url, "cloudflare_waf"
    except Exception:
        pass

    log(f"[fingerprint] {url} → desconhecido", "WARN")
    return url, "desconhecido"


def run_fingerprint(alive_dedup_file, nmap_banners: dict, outdir: str) -> dict:
    """
    Roda fingerprint em paralelo em todas as URLs do alive_dedup.txt.
    Chave do resultado é a URL completa (ex: http://1.2.3.4:8080) — não só o IP.
    Retorna dict {url: classificacao}.
    """
    log("=== FINGERPRINT DE SERVIDOR ===")

    if not alive_dedup_file or not Path(alive_dedup_file).exists():
        log("alive_dedup.txt não encontrado, pulando fingerprint", "WARN")
        return {}

    urls = [l.strip() for l in Path(alive_dedup_file).read_text().splitlines() if l.strip()]
    if not urls:
        log("Nenhuma URL para fingerprint", "WARN")
        return {}

    log(f"Iniciando fingerprint em {len(urls)} URLs (threads={FINGERPRINT_THREADS})", "INFO")

    results = {}
    with ThreadPoolExecutor(max_workers=FINGERPRINT_THREADS) as executor:
        futures = {executor.submit(_fingerprint_url, url, nmap_banners): url for url in urls}
        for future in as_completed(futures):
            url_key, cls = future.result()
            results[url_key] = cls

    # Salva log de fingerprint — agora por URL:porta
    fp_lines = [f"{url_key} - {cls}" for url_key, cls in sorted(results.items())]
    fp_file  = f"{outdir}/server_fingerprint.txt"
    write_lines(fp_file, fp_lines)
    log(f"Fingerprint salvo em: {fp_file}", "OK")

    # Resumo por categoria
    from collections import Counter
    counts = Counter(
        (c if not c.startswith("outro:") else "outro") for c in results.values()
    )
    for cat, n in sorted(counts.items()):
        log(f"  {cat}: {n} URL(s)", "OK")

    return results


# ──────────────────────────────────────────────
# EXECUÇÃO DOS SCRIPTS CVE / SHORTSCAN  (novo)
# ──────────────────────────────────────────────

def _run_script(script_path: str, url: str, label: str, outdir: str = ""):
    """
    Executa script CVE externo com output em tempo real (streaming).
    Printa cada linha conforme sai, sem buffering.
    """
    if not script_path:
        log(f"Caminho do script {label} não configurado (edite NGINX_CVE_SCRIPT / APACHE_CVE_SCRIPT)", "WARN")
        return
    if not Path(script_path).exists():
        log(f"Script {label} não encontrado: {script_path}", "ERR")
        return

    output_flag = []
    if outdir:
        output_flag = ["--output", f"{outdir}/cve_results.txt"]

    cmd_parts = ["python3", "-u", script_path, url] + output_flag
    log(f"{'─'*60}", "INFO")
    log(f"Iniciando {label} → {url}", "OK")
    log(f"{'─'*60}", "INFO")

    try:
        proc = subprocess.Popen(
            cmd_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # Streaming linha a linha
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                print(line)
        proc.wait(timeout=600)
        if proc.returncode != 0:
            log(f"{label} encerrou com código {proc.returncode}", "WARN")
        else:
            log(f"{label} concluído em {url}", "OK")
    except subprocess.TimeoutExpired:
        proc.kill()
        log(f"Timeout ao executar {label}", "WARN")
    except Exception as e:
        log(f"Erro ao executar {label}: {e}", "ERR")


def _run_shortscan(url: str, outdir: str = ""):
    """Executa shortscan em uma URL e salva output em outdir."""
    if not tool_available("shortscan"):
        log("shortscan não instalado — pulando IIS scan", "WARN")
        return
    log(f"Executando shortscan em {url}")
    out_flag = ""
    if outdir:
        out_flag = f'>> "{outdir}/shortscan_results.txt" 2>&1'
    run_cmd(f'shortscan "{url}" {out_flag}', timeout=120)


def dispatch_cve_scripts(
    fingerprint: dict,
    alive_dedup_file: str,
    no_nginx: bool,
    no_apache: bool,
    no_iis: bool,
    no_haproxy: bool = False,
    outdir: str = "",
):
    """
    Para cada host identificado, executa o script CVE correspondente.
    Usa as URLs do alive_dedup para ter protocolo+porta corretos.
    """
    log("=== EXECUÇÃO DE SCRIPTS CVE ===")

    if not alive_dedup_file or not Path(alive_dedup_file).exists():
        log("alive_dedup.txt não encontrado, pulando CVE dispatch", "WARN")
        return

    # fingerprint agora é {url: cls} — itera diretamente por URL:porta
    total = len(fingerprint)
    log(f"Disparando CVE scripts para {total} URL(s) identificadas", "INFO")

    for idx, (url, cls) in enumerate(sorted(fingerprint.items()), 1):
        log(f"[CVE {idx}/{total}] {url} → {cls}", "INFO")

        if cls == "nginx":
            if no_nginx:
                log(f"[CVE] {url} → nginx (--no-nginx ativo, pulando)", "WARN")
            else:
                _run_script(NGINX_CVE_SCRIPT, url, "nginx_cve", outdir)

        elif cls == "openresty":
            if no_nginx:
                log(f"[CVE] {url} → openresty (--no-nginx ativo, pulando)", "WARN")
            else:
                _run_script(OPENRESTY_CVE_SCRIPT, url, "openresty_cve", outdir)

        elif cls == "apache":
            if no_apache:
                log(f"[CVE] {url} → apache (--no-apache ativo, pulando)", "WARN")
            else:
                _run_script(APACHE_CVE_SCRIPT, url, "apache_cve", outdir)

        elif cls == "iis":
            if no_iis:
                log(f"[CVE] {url} → IIS (--no-iis ativo, pulando)", "WARN")
            else:
                _run_shortscan(url, outdir)

        elif cls == "haproxy":
            if no_haproxy:
                log(f"[CVE] {url} → haproxy (--no-haproxy ativo, pulando)", "WARN")
            else:
                _run_script(HAPROXY_CVE_SCRIPT, url, "haproxy_cve", outdir)

        elif cls in ("cloudflare_waf", "desconhecido"):
            log(f"[CVE] {url} → {cls} → rodando nginx + apache", "WARN")
            if not no_nginx:
                _run_script(NGINX_CVE_SCRIPT, url, "nginx_cve", outdir)
            else:
                log(f"[CVE] nginx pulado (--no-nginx)", "WARN")
            if not no_apache:
                _run_script(APACHE_CVE_SCRIPT, url, "apache_cve", outdir)
            else:
                log(f"[CVE] apache pulado (--no-apache)", "WARN")

        elif cls.startswith("outro:"):
            servidor = cls.split(":", 1)[1]
            log(f"[CVE] {url} → servidor: {servidor} (sem script disponível)", "INFO")

        else:
            log(f"[CVE] {url} → classificação inesperada: {cls}", "WARN")


# ──────────────────────────────────────────────
# PARSE & CONSOLIDAÇÃO
# ──────────────────────────────────────────────

def parse_httpx_json(alive_json):
    entries = []
    if not Path(alive_json).exists():
        return entries

    for line in Path(alive_json).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj    = json.loads(line)
            url    = obj.get("url", "")
            host   = obj.get("host", obj.get("input", ""))
            ip     = obj.get("a", [""])[0] if obj.get("a") else obj.get("ip", "")
            port   = str(obj.get("port", ""))
            scheme = obj.get("scheme", "http")
            if url:
                entries.append({"url": url, "host": host, "ip": ip, "port": port, "scheme": scheme})
        except json.JSONDecodeError:
            pass

    return entries


def build_output_files(entries, nmap_results, outdir):
    log("=== GERANDO ARQUIVOS DE SAÍDA ===")

    # ── 1. Subdomínios ativos + portas
    sub_ports = set()
    for e in entries:
        host = e["host"]
        port = e["port"]
        if host and port:
            sub_ports.add(f"{host}:{port}")

    sub_ports_file = f"{outdir}/subdominios_ativos_portas.txt"
    write_lines(sub_ports_file, sorted(sub_ports))

    # ── 2. IPs com http/https
    SSL_PORTS = {"443", "8443", "9443", "6443", "4443", "2076", "10000"}
    ip_url_set = set()
    for e in entries:
        ip     = e["ip"]
        port   = e["port"]
        scheme = e["scheme"]
        if ip and port:
            ip_url_set.add(f"{scheme}://{ip}:{port}")

    for ip, ports in nmap_results.items():
        for p in ports:
            scheme = "https" if p in SSL_PORTS else "http"
            ip_url_set.add(f"{scheme}://{ip}:{p}")

    ip_url_file = f"{outdir}/ips_ativos_com_protocolo.txt"
    write_lines(ip_url_file, sorted(ip_url_set))

    # ── 3. IPs + porta simples
    ip_port_set = set()
    for entry in ip_url_set:
        clean = re.sub(r"^https?://", "", entry)
        ip_port_set.add(clean)

    ip_port_file = f"{outdir}/ips_ativos_portas.txt"
    write_lines(ip_port_file, sorted(ip_port_set))

    return sub_ports_file, ip_url_file, ip_port_file


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recon automatizado: subdomínios → nmap → httpx → fingerprint → CVE"
    )
    parser.add_argument("domain", help="Domínio alvo (ex: exemplo.com.br)")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Diretório de saída (padrão: recon_<domain>_<timestamp>)"
    )
    parser.add_argument(
        "--skip-nmap", action="store_true",
        help="Pula o nmap"
    )
    parser.add_argument(
        "--skip-fingerprint", action="store_true",
        help="Pula a etapa de fingerprint de servidor"
    )
    parser.add_argument(
        "--subs-file", default=None,
        help="Usa arquivo de subdomínios existente (pula coleta)"
    )
    parser.add_argument(
        "--no-nginx", action="store_true",
        help="Não executa o script CVE de Nginx"
    )
    parser.add_argument(
        "--no-apache", action="store_true",
        help="Não executa o script CVE de Apache"
    )
    parser.add_argument(
        "--no-iis", action="store_true",
        help="Não executa shortscan em hosts IIS"
    )
    parser.add_argument(
        "--no-haproxy", action="store_true",
        help="Não executa o script CVE de HAProxy"
    )
    parser.add_argument(
        "--skip-cve", action="store_true",
        help="Pula a execução dos scripts CVE (mantém fingerprint)"
    )
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = args.output or f"recon_{domain.replace('.', '_')}_{ts}"
    Path(outdir).mkdir(parents=True, exist_ok=True)

    banner()
    log(f"Alvo  : {domain}")
    log(f"Output: {outdir}")
    log(f"Portas: {PORTS}")
    print()

    check_tools()

    # 1. Subdomínios
    if args.subs_file:
        subs_file = args.subs_file
        subs = Path(subs_file).read_text().splitlines()
        log(f"Usando arquivo de subs existente: {subs_file} ({len(subs)} entradas)")
    else:
        subs_file, subs = collect_subdomains(domain, outdir)

    if not subs:
        log("Nenhum subdomínio encontrado. Encerrando.", "ERR")
        sys.exit(1)

    # 2. Nmap
    nmap_results = {}
    nmap_banners = {}
    if not args.skip_nmap:
        nmap_results, nmap_banners = run_nmap(subs_file, outdir)
    else:
        log("Nmap pulado (--skip-nmap)", "WARN")

    # 3. HTTPX
    alive_file, alive_json = run_httpx(subs_file, outdir)

    # 4. Parse & consolidação
    entries = parse_httpx_json(alive_json) if alive_json else []
    log(f"HTTPX retornou {len(entries)} URLs ativas", "OK")

    sub_ports_file, ip_url_file, ip_port_file = build_output_files(entries, nmap_results, outdir)

    # 5. Alive dedup
    alive_dedup_file = build_alive_dedup(alive_file, outdir) if alive_file else None

    # 5b. Fallback: se httpx falhou, gera alive_dedup a partir de ips_ativos_com_protocolo.txt
    if not alive_dedup_file and Path(ip_url_file).exists():
        log("Fallback: gerando alive_dedup.txt a partir de ips_ativos_com_protocolo.txt", "WARN")
        alive_dedup_file = build_alive_dedup(ip_url_file, outdir)

    # 6. IPs only
    build_ips_only(ip_port_file, outdir)

    # 7. Fingerprint
    fingerprint = {}
    if not args.skip_fingerprint:
        fingerprint = run_fingerprint(alive_dedup_file, nmap_banners, outdir)
    else:
        log("Fingerprint pulado (--skip-fingerprint)", "WARN")

    # 8. Dispatch CVE scripts
    if fingerprint and not args.skip_cve:
        dispatch_cve_scripts(
            fingerprint,
            alive_dedup_file,
            no_nginx=args.no_nginx,
            no_apache=args.no_apache,
            no_iis=args.no_iis,
            no_haproxy=args.no_haproxy,
            outdir=outdir,
        )
    elif args.skip_cve:
        log("Scripts CVE pulados (--skip-cve)", "WARN")

    # Resumo final
    httpx_ok = alive_file and Path(alive_file).exists()
    print()
    log("══════════════ RESUMO ══════════════", "OK")
    log(f"Subdomínios ativos + portas : {sub_ports_file}", "OK")
    log(f"IPs com protocolo           : {ip_url_file}", "OK")
    log(f"IPs + porta (simples)       : {ip_port_file}", "OK")
    if httpx_ok:
        log(f"Alive dedup                 : {outdir}/alive_dedup.txt", "OK")
    else:
        log(f"Alive dedup                 : {outdir}/alive_dedup.txt (fallback via nmap)", "WARN")
    log(f"IPs only                    : {outdir}/ips_only.txt", "OK")
    log(f"Fingerprint de servidor     : {outdir}/server_fingerprint.txt", "OK")
    if not args.skip_cve and fingerprint:
        log(f"CVE results                 : {outdir}/cve_results.txt", "OK")
        if any(v == "iis" for v in fingerprint.values()):
            log(f"Shortscan results           : {outdir}/shortscan_results.txt", "OK")
    if not httpx_ok:
        log("ATENÇÃO: httpx não funcionou — instale o ProjectDiscovery httpx para cobertura completa", "WARN")
        log("         go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "WARN")
    print()
    log(f"Recon finalizado! Resultados em: {outdir}/", "OK")


if __name__ == "__main__":
    main()
