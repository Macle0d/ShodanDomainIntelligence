#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ShodanDomainIntel.py
===========================

Integración de Shodan para recolección de inteligencia de dominios e IPs.:
- **Descarga dinámica de rangos WAF** (Imperva y Cloudflare) desde las URLs públicas con el siguiente orden de resolución:

  Imperva (en este orden):
    1) Si `--imperva` empieza por `http`, se consulta esa URL.
    2) Si `--imperva` == `auto` o no se pasó `--imperva`, se intenta
       `https://my.imperva.com/api/integration/v1/ips`.
    3) Si la descarga falla, se intenta archivo local `./imperva.txt`.

  Cloudflare (en este orden):
    1) Si `--cloudflare` empieza por `http`, se consulta esa URL.
    2) Si `--cloudflare` == `auto` o no se pasó `--cloudflare`, se intenta
       `https://api.cloudflare.com/client/v4/ips`.
       (como alternativa de respaldo, si esa respuesta no es JSON válido,
       se prueban `https://www.cloudflare.com/ips-v4` y `.../ips-v6`).
    3) Si la descarga falla, se intenta archivo local `./cloudflare.txt`.

- El resto de funcionalidades:
  * `-o/--output`: archivo `<output>/<dominio>.txt` que contiene **solo IPs** (sin WAF).
  * Filtro de IPs por WAF (Imperva/Cloudflare) aplicado a lo que se muestra y a lo que se escribe.
  * Proxy opcional, SSL deshabilitado globalmente, manejo básico de rate-limit.
  * Dedupe por (IP, puerto) para alinear pantalla/archivo.

Requerimientos:
    pip install requests rich

Uso (ejemplos):
    python ShodanDomainIntel.py -d ejemplo.com -o output --imperva auto --cloudflare auto
    python ShodanDomainIntel.py -f dominios.txt -o salidas --cloudflare https://api.cloudflare.com/client/v4/ips
    python ShodanDomainIntel.py -ip 8.8.8.8 --imperva https://my.imperva.com/api/integration/v1/ips

Notas:
- Si se pasan -d y -f, se prioriza el archivo (-f).
- Si se pasan -f y -ips, se procesan ambas búsquedas.
- Ajuste la variable API_KEY con su clave de Shodan.
"""

import argparse
import json
import os
import ipaddress
import sys
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests
from requests.exceptions import RequestException
import urllib3

from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.traceback import install as rich_traceback

# ==========================
# CONFIGURACIÓN DEL USUARIO
# ==========================
API_KEY = "SHODAN_API_KEY_AQUI"  # <-- Reemplace por su API Key de Shodan

# ==========================
# AJUSTES GLOBALES
# ==========================
# No verificar SSL ni mostrar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
rich_traceback(show_locals=False)
console = Console()


def banner() -> None:
    """Muestra el banner de la herramienta."""
    title = r"""
    
█▀ █░█ █▀█ █▀▄ ▄▀█ █▄░█   █▀▄ █▀█ █▀▄▀█ ▄▀█ █ █▄░█   █ █▄░█ ▀█▀ █▀▀ █░░
▄█ █▀█ █▄█ █▄▀ █▀█ █░▀█   █▄▀ █▄█ █░▀░█ █▀█ █ █░▀█   █ █░▀█ ░█░ ██▄ █▄▄
                                    Shodan Domain & IP Intelligence 1.0
"""
    console.print(title)


# ==========================
# CLIENTE SHODAN (REST)
# ==========================
class ShodanClient:
    """Cliente mínimo para la API de Shodan usando requests.

    - Respeta proxy si se especifica.
    - Desactiva verificación SSL y suprime errores.
    - Maneja backoff simple en 429/rate limit.
    """

    BASE = "https://api.shodan.io"

    def __init__(self, api_key: str, proxy: Optional[str] = None, timeout: int = 25):
        if not api_key or api_key == "SHODAN_API_KEY_AQUI":
            console.print("[bold red]ERROR:[/bold red] Configure su API Key en la variable API_KEY.", style="red")
            sys.exit(1)

        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # No validar SSL para todas las requests

        # Configuración de proxy opcional: se aplica tanto a http como a https
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Encabezados mínimos
        self.session.headers.update({
            "User-Agent": "ShodanDomainIntel/1.3 (+https://www.shodan.io/)"
        })

    def _get(self, path: str, params: Dict) -> Dict:
        """Solicitud GET con manejo de timeouts/errores y backoff en 429."""
        url = f"{self.BASE}{path}"
        params = dict(params or {})
        params.setdefault("key", self.api_key)

        for attempt in range(5):
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                if r.status_code == 429:
                    wait = min(60 * (attempt + 1), 300)
                    console.log(f"[yellow]Rate limit (429). Reintentando en {wait}s...[/yellow]")
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                return r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            except RequestException as e:
                console.log(f"[red]Aviso:[/red] error de red en intento {attempt + 1}: {type(e).__name__}")
                time.sleep(1)
        return {}

    # ---- Endpoints usados ----
    def search_hostname(self, query: str, page: int = 1) -> Dict:
        return self._get("/shodan/host/search", {"query": query, "page": page})

    def host_info(self, ip: str) -> Dict:
        return self._get(f"/shodan/host/{ip}", {})

    def dns_resolve(self, hostnames: List[str]) -> Dict:
        return self._get("/dns/resolve", {"hostnames": ",".join(hostnames)})

    def dns_reverse(self, ips: List[str]) -> Dict:
        return self._get("/dns/reverse", {"ips": ",".join(ips)})


# ==========================
# UTILIDADES GENERALES
# ==========================

def read_lines(path: str) -> List[str]:
    """Lee líneas no vacías, sin comentarios, quitando espacios."""
    out: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out


def unique(seq: Iterable[str]) -> List[str]:
    """Orden estable y sin duplicados."""
    seen: Set[str] = set()
    res: List[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def dedup_by_ip_port(items: List[Dict]) -> List[Dict]:
    """Elimina duplicados por (ip_str, port). Mantiene el primer match por combinación."""
    seen: Set[Tuple[str, Optional[int]]] = set()
    out: List[Dict] = []
    for it in items:
        ip = it.get("ip_str")
        port = it.get("port")
        key = (ip if isinstance(ip, str) else "", int(port) if isinstance(port, int) else None)
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


# ==========================
# WAF RANGES (Imperva / Cloudflare)
# ==========================

def _parse_cidrs_from_json(text: str, provider: str) -> List[str]:
    """Extrae CIDRs desde JSON de Imperva / Cloudflare.
    - Imperva: {"ipRanges": [...], "ipv6Ranges": [...]}.
    - Cloudflare: {"result": {"ipv4_cidrs": [...], "ipv6_cidrs": [...]}}.
    Retorna lista de cadenas CIDR.
    """
    try:
        data = json.loads(text)
    except Exception:
        return []

    cidrs: List[str] = []
    if provider.lower() == "imperva":
        for k in ("ipRanges", "ipv6Ranges"):
            vals = data.get(k) or []
            if isinstance(vals, list):
                cidrs.extend([str(x).strip() for x in vals if isinstance(x, str) and x.strip()])
    elif provider.lower() == "cloudflare":
        result = data.get("result") if isinstance(data, dict) else None
        if isinstance(result, dict):
            for k in ("ipv4_cidrs", "ipv6_cidrs"):
                vals = result.get(k) or []
                if isinstance(vals, list):
                    cidrs.extend([str(x).strip() for x in vals if isinstance(x, str) and x.strip()])
    return cidrs


def _fetch_text(session: requests.Session, url: str, timeout: int = 20) -> Optional[str]:
    """GET simple (verify desactivado por sesión). Silencia errores y devuelve texto o None."""
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code == 200 and r.text:
            return r.text
    except RequestException:
        pass
    return None


def load_cidrs_from_source(session: requests.Session, source: Optional[str], provider: str, fallback_file: str) -> List[ipaddress._BaseNetwork]:
    """Carga redes CIDR desde:
    - URL explícita (si `source` empieza por http)
    - Modo `auto` (URLs por defecto del proveedor)
    - Archivo local de respaldo (fallback_file)
    Devuelve lista de redes ip_network (v4/v6). Ignora entradas inválidas.
    """
    nets: List[ipaddress._BaseNetwork] = []

    def _append_all(cidrs: List[str]) -> None:
        for c in cidrs:
            try:
                nets.append(ipaddress.ip_network(c.strip(), strict=False))
            except Exception:
                continue

    # 1) URL explícita
    if source and source.lower().startswith("http"):
        text = _fetch_text(session, source)
        if text:
            # intentar JSON primero
            cidrs = _parse_cidrs_from_json(text, provider)
            if not cidrs:
                # si no es JSON, asumir texto con una red por línea
                cidrs = [ln.strip() for ln in text.splitlines() if ln.strip()]
            _append_all(cidrs)
            if nets:
                return nets

    # 2) AUTO o no especificado -> URLs por defecto
    if (not source) or (source and source.lower() == "auto"):
        if provider.lower() == "imperva":
            url = "https://my.imperva.com/api/integration/v1/ips"
            text = _fetch_text(session, url)
            if text:
                _append_all(_parse_cidrs_from_json(text, "imperva"))
        elif provider.lower() == "cloudflare":
            # Primero API JSON
            url_api = "https://api.cloudflare.com/client/v4/ips"
            text_api = _fetch_text(session, url_api)
            if text_api:
                _append_all(_parse_cidrs_from_json(text_api, "cloudflare"))
            # Respaldo: listas en texto plano
            if not nets:
                for u in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
                    t = _fetch_text(session, u)
                    if t:
                        _append_all([ln.strip() for ln in t.splitlines() if ln.strip()])
        if nets:
            return nets

    # 3) Fallback a archivo local
    if os.path.isfile(fallback_file):
        try:
            for ln in read_lines(fallback_file):
                try:
                    nets.append(ipaddress.ip_network(ln.strip(), strict=False))
                except Exception:
                    continue
        except Exception:
            pass

    return nets


def ip_in_any(ip_str: str, nets: List[ipaddress._BaseNetwork]) -> bool:
    """True si la IP (v4/v6) pertenece a alguna red de la lista."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in nets:
        if ip_obj in net:
            return True
    return False


# ==========================
# PROCESAMIENTO PRINCIPAL (Shodan)
# ==========================

def gather_from_domains(api: ShodanClient, domains: List[str]) -> Tuple[Dict[str, List[Dict]], Set[str]]:
    """Para cada dominio:
    - DNS -> IPs (si aplica)
    - Búsqueda por hostname y CN de certificado
    - Enriquecimiento por host_info para IPs resueltas que no aparecieron en búsqueda
    Devuelve mapping dominio -> lista de matches crudos, y set de IPs vistas.
    """
    result: Dict[str, List[Dict]] = {}
    all_ips: Set[str] = set()

    for dom in domains:
        console.log(f"[cyan]Consultando dominio:[/cyan] {dom}")
        matches: List[Dict] = []

        # (1) Resolver DNS
        resolved_ips: List[str] = []
        res = api.dns_resolve([dom])
        if isinstance(res, dict):
            ip = res.get(dom)
            if isinstance(ip, str):
                resolved_ips.append(ip)

        # (2) Buscar por hostname y CN
        queries = [f'hostname:"{dom}"', f'ssl.cert.subject.cn:"{dom}"']
        seen_shodan_ips: Set[str] = set()
        for q in queries:
            page = 1
            while True:
                data = api.search_hostname(q, page=page)
                if not data or "matches" not in data:
                    break
                for m in data.get("matches", []):
                    ip_str = m.get("ip_str")
                    if ip_str:
                        seen_shodan_ips.add(ip_str)
                        matches.append(m)
                total = data.get("total", 0)
                if page * len(data.get("matches", [])) >= total or not data.get("matches"):
                    break
                page += 1

        # (3) host_info para IPs resueltas que no salieron en búsqueda
        add_ips = set(resolved_ips) - seen_shodan_ips
        for ip in add_ips:
            host = api.host_info(ip)
            for item in host.get("data", []):
                matches.append(item)

        result[dom] = matches
        all_ips.update([m.get("ip_str", "") for m in matches if m.get("ip_str")])

    return result, all_ips


def gather_from_ips(api: ShodanClient, ips: List[str]) -> Dict[str, List[Dict]]:
    result: Dict[str, List[Dict]] = {}
    for ip in ips:
        console.log(f"[cyan]Consultando IP:[/cyan] {ip}")
        host = api.host_info(ip)
        result[ip] = host.get("data", [])
    return result


# ==========================
# RENDER TABLAS (RICH)
# ==========================

def render_domain_table(dom: str, items: List[Dict]) -> None:
    if not items:
        console.print(Panel.fit(f"[bold yellow]Sin resultados para[/bold yellow] {dom}", box=box.SQUARE))
        return

    table = Table(
        title=f"[bold]Resultados para dominio:[/bold] {dom}",
        box=box.SQUARE,
        show_lines=True,
        header_style="bold cyan",
        title_style="bold white",
    )
    table.add_column("IP", no_wrap=True)
    table.add_column("Puerto", no_wrap=True, justify="right")
    table.add_column("Proto", no_wrap=True)
    table.add_column("Producto", overflow="fold")
    table.add_column("Versión", overflow="fold")
    table.add_column("Hostnames", overflow="fold")
    table.add_column("Org/ASN", overflow="fold")
    table.add_column("Geo", overflow="fold")
    table.add_column("Tags", overflow="fold")
    table.add_column("CVEs", overflow="fold")

    for it in items:
        ip = it.get("ip_str", "-")
        port = str(it.get("port", "-"))
        proto = (it.get("_shodan", {}) or {}).get("module", "-")
        product = it.get("product") or (it.get("http", {}) or {}).get("server") or "-"
        version = it.get("version") or "-"
        hostnames = ", ".join(it.get("hostnames", []) or it.get("opts", {}).get("hostnames", []) or []) or "-"
        org = it.get("org") or "-"
        asn = it.get("asn") or "-"
        org_asn = f"{org} / {asn}" if org != "-" or asn != "-" else "-"
        loc = []
        if it.get("location"):
            locd = it["location"]
            for k in ("city", "region_code", "country_name"):
                v = locd.get(k)
                if v:
                    loc.append(str(v))
        geo = ", ".join(loc) if loc else "-"
        tags = ", ".join(it.get("tags", [])) if it.get("tags") else "-"
        cves = "-"
        vulns = it.get("vulns") or (it.get("opts", {}) or {}).get("vulns")
        if isinstance(vulns, dict):
            cves = ", ".join(sorted(vulns.keys()))[:200]

        table.add_row(ip, port, proto or "-", product or "-", version or "-", hostnames, org_asn, geo, tags, cves)

    console.print(table)


def render_ip_table(ip: str, items: List[Dict]) -> None:
    title = f"[bold]Resultados para IP:[/bold] {ip}"
    if not items:
        console.print(Panel.fit(f"[bold yellow]Sin resultados para[/bold yellow] {ip}", box=box.SQUARE))
        return

    table = Table(
        title=title,
        box=box.SQUARE,
        show_lines=True,
        header_style="bold cyan",
        title_style="bold white",
    )
    table.add_column("Puerto", no_wrap=True, justify="right")
    table.add_column("Proto", no_wrap=True)
    table.add_column("Producto", overflow="fold")
    table.add_column("Versión", overflow="fold")
    table.add_column("Hostnames", overflow="fold")
    table.add_column("Org/ASN", overflow="fold")
    table.add_column("Geo", overflow="fold")
    table.add_column("Tags", overflow="fold")
    table.add_column("CVEs", overflow="fold")

    for it in items:
        port = str(it.get("port", "-"))
        proto = (it.get("_shodan", {}) or {}).get("module", "-")
        product = it.get("product") or (it.get("http", {}) or {}).get("server") or "-"
        version = it.get("version") or "-"
        hostnames = ", ".join(it.get("hostnames", []) or it.get("opts", {}).get("hostnames", []) or []) or "-"
        org = it.get("org") or "-"
        asn = it.get("asn") or "-"
        org_asn = f"{org} / {asn}" if org != "-" or asn != "-" else "-"
        loc = []
        if it.get("location"):
            locd = it["location"]
            for k in ("city", "region_code", "country_name"):
                v = locd.get(k)
                if v:
                    loc.append(str(v))
        geo = ", ".join(loc) if loc else "-"
        tags = ", ".join(it.get("tags", [])) if it.get("tags") else "-"
        cves = "-"
        vulns = it.get("vulns") or (it.get("opts", {}) or {}).get("vulns")
        if isinstance(vulns, dict):
            cves = ", ".join(sorted(vulns.keys()))[:200]

        table.add_row(port, proto or "-", product or "-", version or "-", hostnames, org_asn, geo, tags, cves)

    console.print(table)


# ==========================
# MAIN
# ==========================

def parse_args() -> argparse.Namespace:
    """Argumentos CLI."""
    p = argparse.ArgumentParser(
        description="Recolección de inteligencia de dominios e IPs usando Shodan",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-p", "--proxy", help="Proxy opcional (ej: http://127.0.0.1:8080)")
    p.add_argument("-f", "--file", help="Archivo con dominios/subdominios (uno por línea)")
    p.add_argument("-d", "--domain", help="Dominio o subdominio a consultar")
    p.add_argument("-ip", "--ip", help="IP a consultar")
    p.add_argument("-ips", "--ips", help="Archivo con IPs (una por línea)")
    p.add_argument("-o", "--output", help="Directorio donde guardar un .txt por dominio con IPs")
    p.add_argument("--imperva", help="Fuente de rangos Imperva: URL, 'auto' o archivo local (fallback ./imperva.txt)")
    p.add_argument("--cloudflare", help="Fuente de rangos Cloudflare: URL, 'auto' o archivo local (fallback ./cloudflare.txt)")
    return p.parse_args()


def main() -> None:
    banner()
    args = parse_args()

    # Preparar cliente (sesión) para reusar proxy/verify también al descargar rangos WAF
    # Usamos una sesión dedicada para WAF para no mezclar params con ShodanClient pero con misma política de SSL y proxy.
    waf_session = requests.Session()
    waf_session.verify = False
    if args.proxy:
        waf_session.proxies = {"http": args.proxy, "https": args.proxy}
    waf_session.headers.update({"User-Agent": "ShodanDomainIntel-WAF/1.3"})

    # Resolver fuentes Imperva y Cloudflare según la lógica descrita (URL -> auto -> archivo)
    imperva_fallback = os.path.join(os.getcwd(), "imperva.txt")
    cloudflare_fallback = os.path.join(os.getcwd(), "cloudflare.txt")

    imperva_nets = load_cidrs_from_source(waf_session, args.imperva, "imperva", imperva_fallback)
    cloudflare_nets = load_cidrs_from_source(waf_session, args.cloudflare, "cloudflare", cloudflare_fallback)

    def is_waf_ip(ip: str) -> bool:
        """Retorna True si la IP está en Imperva o Cloudflare."""
        if ip_in_any(ip, imperva_nets):
            return True
        if ip_in_any(ip, cloudflare_nets):
            return True
        return False

    # Entradas
    domains: List[str] = []
    ips: List[str] = []

    # Si -f y -d ambos: priorizar archivo
    if args.file:
        try:
            domains = read_lines(args.file)
        except Exception as e:
            console.print(f"[red]No se pudo leer el archivo de dominios:[/red] {e}")
            sys.exit(1)
    elif args.domain:
        domains = [args.domain.strip()]

    if args.ip:
        ips.append(args.ip.strip())

    if args.ips:
        try:
            ips.extend(read_lines(args.ips))
        except Exception as e:
            console.print(f"[red]No se pudo leer el archivo de IPs:[/red] {e}")
            sys.exit(1)

    domains = unique([d.lower() for d in domains])
    ips = unique(ips)

    if not domains and not ips:
        console.print("[yellow]No se especificaron objetivos. Use -d/-f y/o -ip/-ips.[/yellow]\n")
        sys.exit(0)

    # Preparar directorio de salida si se solicitó
    outdir = None
    if args.output:
        outdir = args.output
        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception as e:
            console.print(f"[red]No se pudo crear/usar el directorio de salida:[/red] {e}")
            sys.exit(1)

    api = ShodanClient(API_KEY, proxy=args.proxy)

    # --- Dominios ---
    if domains:
        dom_results, _ = gather_from_domains(api, domains)
        for dom, items in dom_results.items():
            waf_filtered = [it for it in items if not is_waf_ip(str(it.get("ip_str", "")))]
            dedup_items = dedup_by_ip_port(waf_filtered)

            # Mostrar tabla en pantalla
            render_domain_table(dom, dedup_items)

            # Escribir archivo de IPs únicas
            if outdir:
                ips_only = unique([ip for ip in (it.get("ip_str") for it in dedup_items) if isinstance(ip, str) and ip])
                outfile = os.path.join(outdir, f"{dom}.txt")
                try:
                    with open(outfile, "w", encoding="utf-8") as f:
                        for ip in ips_only:
                            f.write(f"{ip}\n")
                except Exception as e:
                    console.print(f"[red]No se pudo escribir {outfile}:[/red] {e}")

    # --- IPs --- (no se generan archivos por IP)
    if ips:
        ip_results = gather_from_ips(api, ips)
        for ip, items in ip_results.items():
            if is_waf_ip(ip):
                console.print(Panel.fit(
                    f"[yellow]IP omitida por pertenecer a rangos de WAF conocidos:[/yellow] {ip}", box=box.SQUARE
                ))
                continue
            waf_filtered = [it for it in items if not is_waf_ip(str(it.get("ip_str", ip)))]
            dedup_items = dedup_by_ip_port(waf_filtered)
            render_ip_table(ip, dedup_items)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrumpido por el usuario.[/red]")
