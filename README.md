# Shodan Domain & IP Intelligence

Script en Python para recolectar inteligencia de dominios e IPs usando la API de [Shodan](https://www.shodan.io/).

## Características
- Consulta dominios, subdominios e IPs en Shodan.
- Permite uso opcional de proxy (`-p/--proxy`).
- Filtrado automático de IPs pertenecientes a WAFs conocidos (Imperva y Cloudflare).
  - Descarga rangos desde sus endpoints oficiales:
    - Imperva: `https://my.imperva.com/api/integration/v1/ips`
    - Cloudflare: `https://api.cloudflare.com/client/v4/ips` o `https://www.cloudflare.com/ips-v4` / `ips-v6`
- Soporta carga de rangos WAF desde archivos locales (`--imperva`, `--cloudflare`).
- Genera salidas en tablas modernas usando [Rich](https://rich.readthedocs.io/).
- Genera un archivo `.txt` por dominio consultado (solo IPs, una por línea).
- Deduplicación consistente por `(IP, puerto)`.

## Instalación
```bash
pip install requests rich
```

## Configuración
Edite el archivo `ShodanDomainIntel.py` y reemplace:
```python
API_KEY = "SHODAN_API_KEY_AQUI"
```
por su API Key válida de Shodan.

## Uso
```bash
# Consultar un dominio y guardar resultados en directorio output/
python ShodanDomainIntel.py -d ejemplo.com -o output

# Consultar varios dominios desde archivo
python ShodanDomainIntel.py -f dominios.txt -o salidas

# Consultar IP única
python ShodanDomainIntel.py -ip 8.8.8.8

# Consultar dominios e IPs con proxy y fuentes oficiales de WAFs
python ShodanDomainIntel.py -f dominios.txt -ips ips.txt -p http://127.0.0.1:8080 -o resultados --imperva auto --cloudflare auto
```

## Ejemplo de salida
### Pantalla (tabla Rich)
```
Resultados para dominio: ejemplo.com
┌──────────────┬────────┬───────┬──────────┬─────────┬───────────────┬──────────────┬──────────┬──────┬──────┐
│ IP           │ Puerto │ Proto │ Producto │ Versión │ Hostnames     │ Org/ASN      │ Geo      │ Tags │ CVEs │
├──────────────┼────────┼───────┼──────────┼─────────┼───────────────┼──────────────┼──────────┼──────┼──────┤
│ 93.184.216.34│ 80     │ http  │ nginx    │ -       │ ejemplo.com   │ Edgecast / … │ US       │ cdn  │ -    │
└──────────────┴────────┴───────┴──────────┴─────────┴───────────────┴──────────────┴──────────┴──────┴──────┘
```

### Archivo `output/ejemplo.com.txt`
```
93.184.216.34
```

## Notas
- Si se pasan `-d` y `-f`, se prioriza el archivo (`-f`).
- Si se pasan `-f` y `-ips`, se procesan ambas búsquedas.
- IPs en rangos de Imperva/Cloudflare no aparecen en pantalla ni en los archivos de salida.

---
**Autor:**
- Omar Peña - [@Macle0d](https://github.com/Macle0d) - [@p3nt3ster](https://x.com/p3nt3ster)
