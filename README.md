```
   ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗  ██████╗ ████████╗
   ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔═══██╗╚══██╔══╝
   ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║██║   ██║   ██║   
   ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██║   ██║   ██║   
   ███████║██║     ██║██████╔╝███████╗██║  ██║██║     ╚██████╔╝╚██████╔╝   ██║   
   ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝  ╚═════╝    ╚═╝   
                                                                                    
      ██╗   ██╗██████╗ ██╗         ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗ 
      ██║   ██║██╔══██╗██║         ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
      ██║   ██║██████╔╝██║         ██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝
      ██║   ██║██╔══██╗██║         ██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗
      ╚██████╔╝██║  ██║███████╗    ██║     ██║  ██║██║  ██║███████║███████╗██║  ██║
       ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SpiderFoot](https://img.shields.io/badge/SpiderFoot-Compatible-green.svg)](https://www.spiderfoot.net/)

> **Advanced URL and subdomain extraction tool for SpiderFoot CSV exports with Nuclei/httpx integration.**

---

## 🇬🇧 English

### Description

**SpiderFoot URL Parser** is a specialized tool for extracting and analyzing URLs and subdomains from SpiderFoot CSV exports. Designed for reconnaissance automation and tool chainning.

**Key Features:**
- 🔗 **Robust URL Regex** supporting auth, fragments, IPv6
- 🌐 **Subdomain Hierarchy Analysis** with tree structure
- 🎯 **Tool Integration** (Nuclei, httpx, Amass)
- 📊 **Multiple Export Formats** (JSON, CSV, TXT, Nuclei, httpx)
- 🔍 **Advanced Filtering** by port, scheme, domain
- 📈 **URLInfo Dataclass** for structured parsing

### Why This Tool?

SpiderFoot collects massive amounts of data, **SpiderFoot URL Parser extracts what matters**. Perfect for:
- Automated reconnaissance workflows
- Bug bounty hunting target generation
- Integration with vulnerability scanners
- Asset discovery and enumeration

### Features

✅ **Enterprise Regex**: Supports complex URLs (auth, query params, fragments, IPv6)  
✅ **Subdomain Trees**: Hierarchical organization of discovered subdomains  
✅ **Nuclei Integration**: Direct output to Nuclei target lists  
✅ **httpx Integration**: Generate probe lists for live host detection  
✅ **Pure Python**: No external dependencies required  
✅ **Type Safe**: Dataclass-based architecture  

### Installation

```bash
git clone https://github.com/yourusername/SpiderFoot-URL-Parser.git
cd SpiderFoot-URL-Parser
pip install -r requirements.txt  # No dependencies!
```

### Usage

#### Extract All URLs

```bash
python src/spiderfoot_parser.py spiderfoot_export.csv
```

#### Extract Subdomains for Domain

```bash
python src/spiderfoot_parser.py data.csv -d example.com
```

#### Generate Nuclei Targets

```bash
python src/spiderfoot_parser.py data.csv -d example.com -f nuclei -o targets.txt

# Then run Nuclei
nuclei -l targets.txt -t nuclei-templates/ -o results.txt
```

#### Generate httpx Probe List

```bash
python src/spiderfoot_parser.py data.csv -f httpx -o domains.txt

# Then run httpx
httpx -l domains.txt -title -tech-detect -o live_hosts.txt
```

#### Export to JSON for Analysis

```bash
python src/spiderfoot_parser.py data.csv -d example.com -f json -o analysis.json
```

### Command Reference

```
positional arguments:
  input                SpiderFoot CSV file

optional arguments:
  -d, --domain DOMAIN  Base domain for subdomain filtering
  -f, --format FORMAT  Output format: txt, json, csv, nuclei, httpx (default: txt)
  -o, --output FILE    Output file (default: stdout for txt)
  --urls-only          Output only URLs (not subdomains)
  --subdomains-only    Output only subdomains
  -v, --verbose        Verbose output
```

### Integration Examples

#### Full Reconnaissance Chain

```bash
# 1. Parse SpiderFoot data
python src/spiderfoot_parser.py scan.csv -d target.com -f nuclei -o targets.txt

# 2. Run Nuclei vulnerability scan
nuclei -l targets.txt -t nuclei-templates/ -severity critical,high -o vulns.txt

# 3. Probe for live hosts
python src/spiderfoot_parser.py scan.csv -d target.com -f httpx -o domains.txt
httpx -l domains.txt -tech-detect -title -status-code -o live.txt

# 4. Extract for further analysis
python src/spiderfoot_parser.py scan.csv -d target.com -f json -o full_analysis.json
```

### Sample Output

#### Text Output
```
=== URLs ===
https://www.example.com/
https://api.example.com/v1/users
https://admin.example.com:8443/login

=== Subdomains ===
www.example.com
api.example.com
admin.example.com
dev.example.com
```

#### JSON Output
```json
{
  "total_urls": 1234,
  "total_subdomains": 42,
  "base_domain": "example.com",
  "urls": [...],
  "subdomains": [...],
  "subdomain_tree": {
    "example.com": [
      "www.example.com",
      "api.example.com"
    ]
  },
  "url_details": [...]
}
```

### Project Structure

```
SpiderFoot-URL-Parser/
├── src/
│   ├── spiderfoot_parser.py
│   └── __init__.py
├── examples/
│   ├── sample_output.json
│   └── README.md
├── requirements.txt    # No dependencies!
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🇪🇸 Español

### Descripción

**SpiderFoot URL Parser** es una herramienta especializada para extraer y analizar URLs y subdominios de exportaciones CSV de SpiderFoot. Diseñada para automatización de reconocimiento y encadenamiento de herramientas.

**Características Clave:**
- 🔗 **Regex Robusto de URL** soportando auth, fragments, IPv6
- 🌐 **Análisis Jerárquico de Subdominios**
- 🎯 **Integración con Herramientas** (Nuclei, httpx, Amass)
- 📊 **Múltiples Formatos de Exportación**
- 🔍 **Filtrado Avanzado** por puerto, esquema, dominio

### Instalación

```bash
git clone https://github.com/yourusername/SpiderFoot-URL-Parser.git
cd SpiderFoot-URL-Parser
# No requiere dependencias externas!
```

### Uso Básico

```bash
# Extraer URLs y subdominios
python src/spiderfoot_parser.py scan.csv -d ejemplo.com

# Generar lista para Nuclei
python src/spiderfoot_parser.py scan.csv -d ejemplo.com -f nuclei -o targets.txt
nuclei -l targets.txt -t nuclei-templates/

# Generar lista para httpx
python src/spiderfoot_parser.py scan.csv -f httpx -o dominios.txt
httpx -l dominios.txt -o hosts_vivos.txt
```

### Ejemplos de Integración

La herramienta se integra perfectamente con:
- **Nuclei**: Para escaneo de vulnerabilidades
- **httpx**: Para detección de hosts vivos
- **Amass**: Para enumeración adicional de subdominios
- **Subfinder**: Para descubrimiento pasivo

---

## 📋 Requirements

- Python 3.8+
- **No external dependencies!** Pure Python implementation

## 🔒 Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

Only use on domains you own or have explicit written permission to test.

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👤 Author

**Esteban Jiménez**
- 🏆 Top 1 Hack The Box Ecuador
- 🎯 Red Team Operator
- 🔗 [GitHub](https://github.com/virtualshoot)

## 🙏 Acknowledgments

- SpiderFoot team for OSINT automation
- ProjectDiscovery for Nuclei and httpx
- Bug bounty community for workflow inspiration

---

**⚠️ Use responsibly. Happy hunting!**
