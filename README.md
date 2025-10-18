# SCANYX

<p align="center">
  <img src="images/banner.jpeg" alt="Banner" width="100%">
</p>

[![Version](https://img.shields.io/badge/version-2.8.0-blue.svg)](https://github.com/xtormin/scanyx)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

**SCANYX** es una herramienta para automatizar escaneos de red con Nmap. Soporta ejecución paralela, workflows secuenciales, sesiones, hosts sensibles y excluidos, y persistencia de estado, entre otras.

---

# 🚀 Características Principales

- ✅ **Ejecución paralela** - Escanea múltiples hosts simultáneamente
- ✅ **Workflows secuenciales** - Encadena múltiples perfiles de escaneo
- ✅ **Gestión de sesiones** - Crea, lista y reanuda sesiones con nombres personalizados
- ✅ **Persistencia de estado** - Reanuda escaneos interrumpidos
- ✅ **Hosts sensibles** - Timing y scripts personalizados para hosts críticos
- ✅ **Exclusiones inteligentes** - CIDR, IPs individuales, hostnames
- ✅ **Carga remota** - Ejecuta desde URL sin descargar archivos
- ✅ **Modo Wizard** - Configuración interactiva paso a paso
---

# TL;DR - Inicio Rápido

## Crear archivo con hosts/redes
```powershell
echo "192.168.1.0/24" > hosts.txt
```

## Carga del fichero
```powershell
# Carga local
git clone https://github.com/xtormin/scanyx.git
cd scanyx
. scanyx

# Cargar script desde URL
. ([scriptblock]::Create((iwr -useb https://raw.githubusercontent.com/xtormin/scanyx/main/scanyx.ps1)))
```

## Edición de la configuración de perfiles y workflows (opcional)
```powershell
notepad "nmap-profiles-workflows.json"
```

## Escaneo básico
```powershell
# Un tipo de escaneo
scanyx -HostFile hosts.txt -ScanType "tcp-1000"

# Multiples tipos de escaneo secuenciales
scanyx -HostFile hosts.txt -Workflow "full-discovery" -MaxConcurrent 5
```

## Escaneo avanzado

Un tipo de escaneo:
```powershell
scanyx `
    -HostFile "C:\Pentest\PROYECTO\scope\networks.txt" `
    -SensitiveFile "C:\Pentest\PROYECTO\scope\sensitive.txt" `
    -ExcludeFile "C:\Pentest\PROYECTO\scope\excluded.txt" `
    -ConfigFile "nmap-profiles-workflows.json" `
    -ScanType "tcp-1000"
    -SessionName "scan-01" `
    -OutputDir "C:\Pentest\PROYECTO\scans" `
    -SensitiveTiming T1 `
    -SensitiveScripts default `
    -MaxConcurrent 5 `
    -MaxRetries 1 `
    -ResolveHostnames `
    -ConfigFile "nmap-profiles-workflows.json" `
    -VerboseMode
```

Con varios tipos de escaneo secuenciales:
```powershell
scanyx `
    -HostFile "C:\Pentest\PROYECTO\scope\networks.txt" `
    -SensitiveFile "C:\Pentest\PROYECTO\scope\sensitive.txt" `
    -ExcludeFile "C:\Pentest\PROYECTO\scope\excluded.txt" `
    -ConfigFile "nmap-profiles-workflows.json" `
    -Workflow "full-discovery" `
    -SessionName "workflow-01" `
    -OutputDir "C:\Pentest\PROYECTO\scans" `
    -SensitiveTiming T1 `
    -SensitiveScripts default `
    -MaxConcurrent 5 `
    -MaxRetries 1 `
    -ResolveHostnames `
    -OverwriteMode Skip `
    -VerboseMode
```

## Reanudar sesión

```powershell
# Reanuda la sesión continuando los que no se han completado y reintentando los fallidos
scanyx `
    -ResumeSession "workflow-01" `
    -OutputDir "C:\Pentest\PROYECTO\scans" `
    -ResumeRetryFailed
```

---

# Requisitos

- **PowerShell**: 5.1 o superior
- **Nmap**: Instalado y en PATH ([descargar](https://nmap.org/download.html))

```powershell
# Verificar instalación
nmap --version
$PSVersionTable.PSVersion
```

---

# Uso Básico

## Escaneo Simple
```powershell
# Escaneo básico
scanyx -HostFile hosts.txt -ScanType "tcp-1000"

# Escaneo directo sin archivo (parámetro inline)
scanyx -Hosts "192.168.1.0/24","10.0.0.50" -ScanType "tcp-1000"
```

## Con Exclusiones
```powershell
# Exclusiones desde archivo
scanyx -HostFile hosts.txt -ExcludeFile gateways.txt -ScanType "tcp-1000"

# Exclusiones inline (sin archivo)
scanyx -Hosts "192.168.1.0/24" -ExcludeHosts "192.168.1.1","192.168.1.254" -ScanType "tcp-1000"
```

## Hosts Sensibles
```powershell
# Escaneo diferenciado: normal (T4) vs sensible (T2)
scanyx `
    -HostFile all_hosts.txt `
    -SensitiveFile production_servers.txt `
    -ScanType "tcp-1000" `
    -SensitiveTiming T2 `
    -MaxConcurrent 5
```

## Workflows
```powershell
# Workflow progresivo (tcp-1000 → tcp-full → udp-common)
scanyx -HostFile hosts.txt -Workflow full-discovery -MaxConcurrent 5
```

## Gestión de Sesiones
```powershell
# Crear sesión con nombre personalizado
scanyx -HostFile targets.txt -ScanType tcp-1000 -SessionName "pentest-cliente-2025"

# Listar todas las sesiones
scanyx -ListSessions -OutputDir "C:\Pentest\PROYECTO\scans"

# Reanudar sesión específica
scanyx -ResumeSession "pentest-cliente-2025" -Resume -OutputDir "C:\Pentest\PROYECTO\scans"
```

## Reanudar Escaneos
```powershell
# Continuar escaneo interrumpido (solo pendientes)
scanyx -HostFile hosts.txt -ScanType tcp-1000 -Resume

# Continuar y reintentar fallidos
scanyx -HostFile hosts.txt -ScanType tcp-1000 -ResumeRetryFailed

# Empezar desde cero (ignora estado previo)
scanyx -HostFile hosts.txt -ScanType tcp-1000 -Force
```

## Modo Wizard (Interactivo)
```powershell
# Configuración guiada paso a paso
scanyx -Wizard
```

---

# Perfiles de Escaneo Disponibles

| Perfil | Descripción | Velocidad |
|--------|-------------|-----------|
| `tcp-100` | Top 100 puertos TCP | ⚡⚡⚡ Muy rápido |
| `tcp-1000` | Top 1000 puertos TCP | ⚡⚡⚡ Rápido |
| `tcp-full` | Todos los 65535 puertos TCP | ⚡ Lento |
| `udp-common` | Puertos UDP comunes | ⚡⚡ Medio |
| `udp-1000` | Top 1000 puertos UDP | ⚡ Lento |
| `udp-full` | Todos los 65535 puertos UDP | 🐢 Muy lento |

> **Nota**: Configura perfiles personalizados editando [nmap-profiles-workflows.json](nmap-profiles-workflows.json)

---

# Comandos más usados

```powershell
# Escaneo básico
scanyx -HostFile hosts.txt -ScanType tcp-1000 -OutputDir "C:\Pentest\PROYECTO\scans"

# Escaneo rápido paralelo
scanyx -HostFile hosts.txt -ScanType tcp-1000 -MaxConcurrent 20

# Con exclusiones
scanyx -HostFile hosts.txt -ExcludeFile excluded.txt -ScanType tcp-1000

# Hosts sensibles
scanyx -HostFile hosts.txt -SensitiveFile prod.txt -ScanType tcp-1000 -SensitiveTiming T2

# Workflow completo
scanyx -HostFile hosts.txt -Workflow full-discovery -MaxConcurrent 10

# Gestión de sesiones
scanyx -HostFile hosts.txt -ScanType tcp-1000 -SessionName "mi-proyecto" -OutputDir "C:\Pentest\PROYECTO\scans"
scanyx -ListSessions -OutputDir "C:\Pentest\PROYECTO\scans"
scanyx -ResumeSession "mi-proyecto" -Resume -OutputDir "C:\Pentest\PROYECTO\scans"

# Reanudar interrumpido
scanyx -HostFile hosts.txt -ScanType tcp-1000 -Resume

# Reintentar fallidos
scanyx -HostFile hosts.txt -ScanType tcp-1000 -RetryFailed

# Modo verbose (debugging)
scanyx -HostFile hosts.txt -ScanType tcp-1000 -VerboseMode
```

---

# 📚 Documentación Completa

Para documentación exhaustiva, todos los parámetros, casos de uso avanzados, troubleshooting y cheatsheet completo:

## ➡️ **[Ver WIKI.md](WIKI.md)**

**Incluye:**
- Tabla completa de parámetros (30+ parámetros)
- Modos de reanudación detallados (6 modos)
- Gestión avanzada de hosts y CIDR
- Troubleshooting completo
- Cheatsheet de 30+ comandos
- Casos de uso completos (pentesting, auditorías, automatización)
- Configuración personalizada de perfiles y workflows

---

# Integración

## Post-Procesamiento con XNP

Usa [XtremeNmapParser (XNP)](https://github.com/xtormin/XtremeNmapParser) para fusionar y analizar resultados:

```bash
# Fusionar todos los XMLs con salida en Excel, CSV y JSON
python3 xnp.py -d nmap/ -M -R --open -C all
```

---

# Registro de Cambios

## Versión 2.8.0 (2025-10-17)
- ✨ **Nueva función `scanyx`**: Carga en memoria y ejecución desde URL
- ✅ **Testing completo**: 118 de 118 tests (100%)
- 🔧 **Archivo de configuración**: Renombrado a `nmap-profiles-workflows.json`
- 📚 **Documentación**: README simplificado + WIKI.md exhaustivo


## Versión 2.7 (2025-10-13)
- ✨ Sistema de workflows para encadenar múltiples perfiles secuencialmente
- ✨ Gestión de sesiones
- ✨ Configuración externa en JSON (`scan-profiles.json`)
- ✨ Modo verbose (`-VerboseMode`) para debugging
- ✨ Condiciones de ejecución para pasos de workflow
- 🔧 Mejoras en detección de escaneos fallidos
- 📚 README optimizado y simplificado

## Versión 2.6 (2025-03-05)
- 🐛 Corrección de clasificación de hosts sensibles
- ⚡ Optimización con hashtables para búsquedas

## Versión 2.1-2.5 (2024-11-21)
- ✨ Soporte completo para notación CIDR
- ✨ Sistema de exclusión de hosts (`-ExcludeFile`)
- ✨ Resolución de hostnames (`-ResolveHostnames`)
- ✨ Expansión automática de CIDR con deduplicación
- ✨ Detección de conflictos entre listas
- 📊 Logging mejorado

> Este script se proporciona con fines educativos y de pruebas de seguridad autorizadas únicamente. Escanea redes y sistemas para los que tienes permiso explícito.

---

# Licencia

Este proyecto está licenciado bajo la licencia GPL v3.0 - ver el archivo [LICENSE](LICENSE) para más detalles.

> **Disclaimer**: Este script se proporciona con fines educativos y de pruebas de seguridad autorizadas únicamente. Escanea redes y sistemas para los que tienes permiso explícito.

---


# Redes sociales

* Website: https://xtormin.com
* Linkedin: https://www.linkedin.com/in/xtormin/
* Instagram: https://www.instagram.com/xtormin/