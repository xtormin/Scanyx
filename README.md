# SCANYX

<p align="center">
  <img src="images/banner.jpeg" alt="Banner" width="100%">
</p>

[![Version](https://img.shields.io/badge/version-2.8.1-blue.svg)](https://github.com/xtormin/scanyx)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20(Windows)%20%C2%B7%207.2%2B%20(macOS%2FLinux)-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Plataformas](https://img.shields.io/badge/plataformas-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-lightgrey.svg)](#instalación-en-macos--linux)

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
- ✅ **ConfigFile** - Carga perfiles de configuración remotos o locales
- ✅ **Límite de fallos** - Detiene escaneos tras N fallos consecutivos
- ✅ **Modo Wizard** - Configuración interactiva paso a paso
---

# TL;DR - Inicio Rápido

## Carga del script

### Instalación en macOS / Linux

En Unix se usa el lanzador `scanyx.sh`, que resuelve `pwsh` y `nmap` y arranca el script por ti.

```bash
git clone "https://github.com/xtormin/scanyx.git"
cd scanyx
chmod +x scanyx.sh
./scanyx.sh --check      # diagnóstico: SO, arquitectura, pwsh, nmap, uid
./scanyx.sh --install    # instala lo que falte (brew / apt / tarball oficial)
```

`--check` no instala nada: solo informa y sale con código 2 si falta algo. La
instalación solo ocurre con `--install` (o `--yes`). En Kali sobre ARM64, donde
el paquete `powershell` no suele estar en apt, el lanzador cae automáticamente
al tarball oficial de Microsoft.

Después, se invoca igual que en Windows pero a través del lanzador:

```bash
./scanyx.sh -Hosts "192.168.1.2" -ScanType "tcp-1000"
./scanyx.sh -HostFile hosts.txt -Workflow "full-discovery" -MaxConcurrent 5
```

Opciones propias del lanzador (siempre con doble guion, para no chocar con los
parámetros de Scanyx): `--check`, `--install`/`--yes`, `--no-install`,
`--sudo`/`--no-sudo`, `--remote [URL]`, `--help`. Cualquier otro argumento se
reenvía tal cual a `Invoke-Scanyx`.

### Carga local (Windows)
```powershell
git clone "https://github.com/xtormin/scanyx.git"
cd scanyx
. .\scanyx.ps1
```

### Carga remota
```powershell
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xtormin/Scanyx/refs/heads/main/scanyx.ps1'))
```

## Edición de la configuración de perfiles y workflows (opcional)
```powershell
# Windows
notepad "nmap-profiles-workflows.json"
```
```bash
# macOS / Linux
${EDITOR:-nano} nmap-profiles-workflows.json
```

## Crear archivo con hosts/redes
```powershell
echo "192.168.1.0/24" > hosts.txt
```

## Escaneo básico
```powershell
# Un tipo de escaneo
scanyx -Hosts "192.168.1.2" -ScanType "tcp-1000"

# Multiples tipos de escaneo secuenciales
scanyx -HostFile hosts.txt -Workflow "full-discovery" -MaxConcurrent 5
```

## Escaneo avanzado

Un tipo de escaneo:
```powershell
scanyx `
    -HostFile "networks.txt" `
    -SensitiveFile "sensitive.txt" `
    -ExcludeFile "excluded.txt" `
    -ConfigFile "nmap-profiles-workflows.json" `
    -ScanType "tcp-1000"
    -SessionName "scan-01" `
    -OutputDir "scans" `
    -SensitiveTiming T1 `
    -SensitiveScripts default `
    -MaxConcurrent 5 `
    -MaxRetries 1 `
    -ResolveHostnames `
    -VerboseMode
```

Con varios tipos de escaneo secuenciales:
```powershell
scanyx `
    -SessionName "workflow-01" `
    -OutputDir "scans" `
    -Workflow "full-discovery" `
    -HostFile "networks.txt" `
    -SensitiveFile "sensitive.txt" `
    -ExcludeFile "excluded.txt" `
    -ConfigFile "nmap-profiles-workflows.json" `
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
# Reanuda la sesión continuando el escaneo con todos los hosts que no se han completado
scanyx `
    -ResumeSession "workflow-01" `
    -OutputDir "scans" `
    -Resume
    -VerboseMode
```

---

# Privilegios

En Windows no cambia nada. En **macOS y Linux**, nmap necesita privilegios de
root para abrir raw sockets, y **los seis perfiles de serie lo requieren**:
`tcp-100`, `tcp-1000` y `tcp-full` usan `-sS` y `-A`; `udp-common`, `udp-1000` y
`udp-full` usan `-sU` y `-A`.

Si lanzas Scanyx sin root, comprueba **todos los pasos del workflow antes de
empezar** (no tiene sentido abortar en el paso 3 tras 40 minutos de escaneo) y
se comporta así:

| Situación | Qué hace |
|---|---|
| Perfil degradable, con terminal | Te ofrece degradar o abortar. **Por defecto aborta** |
| Perfil degradable, sin terminal | Aborta e imprime la orden exacta con `sudo` |
| Perfil con `-sU` o `-sO` | **Aborta siempre**: no se puede degradar |

Degradar no es gratis y por eso no se hace en silencio: `-sS` pasa a `-sT`, que
es más lento y deja conexiones completas en el log del objetivo, y se pierden la
detección de sistema operativo (`-O`) y el traceroute. `-sU` directamente no
tiene equivalente sin privilegios.

```bash
# Lo normal: escanear con privilegios
sudo ./scanyx.sh -Hosts 192.168.1.0/24 -ScanType tcp-1000

# Aceptar la degradación sin que pregunte (CI, cron)
./scanyx.sh -Hosts 192.168.1.0/24 -ScanType tcp-1000 -AutoUnprivileged
```

Cuando lanzas con `sudo`, el lanzador devuelve la propiedad del directorio de
resultados a tu usuario al terminar, para no dejarte ficheros de root en el home.

> **Ctrl+C en macOS/Linux**: la limpieza de procesos no siempre alcanza a nmap.
> Si interrumpes un escaneo, comprueba con `pgrep -fl nmap` y limpia con
> `pkill -f nmap` si quedan huérfanos.

---

# Requisitos

- **PowerShell**: 5.1 o superior en Windows; **7.2 o superior** en macOS y Linux
  (en 6.x `Start-Job` es inestable, así que el lanzador lo rechaza)
  - macOS: `brew install powershell` (es una fórmula, no un cask: no pide contraseña)
  - Debian/Kali: `sudo apt-get install -y powershell`, o el tarball oficial en ARM64
- **Nmap**: Instalado y en PATH ([descargar](https://nmap.org/download.html))
- **En macOS/Linux**: privilegios de root para los perfiles de serie (ver
  [Privilegios](#privilegios))

```powershell
# Verificar instalación (Windows)
nmap --version
$PSVersionTable.PSVersion
```
```bash
# Verificar instalación (macOS / Linux)
./scanyx.sh --check
```

---

# Uso Básico

## Escaneo Simple
```powershell
# Escaneo básico
scanyx -HostFile hosts.txt -ScanType "tcp-1000"

# Escaneo directo sin archivo
scanyx -Hosts "192.168.1.0/24","10.0.0.50" -ScanType "tcp-1000"
```

## Con Exclusiones
```powershell
# Exclusiones desde archivo
scanyx -HostFile hosts.txt -ExcludeFile gateways.txt -ScanType "tcp-1000"

# Exclusiones sin archivo
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
```bash
# Lo mismo en macOS / Linux
./scanyx.sh -ListSessions -OutputDir ~/Pentest/PROYECTO/scans
./scanyx.sh -ResumeSession "pentest-cliente-2025" -Resume -OutputDir ~/Pentest/PROYECTO/scans
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

## Modo lista de comandos

Cuando ya tienes la lista escrita a tu gusto —un comando nmap por host, con sus
puertos y sus flags decididos uno a uno— no hace falta traducirla a perfiles.
Scanyx la ejecuta tal cual y le pone encima su motor: concurrencia, reintentos,
log, estado en disco, sesiones y reanudación.

Crea el fichero, un comando por línea. `#` es comentario, y un comentario al
final de la línea es la etiqueta que verás en el progreso y en el resumen:

```
# Controladores de dominio
nmap -sV -T3 -oA nmap/10.30.0.10 -p 53,88,389,445,636 10.30.0.10   # DC01
nmap -sV -T3 -oA nmap/10.30.0.11 -p 135,445,1433,3389 10.30.0.11   # SQL01

# Perímetro
nmap -sV -T3 -oA nmap/192.168.100.10 -p 80,443 192.168.100.10      # WEB01
```

```powershell
# Revisar la lista sin ejecutar nada: qué se va a lanzar y qué estado tiene
scanyx -CommandFile comandos.txt -ListCommands

# Ejecutarla con nombre de sesión, para poder reanudarla después
scanyx -CommandFile comandos.txt -SessionName cliente-2025

# Reanudar: solo corre lo que quedó pendiente o falló
scanyx -CommandFile comandos.txt -SessionName cliente-2025 -Resume
```

**Dónde se guardan los resultados.** Donde diga el `-oA` de cada línea, igual
que si ejecutaras la lista a mano; las rutas relativas se resuelven contra el
directorio desde el que lanzas Scanyx. `-OutputDir` se usa solo para la
contabilidad de Scanyx (`.sessions/`: estado, logs y resultados). Si una línea
no lleva ningún flag de salida, Scanyx le añade un `-oA` dentro de `-OutputDir`.

**Editar la lista entre ejecuciones.** Cada comando se identifica por su
contenido, así que puedes reordenar, añadir y borrar líneas sin perder el
progreso de las que no tocaste. Si modificas una línea, pasa a ser un trabajo
nuevo y se vuelve a ejecutar aunque el fichero de salida de la versión anterior
siga ahí: Scanyx compara el comando que nmap dejó grabado en el `.nmap`.

**Lo que se rechaza.** Una línea que no empiece por `nmap`, que lleve
metacaracteres de shell (`;`, `&&`, `|`, backticks, `$(...)`, redirecciones) o
que combine `-oA` con `-oN`/`-oX`/`-oG`, que es algo que el propio nmap no
acepta. Los comandos se ejecutan pasando argumentos directamente al proceso,
sin shell de por medio.

**Privilegios.** La lista se revisa entera antes de empezar: si alguna línea
necesita root (`-sS`, `-sU`, `-A`…) Scanyx lo dice de antemano en vez de fallar
a mitad del recorrido.

## Carga Remota y ConfigFile desde URL

### Carga con WebClient 
```powershell
# Cargar desde cualquier servidor web
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xtormin/Scanyx/refs/heads/main/scanyx.ps1'))
# Usar la función
scanyx -HostFile hosts.txt -ScanType tcp-1000
```

### Verificar carga exitosa
```powershell
# Verificar que la función está disponible
Get-Command Invoke-Scanyx
Get-Command scanyx

# Ver ayuda
Get-Help Invoke-Scanyx -Examples
```

### ConfigFile desde URL
```powershell
# Usar configuración remota
scanyx -HostFile hosts.txt -ScanType tcp-1000 -ConfigFile "https://raw.githubusercontent.com/xtormin/Scanyx/refs/heads/main/nmap-profiles-workflows.json"
```
```powershell
# Combinación: Script remoto + ConfigFile remoto
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xtormin/Scanyx/refs/heads/main/scanyx.ps1'))
scanyx -Hosts "10.0.0.0/24" -ScanType tcp-full -ConfigFile "https://raw.githubusercontent.com/xtormin/Scanyx/refs/heads/main/nmap-profiles-workflows.json"
```

### Notas Importantes
- ⚠️ **El script NO se ejecuta automáticamente** al cargarse con `iex` - solo define las funciones
- ✅ **Funciona en la sesión actual** - al cerrar PowerShell se debe recargar

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

# 📚 Documentación Completa

Para documentación exhaustiva, todos los parámetros, casos de uso avanzados, troubleshooting y cheatsheet completo:

## ➡️ **[Ver WIKI](https://github.com/xtormin/Scanyx/wiki)**

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
xnp -d nmap/ --show
```

---

# Registro de Cambios

## Versión 2.8.1 (2025-10-22)
- ✨ **Carga remota via IEX optimizada**: El script puede cargarse directamente desde URL sin descargar archivos:
  - Eliminado bloque `param()` del nivel script (solo en función `Invoke-Scanyx`)
  - Reemplazadas 22 sentencias `exit` por `return` para evitar cerrar la sesión
  - Deshabilitada auto-ejecución del script al cargarlo
  - Detección automática de contexto de ejecución (IEX vs local)
  - No se ejecuta automáticamente cuando se carga via IEX
  - Funciones y aliases disponibles tras la carga
  - Compatible con `iex ((New-Object Net.WebClient).DownloadString('url'))`
- ✨ **ConfigFile desde URL**: Soporte para cargar perfiles de configuración desde HTTP/HTTPS
  - Fallback automático a configuración por defecto si falla la descarga
  - Mensajes informativos sobre el origen de la configuración
- 📚 **Documentación**: README ampliado con ejemplos detallados de carga remota.

## Versión 2.8.0 (2025-10-17)
- ✨ **Nueva función `scanyx`**: Carga en memoria y ejecución desde URL
- ✅ **Testing completo**: 118 de 118 tests (100%)
- 🔧 **Archivo de configuración**: Renombrado a `nmap-profiles-workflows.json`
- 📚 **Documentación**: README simplificado + WIKI completa


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

Este proyecto está licenciado bajo la licencia **AGPL v3.0** - ver el archivo [LICENSE](LICENSE) para más detalles.

---

# Redes sociales

* Website: https://xtormin.com
* Linkedin: https://www.linkedin.com/in/xtormin/
* Instagram: https://www.instagram.com/xtormin/