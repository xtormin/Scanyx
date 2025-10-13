# SCANYX

<p align="center">
  <img src="Images/banner.jpeg" alt="AzRA Banner" width="100%">
</p>

[![Version](https://img.shields.io/badge/version-2.7-blue.svg)](https://github.com/xtormin/scanyx)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

**SCANYX** es una herramienta para automatizar escaneos de red con Nmap. Soporta ejecución paralela, workflows secuenciales, sesiones, hosts sensibles y excluidos, y persistencia de estado, entre otras.

---

## TL;DR - Inicio Rápido

```powershell
# 1. Crear archivo con hosts/redes
echo "192.168.1.0/24" > hosts.txt

# 2. Escaneo básico
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000

# 3. Workflow completo con 10 hosts paralelos
.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery -MaxConcurrent 10
```

## Comando completo

Solu un tipo de escaneo:

```powershell
.\scanyx.ps1 `
    -HostFile "C:\Pentest\PROYECTO\networks.txt" `
    -SensitiveFile "C:\Pentest\PROYECTO\sensitive.txt" `
    -ExcludeFile "C:\Pentest\PROYECTO\excluded.txt" `
    -ScanType tcp-1000
    -OutputDir "C:\Pentest\PROYECTO\scans" `
    -SensitiveTiming T1 `
    -SensitiveScripts default `
    -MaxConcurrent 10 `
    -MaxRetries 1 `
    -ResolveHostnames
    -VerboseMode
```

Con workflow:

```powershell
.\scanyx.ps1 `
    -HostFile "C:\Pentest\PROYECTO\networks.txt" `
    -SensitiveFile "C:\Pentest\PROYECTO\sensitive.txt" `
    -ExcludeFile "C:\Pentest\PROYECTO\excluded.txt" `
    -Workflow full-discovery `
    -OutputDir "C:\Pentest\PROYECTO\scans" `
    -SensitiveTiming T1 `
    -SensitiveScripts default `
    -MaxConcurrent 10 `
    -MaxRetries 1 `
    -ResolveHostnames
    -VerboseMode
```

---

## Tabla de Contenidos

- [Instalación](#instalación)
- [Uso Básico](#uso-básico)
  - [Modo Wizard (Configuración Interactiva)](#modo-wizard-configuración-interactiva-)
- [Parámetros](#parámetros)
- [Tipos de Escaneo y Workflows](#tipos-de-escaneo-y-workflows)
- [Gestión de Sesiones](#gestión-de-sesiones)
- [Modos de Reanudación](#modos-de-reanudación)
- [Ejemplos Esenciales](#ejemplos-esenciales)
- [Gestión Avanzada](#gestión-avanzada)
  - [CIDR, Exclusiones y Hosts Sensibles](#cidr-exclusiones-y-hosts-sensibles)
- [Archivos de Salida](#archivos-de-salida)
- [Troubleshooting](#troubleshooting)
- [Integración](#integración)
- [Cheatsheet Básico](#cheatsheet-básico)

---

## Instalación

### Requisitos
- **PowerShell**: 5.1 o superior
- **Nmap**: Instalado y en PATH ([descargar](https://nmap.org/download.html))

### Verificación
```powershell
# Verificar instalación de Nmap
nmap --version

# Verificar PowerShell
$PSVersionTable.PSVersion
```

### Setup
```powershell
# 1. Clonar/descargar repositorio
git clone https://github.com/xtormin/scanyx.git
cd scanyx

# 2. Crear archivo de hosts
# Soporta: IPs individuales, CIDR, hostnames, comentarios
@"
# Red interna
192.168.1.0/24
10.0.0.0/16

# Hosts individuales
server.example.com
192.168.2.100
"@ | Out-File hosts.txt

# 3. Editar el fichero scan-profiles.json
# Contiene la configuración de los escaneos que se lanzarán
notepad scan-profiles.json
```

---

## Uso Básico

### Formatos Soportados en Archivo de Hosts

```text
# Comentarios - ignorados
192.168.1.10                  # IP individual
192.168.1.0/24                # CIDR (expande a 254 hosts: .1-.254)
10.0.0.0/16                   # CIDR grande (65,534 hosts)
server.example.com            # Hostname
web01.domain.local            # FQDN
```

### Comandos Básicos

```powershell
# Escaneo simple
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000

# Con exclusiones
.\scanyx.ps1 -HostFile hosts.txt -ExcludeFile gateways.txt -ScanType tcp-full

# Hosts sensibles (menos agresivo)
.\scanyx.ps1 -HostFile hosts.txt -SensitiveFile production.txt -ScanType tcp-1000

# Workflow progresivo
.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery -MaxConcurrent 10
```

### Modo Wizard (Configuración Interactiva) 🧙

El modo wizard guía paso a paso en la configuración del escaneo, ideal para nuevos usuarios o configuraciones complejas.

```powershell
# Iniciar wizard interactivo
.\scanyx.ps1 -Wizard
```

**Características del Wizard:**
- **10 pasos guiados**: Configuración completa paso a paso
- **Validación en tiempo real**: Detecta errores antes de ejecutar
- **Visualización del comando**: Muestra el comando completo generado
- **Reutilizable**: Copia el comando para futuras ejecuciones

**Flujo del Wizard:**
1. **Tipo de Escaneo**: Selección de perfil o workflow
2. **Hosts**: Archivo o entrada directa de IPs/CIDRs
3. **Nombre de Sesión**: Identificador personalizado (opcional)
4. **Exclusiones**: Hosts a omitir del escaneo
5. **Hosts Sensibles**: Configuración de escaneo menos agresivo
6. **Rendimiento**: Concurrencia, reintentos, delays
7. **Salida**: Directorio, modo de sobrescritura, verbose
8. **Opciones Avanzadas**: Modo no privilegiado, config personalizada
9. **Resumen**: Vista previa de toda la configuración
10. **Confirmación**: Ejecutar o cancelar

---

## Parámetros

### Tabla Maestra de Parámetros

| Parámetro | Tipo | Por Defecto | Descripción |
|-----------|------|-------------|-------------|
| **OBLIGATORIOS (uno requerido)** |
| `-HostFile` | String | - | Archivo con hosts a escanear (IPs, CIDR, hostnames) |
| `-ScanType` | String | - | Tipo de escaneo (ver [tipos](#tipos-de-escaneo-y-workflows)). Mutuamente excluyente con `-Workflow` |
| `-Workflow` | String | - | Nombre del workflow a ejecutar. Mutuamente excluyente con `-ScanType` |
| **ARCHIVOS DE ENTRADA** |
| `-ExcludeFile` | String | - | Archivo con hosts a excluir del escaneo |
| `-SensitiveFile` | String | - | Archivo con hosts sensibles (timing/scripts personalizados) |
| `-ConfigFile` | String | `scan-profiles.json` | Archivo de configuración con perfiles y workflows |
| **HOSTS SENSIBLES** |
| `-SensitiveHosts` | String[] | - | Array de hosts sensibles (alternativa a `-SensitiveFile`) |
| `-SensitiveTiming` | String | `T2` | Timing de Nmap para hosts sensibles: T0, T1, T2, T3, T4 |
| `-SensitiveScripts` | String | `default` | NSE scripts: default, vuln, none, default+vuln |
| **RENDIMIENTO** |
| `-MaxConcurrent` | Int | `5` | Hosts escaneados simultáneamente (1-50) |
| `-MaxRetries` | Int | `1` | Reintentos para hosts fallidos (0-10) |
| `-RetryDelay` | Int | `60` | Segundos entre reintentos (0-3600) |
| **CONFIGURACIÓN** |
| `-OutputDir` | String | `nmap` | Directorio de salida para resultados |
| `-OverwriteMode` | String | `Ask` | Modo sobrescritura: Skip, Overwrite, Ask |
| `-WorkflowCondition` | String | `always` | Condición para pasos: always, previous_success, previous_has_results |
| `-ResolveHostnames` | Switch | - | Resuelve hostnames a IPs para matching de exclusiones |
| `-VerboseMode` | Switch | - | Muestra comandos nmap completos y salida en tiempo real |
| `-Wizard` | Switch | - | Modo interactivo: configuración guiada paso a paso (ideal para principiantes) |
| **GESTIÓN DE SESIONES** |
| `-SessionName` | String | - | Nombre personalizado para la sesión (3-50 caracteres, alfanuméricos + guiones) |
| `-ListSessions` | Switch | - | Lista todas las sesiones disponibles y sale |
| `-ResumeSession` | String | - | Reanuda sesión específica por nombre |
| **GESTIÓN DE ESTADO** (mutuamente excluyentes) |
| `-Resume` | Switch | - | Continúa solo hosts pendientes (salta completados y fallidos) |
| `-ResumeRetryFailed` | Switch | - | Continúa hosts pendientes Y reintenta fallidos |
| `-ResumeRetryDead` | Switch | - | Continúa pendientes, reintenta fallidos y reescanea hosts sin puertos abiertos |
| `-RetryFailed` | Switch | - | Solo reintenta hosts fallidos |
| `-RetryDead` | Switch | - | Reescanea SOLO hosts completados sin puertos abiertos. Salta pendientes, fallidos y vivos. [Ver guía](#modos-de-reanudación) |
| `-Force` | Switch | - | Ignora estado previo e inicia desde cero (archiva estado antiguo) |

---

## Tipos de Escaneo y Workflows

### Tipos de Escaneo (ScanType)

| Tipo | Puertos | Velocidad | Comando Base |
|------|---------|-----------|--------------|
| `tcp-1000` | Top 1000 TCP | ⚡⚡⚡ Rápido | `nmap -sS -T4 --script=default,vuln -A` |
| `tcp-full` | 65535 TCP | ⚡ Lento | `nmap -sS -T4 --script=default,vuln -A -p-` |
| `udp-common` | UDP comunes | ⚡⚡ Medio | `nmap -sU -T4 -p 53,67,69,123,137,161...` |
| `udp-1000` | Top 1000 UDP | ⚡ Lento | `nmap -sU -T4` |
| `udp-full` | 65535 UDP | 🐢 Muy lento | `nmap -sU -T4 -p-` |

> **Nota**: Todos los perfiles incluyen `--host-timeout 60m` y `-Pn` (sin ping). Los scans TCP usan `-sS` (requiere admin/root). Esto es configurable desde el fichero `scan-profiles.json`.

### Workflows

Los workflows encadenan múltiples perfiles secuencialmente. Configurables en `scan-profiles.json`.

**Workflow incluido**: `full-discovery`
```
Step 1: tcp-1000 (quick recon)
   ↓
Step 2: tcp-full (solo si step 1 exitoso)
   ↓
Step 3: udp-common (solo si step 2 encuentra puertos)
```

**Condiciones disponibles**:
- `always`: Siempre ejecuta el paso
- `previous_success`: Solo si el anterior completó sin errores
- `previous_has_results`: Solo si el anterior encontró puertos abiertos

**Uso**:
```powershell
# Ejecutar workflow
.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery

# Forzar todas las condiciones a "always"
.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery -WorkflowCondition always

# Workflow con hosts sensibles
.\scanyx.ps1 -HostFile hosts.txt -SensitiveFile prod.txt -Workflow full-discovery
```

**Estructura de salida**:
```
workflows/
└── full-discovery/
    ├── step-1-tcp-1000/
    │   ├── networks/
    │   └── hosts/
    ├── step-2-tcp-full/
    └── step-3-udp-common/
```

---

## Gestión de Sesiones

SCANYX incluye un sistema completo de gestión de sesiones que permite crear, listar y reanudar escaneos con nombres personalizados.

### Características

- **Nombres Personalizados**: Asigna nombres descriptivos a tus sesiones de escaneo
- **Múltiples Sesiones**: Ejecuta y gestiona múltiples sesiones simultáneamente
- **Listado de Sesiones**: Ve todas las sesiones disponibles con su estado y progreso
- **Reanudación por Nombre**: Reanuda cualquier sesión específica por su nombre
- **Organización Automática**: Cada sesión tiene su propia carpeta `.sessions/<nombre>/`

### Estructura de Archivos

```
OutputDir/
├── .sessions/
│   ├── pentest-cliente-2025/
│   │   ├── scan-state.json
│   │   ├── scan.log
│   │   ├── scan-errors.log
│   │   └── scan-results.json
│   ├── weekly-scan/
│   │   └── ...
│   └── infrastructure-audit/
│       └── ...
├── networks/                 # Resultados compartidos
│   └── 192.168.1.0-24/
└── hosts/                    # Resultados compartidos
    └── ...
```

### Crear Sesión con Nombre

```powershell
# Sesión de pentest
.\scanyx.ps1 `
    -HostFile targets.txt `
    -ScanType tcp-1000 `
    -SessionName "pentest-cliente-2025"

# Workflow con nombre descriptivo
.\scanyx.ps1 `
    -HostFile networks.txt `
    -Workflow full-discovery `
    -SessionName "infrastructure-audit-Q4"

# Escaneo semanal automatizado
.\scanyx.ps1 `
    -HostFile hosts.txt `
    -ScanType tcp-1000 `
    -SessionName "weekly-scan-$(Get-Date -Format 'yyyy-MM-dd')"
```

### Listar Sesiones Disponibles

```powershell
# Listar todas las sesiones
.\scanyx.ps1 -ListSessions

# Listar sesiones en OutputDir específico
.\scanyx.ps1 -ListSessions -OutputDir "C:\Scans\Project1"
```

**Salida ejemplo**:
```
Available Sessions in: nmap/

┌─────────────────────────────────────────────────────────────────────┐
│ Session: pentest-cliente-2025                                       │
├─────────────────────────────────────────────────────────────────────┤
│ Type       : tcp-1000                                               │
│ Status     : in_progress                                            │
│ Progress   : 350/1000 (35.0%) | Success: 340 | Failed: 10          │
│ Started    : 2025-10-11 14:30:00                                   │
│ Elapsed    : 2h 45m                                                │
│ State File : .sessions/pentest-cliente-2025/scan-state.json        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ Session: weekly-scan-2025-10-07                                     │
├─────────────────────────────────────────────────────────────────────┤
│ Type       : Workflow: full-discovery                               │
│ Status     : completed                                              │
│ Progress   : 500/500 (100.0%) | Success: 485 | Failed: 15          │
│ Started    : 2025-10-07 02:00:00                                   │
│ Duration   : 12h 34m                                               │
│ State File : .sessions/weekly-scan-2025-10-07/scan-state.json      │
└─────────────────────────────────────────────────────────────────────┘

Total: 2 session(s) found
```

### Reanudar Sesión por Nombre

```powershell
# Reanudar solo hosts pendientes
.\scanyx.ps1 -ResumeSession "pentest-cliente-2025" -Resume

# Reanudar y reintentar fallidos
.\scanyx.ps1 -ResumeSession "pentest-cliente-2025" -ResumeRetryFailed

# Solo reintentar hosts fallidos de una sesión
.\scanyx.ps1 -ResumeSession "infrastructure-audit-Q4" -RetryFailed

# Reanudar con parámetros modificados
.\scanyx.ps1 `
    -ResumeSession "pentest-cliente-2025" `
    -Resume `
    -MaxConcurrent 20  # Aumentar concurrencia
```

### Requisitos de Nombres de Sesión

Los nombres de sesión deben cumplir:
- **Longitud**: 3-50 caracteres
- **Caracteres permitidos**: Letras, números, guiones (`-`), guiones bajos (`_`)
- **No permitido**: Espacios, caracteres especiales

**Ejemplos válidos**:
```
"pentest-cliente-2025"
"weekly_scan_october"
"infrastructure-audit-phase1"
"internal-network-sweep"
"vuln-assessment-2025-Q4"
```

**Ejemplos inválidos**:
```
"ab"                           # Muy corto (<3 caracteres)
"sesión con espacios"          # Contiene espacios
"scan/network"                 # Contiene /
"nombre-demasiado-largo-..."   # >50 caracteres
```

### Casos de Uso

#### Proyectos de Pentesting
```powershell
# Fase 1: Reconocimiento
.\scanyx.ps1 -HostFile external.txt -ScanType tcp-1000 -SessionName "client-pentest-phase1"

# Fase 2: Escaneo profundo (días después)
.\scanyx.ps1 -HostFile discovered.txt -Workflow full-discovery -SessionName "client-pentest-phase2"

# Listar todas las sesiones
.\scanyx.ps1 -ListSessions
```

#### Escaneos Programados
```powershell
# Script automatizado
$sessionName = "daily-scan-$(Get-Date -Format 'yyyy-MM-dd')"
.\scanyx.ps1 -HostFile monitored-hosts.txt -ScanType tcp-1000 -SessionName $sessionName

# Ver histórico de escaneos diarios
.\scanyx.ps1 -ListSessions | Select-String "daily-scan"
```

### Sesiones Automáticas

Si no usas `-SessionName`, el script crea automáticamente un nombre con formato `yyyyMMdd-HHmmss_session` (ej: `20251013-142032_session`).

**TODAS las sesiones** (con nombre o automáticas) usan la estructura `.sessions/`:
- Sesión con nombre: `.sessions/pentest-cliente-2025/`
- Sesión automática: `.sessions/20251013-142032_session/`

Esto asegura que `-ListSessions` encuentre todas las sesiones, sin importar cómo se crearon.

---

## Ejemplos Esenciales

### 1. Escaneo Básico de Red
```powershell
# Escanear red con top 1000 puertos TCP
.\scanyx.ps1 -HostFile networks.txt -ScanType tcp-1000
```

### 2. Escaneo Paralelo
```powershell
# 15 hosts simultáneos, skip existentes
.\scanyx.ps1 `
    -HostFile hosts.txt `
    -ScanType tcp-full `
    -MaxConcurrent 10 `
    -OverwriteMode Skip
```

### 3. Escaneo con Exclusiones y Resolución DNS
```powershell
# Escanear red excluyendo gateways, resolviendo hostnames
.\scanyx.ps1 `
    -HostFile networks.txt `
    -ExcludeFile gateways.txt `
    -ResolveHostnames `
    -ScanType tcp-1000 `
    -MaxConcurrent 10
```

### 4. Hosts Sensibles con Configuración Personalizada
```powershell
# Escaneo diferenciado: normal (T4) vs sensible (T2)
.\scanyx.ps1 `
    -HostFile all_hosts.txt `
    -SensitiveFile production_servers.txt `
    -ExcludeFile excluded.txt `
    -ScanType tcp-1000 `
    -SensitiveTiming T2 `
    -SensitiveScripts default `
    -MaxConcurrent 10
```

### 5. Workflow Progresivo con Verbose
```powershell
# Ver comandos nmap en tiempo real
.\scanyx.ps1 `
    -HostFile hosts.txt `
    -Workflow full-discovery `
    -VerboseMode `
    -MaxConcurrent 5
```

### 6. Reanudar Escaneo Interrumpido

> **💡 Ver [Modos de Reanudación](#modos-de-reanudación) para guía completa sobre cuándo usar cada modo.**

```powershell
# Escaneo interrumpido → continuar solo pendientes
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Resume

# Escaneo interrumpido + errores → continuar + reintentar fallidos
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -ResumeRetryFailed

# Escaneo completo → verificar hosts "muertos" (sin puertos)
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -ResumeRetryDead

# Solo reintentar hosts fallidos (salta pendientes)
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -RetryFailed

# Solo reescanear hosts muertos (salta fallidos y pendientes)
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -RetryDead

# Empezar desde cero (ignora estado previo)
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Force
```

### 7. Reintentos de escaneos fallidos
```powershell
# 3 reintentos con delay de 30 segundos
.\scanyx.ps1 `
    -HostFile hosts.txt `
    -ScanType tcp-1000 `
    -MaxRetries 3 `
    -RetryDelay 30 `
    -MaxConcurrent 10
```


---

## Gestión Avanzada

### CIDR, Exclusiones y Hosts Sensibles

#### Expansión Automática de CIDR

El script expande rangos CIDR automáticamente (excluye network/broadcast).

| CIDR | Hosts Generados | Rango |
|------|-----------------|-------|
| `192.168.1.0/24` | 254 | 192.168.1.1 - 192.168.1.254 |
| `10.0.0.0/16` | 65,534 | 10.0.0.1 - 10.0.255.254 |
| `172.16.5.0/28` | 14 | 172.16.5.1 - 172.16.5.14 |
| `10.10.10.10/32` | 1 | 10.10.10.10 |

**Advertencias**: CIDR >5000 hosts muestra warning pero continúa.

#### Ejemplo Práctico Completo

**networks.txt** (762 hosts tras expansión):
```text
192.168.1.0/24    # 254 hosts
192.168.2.0/24    # 254 hosts
10.0.0.0/24       # 254 hosts
```

**excluded.txt** (19 hosts):
```text
# Gateways
192.168.1.1
192.168.2.1
10.0.0.1

# Servidores críticos
192.168.1.10
192.168.1.20

# Rango de impresoras
192.168.2.240/28  # 14 hosts
```

**sensitive.txt** (16 hosts):
```text
# Servidores de producción
192.168.1.10
192.168.1.20

# Dispositivos de red
192.168.2.0/28    # 14 hosts
```

**Resultado del procesamiento**:
- Total después de expansión: 762 hosts
- Excluidos: 19 hosts
- **Hosts normales**: 727 hosts → escaneo con `-T4 --script=default,vuln`
- **Hosts sensibles**: 16 hosts → escaneo con `-T2 --script=default`
- **Total a escanear**: 743 hosts

> **Importante**: Si un host aparece en HostFile Y SensitiveFile, se marca como sensible (no se escanea dos veces).

**Comando**:
```powershell
.\scanyx.ps1 `
    -HostFile networks.txt `
    -SensitiveFile sensitive.txt `
    -ExcludeFile excluded.txt `
    -ScanType tcp-1000 `
    -SensitiveTiming T2 `
    -MaxConcurrent 10
```

#### Resolución de Hostnames (`-ResolveHostnames`)

**Sin `-ResolveHostnames`**:
- Solo coincidencia exacta de strings
- Si `excluded.txt` tiene `server.domain.local`, pero `hosts.txt` tiene `192.168.1.50`, NO se excluye

**Con `-ResolveHostnames`**:
- Resuelve hostnames a IPs
- Si `server.domain.local` → `192.168.1.50`, ambas formas se excluyen

**Nota**: Puede ser lento para listas grandes.

> **💡 Ver [Modos de Reanudación](#modos-de-reanudación) para información sobre gestión de estado y reanudación de escaneos.**

---

## Archivos de Salida

### Estructura de Directorios

```
nmap/                                    # OutputDir (configurable)
├── networks/                            # Hosts de rangos CIDR
│   ├── 192.168.1.0-24/
│   │   ├── 192.168.1.10_tcp-1000.nmap   # Resultado Nmap
│   │   ├── 192.168.1.10_tcp-1000.xml    # XML parseable
│   │   ├── 192.168.1.10_tcp-1000.gnmap  # Grep-friendly
│   │   ├── 192.168.1.10_tcp-1000.stdout # Salida estándar
│   │   └── 192.168.1.10_tcp-1000.stderr # Errores
│   └── 10.0.0.0-16/
│       └── ...
├── hosts/                               # Hosts individuales
│   ├── 192.168.2.100/
│   │   └── ...
│   └── server.example.com/
│       └── ...
├── scan.log                             # Log completo (texto)
├── scan-errors.log                      # Solo errores
├── scan-results.json                    # Resultados estructurados
└── scan-state.json                      # Estado para reanudación
```

> **Nota**: Hosts sensibles NO tienen sufijos especiales. La diferenciación está en `scan-state.json`.

### Logs

**scan.log** (con colores):
```
[2025-10-10 14:30:00] [INFO] Scan started: 192.168.1.10 | tcp-1000
[2025-10-10 14:35:47] [SUCCESS] Scan completed: 192.168.1.10 | tcp-1000 | Duration: 5m 47s
[2025-10-10 14:36:00] [ERROR] Scan failed: 192.168.1.11 | tcp-1000 | Host timeout
```

**scan-errors.log**:
Solo entradas `[ERROR]` para troubleshooting rápido.

**scan-results.json**:
```json
{
  "scan_session": "2025-10-10_143000",
  "scans": [
    {
      "host": "192.168.1.10",
      "scan_type": "tcp-1000",
      "status": "completed",
      "duration_seconds": 347,
      "attempts": 1
    }
  ]
}
```

---

## Troubleshooting

### FAQ - Problemas Comunes

#### 🔄 Quiero cancelar y reiniciar
**Solución**:
```powershell
# Cancelar: Ctrl+C (limpieza automática de jobs)

# Reiniciar desde cero
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Force
```

#### 🔒 Errores de permisos (Windows)
**Solución**: Ejecutar PowerShell como Administrador
- Los escaneos SYN (`-sS`) requieren privilegios elevados
- Click derecho → "Ejecutar como administrador"

#### 📁 Archivos de salida no se crean
**Verificar**:
```powershell
# 1. Comprobar permisos de escritura
Test-Path -Path ".\nmap" -PathType Container

# 2. Verificar que nmap genera salida
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -VerboseMode

# 3. Revisar stderr files
Get-Content nmap/hosts/*/*.stderr
```

#### ⚠️ "CONFLICT: host is in both sensitive and excluded lists"
**Explicación**: El host aparece en ambas listas.
**Comportamiento**: La exclusión gana, el host NO se escanea.
**Solución**: Revisar y corregir los archivos para evitar conflictos.

---

## Integración

### Post-Procesamiento con XNP

Usa [XtremeNmapParser (XNP)](https://github.com/xtormin/XtremeNmapParser) para fusionar resultados:

```bash
# Fusionar todos los XMLs con salida en formato Excel, CVS y JSON
python3 xnp.py -d nmap/ -M -R --open -C all
```

## Cheatsheet básico

| Tarea | Comando |
|-------|---------|
| Escaneo básico | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000` |
| Escaneo con nombre | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -SessionName "pentest-2025"` |
| Listar sesiones | `.\scanyx.ps1 -ListSessions` |
| Reanudar sesión | `.\scanyx.ps1 -ResumeSession "pentest-2025" -Resume` |
| Escaneo rápido paralelo | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -MaxConcurrent 20` |
| Con exclusiones | `.\scanyx.ps1 -HostFile hosts.txt -ExcludeFile excluded.txt -ScanType tcp-1000` |
| Hosts sensibles | `.\scanyx.ps1 -HostFile hosts.txt -SensitiveFile prod.txt -ScanType tcp-1000 -SensitiveTiming T2` |
| Workflow completo | `.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery -MaxConcurrent 10` |
| Reanudar interrumpido | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Resume` |
| Reintentar fallidos | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -RetryFailed` |
| Solo verificar hosts muertos | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -RetryDead` |
| Reescanear hosts muertos | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -ResumeRetryDead` |
| Empezar desde cero | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Force` |
| Modo verbose | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -VerboseMode` |

> **💡 Tip**: Ver [Modos de Reanudación](#modos-de-reanudación) para guía detallada de cuándo usar cada comando.

---

## Registro de Cambios

### Versión 2.7 (2025-10-13)
- ✨ Sistema de workflows para encadenar múltiples perfiles secuencialmente
- ✨ Gestión de sesiones
- ✨ Configuración externa en JSON (`scan-profiles.json`)
- ✨ Modo verbose (`-VerboseMode`) para debugging
- ✨ Condiciones de ejecución para pasos de workflow
- 🔧 Mejoras en detección de escaneos fallidos
- 📚 README optimizado y simplificado

### Versión 2.6 (2025-03-05)
- 🐛 Corrección de clasificación de hosts sensibles
- ⚡ Optimización con hashtables para búsquedas

### Versión 2.1-2.5 (2024-11-21)
- ✨ Soporte completo para notación CIDR
- ✨ Sistema de exclusión de hosts (`-ExcludeFile`)
- ✨ Resolución de hostnames (`-ResolveHostnames`)
- ✨ Expansión automática de CIDR con deduplicación
- ✨ Detección de conflictos entre listas
- 📊 Logging mejorado

> Este script se proporciona con fines educativos y de pruebas de seguridad autorizadas únicamente. Escanea redes y sistemas para los que tienes permiso explícito.

# Redes sociales

* Website: https://xtormin.com
* Linkedin: https://www.linkedin.com/in/xtormin/
* Instagram: https://www.instagram.com/xtormin/