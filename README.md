# SCANYX - Scan Analysis eXecution v2.7

Script avanzado de PowerShell para escaneo automatizado de redes usando Nmap con ejecución paralela, persistencia de estado, soporte CIDR, hosts sensibles, workflows y registro completo.

**SCANYX** (Scan Analysis eXecution) es una herramienta de pentesting diseñada para automatizar y gestionar escaneos de red complejos con capacidades avanzadas de workflow y logging.

## Tabla de Contenidos

- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Inicio Rápido](#inicio-rápido)
- [Parámetros](#parámetros)
- [Tipos de Escaneo](#tipos-de-escaneo)
- [Workflows](#workflows)
- [Ejemplos de Uso](#ejemplos-de-uso)
- [Soporte CIDR y Exclusiones](#soporte-cidr-y-exclusiones)
- [Hosts Sensibles](#hosts-sensibles)
- [Gestión de Estado](#gestión-de-estado)
- [Archivos de Salida](#archivos-de-salida)
- [Características Avanzadas](#características-avanzadas)
- [Solución de Problemas](#solución-de-problemas)
- [Integración](#integración)

---

## Características

- **Escaneo Paralelo**: Escanea múltiples hosts concurrentemente (configurable 1-50)
- **Soporte CIDR**: Acepta notación CIDR para escanear rangos completos de red
- **Exclusión de Hosts**: Archivo separado para excluir hosts específicos del escaneo
- **Hosts Sensibles**: Escaneo diferenciado para hosts críticos con timing y scripts personalizados
- **Persistencia de Estado**: Reanuda escaneos interrumpidos desde donde se detuvieron
- **Registro Completo**: Tres formatos de log (texto, JSON, errores)
- **Reintentos Automáticos**: Mecanismo de reintento configurable para escaneos fallidos
- **Seguimiento de Progreso**: Barra de progreso en tiempo real con estadísticas
- **Validación de Entradas**: Valida IPs, CIDR, hostnames y dependencias
- **Opciones Flexibles de Reanudación**: Múltiples modos para continuar escaneos previos
- **Protección contra Sobrescritura**: Controla el comportamiento para resultados existentes
- **Resolución de Hostnames**: Opción para resolver nombres a IPs en exclusiones
- **Estructura Jerárquica**: Separa resultados de redes CIDR y hosts individuales
- **Detección de Conflictos**: Identifica y resuelve hosts en múltiples listas
- **Manejo de Ctrl+C**: Cierre limpio con limpieza de trabajos
- **Workflows**: Encadena múltiples perfiles de escaneo secuencialmente
- **Configuración Externa**: Perfiles de escaneo y workflows en JSON
- **Modo Verbose**: Muestra comandos nmap y salida en vivo

---

## Requisitos

- **PowerShell**: Versión 5.1 o superior
- **Nmap**: Debe estar instalado y disponible en PATH
  - Windows: Descargar desde [nmap.org](https://nmap.org/download.html)
  - Linux: `sudo apt install nmap` o `sudo yum install nmap`
  - macOS: `brew install nmap`

### Verificar Instalación de Nmap

```powershell
nmap --version
```

---

## Instalación

1. Clona o descarga este repositorio
2. Asegúrate de que Nmap esté instalado y en tu PATH
3. Crea un archivo de hosts con IPs/hostnames objetivo (uno por línea)

---

## Inicio Rápido

### Escaneo Básico

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000
```

### Crear un Archivo de Hosts

Crea `hosts.txt` con tus hosts objetivo. Soporta **IPs individuales**, **notación CIDR** y **hostnames**:

```text
# IPs individuales
192.168.1.10
192.168.1.20

# Rangos CIDR (se expanden automáticamente)
192.168.1.0/24
10.0.0.0/16

# Hostnames
server.example.com
web.domain.local

# Esto es un comentario - será ignorado
```

### Archivo de Exclusión (Opcional)

Crea `excluded.txt` para excluir hosts específicos:

```text
# IPs a excluir
192.168.1.1
192.168.1.254

# Rangos CIDR a excluir
192.168.1.240/28

# Hostnames a excluir
gateway.example.com
```

---

## Parámetros

### Parámetros Obligatorios

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `-HostFile` | String | Ruta al archivo de texto con los hosts a escanear. Soporta: IPs, CIDR, hostnames (uno por línea) |
| `-ScanType` | String | Tipo de escaneo a realizar (ver [Tipos de Escaneo](#tipos-de-escaneo)). Mutuamente excluyente con `-Workflow` |
| `-Workflow` | String | Nombre del workflow a ejecutar (ver [Workflows](#workflows)). Mutuamente excluyente con `-ScanType` |

> **Nota**: Debes especificar `-ScanType` O `-Workflow`, pero no ambos.

### Parámetros Opcionales

| Parámetro | Tipo | Por Defecto | Rango/Opciones | Descripción |
|-----------|------|-------------|----------------|-------------|
| `-ExcludeFile` | String | _(ninguno)_ | Cualquier ruta válida | Archivo con hosts a excluir (soporta IPs, CIDR, hostnames) |
| `-SensitiveFile` | String | _(ninguno)_ | Cualquier ruta válida | Archivo con hosts sensibles (timing y scripts personalizados) |
| `-SensitiveTiming` | String | `"T2"` | T0, T1, T2, T3, T4 | Timing template de Nmap para hosts sensibles |
| `-SensitiveScripts` | String | `"default"` | default, vuln, none, default+vuln | NSE scripts para hosts sensibles |
| `-ResolveHostnames` | Switch | `$false` | - | Resuelve hostnames a IPs para matching de exclusiones (puede ser lento) |
| `-OutputDir` | String | `"nmap"` | Cualquier ruta válida | Directorio de salida para resultados |
| `-MaxConcurrent` | Int | `5` | 1-50 | Número máximo de escaneos concurrentes |
| `-MaxRetries` | Int | `1` | 0-10 | Intentos máximos de reintento para escaneos fallidos |
| `-RetryDelay` | Int | `60` | 0-3600 | Delay en segundos entre reintentos |
| `-OverwriteMode` | String | `"Ask"` | Skip, Overwrite, Ask | Comportamiento cuando ya existen resultados |
| `-WorkflowCondition` | String | `"always"` | always, previous_success, previous_has_results | Condición para ejecutar pasos del workflow |
| `-VerboseMode` | Switch | `$false` | - | Muestra comandos nmap y salida en vivo |
| `-ConfigFile` | String | `"scan-profiles.json"` | Cualquier ruta válida | Archivo de configuración con perfiles y workflows |

### Parámetros de Gestión de Estado (Mutuamente Excluyentes)

| Parámetro | Descripción |
|-----------|-------------|
| `-Resume` | Continúa escaneando solo hosts pendientes (salta completados y fallidos) |
| `-ResumeRetryFailed` | Continúa hosts pendientes Y reintenta hosts fallidos |
| `-RetryFailed` | Solo reintenta hosts que fallaron previamente |
| `-Force` | Ignora estado previo e inicia desde cero (archiva estado antiguo) |

> **Nota**: Solo un parámetro de gestión de estado puede usarse a la vez. Si no se especifica ninguno y existe un estado previo, el script preguntará interactivamente.

---

## Tipos de Escaneo

| Tipo de Escaneo | Descripción | Comando Nmap |
|-----------------|-------------|--------------|
| `tcp-1000` | Top 1000 puertos TCP (rápido) | `nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m` |
| `tcp-full` | Todos los 65535 puertos TCP (completo) | `nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m -p-` |
| `udp-common` | Puertos UDP comunes | `nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m -p '53,67,69,11,123,137,161,500,514,520,563'` |
| `udp-1000` | Top 1000 puertos UDP | `nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m` |
| `udp-full` | Todos los 65535 puertos UDP (muy lento) | `nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m -p-` |

> **Nota**: Los perfiles de escaneo se cargan desde el archivo `scan-profiles.json`. Puedes personalizarlos editando ese archivo.

### Desglose de Puertos UDP Comunes

- **53**: DNS
- **67**: DHCP (Servidor)
- **69**: TFTP
- **11**: Systat
- **123**: NTP
- **137**: NetBIOS Name Service
- **161**: SNMP
- **500**: IPsec/IKE
- **514**: Syslog
- **520**: RIP
- **563**: SNMP over TLS

---

## Workflows

Los workflows permiten encadenar múltiples perfiles de escaneo secuencialmente, ejecutando cada paso en todos los hosts antes de pasar al siguiente. Esto es útil para estrategias de escaneo progresivo (ej. reconocimiento rápido → escaneo completo → enumeración de servicios).

### Características de Workflows

- **Ejecución Secuencial**: Cada paso se ejecuta en TODOS los hosts antes de continuar al siguiente paso
- **Configuración Externa**: Los workflows se definen en `scan-profiles.json`
- **Condiciones de Ejecución**: Control sobre cuándo ejecutar cada paso
- **Estructura Organizada**: Resultados en `workflows/{nombre}/step-{N}-{perfil}/`
- **Estado Persistente**: Cada paso puede reanudarse independientemente

### Definición de Workflows

Los workflows se definen en el archivo `scan-profiles.json`:

```json
{
  "profiles": {
    "tcp-1000": {
      "name": "TCP Top 1000",
      "command": "nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m"
    },
    "tcp-full": {
      "name": "TCP Full Port Scan",
      "command": "nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m -p-"
    }
  },
  "workflows": {
    "full-discovery": {
      "name": "Full Network Discovery",
      "description": "Complete network discovery workflow from fast recon to full enumeration",
      "steps": [
        {
          "profile": "tcp-1000",
          "description": "Quick port scan to identify live hosts and common services",
          "condition": "always"
        },
        {
          "profile": "tcp-full",
          "description": "Comprehensive scan of all TCP ports",
          "condition": "previous_success"
        },
        {
          "profile": "udp-common",
          "description": "Scan common UDP services",
          "condition": "previous_has_results"
        }
      ]
    }
  }
}
```

### Condiciones de Ejecución

Cada paso del workflow puede tener una condición:

| Condición | Descripción | Uso Recomendado |
|-----------|-------------|-----------------|
| `always` | Siempre ejecuta el paso | Primer paso o pasos independientes |
| `previous_success` | Solo si el paso anterior completó exitosamente | Escaneos dependientes del anterior |
| `previous_has_results` | Solo si el paso anterior encontró puertos/servicios | Enumeración profunda condicional |

> **Nota**: Puedes sobrescribir la condición por defecto usando el parámetro `-WorkflowCondition`.

### Estructura de Salida de Workflows

Los resultados de workflows se organizan por paso:

```
workflows/
└── full-discovery/
    ├── step-1-tcp-1000/
    │   ├── networks/
    │   │   └── 192.168.1.0-24/
    │   │       ├── 192.168.1.10_tcp-1000.nmap
    │   │       └── 192.168.1.10_tcp-1000.xml
    │   └── hosts/
    │       └── server.example.com/
    │           └── server.example.com_tcp-1000.nmap
    ├── step-2-tcp-full/
    │   ├── networks/
    │   └── hosts/
    ├── step-3-udp-common/
    │   ├── networks/
    │   └── hosts/
    ├── scan.log
    ├── scan-errors.log
    ├── scan-results.json
    └── scan-state.json
```

### Ejemplos de Workflows

#### Ejemplo 1: Workflow Básico
```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -Workflow full-discovery
```

#### Ejemplo 2: Workflow con Condición Personalizada
```powershell
.\scanyx.ps1 `
    -HostFile .\hosts.txt `
    -Workflow full-discovery `
    -WorkflowCondition always
```

#### Ejemplo 3: Workflow con Hosts Sensibles
```powershell
.\scanyx.ps1 `
    -HostFile .\networks.txt `
    -SensitiveFile .\production.txt `
    -Workflow full-discovery `
    -SensitiveTiming T2 `
    -MaxConcurrent 10
```

#### Ejemplo 4: Reanudar Workflow Interrumpido
```powershell
.\scanyx.ps1 `
    -HostFile .\hosts.txt `
    -Workflow full-discovery `
    -Resume
```

### Casos de Uso de Workflows

#### Reconocimiento Progresivo
```json
{
  "progressive-recon": {
    "name": "Progressive Reconnaissance",
    "description": "Quick to comprehensive scanning strategy",
    "steps": [
      {
        "profile": "tcp-1000",
        "description": "Fast identification of common services",
        "condition": "always"
      },
      {
        "profile": "tcp-full",
        "description": "Full TCP port scan on responsive hosts",
        "condition": "previous_success"
      }
    ]
  }
}
```

#### Auditoría Completa
```json
{
  "full-audit": {
    "name": "Complete Security Audit",
    "description": "Comprehensive security assessment workflow",
    "steps": [
      {
        "profile": "tcp-1000",
        "description": "Initial TCP reconnaissance",
        "condition": "always"
      },
      {
        "profile": "udp-common",
        "description": "Common UDP services discovery",
        "condition": "always"
      },
      {
        "profile": "tcp-full",
        "description": "Exhaustive TCP port enumeration",
        "condition": "previous_has_results"
      }
    ]
  }
}
```

### Ventajas de Workflows

- **Estrategia Organizada**: Define tu metodología de escaneo en un archivo reutilizable
- **Ahorro de Tiempo**: Automatiza secuencias de escaneos sin intervención manual
- **Trazabilidad**: Cada paso queda claramente separado en carpetas
- **Reanudación**: Puedes reanudar desde cualquier paso interrumpido
- **Condicional**: Ejecuta pasos costosos solo cuando hay resultados previos

---

## Archivo de Configuración

### Ubicación por Defecto
Por defecto, el script usa `scan-profiles.json` en el mismo directorio que el script.

### Archivo de Configuración Personalizado
Usa `-ConfigFile` para especificar una configuración personalizada:

```powershell
.\scanyx.ps1 `
    -HostFile hosts.txt `
    -ScanType tcp-1000 `
    -ConfigFile "C:\Configs\my-custom-profiles.json"
```

### Múltiples Configuraciones
Útil para diferentes proyectos o escenarios de escaneo:

```powershell
# Escaneo de red interna (con privilegios)
.\scanyx.ps1 -ConfigFile "profiles-internal.json" -HostFile internal-hosts.txt

# Escaneo externo (sin privilegios)
.\scanyx.ps1 -ConfigFile "profiles-external.json" -HostFile external-hosts.txt -Unprivileged
```

### Ejemplo: Crear Configuración Personalizada

```powershell
# Crear configuración personalizada para Windows (sin admin)
$config = @{
    profiles = @{
        "quick-scan" = @{
            name = "Quick Scan"
            command = "nmap -v -T4 -Pn -open -sT --top-ports 100"
        }
        "full-scan" = @{
            name = "Full TCP Scan"
            command = "nmap -v -T4 -Pn -open -sT -A -p-"
        }
    }
    workflows = @{
        "fast-enum" = @{
            name = "Fast Enumeration"
            description = "Quick scan followed by deep scan on discovered hosts"
            steps = @(
                @{
                    profile = "quick-scan"
                    description = "Quick port discovery"
                    condition = "always"
                }
                @{
                    profile = "full-scan"
                    description = "Full scan of responsive hosts"
                    condition = "previous_has_results"
                }
            )
        }
    }
}

# Guardar configuración
$config | ConvertTo-Json -Depth 5 | Out-File "windows-scan.json"

# Usar configuración personalizada
.\scanyx.ps1 `
    -HostFile hosts.txt `
    -ScanType quick-scan `
    -ConfigFile "windows-scan.json"
```

---

## Modos de Escaneo y Privilegios

### Comportamiento por Defecto
Los perfiles de escaneo por defecto usan `-sS` (SYN scan) que requiere **privilegios de administrador**.

### Ejecutar Sin Privilegios

#### Opción 1: Usar -Unprivileged (Automático - Recomendado)
```powershell
.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Unprivileged
```

Esto automáticamente:
- Reemplaza `-sS` con `-sT` (TCP connect scan)
- Añade flag `--unprivileged` a nmap

#### Opción 2: Archivo de Configuración Personalizado
Crea un archivo de configuración con `-sT` en lugar de `-sS`:

```json
{
  "profiles": {
    "tcp-1000": {
      "name": "TCP Top 1000",
      "command": "nmap -v -T4 -Pn -open -sT --script=default,vuln -A --host-timeout 60m"
    },
    "tcp-full": {
      "name": "TCP Full Port Scan",
      "command": "nmap -v -T4 -Pn -open -sT --script=default,vuln -A --host-timeout 60m -p-"
    }
  }
}
```

Luego usa:
```powershell
.\scanyx.ps1 -ConfigFile "unprivileged-profiles.json" -HostFile hosts.txt -ScanType tcp-1000
```

### Comparación de Tipos de Escaneo

| Flag | Nombre | Requiere Admin | Velocidad | Sigilo | Uso Recomendado |
|------|--------|----------------|-----------|--------|-----------------|
| `-sS` | SYN scan | ✅ Sí | Rápido | Mayor | Escaneos internos con permisos |
| `-sT` | TCP Connect | ❌ No | Más lento | Menor | Windows sin admin, escaneos externos |
| `-sU` | UDP scan | ✅ Sí | Lento | Variable | Servicios UDP (DNS, SNMP, etc.) |

### Ejemplos de Uso Sin Privilegios

**Workflow sin privilegios:**
```powershell
.\scanyx.ps1 `
    -HostFile targets.txt `
    -Workflow full-discovery `
    -Unprivileged `
    -VerboseMode
```

**Escaneo directo con configuración personalizada:**
```powershell
.\scanyx.ps1 `
    -Hosts "192.168.1.0/24", "10.0.0.1" `
    -ConfigFile "no-admin-scan.json" `
    -ScanType tcp-1000 `
    -MaxConcurrent 10
```

---

## Ejemplos de Uso

### Ejemplo 1: Escaneo Básico
Escanear hosts con configuración por defecto (5 concurrentes, 1 reintento):

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000
```

### Ejemplo 2: Escaneo de Alto Rendimiento
Escanear con 10 hosts concurrentes, saltando resultados existentes:

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-full -MaxConcurrent 10 -OverwriteMode Skip
```

### Ejemplo 3: Escaneo UDP Completo
Escanear puertos UDP comunes con directorio de salida personalizado:

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType udp-common -OutputDir "C:\Escaneos\2025-10-06"
```

### Ejemplo 4: Estrategia Agresiva de Reintentos
Más reintentos con delays más cortos:

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -MaxRetries 3 -RetryDelay 30
```

### Ejemplo 5: Reanudar Escaneo Previo
Continuar solo con hosts pendientes (saltar completados y fallidos):

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -Resume
```

### Ejemplo 6: Reanudar y Reintentar Fallidos
Continuar hosts pendientes Y reintentar los fallidos:

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -ResumeRetryFailed
```

### Ejemplo 7: Solo Reintentar Hosts Fallidos
Solo reintentar hosts que fallaron en sesión previa:

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -RetryFailed
```

### Ejemplo 8: Forzar Inicio Nuevo
Empezar completamente desde cero, archivando estado previo:

```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -Force
```

### Ejemplo 9: Escaneo con CIDR y Exclusiones
Escanear rangos CIDR excluyendo gateways y servidores críticos:

```powershell
.\scanyx.ps1 `
    -HostFile .\networks.txt `
    -ExcludeFile .\critical_systems.txt `
    -ScanType tcp-1000 `
    -MaxConcurrent 10
```

### Ejemplo 10: Resolución de Hostnames en Exclusiones
Resolver hostnames a IPs para mejor matching de exclusiones:

```powershell
.\scanyx.ps1 `
    -HostFile .\targets.txt `
    -ExcludeFile .\excluded_hosts.txt `
    -ResolveHostnames `
    -ScanType tcp-full
```

### Ejemplo 11: Escaneo con Hosts Sensibles
Diferenciar hosts críticos con parámetros menos agresivos:

```powershell
.\scanyx.ps1 `
    -HostFile .\targets.txt `
    -SensitiveFile .\production_servers.txt `
    -ExcludeFile .\excluded.txt `
    -ScanType tcp-1000 `
    -SensitiveTiming T2 `
    -SensitiveScripts default `
    -MaxConcurrent 10
```

### Ejemplo 12: Workflow de Reconocimiento Progresivo
Ejecutar un workflow que va de reconocimiento rápido a escaneo completo:

```powershell
.\scanyx.ps1 `
    -HostFile .\networks.txt `
    -Workflow full-discovery `
    -MaxConcurrent 10
```

### Ejemplo 13: Workflow con Modo Verbose
Ver comandos y salida de nmap en tiempo real durante el workflow:

```powershell
.\scanyx.ps1 `
    -HostFile .\hosts.txt `
    -Workflow progressive-recon `
    -VerboseMode `
    -MaxConcurrent 5
```

### Ejemplo 14: Workflow con Hosts Sensibles
Ejecutar workflow diferenciando hosts críticos:

```powershell
.\scanyx.ps1 `
    -HostFile .\all_hosts.txt `
    -SensitiveFile .\production_servers.txt `
    -Workflow full-audit `
    -SensitiveTiming T2 `
    -SensitiveScripts default `
    -MaxConcurrent 8
```

### Ejemplo 15: Personalización Completa
Control total sobre todos los parámetros:

```powershell
.\scanyx.ps1 `
    -HostFile "C:\objetivos\networks.txt" `
    -SensitiveFile "C:\objetivos\sensitive.txt" `
    -ExcludeFile "C:\objetivos\excluded.txt" `
    -ScanType tcp-full `
    -OutputDir "C:\PenTest\Cliente_2025\Escaneos" `
    -SensitiveTiming T1 `
    -SensitiveScripts default `
    -MaxConcurrent 15 `
    -MaxRetries 2 `
    -RetryDelay 45 `
    -OverwriteMode Overwrite `
    -ResolveHostnames `
    -Resume
```

---

## Soporte CIDR y Exclusiones

### Notación CIDR

El script soporta notación CIDR para escanear rangos completos de red automáticamente.

#### Rangos Soportados

- **Subnet Mask**: `/8` a `/32`
- **Expansión**: Excluye automáticamente direcciones de red y broadcast
- **Ejemplo**: `192.168.1.0/24` se expande a 254 hosts (`.1` a `.254`)

#### Ejemplos de CIDR

| Notación CIDR | Hosts Generados | Rango |
|---------------|-----------------|-------|
| `192.168.1.0/24` | 254 | 192.168.1.1 - 192.168.1.254 |
| `10.0.0.0/16` | 65,534 | 10.0.0.1 - 10.0.255.254 |
| `172.16.5.0/28` | 14 | 172.16.5.1 - 172.16.5.14 |
| `192.168.1.0/30` | 2 | 192.168.1.1 - 192.168.1.2 |
| `10.10.10.10/32` | 1 | 10.10.10.10 (single host) |

#### Advertencias de CIDR Grandes

- **>5000 hosts**: El script mostrará una advertencia pero continuará
- **Deduplicación**: Los hosts duplicados se eliminan automáticamente
- **Logging**: Se registra cuántos hosts se expandieron de cada CIDR

**Ejemplo de archivo con CIDR:**

```text
# Redes internas
192.168.0.0/24
192.168.1.0/24
10.0.0.0/16

# Hosts individuales adicionales
172.16.5.10
server.example.com
```

### Exclusión de Hosts

Usa el parámetro `-ExcludeFile` para especificar hosts que deben ser excluidos del escaneo.

#### Cómo Funciona

1. El script expande todos los hosts objetivo (incluidos CIDR)
2. Expande todos los hosts de exclusión (incluidos CIDR)
3. Elimina los hosts de exclusión de la lista objetivo
4. Registra cuántos hosts fueron excluidos

#### Ejemplo Práctico

**networks.txt** (hosts objetivo):
```text
192.168.1.0/24
192.168.2.0/24
10.0.0.0/24
```
Total: 762 hosts

**excluded.txt** (hosts a excluir):
```text
# Gateways
192.168.1.1
192.168.2.1
10.0.0.1

# Servidores críticos
192.168.1.10
192.168.1.20

# Rango de impresoras
192.168.2.240/28
```
Total a excluir: 19 hosts (3 IPs + 2 IPs + 14 del CIDR)

**Resultado**: 743 hosts escaneados (762 - 19)

**Comando:**
```powershell
.\scanyx.ps1 -HostFile networks.txt -ExcludeFile excluded.txt -ScanType tcp-1000
```

### Resolución de Hostnames

El parámetro `-ResolveHostnames` intenta resolver nombres de host a direcciones IP.

#### Cuándo Usarlo

- **Con exclusiones**: Para asegurar que hostnames en el archivo de exclusión coincidan con IPs en el objetivo
- **Redes mixtas**: Cuando algunos hosts se especifican por nombre y otros por IP

#### Ejemplo

**targets.txt:**
```text
192.168.1.0/24
server1.domain.local
server2.domain.local
```

**excluded.txt:**
```text
server1.domain.local
gateway.domain.local
```

**Sin `-ResolveHostnames`:**
- Solo excluye si el string coincide exactamente
- `server1.domain.local` será excluido (coincidencia exacta)
- Si `server1.domain.local` resuelve a `192.168.1.50`, esa IP **NO** será excluida

**Con `-ResolveHostnames`:**
- Intenta resolver cada hostname a IP
- `server1.domain.local` será excluido
- Si resuelve a `192.168.1.50`, esa IP **TAMBIÉN** será excluida del escaneo

**Comando:**
```powershell
.\scanyx.ps1 `
    -HostFile targets.txt `
    -ExcludeFile excluded.txt `
    -ResolveHostnames `
    -ScanType tcp-1000
```

**Nota**: La resolución DNS puede ser lenta para listas grandes.

### Logging de CIDR y Exclusiones

El script registra información detallada sobre la expansión y exclusión:

```
[2025-10-06 14:23:45] [INFO] Processing target hosts file: networks.txt
[2025-10-06 14:23:45] [INFO] Expanded 192.168.1.0/24 to 254 hosts
[2025-10-06 14:23:46] [INFO] Expanded 10.0.0.0/16 to 65534 hosts
[2025-10-06 14:23:46] [INFO] Total entries processed: 5
[2025-10-06 14:23:46] [INFO] Total target hosts after expansion: 65792
[2025-10-06 14:23:46] [INFO] Duplicates removed: 4
[2025-10-06 14:23:46] [INFO] Unique target hosts: 65788
[2025-10-06 14:23:46] [INFO] Processing exclusion file: excluded.txt
[2025-10-06 14:23:46] [INFO] Expanded 192.168.1.240/28 to 14 hosts
[2025-10-06 14:23:46] [INFO] Total exclusion hosts after expansion: 16
[2025-10-06 14:23:46] [INFO] Hosts excluded from scan: 16
[2025-10-06 14:23:46] [INFO] Final host count after exclusions: 65772
```

---

## Hosts Sensibles

El parámetro `-SensitiveFile` permite definir hosts críticos que deben escanearse con parámetros personalizados menos agresivos.

### ¿Por Qué Usar Hosts Sensibles?

- **Sistemas de Producción**: Servidores críticos que no deben ser sobrecargados
- **Dispositivos de Red**: Firewalls, routers, switches que son sensibles al tráfico pesado
- **Sistemas Legacy**: Hardware antiguo que puede no soportar escaneos agresivos
- **IDS/IPS**: Evitar detección o bloqueos de sistemas de seguridad

### Parámetros de Hosts Sensibles

| Parámetro | Opciones | Por Defecto | Descripción |
|-----------|----------|-------------|-------------|
| `-SensitiveFile` | Ruta al archivo | _(ninguno)_ | Archivo con hosts sensibles (IPs, CIDR, hostnames) |
| `-SensitiveTiming` | T0, T1, T2, T3, T4 | `T2` | Timing template de Nmap (menor = más lento y sigiloso) |
| `-SensitiveScripts` | default, vuln, none, default+vuln | `default` | NSE scripts a usar en hosts sensibles |

### Timing Templates de Nmap

| Template | Velocidad | Uso Recomendado |
|----------|-----------|-----------------|
| **T0** (Paranoid) | Extremadamente lento | IDS evasion, máxima precaución |
| **T1** (Sneaky) | Muy lento | IDS evasion, sistemas muy sensibles |
| **T2** (Polite) | Lento | Sistemas de producción, menos intrusivo |
| **T3** (Normal) | Normal | Balance entre velocidad y sigilo |
| **T4** (Aggressive) | Rápido | Redes rápidas y confiables (usado para hosts normales) |

### Opciones de NSE Scripts

| Opción | Scripts Ejecutados | Uso Recomendado |
|--------|-------------------|-----------------|
| `default` | Solo scripts default de Nmap | Mínima intrusión, detección básica |
| `vuln` | Solo scripts de vulnerabilidades | Foco en CVEs conocidos |
| `none` | Sin scripts NSE | Máxima velocidad, mínima intrusión |
| `default+vuln` | Scripts default y vulnerabilidades | Usado para hosts normales |

### Cómo Funciona

1. **Procesamiento Independiente**: Los archivos de hosts objetivo y sensibles se procesan por separado
2. **Deduplicación Inteligente**: Si un host aparece en ambas listas, se trata como sensible
3. **Comandos Personalizados**: Los hosts sensibles reciben comandos Nmap modificados:
   - Timing más lento (`-T2` en vez de `-T4`)
   - Scripts reducidos (ej. solo `--script=default` en vez de `--script=default,vuln`)
4. **Sin Diferenciación en Nombres**: Los archivos de salida no tienen sufijos especiales
5. **Tracking en Estado**: El archivo `scan-state.json` registra qué hosts son sensibles

### Ejemplo Práctico

**targets.txt** (hosts objetivo):
```text
192.168.1.0/24
192.168.2.0/24
10.0.0.0/24
```

**sensitive.txt** (hosts sensibles):
```text
# Servidores de producción
192.168.1.10
192.168.1.20

# Rango de dispositivos de red
192.168.2.0/28

# Firewall crítico
firewall.domain.local
```

**excluded.txt** (hosts a excluir):
```text
# Gateways
192.168.1.1
192.168.2.1
```

**Comando:**
```powershell
.\scanyx.ps1 `
    -HostFile targets.txt `
    -SensitiveFile sensitive.txt `
    -ExcludeFile excluded.txt `
    -ScanType tcp-1000 `
    -SensitiveTiming T2 `
    -SensitiveScripts default `
    -MaxConcurrent 10
```

**Resultado del procesamiento:**
- Total hosts objetivo: 762 (después de expandir CIDR)
- Hosts sensibles: 16 (2 IPs + 14 del CIDR)
- Hosts excluidos: 2 (gateways)
- **Hosts normales a escanear**: 744 con `-T4 --script=default,vuln`
- **Hosts sensibles a escanear**: 16 con `-T2 --script=default`

### Detección de Conflictos

El script detecta automáticamente hosts que aparecen en múltiples listas:

#### Conflicto: Sensible + Excluido

Si un host aparece en ambos `-SensitiveFile` y `-ExcludeFile`:
- **Resultado**: La exclusión gana, el host NO se escanea
- **Log**: Se registra una advertencia sobre el conflicto

**Ejemplo de log:**
```
[2025-10-06 14:25:10] [WARNING] CONFLICT: 192.168.1.10 is in both sensitive and excluded lists (excluded wins)
```

#### Host en Objetivo y Sensible

Si un host aparece tanto en `-HostFile` como en `-SensitiveFile`:
- **Resultado**: Se trata como sensible (usa parámetros personalizados)
- **Sin conflicto**: Es el comportamiento esperado

### Estructura de Salida Jerárquica

Los resultados se organizan según el origen del host:

```
nmap/
├── networks/                # Hosts de rangos CIDR
│   ├── 192.168.1.0-24/
│   │   ├── 192.168.1.10.xml
│   │   ├── 192.168.1.10.nmap
│   │   └── 192.168.1.10.gnmap
│   └── 192.168.2.0-28/
│       ├── 192.168.2.5.xml
│       └── 192.168.2.5.nmap
├── hosts/                   # Hosts individuales
│   ├── 10.50.1.100/
│   │   ├── 10.50.1.100.xml
│   │   └── 10.50.1.100.nmap
│   └── firewall.domain.local/
│       └── firewall.domain.local.xml
├── scan.log
├── scan-errors.log
├── scan-results.json
└── scan-state.json
```

**Nota**: No hay sufijos como `_sensitive` en los nombres de archivos. La diferenciación se hace solo en el archivo `scan-state.json`.

### Estado de Hosts Sensibles en JSON

El archivo `scan-state.json` incluye metadata completa:

```json
{
  "session_id": "2025-10-06_142510",
  "scan_type": "tcp-1000",
  "start_time": "2025-10-06T14:25:10",
  "status": "in_progress",
  "hosts": {
    "192.168.1.10": {
      "status": "completed",
      "attempts": 1,
      "sensitive": true,
      "scan_type": "tcp-1000",
      "timing": "T2",
      "scripts": "default",
      "source_cidr": "192.168.1.0/24",
      "alternative_cidrs": [],
      "output_folder": "nmap\\networks\\192.168.1.0-24"
    },
    "192.168.1.50": {
      "status": "completed",
      "attempts": 1,
      "sensitive": false,
      "scan_type": "tcp-1000",
      "timing": "T4",
      "scripts": "default+vuln",
      "source_cidr": "192.168.1.0/24",
      "alternative_cidrs": [],
      "output_folder": "nmap\\networks\\192.168.1.0-24"
    },
    "firewall.domain.local": {
      "status": "in_progress",
      "attempts": 1,
      "sensitive": true,
      "scan_type": "tcp-1000",
      "timing": "T2",
      "scripts": "default",
      "source_cidr": null,
      "alternative_cidrs": [],
      "output_folder": "nmap\\hosts\\firewall.domain.local"
    }
  }
}
```

### Resumen en Consola

Al finalizar, el script muestra estadísticas detalladas:

```
========================================
  Scan Summary
========================================
Session ID      : 2025-10-06_142510
Scan Type       : tcp-1000

Total Hosts     : 760
  Networks (CIDR): 746
    - Normal     : 730 (success: 728, failed: 2)
    - Sensitive  : 16 (success: 16, failed: 0)
  Individual     : 14
    - Normal     : 13 (success: 12, failed: 1)
    - Sensitive  : 1 (success: 1, failed: 0)

Total Normal    : 743 (success: 740, failed: 3)
Total Sensitive : 17 (success: 17, failed: 0)
Excluded        : 2
Conflicts       : 0

Total Duration  : 02h 15m 32s
========================================
```

### Casos de Uso Recomendados

#### Caso 1: Escaneo de Red Corporativa
```powershell
.\scanyx.ps1 `
    -HostFile internal_networks.txt `
    -SensitiveFile production_servers.txt `
    -ExcludeFile management_devices.txt `
    -ScanType tcp-1000 `
    -SensitiveTiming T2 `
    -SensitiveScripts default `
    -MaxConcurrent 10
```

#### Caso 2: Pentest Sigiloso
```powershell
.\scanyx.ps1 `
    -HostFile all_targets.txt `
    -SensitiveFile high_security_systems.txt `
    -ScanType tcp-full `
    -SensitiveTiming T1 `
    -SensitiveScripts none `
    -MaxConcurrent 3
```

#### Caso 3: Auditoría de Vulnerabilidades
```powershell
.\scanyx.ps1 `
    -HostFile networks.txt `
    -SensitiveFile legacy_systems.txt `
    -ScanType tcp-1000 `
    -SensitiveTiming T2 `
    -SensitiveScripts vuln `
    -MaxConcurrent 5
```

---

## Gestión de Estado

### Cómo Funciona la Persistencia de Estado

El script mantiene un archivo `scan-state.json` que rastrea:
- ID de sesión y configuración de escaneo
- Estado por host (pending, in_progress, completed, failed)
- Número de intentos por host
- Mensajes de error para hosts fallidos
- Estadísticas generales de progreso

### Ubicación del Archivo de Estado

```
<OutputDir>/scan-state.json
```

### Ejemplo de Archivo de Estado

```json
{
  "session_id": "2025-10-06_142345",
  "scan_type": "tcp-1000",
  "start_time": "2025-10-06T14:23:45",
  "status": "in_progress",
  "total_hosts": 50,
  "completed": 35,
  "failed": 3,
  "in_progress": 1,
  "pending": 11,
  "hosts": {
    "192.168.1.10": {
      "status": "completed",
      "attempts": 1,
      "last_update": "2025-10-06T14:28:32",
      "error": ""
    },
    "192.168.1.11": {
      "status": "failed",
      "attempts": 2,
      "last_update": "2025-10-06T14:35:10",
      "error": "Host timeout"
    }
  }
}
```

### Comparación de Modos de Reanudación

| Modo | Hosts Pendientes | Hosts Fallidos | Hosts Completados |
|------|------------------|----------------|-------------------|
| **Resume** | ✅ Escanea | ❌ Salta | ❌ Salta |
| **ResumeRetryFailed** | ✅ Escanea | ✅ Reintenta | ❌ Salta |
| **RetryFailed** | ❌ Salta | ✅ Reintenta | ❌ Salta |
| **Force** | ✅ Escanea | ✅ Escanea | ✅ Escanea |

### Modo Interactivo

Si ejecutas el script sin especificar un parámetro de reanudación y existe un estado previo, verás:

```
Previous scan state detected. What would you like to do?
  [1]* Resume (pending only)
  [2]  Resume and retry failed
  [3]  Retry failed only
  [4]  Force (start fresh)
  [5]  Cancel

Enter choice (1-5):
```

---

## Archivos de Salida

### Estructura de Directorios

El script organiza los resultados jerárquicamente según el origen de los hosts:

```
nmap/
├── networks/                 # Hosts expandidos de rangos CIDR
│   ├── 192.168.1.0-24/
│   │   ├── 192.168.1.10_tcp-1000.nmap
│   │   ├── 192.168.1.10_tcp-1000.xml
│   │   ├── 192.168.1.10_tcp-1000.gnmap
│   │   ├── 192.168.1.10_tcp-1000.stdout
│   │   ├── 192.168.1.10_tcp-1000.stderr
│   │   ├── 192.168.1.20_tcp-1000.nmap
│   │   └── ...
│   ├── 10.0.0.0-16/
│   │   └── ...
│   └── ...
├── hosts/                   # Hosts especificados individualmente
│   ├── 192.168.2.100/
│   │   ├── 192.168.2.100_tcp-1000.nmap
│   │   ├── 192.168.2.100_tcp-1000.xml
│   │   └── ...
│   ├── server.example.com/
│   │   └── ...
│   └── ...
├── scan.log                 # Log principal (formato texto)
├── scan-errors.log          # Solo errores
├── scan-results.json        # Resultados estructurados (JSON)
└── scan-state.json          # Estado actual (para reanudar)
```

**Nota importante**: Los hosts sensibles NO tienen sufijos especiales en sus nombres de archivo. La diferenciación entre hosts normales y sensibles se realiza únicamente en el archivo `scan-state.json` mediante los campos `sensitive`, `timing` y `scripts`.

### Archivos de Log

#### 1. scan.log (Log de Texto)
Log legible con timestamps y niveles con códigos de color:

```
[2025-10-06 14:23:45] [INFO] Scan started: 192.168.1.10 | tcp-1000
[2025-10-06 14:28:32] [SUCCESS] Scan completed: 192.168.1.10 | tcp-1000 | Attempt: 1 | Duration: 4m 47s
[2025-10-06 14:28:35] [ERROR] Scan failed: 192.168.1.11 | tcp-1000 | Error: Host timeout
[2025-10-06 14:29:10] [INFO] Retry attempt 1/1: 192.168.1.11 | tcp-1000
```

**Niveles de Log**:
- **INFO** (Blanco): Información general
- **SUCCESS** (Verde): Operaciones exitosas
- **WARNING** (Amarillo): Advertencias e intentos de reintento
- **ERROR** (Rojo): Errores y fallos

#### 2. scan-errors.log (Log de Errores)
Contiene solo entradas de nivel ERROR para solución rápida de problemas:

```
[2025-10-06 14:28:35] [ERROR] Scan failed: 192.168.1.11 | tcp-1000 | Host timeout
[2025-10-06 14:29:45] [ERROR] Scan failed (max retries): 192.168.1.11 | tcp-1000 | Attempts: 2
```

#### 3. scan-results.json (Resultados Estructurados)
Formato JSON legible por máquina para automatización:

```json
{
  "scan_session": "2025-10-06_142345",
  "scans": [
    {
      "host": "192.168.1.10",
      "scan_type": "tcp-1000",
      "status": "completed",
      "start_time": "2025-10-06T14:23:45",
      "end_time": "2025-10-06T14:28:32",
      "duration_seconds": 287,
      "attempts": 1,
      "output_files": ["nmap/hosts/192.168.1.10/192.168.1.10_tcp-1000.nmap"]
    },
    {
      "host": "192.168.1.11",
      "scan_type": "tcp-1000",
      "status": "failed",
      "start_time": "2025-10-06T14:28:35",
      "end_time": "2025-10-06T14:29:45",
      "duration_seconds": 70,
      "attempts": 2,
      "error": "Host timeout"
    }
  ]
}
```

---

## Características Avanzadas

### Barra de Progreso

La visualización de progreso en tiempo real muestra:
- Porcentaje de completitud
- Hosts completados vs. total
- Conteo de éxitos
- Conteo de fallos
- Host actual siendo escaneado

```
Scanning hosts
Progress: 35/50 (70.0%) | Success: 32 | Failed: 3 | Current: 192.168.1.45
[████████████████████░░░░░░░░] 70%
```

### Validación de Entradas

El script valida:
- **Instalación de Nmap**: Verifica si nmap está disponible en PATH
- **Archivo de Hosts**: Verifica que el archivo existe y no está vacío
- **Direcciones IP**: Valida formato IPv4
- **Hostnames**: Valida formato FQDN
- **Comentarios**: Ignora líneas que empiezan con `#`
- **Líneas Vacías**: Se saltan automáticamente

### Manejo de Errores

- Los escaneos fallidos se reintentan automáticamente según `-MaxRetries`
- Los errores se registran tanto en el log principal como en el log de errores
- Las interrupciones de red no pierden el progreso (el estado se guarda después de cada host)
- Los hosts inválidos se reportan pero no detienen el escaneo

### Características de Seguridad

- **Sin Invoke-Expression**: Usa `Start-Process` para ejecución más segura de comandos
- **Sanitización de Entradas**: Valida todas las entradas del usuario
- **Validación de Parámetros**: Atributos ValidateSet y ValidateRange de PowerShell

### Manejo de Ctrl+C

Cuando presionas Ctrl+C:
1. Los trabajos en segundo plano se detienen de forma controlada
2. Todos los trabajos se eliminan de la memoria
3. El estado actual se preserva en `scan-state.json`
4. Puedes reanudar después con `-Resume`

---

## Solución de Problemas

### Problemas Comunes

#### Problema: "Nmap is not installed or not in PATH"

**Solución**: Instala Nmap y agrégalo al PATH
```powershell
# Verificar instalación
nmap --version

# Windows: Agregar al PATH
$env:Path += ";C:\Program Files (x86)\Nmap"
```

#### Problema: "Host file not found"

**Solución**: Verifica que la ruta del archivo sea correcta
```powershell
# Usar ruta absoluta
.\scanyx.ps1 -HostFile "C:\ruta\completa\a\hosts.txt" -ScanType tcp-1000

# O ruta relativa desde la ubicación del script
.\scanyx.ps1 -HostFile ".\hosts.txt" -ScanType tcp-1000
```

#### Problema: Los escaneos son muy lentos

**Soluciones**:
- Aumentar escaneos concurrentes: `-MaxConcurrent 10`
- Usar tipo de escaneo más rápido: `-ScanType tcp-1000` en lugar de `tcp-full`
- Reducir timeout en comando de escaneo (editar script)

#### Problema: Demasiados hosts fallando

**Soluciones**:
- Aumentar reintentos: `-MaxRetries 3`
- Aumentar delay de reintento: `-RetryDelay 120`
- Verificar conectividad de red
- Verificar que los hosts sean alcanzables
- Revisar `scan-errors.log` para buscar patrones

#### Problema: Quiero cancelar y reiniciar

**Solución**: Usa `-Force` para empezar desde cero
```powershell
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -Force
```

#### Problema: Necesito ejecutar como Administrador (Windows)

**Solución**: Click derecho en PowerShell y "Ejecutar como administrador"

**Nota**: Requerido para escaneos SYN (`-sS`) que necesitan acceso a sockets raw

---

## Integración

### Post-Procesamiento con Herramienta XNP

Después del escaneo, usa la [herramienta XNP (Xtreme Nmap Parser)](https://github.com/xtormin/XtremeNmapParser) para fusionar todos los resultados:

```bash
# Fusionar todos los resultados XML en Excel
xnp -i nmap/hosts/*/*.xml -o resultados.xlsx

# Fusionar en JSON
xnp -i nmap/hosts/*/*.xml -o resultados.json

# Fusionar en CSV
xnp -i nmap/hosts/*/*.xml -o resultados.csv
```

### Análisis de Resultados JSON

Usa PowerShell para analizar `scan-results.json`:

```powershell
# Cargar resultados
$resultados = Get-Content "nmap/scan-results.json" | ConvertFrom-Json

# Obtener todos los escaneos completados
$completados = $resultados.scans | Where-Object { $_.status -eq "completed" }

# Obtener todos los escaneos fallidos
$fallidos = $resultados.scans | Where-Object { $_.status -eq "failed" }

# Calcular tiempo promedio de escaneo
$tiempoPromedio = ($resultados.scans | Measure-Object -Property duration_seconds -Average).Average

# Exportar hosts fallidos a CSV
$fallidos | Export-Csv "hosts_fallidos.csv" -NoTypeInformation
```

### Automatización de Escaneos

Crea una tarea programada o cron job:

**Windows (Programador de Tareas)**:
```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\scanyx.ps1 -HostFile C:\Listas\hosts.txt -ScanType tcp-1000"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "EscaneoRed" -Action $action -Trigger $trigger
```

**Linux (Cron)**:
```bash
# Ejecutar todos los días a las 2am
0 2 * * * /usr/bin/pwsh /opt/scripts/scanyx.ps1 -HostFile /opt/listas/hosts.txt -ScanType tcp-1000
```

### Integración CI/CD

Ejemplo de pipeline GitLab CI:

```yaml
escanear_red:
  stage: scan
  script:
    - pwsh ./scanyx.ps1 -HostFile objetivos.txt -ScanType tcp-1000 -OverwriteMode Overwrite
  artifacts:
    paths:
      - nmap/
    expire_in: 30 days
```

---

## Tabla Resumen

### Referencia Rápida

| Tarea | Comando |
|-------|---------|
| Escaneo básico | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000` |
| Escaneo con CIDR | `.\scanyx.ps1 -HostFile networks.txt -ScanType tcp-1000` |
| Escaneo con exclusiones | `.\scanyx.ps1 -HostFile hosts.txt -ExcludeFile excluded.txt -ScanType tcp-1000` |
| Resolver hostnames en exclusiones | `.\scanyx.ps1 -HostFile hosts.txt -ExcludeFile excluded.txt -ResolveHostnames -ScanType tcp-1000` |
| Escaneo paralelo rápido | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -MaxConcurrent 10` |
| Ejecutar workflow | `.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery` |
| Workflow con modo verbose | `.\scanyx.ps1 -HostFile hosts.txt -Workflow full-discovery -VerboseMode` |
| Workflow con hosts sensibles | `.\scanyx.ps1 -HostFile hosts.txt -SensitiveFile production.txt -Workflow full-audit` |
| Reanudar escaneo/workflow interrumpido | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Resume` |
| Reintentar hosts fallidos | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -RetryFailed` |
| Empezar desde cero | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -Force` |
| Directorio salida personalizado | `.\scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000 -OutputDir C:\Escaneos` |

---

## Autor

**Jennifer Torres** ([@xtormin](https://github.com/xtormin))

Versión: 2.7

---

## Licencia

Este script se proporciona tal cual para fines educativos y de pruebas de seguridad autorizadas únicamente.

**Importante**: Solo escanea redes y sistemas para los que tienes permiso explícito. El escaneo no autorizado puede ser ilegal en tu jurisdicción.

---

## Registro de Cambios

### Versión 2.7 (2025-10-07)
- ✨ **Workflows**: Sistema de workflows para encadenar múltiples perfiles de escaneo secuencialmente
- ✨ **Configuración Externa**: Perfiles de escaneo y workflows en archivo JSON (`scan-profiles.json`)
- ✨ **Modo Verbose**: Nuevo parámetro `-VerboseMode` para mostrar comandos nmap y salida en vivo
- ✨ **Condiciones de Ejecución**: Control condicional de pasos del workflow (always, previous_success, previous_has_results)
- ✨ **Estructura de Workflows**: Resultados organizados en `workflows/{nombre}/step-{N}-{perfil}/`
- 🔧 **Host Timeout**: Aumentado de 10m a 60m en todos los perfiles por defecto
- 🔧 **Verificación de Escaneo**: Mejorada detección de escaneos fallidos (verifica existencia de archivos .nmap)
- 🔧 **Rutas con Espacios**: Corrección de manejo de rutas de salida con espacios
- 📚 **Documentación**: README actualizado con sección completa de Workflows

### Versión 2.6 (2025-10-06)
- 🐛 **Hosts Sensibles**: Corrección de clasificación de hosts sensibles (merge con lista de objetivos)
- ⚡ **Optimización**: Uso de hashtables para búsquedas O(1) en lugar de arrays O(n)
- 🔧 **Variable $Host**: Renombrado a $TargetHost para evitar conflictos con variable automática de PowerShell

### Versión 2.1-2.5 (2025-10-06)
- ✨ **Soporte CIDR**: Notación CIDR para escanear rangos completos de red
- ✨ **Exclusión de Hosts**: Parámetro `-ExcludeFile` para excluir hosts/rangos específicos
- ✨ **Resolución de Hostnames**: Parámetro `-ResolveHostnames` para resolver nombres a IPs
- ✨ **Expansión Automática**: CIDR se expande automáticamente (excluye network/broadcast)
- ✨ **Deduplicación**: Elimina automáticamente hosts duplicados con logging
- ✨ **Validación CIDR**: Valida formato y rango de subnet (/8 a /32)
- ✨ **Logging Mejorado**: Información detallada sobre expansión CIDR y exclusiones
- ⚠️ **Advertencias**: Alerta cuando CIDR expande >5000 hosts
- 📊 **Estadísticas**: Reporta hosts expandidos, duplicados y excluidos

### Versión 2.0 (2025-10-06)
- ✨ Añadido escaneo paralelo con concurrencia configurable
- ✨ Añadida persistencia de estado para capacidad de reanudación
- ✨ Añadido registro completo (texto, JSON, errores)
- ✨ Añadido mecanismo de reintento automático
- ✨ Añadido seguimiento de progreso con barra en tiempo real
- ✨ Añadida validación de entradas (IPs, hostnames, dependencias)
- ✨ Añadidos múltiples modos de reanudación (Resume, ResumeRetryFailed, RetryFailed, Force)
- ✨ Añadida protección contra sobrescritura con modos configurables
- ✨ Añadido manejo de Ctrl+C con limpieza de trabajos
- 🔒 Reemplazado Invoke-Expression por Start-Process por seguridad
- 🔒 Añadida sanitización de entradas
- 🎨 Añadida salida de consola con códigos de color
- 📊 Añadidos informes de resumen detallados
- 🐛 Corregida lista de puertos UDP comunes (añadido puerto 67)

### Versión 1.0 (Inicial)
- Escaneo secuencial básico
- Registro simple a un solo archivo
- Estructura básica de carpetas
