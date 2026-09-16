#!/usr/bin/env bash
#
# Scanyx launcher for macOS and Linux.
#
# scanyx.ps1 does not auto-execute: dot-sourcing it only defines Invoke-Scanyx.
# This script resolves pwsh and nmap, then dot-sources the module and splats the
# arguments you passed straight through to Invoke-Scanyx.
#
# Launcher flags use --double-dash. Everything else is forwarded verbatim.
#
#   https://github.com/xtormin/Scanyx

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PS1_PATH="$SCRIPT_DIR/scanyx.ps1"
REMOTE_URL="https://raw.githubusercontent.com/xtormin/Scanyx/refs/heads/main/scanyx.ps1"

PWSH_MIN_MAJOR=7
PWSH_MIN_MINOR=2
PWSH_TARBALL_VERSION="7.5.4"

MODE_CHECK=0
MODE_INSTALL=ask     # ask | yes | never
MODE_SUDO=auto       # auto | force | never
MODE_REMOTE=0
MODE_ASSUME_YES=0

C_RED=''; C_YEL=''; C_GRN=''; C_CYA=''; C_DIM=''; C_OFF=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'
    C_CYA=$'\033[36m'; C_DIM=$'\033[90m'; C_OFF=$'\033[0m'
fi

err()  { printf '%s[ERROR]%s %s\n'   "$C_RED" "$C_OFF" "$*" >&2; }
warn() { printf '%s[WARN]%s %s\n'    "$C_YEL" "$C_OFF" "$*" >&2; }
info() { printf '%s[INFO]%s %s\n'    "$C_CYA" "$C_OFF" "$*"; }
ok()   { printf '%s[OK]%s %s\n'      "$C_GRN" "$C_OFF" "$*"; }
dim()  { printf '%s%s%s\n'           "$C_DIM" "$*" "$C_OFF"; }

usage() {
    cat <<'USAGE'
Scanyx - launcher for macOS and Linux

  ./scanyx.sh [launcher-options] [Scanyx-parameters]

Launcher options (double dash):
  --check           Environment check only: OS, arch, pwsh, nmap, uid. No scan.
  --install         Install whatever is missing without asking.
  --yes             Yes to everything: install without asking and skip the
                    pre-flight scan confirmation.
  --no-install      Never install; print the manual commands and exit 2.
  --sudo            Re-run under sudo.
  --no-sudo         Never escalate privileges.
  --remote [URL]    Load scanyx.ps1 from a URL instead of the local file.
  --help            This help.

Everything else is forwarded verbatim to Invoke-Scanyx. Examples:

  ./scanyx.sh --check
  ./scanyx.sh -Hosts 127.0.0.1 -ScanType tcp-100
  sudo ./scanyx.sh -HostFile hosts.txt -Workflow full-discovery
  ./scanyx.sh -Wizard

The stock profiles use -sS / -sU / -A, which require root on Unix.
Without root, Scanyx offers to downgrade the scan or abort.

Full parameter list:  pwsh -c '. ./scanyx.ps1; Get-Help Invoke-Scanyx -Full'
USAGE
}

# ── Argument split ────────────────────────────────────────────────────────────
FORWARD=()
while [ $# -gt 0 ]; do
    case "$1" in
        --check)      MODE_CHECK=1 ;;
        --install)    MODE_INSTALL=yes ;;
        --yes)        MODE_INSTALL=yes; MODE_ASSUME_YES=1 ;;
        --no-install) MODE_INSTALL=never ;;
        --sudo)       MODE_SUDO=force ;;
        --no-sudo)    MODE_SUDO=never ;;
        --remote)
            MODE_REMOTE=1
            if [ $# -gt 1 ]; then
                case "$2" in
                    -*) : ;;                      # next token is a flag, keep default URL
                    *)  REMOTE_URL="$2"; shift ;;
                esac
            fi
            ;;
        --help|-h)    usage; exit 0 ;;
        *)            FORWARD+=("$1") ;;
    esac
    shift
done

# ── Platform detection ────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
DISTRO_ID=""
DISTRO_LIKE=""
if [ "$OS" = "Linux" ] && [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
fi

case "$ARCH" in
    x86_64|amd64)  PWSH_RID_LINUX="linux-x64";   PWSH_RID_OSX="osx-x64"   ;;
    aarch64|arm64) PWSH_RID_LINUX="linux-arm64"; PWSH_RID_OSX="osx-arm64" ;;
    *)             PWSH_RID_LINUX=""; PWSH_RID_OSX="" ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

is_debian_like() {
    case "$DISTRO_ID" in kali|debian|ubuntu|parrot) return 0 ;; esac
    case "$DISTRO_LIKE" in *debian*|*ubuntu*) return 0 ;; esac
    return 1
}

confirm() {
    # $1 = prompt. Honours --yes / --no-install; needs a TTY otherwise.
    [ "$MODE_INSTALL" = "yes" ] && return 0
    [ "$MODE_INSTALL" = "never" ] && return 1
    [ -t 0 ] || return 1
    printf '%s[?]%s %s [y/N]: ' "$C_CYA" "$C_OFF" "$1"
    read -r reply
    case "$reply" in [sSyY]*) return 0 ;; *) return 1 ;; esac
}

pwsh_version_ok() {
    have pwsh || return 1
    local v major minor
    v="$(pwsh -NoProfile -NoLogo -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)" || return 1
    major="${v%%.*}"
    minor="${v#*.}"; minor="${minor%%.*}"
    [ -n "$major" ] || return 1
    [ "$major" -gt "$PWSH_MIN_MAJOR" ] && return 0
    [ "$major" -eq "$PWSH_MIN_MAJOR" ] && [ "${minor:-0}" -ge "$PWSH_MIN_MINOR" ] && return 0
    return 1
}

# ── Installers ────────────────────────────────────────────────────────────────
install_pwsh_tarball() {
    local rid="$1" dest="/opt/microsoft/powershell/7"
    if [ -z "$rid" ]; then
        err "Unsupported architecture for the PowerShell tarball: $ARCH"
        return 1
    fi
    local url="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_TARBALL_VERSION}/powershell-${PWSH_TARBALL_VERSION}-${rid}.tar.gz"
    info "Downloading PowerShell ${PWSH_TARBALL_VERSION} (${rid})"
    dim "  $url"
    local tmp; tmp="$(mktemp -d)" || return 1
    if ! curl -fsSL "$url" -o "$tmp/pwsh.tar.gz"; then
        err "Could not download the PowerShell tarball."
        rm -rf "$tmp"; return 1
    fi
    sudo mkdir -p "$dest" \
      && sudo tar zxf "$tmp/pwsh.tar.gz" -C "$dest" \
      && sudo chmod +x "$dest/pwsh" \
      && sudo ln -sf "$dest/pwsh" /usr/local/bin/pwsh
    local rc=$?
    rm -rf "$tmp"
    return $rc
}

install_pwsh_tarball_macos() {
    # User-local install: no sudo, no .pkg, nothing outside $HOME.
    local rid="$1" dest="$HOME/.local/share/powershell/7"
    if [ -z "$rid" ]; then
        err "Unsupported architecture for the PowerShell tarball: $ARCH"
        return 1
    fi
    local url="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_TARBALL_VERSION}/powershell-${PWSH_TARBALL_VERSION}-${rid}.tar.gz"
    info "Downloading PowerShell ${PWSH_TARBALL_VERSION} (${rid})"
    dim "  $url"
    local tmp; tmp="$(mktemp -d)" || return 1
    if ! curl -fsSL "$url" -o "$tmp/pwsh.tar.gz"; then
        err "Could not download the PowerShell tarball."
        rm -rf "$tmp"; return 1
    fi
    mkdir -p "$dest" && tar zxf "$tmp/pwsh.tar.gz" -C "$dest" && chmod +x "$dest/pwsh"
    local rc=$?
    rm -rf "$tmp"
    [ $rc -ne 0 ] && return $rc

    mkdir -p "$HOME/.local/bin" && ln -sf "$dest/pwsh" "$HOME/.local/bin/pwsh"
    if ! have pwsh; then
        PATH="$HOME/.local/bin:$PATH"
        export PATH
        warn "pwsh installed in $HOME/.local/bin, which is not on your PATH."
        dim "  Add this to your ~/.zshrc:  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
    return 0
}

install_pwsh() {
    if [ "$OS" = "Darwin" ]; then
        if have brew; then
            # PowerShell moved from a cask to a core formula. Probe instead of
            # assuming: the formula needs no password, the old cask does.
            if brew info --formula powershell >/dev/null 2>&1; then
                info "Installing PowerShell with Homebrew (formula)"
                brew install powershell && return 0
            elif brew info --cask powershell >/dev/null 2>&1; then
                info "Installing PowerShell with Homebrew (cask; it will ask for your password for the .pkg)"
                brew install --cask powershell && return 0
            else
                warn "Homebrew knows no package named powershell."
            fi
            warn "Homebrew install failed; trying the official tarball"
        else
            warn "Homebrew is not installed."
            dim "  Install it from https://brew.sh and run --install again,"
            dim "  or let Scanyx use the official Microsoft tarball."
        fi
        install_pwsh_tarball_macos "$PWSH_RID_OSX"
        return $?
    fi

    if is_debian_like; then
        # Rather than parsing apt-cache output (locale-dependent), just try it.
        # On Kali arm64 the powershell package usually does not exist, and the
        # official tarball is the only route.
        info "Looking for PowerShell in apt"
        if sudo apt-get update >/dev/null 2>&1 && sudo apt-get install -y powershell 2>/dev/null; then
            return 0
        fi
        info "PowerShell is not available in apt for $ARCH; using the official tarball"
    fi
    install_pwsh_tarball "$PWSH_RID_LINUX"
}

install_nmap() {
    if [ "$OS" = "Darwin" ]; then
        if have brew; then
            info "Installing nmap with Homebrew"
            brew install nmap
            return $?
        fi
        err "Homebrew is not installed."
        dim "  Install Homebrew (https://brew.sh) then run: brew install nmap"
        return 1
    fi
    info "Installing nmap with apt"
    sudo apt-get update && sudo apt-get install -y nmap
}

# ── Diagnostics ───────────────────────────────────────────────────────────────
print_check() {
    printf '\n%sScanyx - environment check%s\n\n' "$C_CYA" "$C_OFF"
    printf '  OS            : %s %s\n' "$OS" "$ARCH"
    [ -n "$DISTRO_ID" ] && printf '  Distribution  : %s\n' "$DISTRO_ID"
    printf '  User          : uid=%s%s\n' "$(id -u)" "$([ "$(id -u)" -eq 0 ] && echo ' (root)')"

    if have pwsh; then
        local v; v="$(pwsh -NoProfile -NoLogo -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)"
        if pwsh_version_ok; then
            printf '  PowerShell    : %s%s%s (%s)\n' "$C_GRN" "$v" "$C_OFF" "$(command -v pwsh)"
        else
            printf '  PowerShell    : %s%s - requires >= %s.%s%s\n' "$C_YEL" "$v" "$PWSH_MIN_MAJOR" "$PWSH_MIN_MINOR" "$C_OFF"
        fi
    else
        printf '  PowerShell    : %snot found%s\n' "$C_RED" "$C_OFF"
    fi

    if have nmap; then
        printf '  nmap          : %s%s%s (%s)\n' "$C_GRN" "$(nmap --version 2>/dev/null | head -1 | sed -n 's/.*version \([^ ]*\).*/\1/p')" "$C_OFF" "$(command -v nmap)"
    else
        printf '  nmap          : %snot found%s\n' "$C_RED" "$C_OFF"
    fi

    if [ "$MODE_REMOTE" -eq 1 ]; then
        printf '  scanyx.ps1    : remote - %s\n' "$REMOTE_URL"
    elif [ -r "$PS1_PATH" ]; then
        printf '  scanyx.ps1    : %s%s%s\n' "$C_GRN" "$PS1_PATH" "$C_OFF"
    else
        printf '  scanyx.ps1    : %snot found at %s%s\n' "$C_RED" "$PS1_PATH" "$C_OFF"
    fi
    printf '\n'
}

# ── Dependency resolution ─────────────────────────────────────────────────────
ensure_deps() {
    local missing=0

    if ! pwsh_version_ok; then
        if have pwsh; then
            warn "PowerShell is installed but older than ${PWSH_MIN_MAJOR}.${PWSH_MIN_MINOR} (Start-Job is unreliable on 6.x)."
        else
            warn "PowerShell (pwsh) is not installed."
        fi
        if confirm "Install PowerShell now?"; then
            install_pwsh || missing=1
            pwsh_version_ok || missing=1
        else
            missing=1
            if [ "$OS" = "Darwin" ]; then
                dim "  Manual: brew install powershell"
            else
                dim "  Manual: sudo apt-get install -y powershell   (or use --install for the tarball)"
            fi
        fi
    fi

    if ! have nmap; then
        warn "nmap is not installed."
        if confirm "Install nmap now?"; then
            install_nmap || missing=1
            have nmap || missing=1
        else
            missing=1
            if [ "$OS" = "Darwin" ]; then
                dim "  Manual: brew install nmap"
            else
                dim "  Manual: sudo apt-get install -y nmap"
            fi
        fi
    fi

    return $missing
}

# ── Main ──────────────────────────────────────────────────────────────────────
if [ "$MODE_CHECK" -eq 1 ]; then
    print_check
    if pwsh_version_ok && have nmap; then
        ok "Everything is ready."
        exit 0
    fi
    err "Missing dependencies. Run: ./scanyx.sh --install"
    exit 2
fi

if [ "$MODE_REMOTE" -eq 0 ] && [ ! -r "$PS1_PATH" ]; then
    err "Cannot find scanyx.ps1 at $PS1_PATH"
    dim "  Use --remote to load it from GitHub."
    exit 2
fi

if ! ensure_deps; then
    err "Cannot continue without the dependencies."
    exit 2
fi

# "--install" with nothing else to do is a request to install, not to scan.
if [ "$MODE_INSTALL" = "yes" ] && [ "$MODE_ASSUME_YES" -eq 0 ] && [ "${#FORWARD[@]}" -eq 0 ]; then
    print_check
    ok "Everything is ready. Run a scan, for example:"
    dim "  ./scanyx.sh -Hosts 127.0.0.1 -ScanType tcp-100"
    exit 0
fi

# Re-exec under sudo only when explicitly asked. Scanyx's own privilege gate
# knows which profile is in play and prints the exact sudo command to use,
# so prompting here too would ask the same question twice.
if [ "$MODE_SUDO" = "force" ] && [ "$(id -u)" -ne 0 ]; then
    info "Escalating privileges with sudo"
    if [ "$MODE_REMOTE" -eq 1 ]; then
        exec sudo -E "$0" --no-sudo --remote "$REMOTE_URL" ${FORWARD[@]+"${FORWARD[@]}"}
    fi
    exec sudo -E "$0" --no-sudo ${FORWARD[@]+"${FORWARD[@]}"}
fi

# Build a PowerShell array literal from the forwarded arguments.
# Single-quoted PowerShell strings escape an embedded quote by doubling it,
# so nothing in an argument can break out into code.
if [ "$MODE_ASSUME_YES" -eq 1 ]; then
    FORWARD+=("-Yes")
fi

ps_args=""
if [ "${#FORWARD[@]}" -gt 0 ]; then
    for a in "${FORWARD[@]}"; do
        esc=$(printf '%s' "$a" | sed "s/'/''/g")
        ps_args="${ps_args}'${esc}',"
    done
    ps_args="${ps_args%,}"
fi

if [ "$MODE_REMOTE" -eq 1 ]; then
    export SCANYX_URL="$REMOTE_URL"
    loader='$r = Invoke-WebRequest -Uri $env:SCANYX_URL -UseBasicParsing -ErrorAction Stop; $code = if ($r.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($r.Content) } else { $r.Content }; Invoke-Expression ($code -replace "^\uFEFF", "")'
else
    export SCANYX_PS1="$PS1_PATH"
    loader='. $env:SCANYX_PS1'
fi

# Bind the forwarded tokens to Invoke-Scanyx by NAME.
# Splatting an *array* binds positionally, so the arguments are turned into a
# hashtable first. Switches and array-typed parameters are identified from the
# function's own metadata rather than guessed, so this keeps working when
# Scanyx gains or renames a parameter.
PS_BINDER='
$meta = (Get-Command Invoke-Scanyx).Parameters
$sx = @{}
$positional = @()
$i = 0
while ($i -lt $raw.Count) {
    $tok = $raw[$i]
    if ($tok -match "^-{1,2}([A-Za-z][A-Za-z0-9_]*)(?::(.*))?$") {
        $askedFor = $Matches[1]
        $inline = if ($Matches.Count -gt 2) { $Matches[2] } else { $null }

        $name = @($meta.Keys | Where-Object { $_ -ieq $askedFor })[0]
        if (-not $name) {
            $cands = @($meta.Keys | Where-Object { $_ -ilike "$askedFor*" })
            if ($cands.Count -eq 1) {
                $name = $cands[0]
            } elseif ($cands.Count -gt 1) {
                Write-Host "[ERROR] Ambiguous parameter: $tok" -ForegroundColor Red
                Write-Host "        Matches: $($cands -join ", ")" -ForegroundColor Yellow
                exit 64
            }
        }
        if (-not $name) {
            Write-Host "[ERROR] Unknown parameter: $tok" -ForegroundColor Red
            Write-Host "        Available parameters: Get-Help Invoke-Scanyx -Full" -ForegroundColor Yellow
            exit 64
        }

        $p = $meta[$name]
        if ($p.SwitchParameter) {
            $sx[$name] = if ($inline) { [bool]::Parse($inline) } else { $true }
            $i++
            continue
        }

        if ($inline) {
            $value = $inline
            $i++
        } elseif (($i + 1) -lt $raw.Count) {
            $value = $raw[$i + 1]
            $i += 2
        } else {
            Write-Host "[ERROR] Missing value for parameter $tok" -ForegroundColor Red
            exit 64
        }

        if ($p.ParameterType.IsArray) {
            $sx[$name] = [string[]]@($value -split "," | Where-Object { $_ -ne "" })
        } else {
            $sx[$name] = $value
        }
        continue
    }
    $positional += $tok
    $i++
}
Invoke-Scanyx @sx @positional
'
pwsh -NoLogo -NoProfile -Command "${loader}; \$raw = @(${ps_args}); ${PS_BINDER}"
rc=$?

# Hand the results back to the invoking user when we ran under sudo, so the
# output tree is not left owned by root inside their home directory.
if [ -n "${SUDO_UID:-}" ] && [ "$(id -u)" -eq 0 ]; then
    out_dir="nmap"
    prev=""
    for a in ${FORWARD[@]+"${FORWARD[@]}"}; do
        case "$prev" in -OutputDir|-outputdir|-OUTPUTDIR) out_dir="$a" ;; esac
        prev="$a"
    done
    case "$out_dir" in /*) : ;; *) out_dir="$PWD/$out_dir" ;; esac
    if [ -d "$out_dir" ]; then
        chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$out_dir" 2>/dev/null \
            && dim "[INFO] Ownership of $out_dir returned to uid ${SUDO_UID}"
    fi
fi

exit $rc
