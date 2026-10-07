# OSCPToolkit independent review — 2026-10-07

This review treats each bundled component as a separate workstream, then reconciles the findings at the toolkit level. The goals are exam reliability, offline usefulness, provenance, low operator error, and avoiding unnecessary tool duplication.

## Executive summary

The toolkit has strong OSCP/PEN-200 coverage, but v6.5 has four high-priority issues:

1. **CopyFail prereq status is inverted**: the checker returns failure on success and success when a prerequisite fails.
2. **Pinned pivot versions are stale**: v6.5 pins Chisel 1.11.7 and Ligolo-ng 0.8.3. Upstream latest releases checked on 2026-10-07 are Chisel 1.12.0 and Ligolo-ng 0.9.2.
3. **Supply-chain/provenance is inconsistent**: CopyFail is hash-pinned, while many artifacts use latest releases, raw default branches, community compiled binaries, or shallow clones without recording the resolved commit.
4. **Archive extraction is too trusting**: directory extraction did not reject path-traversal members, and Chisel for Windows used the first file in the ZIP instead of matching the expected executable.

v7 fixes those items and adds a source ledger, safer archive extraction, exact Chisel ZIP matching, pipx-first Python tooling, custom-TOOLKIT-aware verification, a post-stage doctor, improved encoding/decoding helpers, deterministic manifest generation, and safer treatment of the bundled legacy dfold archive.

## Per-tool disposition

| Tool / group | Disposition | Review |
|---|---|---|
| LinPEAS | Primary | Keep script + amd64 binary. First-pass Linux enum. |
| linux-smart-enumeration | Primary fallback | Keep. Smaller fallback when LinPEAS is noisy. |
| LinEnum | Legacy fallback | Keep but label legacy. |
| unix-privesc-check | Legacy cross-check | Keep low priority. |
| linux-exploit-suggester | Secondary | Keep as hypothesis generator; manually validate distro backports. |
| linux-exploit-suggester-2 | Legacy secondary | Keep only as cross-check. |
| pspy 64/32 | Primary | Keep both architectures. |
| static ncat/socat/curl/busybox/bash | Primary resilience | Keep; provenance/file-type validation is important. |
| DirtyPipe PoCs | Conditional | Keep source + locally compiled binaries. |
| PwnKit | Conditional | Keep as fallback after simpler paths. |
| CopyFail | Conditional | Keep; v7 fixes the prereq checker exit-code bug. |
| dfold / legacy DirtyFrag | Legacy/high-risk | Do not auto-extract or execute. Prefer reproducible upstream builds. |
| Chisel | Primary pivot | Keep; update default to 1.12.0. |
| Ligolo-ng | Primary pivot | Keep; update default to 0.9.2. Prefer for multi-subnet routing. |
| WinPEAS family | Primary | Keep x64 + script fallback; other variants are compatibility options. |
| PrivescCheck | Primary | Keep; upstream is active and released 2026.10.07-1 on review day. |
| PowerUp | Legacy-but-useful | Keep for OSCP-style environments; upstream PowerSploit is archived. |
| Seatbelt / SharpUp | Secondary | Keep, but avoid sole reliance on unofficial compiled mirrors. |
| SharpCollection | Compatibility bundle | Keep and record resolved commit. |
| accesschk64 | Primary targeted | Keep official Sysinternals source. |
| GodPotato | Primary token-abuse option | Keep NET4 + NET35. |
| PrintSpoofer | Primary legacy token-abuse | Keep; canonical upstream is archived. |
| JuicyPotato | Legacy | Keep for old Windows only. |
| JuicyPotatoNG | Secondary | Keep. |
| RoguePotato | Secondary | Keep as fallback; document prerequisites. |
| SigmaPotato | Secondary | Keep as alternate implementation. |
| FullPowers | Niche | Keep but label archived/niche. |
| SharpEfsPotato | Source-only fallback | Keep source; prebuild before exam if you intend to use it. |
| Mimikatz variants | Compatibility set | Useful but duplicated. Prefer one current compatible build + canonical stable fallback. |
| LaZagne | Secondary creds | Keep for credential discovery after compromise. |
| RunasCs | Primary credential-use helper | Keep. |
| Rubeus | Primary AD | Keep; provenance-track the build. |
| Certify | Primary ADCS triage | Keep alongside Certipy. |
| SharpHound | Primary AD collection | Keep latest release and record resolved source. |
| PowerView | Legacy-but-core | Keep; still highly useful despite archived PowerSploit upstream. |
| PowerUpSQL | Conditional | Keep for MSSQL-heavy paths. |
| McAfee SiteList decryptors | Niche | Keep isolated under decryptors. |
| brutalkeepass | Niche fallback | Keep source only. |
| nc64 | Compatibility shell tool | Keep. |
| Invoke-PowerShellTcp | Legacy shell fallback | Keep minimal. |
| Invoke-ConPtyShell | Primary shell stabilization | Keep. |
| PsExec64 | Primary admin execution | Keep official Sysinternals source. |
| UACME | Reference/source | Keep as technique/reference library. |
| Certipy | Primary attacker-side ADCS | Keep; install with pipx. |
| BloodHound CE CLI/Docker | Primary AD analysis | Keep. Do not enable Docker at boot automatically. |
| git-dumper | Conditional web | Keep. |
| Evil-WinRM | Primary remote shell | Keep; prefer Kali package, gem fallback acceptable. |
| NetExec | Primary AD/SMB/WinRM | Keep; avoid indiscriminate spraying. |
| Kerbrute | Secondary AD enum | Keep; old release but stable utility. |
| Impacket | Primary | Keep via Kali package to avoid Python conflicts. |
| WES-NG | Secondary patch triage | Keep; results are leads, not proof. |
| Inbit Messenger exploit reference | Target-specific | Consider moving target-specific exploits to an optional pack. |
| Nmap/NSE | Primary initial access | Keep. |
| feroxbuster/gobuster/ffuf | Primary web discovery | All work; choose one primary + one fallback mentally to reduce cognitive load. |
| whatweb | Secondary fingerprinting | Keep. |
| hydra | Conditional credential testing | Keep with small-list/rate-limit discipline. |
| SMB/RPC/NFS clients | Primary service enum | Keep. |
| ldapsearch | Primary manual LDAP | Keep. |
| SNMP tools | Conditional | Keep. |
| DB clients | Conditional | Keep native clients. |
| MQTT clients | Conditional | Keep. |
| smtp-user-enum/finger-user-enum | Conditional | Keep. |
| WPScan | Conditional | Keep while respecting current exam restrictions on automated exploitation. |
| high-port-http-check.sh | Improved | v7 validates ports. Future: IPv6 URL formatting + output directory. |
| finger-quick-enum.sh | Good | Future: optional custom user list + timeout flag. |
| ftp-anon-mirror.sh | Good | Future: total-size/file-count caps. |
| make-ps-enc.sh | Improved in v7 | Adds stdin support and dependency checks. |
| decode-helper.sh | Improved in v7 | Adds URL, standard/url-safe Base64, hex, UTF-16LE and second-layer decode. |
| BloodHound helpers | Improved in v7 | Start Docker without enabling it persistently. |
| web shells/manual payload templates | Keep | Transparent and exam-oriented; avoid turning them into automated exploitation frameworks. |
| cron PATH templates | Keep | Use only after confirming writable PATH conditions. |
| adduser.c | Needs follow-up | Replace hard-coded dave2/password12345! with configurable/generated values. |

## Next improvements

1. Expand hash pinning from CopyFail to upstream assets that publish checksums.
2. Add a machine-readable tools manifest: name, role, source, version/ref, architecture, priority, exam note.
3. Split a smaller core exam pack from legacy/edge-case tooling.
4. Rebuild dfold reproducibly from a pinned DirtyFrag source commit and store build metadata.
5. Replace hard-coded credentials in windows/adduser.c.
6. Add x86/x64/.NET selection helpers so compatibility binaries are not all presented as equal first choices.
