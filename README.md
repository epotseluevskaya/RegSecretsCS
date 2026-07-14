# RegSecretsCS

Local Windows credential extraction using registry queries. Inspired by [Impacket's regsecrets.py](https://github.com/fortra/impacket/blob/master/examples/regsecrets.py) and the [Synacktiv research](https://www.synacktiv.com/en/publications/lsa-secrets-revisiting-secretsdump) on registry-only secret extraction. Has most of the python version's capabilities.

## What it extracts

- **SAM hashes** — local account NTLM hashes (LM + NT)
- **LSA secrets** — service account passwords (`_SC_*`), machine account hash (`$MACHINE.ACC`), DPAPI keys, `DefaultPassword`
- **Cached domain credentials** — DCC2/MSCACHEv2 hashes from domain-joined machines

## How it works

Uses `REG_OPTION_BACKUP_RESTORE` flag in `RegOpenKeyEx`. Requires `SeBackupPrivilege`. All data is read and decrypted in memory.

## Build

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:RegSecrets.dll RegSecrets.cs
```

Or as standalone EXE:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:RegSecrets.exe RegSecrets.cs
```

## Usage

**As EXE:**

```
RegSecrets.exe              - full dump
RegSecrets.exe --sam-only   - SAM hashes only
```

**As DLL:**

```powershell
[Reflection.Assembly]::LoadFile((Resolve-Path ".\RegSecrets.dll").Path)
[RegSecrets.Dumper]::Execute(@())              # full dump
[RegSecrets.Dumper]::Execute(@("--sam-only"))   # SAM only
```

**In-memory:**

```powershell
$bytes = [IO.File]::ReadAllBytes(".\RegSecrets.dll")
[Reflection.Assembly]::Load($bytes)
[RegSecrets.Dumper]::Execute(@())
```

**From C#:**

```csharp
RegSecrets.Dumper.Execute(new string[] { });
RegSecrets.Dumper.Execute(new string[] { "--sam-only" });
```

## Disclaimer

This tool is provided for **authorized security testing, research, and educational purposes only**. Use it only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assume no liability for misuse.

This code was AI-generated and then tested manually on domain-joined and standalone Windows machines across SAM revision 1 (RC4) and 2 (AES) systems, LM/NT hash variants, LSA service account secrets, DPAPI keys, machine accounts, and DCC2 cached domain credentials.
