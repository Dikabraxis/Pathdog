"""Plain-English descriptions for each edge type, used in the HTML report.

Each entry has:
    title  : short verb-led label, e.g. "Local admin via psexec"
    plain  : 1-sentence explanation a non-AD-expert can understand
    impact : what changes after the exploit (identity, capability)
"""

from __future__ import annotations


_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "MemberOf": {
        "title": "Group membership",
        "plain": "The source is a member of the group on the right. No exploit needed — this is just structural inheritance: the source automatically has the group's permissions.",
        "impact": "No identity change. You inherit every right the group has.",
    },
    "Contains": {
        "title": "Container hierarchy",
        "plain": "The container on the left holds the object on the right (OU/Domain → object). No exploit, just directory structure.",
        "impact": "No identity change. Used to walk to objects inside the container.",
    },
    "AdminTo": {
        "title": "Local admin on a machine",
        "plain": "You are local administrator on this computer. Run code on it remotely, and once you're SYSTEM you can dump every secret stored locally (SAM, LSA, cached creds, LSASS).",
        "impact": "You become SYSTEM on the target host. Anything stored on it (hashes, tickets, plaintext passwords in LSASS) is yours.",
    },
    "CanRDP": {
        "title": "Remote Desktop access",
        "plain": "You can RDP into this computer with your current credentials. You get an interactive desktop as your user — not necessarily admin on the host.",
        "impact": "You have an interactive session as your current user on the target.",
    },
    "CanPSRemote": {
        "title": "WinRM / PowerShell Remoting",
        "plain": "You can open a PowerShell remote session on this computer (port 5985/5986). Useful when SMB is blocked. You run as your user, not as admin.",
        "impact": "You have a remote shell as your current user on the target.",
    },
    "ExecuteDCOM": {
        "title": "DCOM lateral movement",
        "plain": "You can invoke DCOM objects (MMC20.Application etc.) on this computer to run arbitrary commands. Often works when SMB lateral is blocked.",
        "impact": "Code execution on the target as your current user.",
    },
    "SQLAdmin": {
        "title": "SQL Server sysadmin",
        "plain": "You're sysadmin on the SQL instance running on this computer. Use xp_cmdshell to get OS code execution, almost always as SYSTEM (the SQL service account).",
        "impact": "Code execution on the SQL host, typically SYSTEM.",
    },
    "HasSession": {
        "title": "Stealable session",
        "plain": "A privileged user has logged in to this computer and their token is in memory. If you get local admin on this host, you can steal their session and impersonate them.",
        "impact": "You become the session owner once you reach SYSTEM on the host.",
    },
    "DCSync": {
        "title": "DCSync — dump every domain hash",
        "plain": "You hold the replication right on the domain. You can ask any DC to send you every secret in AD, including the krbtgt key (which lets you forge Golden Tickets forever).",
        "impact": "Full domain compromise. You get NTLM hashes for every account, including Domain Admins.",
    },
    "GetChangesAll": {
        "title": "DCSync (half — all replicated attributes)",
        "plain": "You have the 'Replicating Directory Changes All' right. Combined with 'Replicating Directory Changes' on the same domain, this equals DCSync.",
        "impact": "On its own, not exploitable. Pair it with GetChanges and you can DCSync.",
    },
    "GetChanges": {
        "title": "DCSync (half — directory changes)",
        "plain": "You have the 'Replicating Directory Changes' right. Combined with 'GetChangesAll' on the same domain, this equals DCSync.",
        "impact": "On its own, not exploitable. Pair it with GetChangesAll and you can DCSync.",
    },
    "GetChangesInFilteredSet": {
        "title": "Filtered replication right",
        "plain": "Replication right scoped to the filtered attribute set. It does not substitute for GetChanges.",
        "impact": "On its own, not a DCSync path. DCSync still requires GetChanges + GetChangesAll on the domain.",
    },
    "GenericAll": {
        "title": "Full control over the object",
        "plain": "You have every possible right on this object. For users you can reset their password or add Shadow Credentials. For computers you can do RBCD or Shadow Credentials. For groups you add yourself. For the domain you grant yourself DCSync.",
        "impact": "Depends on the target kind — typically you take over the object or its identity.",
    },
    "AllExtendedRights": {
        "title": "All extended rights",
        "plain": "You hold every extended right on this object. For users that includes ForceChangePassword. For the domain that includes the replication rights (= DCSync).",
        "impact": "User → reset password and become them. Domain → DCSync.",
    },
    "AddMember": {
        "title": "Add a member to a group",
        "plain": "You can add any principal (including yourself) to this group. Once added, you inherit everything the group has.",
        "impact": "You join the group and gain its permissions.",
    },
    "AddSelf": {
        "title": "Add yourself to a group",
        "plain": "Restricted version of AddMember — only your own account can be added.",
        "impact": "You join the group and gain its permissions.",
    },
    "ForceChangePassword": {
        "title": "Reset the user's password",
        "plain": "You can reset this user's password without knowing the current one. Loud (the user will notice on next logon) but very direct.",
        "impact": "You become the target user with a password you set.",
    },
    "GenericWrite": {
        "title": "Generic write on the object",
        "plain": "You can modify most of the object's attributes. Best uses: add a Shadow Credential (msDS-KeyCredentialLink) to authenticate as the target, or write a fake SPN to make them Kerberoastable.",
        "impact": "Typically: become the target via Shadow Credentials, or roast their hash.",
    },
    "WriteSPN": {
        "title": "Write SPN — make target Kerberoastable",
        "plain": "You can write the servicePrincipalName attribute. Set any SPN, then ask for a service ticket — the ticket is encrypted with the target's NT hash, which you can crack offline.",
        "impact": "Offline crack of the target's password (only works on weak passwords).",
    },
    "Owns": {
        "title": "Object owner",
        "plain": "You own the object. As owner you can grant yourself any right by editing its DACL.",
        "impact": "Self-grant FullControl, then exploit as if you had GenericAll.",
    },
    "WriteOwner": {
        "title": "Change the owner",
        "plain": "You can set yourself (or someone you control) as the new owner. Once owner, grant yourself FullControl via the DACL.",
        "impact": "Take ownership, then self-grant rights → equivalent to GenericAll.",
    },
    "WriteDacl": {
        "title": "Write the object's DACL",
        "plain": "You can modify the access-control list on the object. Add an ACE granting yourself any right. On the domain, add a DCSync ACE.",
        "impact": "Self-grant FullControl on the object — domain target gives DCSync.",
    },
    "ReadLAPSPassword": {
        "title": "Read the LAPS local admin password",
        "plain": "LAPS stores a randomized local admin password on the computer's AD object. You can read it and log in as local administrator on that machine.",
        "impact": "You become local Administrator on the target host.",
    },
    "SyncLAPSPassword": {
        "title": "Read LAPS via sync",
        "plain": "Same outcome as ReadLAPSPassword — you can pull the LAPS-managed local admin password.",
        "impact": "You become local Administrator on the target host.",
    },
    "AllowedToDelegate": {
        "title": "Constrained delegation",
        "plain": "The source can request a Kerberos ticket to specific services on the target on behalf of any user — including a Domain Admin. You impersonate Administrator and get code execution on the target as them.",
        "impact": "You impersonate Administrator on the target host (within the allowed SPNs).",
    },
    "AllowedToAct": {
        "title": "Resource-Based Constrained Delegation (RBCD)",
        "plain": "You can configure msDS-AllowedToActOnBehalfOfOtherIdentity on the target. Create a controlled computer account, link it, then impersonate Administrator on the target.",
        "impact": "You impersonate Administrator on the target host.",
    },
    "WriteAccountRestrictions": {
        "title": "Write account restrictions (RBCD-capable)",
        "plain": "You can edit the target's userAccountControl / msDS-AllowedToActOnBehalfOfOtherIdentity. Same outcome as AllowedToAct: set up RBCD and impersonate.",
        "impact": "You impersonate Administrator on the target host.",
    },
    "AddKeyCredentialLink": {
        "title": "Shadow Credentials",
        "plain": "You write a key-credential (msDS-KeyCredentialLink) on the target. You then authenticate as the target via PKINIT and get their TGT — without ever changing their password.",
        "impact": "You become the target user (stealthy — no password reset).",
    },
    "GPLink": {
        "title": "GPO linked to OU/domain",
        "plain": "The GPO on the left is linked to the OU/domain on the right. If you control the GPO, you push a payload (scheduled task / local admin add) to every machine under that OU.",
        "impact": "Code execution on every host that applies the GPO — typically as SYSTEM.",
    },
    "WriteGPLink": {
        "title": "Link a GPO yourself",
        "plain": "You can write the gpLink attribute on the OU/domain — i.e. attach any GPO to it. Combined with control over a GPO, you push payloads to everything underneath.",
        "impact": "Code execution under the OU when paired with a controlled GPO.",
    },
    "TrustedBy": {
        "title": "Domain trust (forge inter-realm ticket)",
        "plain": "The right-hand domain trusts the left-hand one. With the trust key, forge a Golden TGT carrying the target domain's DA SID — full DA in the trusted domain.",
        "impact": "Domain Admin in the trusted (target) domain.",
    },
    "SameForestTrust": {
        "title": "Same-forest trust",
        "plain": "Trust within the same AD forest. SID-history attack with the trust key gives you DA in the trusted domain.",
        "impact": "DA in the trusted domain.",
    },
    "CrossForestTrust": {
        "title": "Cross-forest trust",
        "plain": "Trust spanning forests. With SID filtering off (or via specific bypasses), forge an inter-realm ticket and reach DA in the other forest.",
        "impact": "DA in the trusted forest (when SID filtering is misconfigured).",
    },
    "DCFor": {
        "title": "Is a Domain Controller",
        "plain": "This host serves as a DC for the domain. If you have its credentials, you can DCSync directly through it.",
        "impact": "DCSync the domain via this DC.",
    },
    # ADCS
    "Enroll": {
        "title": "Certificate enrollment right",
        "plain": "You can enroll for certificates from this template/CA. Pair with a vulnerable template (ESC1/2/3...) to get a cert that authenticates as Administrator.",
        "impact": "Path to Domain Admin via certificate authentication when a vulnerable template is reachable.",
    },
    "AutoEnroll": {
        "title": "Certificate auto-enrollment",
        "plain": "Automatic enrollment is permitted. Same exploitation surface as Enroll.",
        "impact": "Same as Enroll — chain with a vulnerable template.",
    },
    "WritePKINameFlag": {
        "title": "Modify cert template name flag (ESC4 → ESC1)",
        "plain": "You can edit the template's name flag. Flip ENROLLEE_SUPPLIES_SUBJECT and you turn the template into ESC1 — you supply a SAN like Administrator and authenticate as them.",
        "impact": "DA via certificate authentication (after restoring the template).",
    },
    "WritePKIEnrollmentFlag": {
        "title": "Modify cert template enrollment flag (ESC4 → ESC1)",
        "plain": "Same as WritePKINameFlag but on the enrollment flag — also pivots a benign template into ESC1.",
        "impact": "DA via certificate authentication.",
    },
    "ManageCA": {
        "title": "CA management right (ESC7)",
        "plain": "You're a CA Manager. Approve any pending request, even denied ones. You can also add yourself as Officer and issue arbitrary certs.",
        "impact": "DA via cert issuance / approval.",
    },
    "ManageCertificates": {
        "title": "CA Officer right",
        "plain": "You can issue certificates on the CA. Combined with ManageCA you get full control of issuance.",
        "impact": "DA via cert issuance.",
    },
    "DelegatedEnrollmentAgent": {
        "title": "Enrollment agent delegation",
        "plain": "You can enroll on behalf of others. Request a cert as Administrator using your agent cert.",
        "impact": "DA via on-behalf-of enrollment.",
    },
    "ADCSESC1": {
        "title": "ADCS ESC1 — vulnerable template",
        "plain": "Template lets the enrollee supply the Subject Alternative Name. Request a cert with SAN=Administrator and you authenticate as Administrator.",
        "impact": "Domain Admin via cert auth.",
    },
    "ADCSESC3": {
        "title": "ADCS ESC3 — Enrollment Agent",
        "plain": "Template grants Enrollment Agent EKU. Request an agent cert, then enroll on-behalf-of Administrator.",
        "impact": "Domain Admin via on-behalf-of enrollment.",
    },
    "ADCSESC4": {
        "title": "ADCS ESC4 — write rights on template",
        "plain": "You can edit the template object. Make it ESC1-vulnerable, enroll, then restore. Stealthy when restored quickly.",
        "impact": "Domain Admin via cert auth.",
    },
    "ADCSESC6a": {
        "title": "ADCS ESC6a — CA flag set",
        "plain": "EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled on the CA. Any client-auth template now lets you supply a SAN, equivalent to ESC1 globally.",
        "impact": "Domain Admin via cert auth.",
    },
    "ADCSESC6b": {
        "title": "ADCS ESC6b — strict mapping bypass",
        "plain": "CA misconfigured for new strong-mapping requirements. Same outcome as ESC6a.",
        "impact": "Domain Admin via cert auth.",
    },
    "ADCSESC9a": {
        "title": "ADCS ESC9a — no security extension",
        "plain": "Template lacks the szOID_NTDS_CA_SECURITY_EXT. Combined with GenericWrite on a victim, swap their UPN to Administrator, enroll, restore.",
        "impact": "Domain Admin via cert auth + UPN swap.",
    },
    "ADCSESC9b": {
        "title": "ADCS ESC9b — DNS hostname swap",
        "plain": "Same as ESC9a but on dnsHostName for computer accounts.",
        "impact": "DA-equivalent (often via DC computer account).",
    },
    "ADCSESC10a": {
        "title": "ADCS ESC10a — weak certificate mapping",
        "plain": "Weak mapping on DC. Swap UPN, enroll, authenticate as Administrator.",
        "impact": "Domain Admin via cert auth.",
    },
    "ADCSESC10b": {
        "title": "ADCS ESC10b — DNS-based weak mapping",
        "plain": "Weak DNS-name mapping on DC. Swap dnsHostName, enroll, take over.",
        "impact": "DA-equivalent.",
    },
    "ADCSESC13": {
        "title": "ADCS ESC13 — issuance policy → group",
        "plain": "Issuance policy on the template is linked to a privileged group. Cert auth implicitly grants membership.",
        "impact": "Implicit privileged group membership.",
    },
    "GoldenCert": {
        "title": "Golden Certificate (CA private key)",
        "plain": "You captured the CA's private key. Forge any user/computer cert offline, forever, until the CA is replaced.",
        "impact": "Permanent domain compromise.",
    },
    # Coercion / relay
    "CoerceAndRelayNTLMToSMB": {
        "title": "Coerce + relay NTLM to SMB",
        "plain": "Coerce a privileged account to authenticate to your relay, then forward its NTLM auth to SMB on the target.",
        "impact": "Code execution on the relay target as the coerced account.",
    },
    "CoerceAndRelayNTLMToLDAP": {
        "title": "Coerce + relay NTLM to LDAP",
        "plain": "Relay coerced NTLM to LDAP. With LDAP signing off you can write directory objects (e.g. add yourself to a group, RBCD).",
        "impact": "Directory writes, often → DA.",
    },
    "CoerceAndRelayNTLMToLDAPS": {
        "title": "Coerce + relay NTLM to LDAPS",
        "plain": "Same but to LDAPS. Bypasses signing/EPA only when channel binding is off.",
        "impact": "Directory writes, often → DA.",
    },
    "CoerceAndRelayNTLMToADCS": {
        "title": "Coerce + relay NTLM to ADCS Web Enrollment",
        "plain": "Relay coerced auth to the CA's HTTP enrollment endpoint and request a cert as the coerced computer/user.",
        "impact": "Cert as the coerced principal — typically a DC → DA.",
    },
    "OwnsLimitedRights": {
        "title": "Limited ownership (post-hardening)",
        "plain": "Owner with reduced rights after recent Windows hardening. You can still grant FullControl on most objects.",
        "impact": "Same as Owns in practice.",
    },
    "WriteOwnerLimitedRights": {
        "title": "Limited WriteOwner",
        "plain": "Same hardening as OwnsLimitedRights but on the WriteOwner side.",
        "impact": "Same as WriteOwner in practice.",
    },
}


def for_edge(rel_type: str) -> dict[str, str]:
    """Return {title, plain, impact} for a relation type, or sensible defaults."""
    return _DESCRIPTIONS.get(rel_type, {
        "title": rel_type,
        "plain": f"Relation '{rel_type}' — see BloodHound documentation.",
        "impact": "Effect varies — read the commands.",
    })


# ── Vector explanations (out-of-band attacks for pivot candidates) ────────────

VECTOR_EXPLANATIONS: dict[str, str] = {
    "AS-REP roast (no creds needed)": (
        "The account has DontReqPreAuth set. You can ask the DC for an AS-REP "
        "without authenticating — the response is encrypted with the user's NT "
        "hash, crackable offline."
    ),
    "Kerberoast": (
        "The account has a Service Principal Name. Any authenticated user can "
        "request a TGS ticket for it, encrypted with the user's NT hash. Crack "
        "offline if the password is weak."
    ),
    "PasswordNotRequired (try empty/weak)": (
        "ADS_UF_PASSWD_NOTREQD is set on the account. The password may be empty "
        "or trivial — try blank, the username, common defaults."
    ),
    "LAPS — read local admin password if you can": (
        "LAPS rotates the local admin password and stores it in AD. If a "
        "principal you control has ReadLAPSPassword on this computer, you read "
        "it directly and log in."
    ),
    "Unconstrained delegation — get local admin then capture DC TGT": (
        "If you reach SYSTEM on this host (with unconstrained delegation), any "
        "user that authenticates to it leaves a usable TGT in LSASS. Coerce a "
        "DC, capture its TGT, DCSync."
    ),
}


def for_vector(label: str) -> str:
    return VECTOR_EXPLANATIONS.get(label, "")


# ── Quick-win category explanations ───────────────────────────────────────────

QUICKWIN_EXPLANATIONS: dict[str, str] = {
    "AS-REP roast": (
        "Users with DontReqPreAuth — no credentials needed to extract a "
        "crackable hash. Free win against weak passwords."
    ),
    "Kerberoast": (
        "Users with a Service Principal Name. Any authenticated user can "
        "harvest their crackable hash."
    ),
    "Unconstrained delegation": (
        "Hosts that store TGTs of authenticators in LSASS. SYSTEM on these = "
        "harvest other users' TGTs (including DC$ via coercion)."
    ),
    "Password not required": (
        "Accounts flagged ADS_UF_PASSWD_NOTREQD — the password may be empty."
    ),
    "LAPS in use": (
        "LAPS-managed hosts. If you control a reader, the local admin "
        "password is yours."
    ),
    "ADCS ESC1": "Vulnerable template lets enrollee supply SAN.",
    "ADCS ESC3": "Enrollment Agent template — request on behalf of others.",
    "ADCS ESC4": "Write rights on template — pivot it into ESC1.",
    "ADCS ESC6a": "CA flag enables SAN supply for any client-auth template.",
    "ADCS ESC6b": "CA strong-mapping bypass.",
    "ADCS ESC9a": "Template lacks security extension — UPN swap.",
    "ADCS ESC9b": "Same but for dnsHostName.",
    "ADCS ESC10a": "Weak DC certificate mapping.",
    "ADCS ESC10b": "Weak DNS-based DC mapping.",
    "ADCS ESC13": "Issuance policy linked to a privileged group.",
    "ADCS GoldenCert": "CA private key compromised — forge anything.",
    "Domain Controller": (
        "DCs are coercion targets (PetitPotam / PrinterBug / DFSCoerce). "
        "Authenticated users can trigger NTLM auth from them."
    ),
    "Privileged user not protected": (
        "AdminCount=1 but not in 'Sensitive and cannot be delegated'. "
        "Vulnerable to delegation attacks."
    ),
    "High-value target": (
        "Tier-0 / privileged objects. Their compromise = domain compromise."
    ),
}


def for_quickwin(category: str) -> str:
    return QUICKWIN_EXPLANATIONS.get(category, "")
