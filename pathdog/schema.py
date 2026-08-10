"""BloodHound relationship classification used by Pathdog.

The two sets below are intentionally explicit.  Pathfinding is fail-closed:
an edge must be both traversable in BloodHound and implemented by Pathdog
before it can enter the attack graph.

Source: https://bloodhound.specterops.io/resources/edges/traversable-edges
Reviewed against BloodHound 9.5.1 / SharpHound 2.14.0 on 2026-08-10.
"""

from .weights import EDGE_WEIGHTS

BLOODHOUND_SCHEMA_VERSION = "9.5.1"
SHARPHOUND_SCHEMA_VERSION = "2.14.0"


TRAVERSABLE_EDGES = frozenset({
    "AbuseTGTDelegation",
    "ADCSESC1",
    "ADCSESC10a",
    "ADCSESC10b",
    "ADCSESC13",
    "ADCSESC3",
    "ADCSESC4",
    "ADCSESC6a",
    "ADCSESC6b",
    "ADCSESC9a",
    "ADCSESC9b",
    "AddAllowedToAct",
    "AddKeyCredentialLink",
    "AddMember",
    "AddSelf",
    "AdminTo",
    "AllExtendedRights",
    "AllowedToAct",
    "AllowedToDelegate",
    "CanPSRemote",
    "CanRDP",
    "ClaimSpecialIdentity",
    "CoerceAndRelayNTLMToADCS",
    "CoerceAndRelayNTLMToLDAP",
    "CoerceAndRelayNTLMToLDAPS",
    "CoerceAndRelayNTLMToSMB",
    "CoerceToTGT",
    "Contains",
    "CrossForestTrust",
    "DCFor",
    "DCSync",
    "DumpSMSAPassword",
    "ExecuteDCOM",
    "ForceChangePassword",
    "GenericAll",
    "GenericWrite",
    "GoldenCert",
    "GPLink",
    "HasSIDHistory",
    "HasSession",
    "HasTrustKeys",
    "ManageCA",
    "ManageCertificates",
    "MemberOf",
    "Owns",
    "OwnsLimitedRights",
    "ReadGMSAPassword",
    "ReadLAPSPassword",
    "SameForestTrust",
    "SpoofSIDHistory",
    "SQLAdmin",
    "SyncedToADUser",
    "SyncedToEntraUser",
    "SyncLAPSPassword",
    "WriteAccountRestrictions",
    "WriteAltSecurityIdentities",
    "WriteDacl",
    "WriteGPLink",
    "WriteOwner",
    "WriteOwnerLimitedRights",
    "WritePublicInformation",
    "WriteSPN",
})


NON_TRAVERSABLE_EDGES = frozenset({
    "DelegatedEnrollmentAgent",
    "Enroll",
    "EnrollOnBehalfOf",
    "EnterpriseCAFor",
    "ExtendedByPolicy",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
    "HostsCAService",
    "IssuedSignedBy",
    "LocalToComputer",
    "MemberOfLocalGroup",
    "NTAuthStoreFor",
    "OIDGroupLink",
    "OwnsRaw",
    "ProtectAdminGroups",
    "PublishedTo",
    "RemoteInteractiveLogonRight",
    "RootCAFor",
    "TrustedForNTAuth",
    "WriteOwnerRaw",
    "WritePKIEnrollmentFlag",
    "WritePKINameFlag",
})


KNOWN_BLOODHOUND_EDGES = TRAVERSABLE_EDGES | NON_TRAVERSABLE_EDGES

# Pathdog's legacy loader can still emit these names.  They are retained for
# context/reporting but are not part of the current BloodHound traversal model.
LEGACY_CONTEXT_EDGES = frozenset({"AutoEnroll", "TrustedBy"})

# A weight means Pathdog has deliberately modelled this edge.  Intersecting
# with BloodHound's list prevents old/context-only weights from accidentally
# becoming traversable (for example TrustedBy or Enroll).
SUPPORTED_TRAVERSABLE_EDGES = frozenset(EDGE_WEIGHTS) & TRAVERSABLE_EDGES
