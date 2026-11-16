export type RoutingRuleKind =
  | "DOMAIN"
  | "DOMAIN-SUFFIX"
  | "DOMAIN-KEYWORD"
  | "DOMAIN-WILDCARD"
  | "IP-CIDR"
  | "IP-CIDR6"
  | "IP-ASN"
  | "URL-REGEX"
  | "USER-AGENT"
  | "PROCESS-NAME"
  | "AND";

export type RoutingExclusionKind =
  | "DOMAIN"
  | "DOMAIN-SUFFIX"
  | "DOMAIN-KEYWORD"
  | "DOMAIN-WILDCARD"
  | "IP-CIDR"
  | "IP-CIDR6"
  | "IP-ASN"
  | "PROCESS-NAME";

export type RoutingOverrideTarget = "direct" | "ai" | "payment" | "telemetry" | "proxy";

export interface RoutingRuleOverride {
  readonly target: RoutingOverrideTarget;
  readonly kind: RoutingRuleKind;
  readonly value: string;
  readonly extendedMatching?: boolean;
  readonly rationale: string;
}

export interface RoutingExclusionOverride {
  readonly target: RoutingOverrideTarget;
  readonly kind: RoutingExclusionKind;
  readonly value: string;
  readonly rationale: string;
}

export interface SharedInfraRootEntry {
  readonly domain: string;
  readonly rationale: string;
}

export interface RoutingOverridesBundle {
  readonly schemaVersion: 1;
  readonly sharedInfraRoots: readonly SharedInfraRootEntry[];
  readonly forceEntries: readonly RoutingRuleOverride[];
  readonly excludeEntries: readonly RoutingExclusionOverride[];
}
