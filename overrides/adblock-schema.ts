export type AllowDomainMatchType = "exact" | "suffix";

export interface AllowDomainEntry {
  readonly matchType: AllowDomainMatchType;
  readonly domain: string;
  readonly rationale: string;
}

export interface ProtectedApexDomainEntry {
  readonly domain: string;
  readonly rationale: string;
}

export type AdblockRuleTarget = "ad" | "privacy";

export type ForceRuleSetKind =
  | "DOMAIN"
  | "DOMAIN-SUFFIX"
  | "DOMAIN-KEYWORD"
  | "DOMAIN-WILDCARD"
  | "IP-CIDR"
  | "IP-CIDR6"
  | "IP-ASN"
  | "USER-AGENT"
  | "PROCESS-NAME";

export interface ForceRuleSetEntry {
  readonly target: AdblockRuleTarget;
  readonly kind: ForceRuleSetKind;
  readonly value: string;
  readonly rationale: string;
}

export interface MitmHostEntry {
  readonly pattern: string;
  readonly rationale: string;
}

export interface ModuleUrlRewriteOverride {
  readonly pattern: string;
  readonly replacement: string;
  readonly mode: "header" | "302" | "307" | "reject";
  readonly rationale: string;
}

export interface ModuleMapLocalOverride {
  readonly pattern: string;
  readonly dataType: "text" | "tiny-gif" | "base64";
  readonly data?: string;
  readonly statusCode?: number;
  readonly header?: string;
  readonly rationale: string;
}

export interface ModuleHeaderRewriteOverride {
  readonly direction: "http-request" | "http-response";
  readonly pattern: string;
  readonly action: "header-del" | "header-add" | "header-replace" | "header-replace-regex";
  readonly field: string;
  readonly value?: string;
  readonly replaceRegex?: string;
  readonly rationale: string;
}

export interface ModuleBodyRewriteOverride {
  readonly kind: "http-request" | "http-response" | "http-request-jq" | "http-response-jq";
  readonly pattern: string;
  readonly expression: string;
  readonly replacement?: string;
  readonly rationale: string;
}

export interface ModuleScriptOverride {
  readonly name: string;
  readonly scriptType: "http-request" | "http-response";
  readonly pattern: string;
  readonly scriptPath: string;
  readonly requiresBody?: boolean;
  readonly binaryBodyMode?: boolean;
  readonly maxSize?: number;
  readonly argument?: string;
  readonly rationale: string;
}

export interface AdblockOverridesBundle {
  readonly schemaVersion: 1;
  readonly allowDomains: readonly AllowDomainEntry[];
  readonly protectedApexDomains: readonly ProtectedApexDomainEntry[];
  readonly forceRuleSetEntries: readonly ForceRuleSetEntry[];
  readonly mitmExcludedHosts: readonly MitmHostEntry[];
  readonly mitmAddedHosts: readonly MitmHostEntry[];
  readonly disabledUrlPatterns: readonly string[];
  readonly urlRewrites: readonly ModuleUrlRewriteOverride[];
  readonly mapLocals: readonly ModuleMapLocalOverride[];
  readonly headerRewrites: readonly ModuleHeaderRewriteOverride[];
  readonly bodyRewrites: readonly ModuleBodyRewriteOverride[];
  readonly scripts: readonly ModuleScriptOverride[];
}
