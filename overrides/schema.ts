export type IpFamily = "ipv4" | "ipv6";

export type SpecialNetworkType =
  | "this_network"
  | "private_lan"
  | "loopback"
  | "link_local"
  | "cgnat_shared"
  | "virtual_mesh"
  | "virtual_mesh_dns"
  | "fake_ip"
  | "nat64_translation"
  | "discard"
  | "ietf_protocol"
  | "benchmarking"
  | "documentation"
  | "tunnel_6to4"
  | "multicast"
  | "reserved";

export type VirtualNetworkProvider = "tailscale" | "cloudflare_mesh" | "surge_vif" | "zerotier";

export interface SpecialNetworkEntry {
  readonly cidr: string;
  readonly networkType: SpecialNetworkType;
  readonly virtualNetwork?: VirtualNetworkProvider;
  readonly organization: string;
  readonly isBogon: boolean;
  readonly isPrivate: boolean;
  readonly isVirtualMesh: boolean;
  readonly rfcOrDoc: string;
}

export interface CountryOverrideEntry {
  readonly cidr: string;
  readonly isoCode: string;
  readonly registeredIsoCode?: string;
  readonly subdivisionIsoCode?: string;
  readonly cityEn?: string;
  readonly cityZhCn?: string;
  readonly isp?: string;
  readonly organization?: string;
  readonly isAnycast?: boolean;
  readonly clearCity?: boolean;
  readonly rationale: string;
}

export interface CnExclusionEntry {
  readonly cidr: string;
  readonly fallbackIsoCode?: string;
  readonly asn?: number;
  readonly rationale: string;
}

export interface AsnOverrideEntry {
  readonly asn: number;
  readonly organization: string;
  readonly isp?: string;
  readonly domain?: string;
  readonly countryHint?: string;
  readonly provinceHintZhCn?: string;
  readonly isHosting?: boolean;
  readonly isCdn?: boolean;
  readonly isAnycast?: boolean;
}

export interface GeoIpOverridesBundle {
  readonly schemaVersion: 1;
  readonly specialNetworks: readonly SpecialNetworkEntry[];
  readonly countryOverrides: readonly CountryOverrideEntry[];
  readonly cnExclusions: readonly CnExclusionEntry[];
  readonly asnOverrides: readonly AsnOverrideEntry[];
}
