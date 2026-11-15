export type ContinentCode = "AF" | "AN" | "AS" | "EU" | "NA" | "OC" | "SA";

export type CloudProviderId = "aws" | "gcp" | "oracle" | "azure";

export interface MetadataUpstreamSource {
  readonly id: string;
  readonly repoOrSite: string;
  readonly description: string;
  readonly urls: readonly string[];
  readonly archiveMember?: string;
}

export interface CountryMetadataEntry {
  isoCode: string;
  continentCode: ContinentCode;
  continentGeonameId: number;
  continentEn: string;
  continentZh: string;
  geonameId: number;
  isEu: boolean;
  nameEn: string;
  nameZh: string;
  defaultTz: string;
  aliases: string[];
}

export interface CnDivisionMetadataEntry {
  adcode: string;
  level: 1 | 2 | 3;
  isoCode: string;
  provinceZh: string;
  provinceEn: string;
  cityZh: string;
  cityEn: string;
  districtZh: string;
  districtEn: string;
  geonameId: number;
  lat: number;
  lon: number;
}

export interface CloudRegionMetadataEntry {
  provider: CloudProviderId;
  region: string;
  isoCode: string;
  subdivisionIso: string;
  subdivisionEn: string;
  cityEn: string;
  tz: string;
  lat: number;
  lon: number;
}

export interface CompiledMetadataBundle {
  schemaVersion: 1;
  upstreams: string[];
  countries: CountryMetadataEntry[];
  cnDivisions: CnDivisionMetadataEntry[];
  cloudRegions: CloudRegionMetadataEntry[];
}
