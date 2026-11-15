use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use encoding_rs::GB18030;
use indexmap::IndexSet;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use proptest::prelude::*;
use rustc_hash::FxBuildHasher;
use tempfile::TempDir;

use surge_rules::config::{
    EndpointConfig, MetadataRegistry, SourceCatalog, SourceConfig, SourceFormat, SourceTier,
    normalize_isp_name,
};
use surge_rules::fusion::{OutputSpanV4, OutputSpanV6, flatten_disjoint_v4, run_fusion};
use surge_rules::inspect_ip_in_dir;
use surge_rules::mmdb_encode::{write_asn_mmdb, write_country_only_mmdb, write_geo_mmdb};
use surge_rules::model::{
    COORD_UNSET, GlobalArena, IntervalV4, IsoCode, ObsPayload, ParsedSource, ResolvedGeoRecord,
    StringPool, TraitFlags, quantize_coord, range_to_ipv4_cidrs, range_to_ipv6_cidrs,
};
use surge_rules::overrides::CompiledOverrides;
use surge_rules::parsers::parse_source_bytes;
use surge_rules::verify::{lookup_opt, verify_artifact_dir};

fn load_real_fixtures() -> (MetadataRegistry, SourceCatalog, CompiledOverrides) {
    let metadata =
        MetadataRegistry::load_from_path(Path::new("metadata/generated/geoip-metadata.json"))
            .expect("metadata/generated/geoip-metadata.json should load cleanly");
    let catalog = SourceCatalog::load_from_path(Path::new("sources/generated/geoip-sources.json"))
        .expect("sources/generated/geoip-sources.json should load cleanly");
    let overrides = CompiledOverrides::load_from_path(
        Path::new("overrides/generated/geoip-overrides.json"),
        &metadata,
    )
    .expect("overrides/generated/geoip-overrides.json should load cleanly");
    (metadata, catalog, overrides)
}

fn dummy_source(id: &str, tier: SourceTier, format: SourceFormat, lineage: &str) -> SourceConfig {
    SourceConfig {
        id: id.to_string(),
        tier,
        format,
        lineage: lineage.to_string(),
        country_weight: 85,
        cn_weight: 85,
        city_weight: 80,
        isp_weight: 80,
        asn_weight: 85,
        registered_country_weight: 60,
        fixed_country: None,
        fixed_isp: None,
        is_hosting: false,
        is_cdn: false,
        is_vpn: false,
        is_anycast: false,
        is_anonymous_proxy: false,
        is_tor_exit: false,
        is_icloud_relay: false,
        is_satellite: false,
        is_crawler: false,
        is_malware: false,
        core: false,
        endpoints: vec![EndpointConfig::Direct {
            url: "https://example.invalid/feed".to_string(),
        }],
    }
}

#[test]
fn catalog_metadata_and_overrides_are_valid_and_complete() {
    let (metadata, catalog, overrides) = load_real_fixtures();

    assert_eq!(
        catalog.sources.len(),
        100,
        "expected 100 upstream sources in catalog, got {}",
        catalog.sources.len()
    );
    for s in &catalog.sources {
        assert!(!s.endpoints.is_empty(), "source {} has no endpoints", s.id);
        assert!(
            !s.lineage.trim().is_empty(),
            "source {} has empty lineage",
            s.id
        );
    }

    // Verify country normalization & strict HK/MO/TW separation
    assert_eq!(metadata.resolve_country("CN"), Some(IsoCode::CN));
    assert_eq!(metadata.resolve_country("中国"), Some(IsoCode::CN));
    assert_eq!(metadata.resolve_country("香港"), Some(IsoCode::HK));
    assert_eq!(metadata.resolve_country("澳门"), Some(IsoCode::MO));
    assert_eq!(metadata.resolve_country("台湾"), Some(IsoCode::TW));
    assert_eq!(metadata.resolve_country("中华民国"), Some(IsoCode::TW));
    assert_eq!(metadata.resolve_country("UK"), Some(IsoCode::GB));
    assert_eq!(metadata.resolve_country("ZZ"), None);
    assert_eq!(metadata.resolve_country("AP"), None);

    // Verify CN division hierarchy splitting
    let (prov_zj, city_hz) = metadata
        .split_cn_location("浙江省杭州市余杭区")
        .expect("Zhejiang Hangzhou should split cleanly");
    assert_eq!(prov_zj.iso_code, "ZJ");
    assert_eq!(prov_zj.province_en, "Zhejiang");
    assert_eq!(prov_zj.province_zh, "浙江省");
    let city_hz = city_hz.expect("Hangzhou city should resolve");
    assert_eq!(city_hz.city_en, "Hangzhou");
    assert_eq!(city_hz.city_zh, "杭州市");

    let (prov_im, city_hh) = metadata
        .split_cn_location("内蒙古自治区呼和浩特市")
        .expect("Inner Mongolia Hohhot should split cleanly");
    assert_eq!(prov_im.iso_code, "NM");
    assert_eq!(city_hh.unwrap().city_en, "Hohhot");

    let (prov_js, city_ks) = metadata
        .split_cn_location("江苏省苏州市昆山市")
        .expect("Jiangsu Suzhou Kunshan should split cleanly");
    assert_eq!(prov_js.iso_code, "JS");
    assert_eq!(city_ks.expect("Kunshan should resolve").city_en, "Kunshan");

    let (prov_hb, city_xt) = metadata
        .split_cn_location("湖北省仙桃市")
        .expect("Hubei Xiantao should split cleanly");
    assert_eq!(prov_hb.iso_code, "HB");
    assert_eq!(city_xt.expect("Xiantao should resolve").city_en, "Xiantao");

    // Verify cloud region resolution with availability zone suffix
    let aws_se = metadata
        .resolve_cloud_region("aws", "eu-north-1a")
        .expect("eu-north-1a should resolve");
    assert_eq!(aws_se.iso_code, IsoCode::parse_raw("SE").unwrap());
    assert_eq!(aws_se.city_en, "Stockholm");

    // Verify ISP normalization
    assert_eq!(
        normalize_isp_name("中国电信").as_deref(),
        Some("China Telecom")
    );
    assert_eq!(normalize_isp_name("CZ88.NET"), None);
    assert_eq!(
        normalize_isp_name("移动数据上网公共出口").as_deref(),
        Some("China Mobile")
    );
    assert_eq!(
        normalize_isp_name("中华电信").as_deref(),
        Some("Chunghwa Telecom")
    );

    // Verify Priority-0 special networks include LAN + Tailscale + Cloudflare Mesh + ZeroTier + Surge Fake-IP
    assert!(!overrides.special_v4.is_empty());
    assert!(!overrides.special_v6.is_empty());
    let has_tailscale_v4 = overrides
        .special_v4
        .iter()
        .any(|s| s.1.virtual_network.as_deref() == Some("tailscale"));
    let has_cf_mesh_v4 = overrides
        .special_v4
        .iter()
        .any(|s| s.1.virtual_network.as_deref() == Some("cloudflare_mesh"));
    let has_surge_vif = overrides
        .special_v4
        .iter()
        .any(|s| s.1.virtual_network.as_deref() == Some("surge_vif"));
    let has_zerotier_v6 = overrides
        .special_v6
        .iter()
        .any(|s| s.1.virtual_network.as_deref() == Some("zerotier"));
    assert!(has_tailscale_v4 && has_cf_mesh_v4 && has_surge_vif && has_zerotier_v6);
}

#[test]
fn parsers_decode_rfc8805_aws_bgp_rir_and_trait_formats() {
    let (metadata, _, _) = load_real_fixtures();

    // 1. RFC 8805 CSV (including CN-HK -> HK normalization)
    let rfc_csv = b"# Geofeed comment\n16.192.0.0/18,SE,SE-AB,Stockholm,111 22\n1.178.103.0/24,CN,CN-HK,Hong Kong,\n2600:9000:2200::/48,JP,JP-13,Tokyo,\n";
    let src_rfc = dummy_source(
        "test_rfc",
        SourceTier::Tier1Geofeed,
        SourceFormat::Rfc8805Csv,
        "rfc",
    );
    let parsed_rfc = parse_source_bytes(&src_rfc, rfc_csv, &metadata).unwrap();
    assert_eq!(parsed_rfc.v4.len(), 2);
    assert_eq!(parsed_rfc.v6.len(), 1);
    let p_hk = &parsed_rfc.payloads[parsed_rfc.v4[0].payload_id() as usize];
    assert_eq!(p_hk.country, Some(IsoCode::HK));
    assert_eq!(parsed_rfc.strings.get(p_hk.subdiv1_iso), "");
    assert_eq!(parsed_rfc.strings.get(p_hk.city_en), "Hong Kong");
    let p0 = &parsed_rfc.payloads[parsed_rfc.v4[1].payload_id() as usize];
    assert_eq!(p0.country, IsoCode::parse_raw("SE"));
    assert_eq!(parsed_rfc.strings.get(p0.subdiv1_iso), "AB");
    assert_eq!(parsed_rfc.strings.get(p0.city_en), "Stockholm");

    // 2. AWS ip-ranges.json
    let aws_json = br#"{
      "prefixes": [{"ip_prefix": "16.192.0.0/18", "region": "eu-north-1", "service": "EC2"}],
      "ipv6_prefixes": [{"ipv6_prefix": "2600:1f18::/32", "region": "us-east-1", "service": "AMAZON"}]
    }"#;
    let mut src_aws = dummy_source(
        "test_aws",
        SourceTier::Tier1Geofeed,
        SourceFormat::AwsIpRangesJson,
        "aws",
    );
    src_aws.is_hosting = true;
    let parsed_aws = parse_source_bytes(&src_aws, aws_json, &metadata).unwrap();
    assert_eq!(parsed_aws.v4.len(), 1);
    assert_eq!(parsed_aws.v6.len(), 1);
    let pa = &parsed_aws.payloads[parsed_aws.v4[0].payload_id() as usize];
    assert_eq!(pa.country, IsoCode::parse_raw("SE"));
    assert!(pa.traits.contains(TraitFlags::IS_HOSTING));

    // 3. BGP.Tools RIB (JSONL + plain text)
    let bgp_raw = b"{\"CIDR\":\"223.5.5.0/24\",\"ASN\":37963}\n2400:3200::/32 AS37963\n";
    let src_bgp = dummy_source(
        "test_bgp",
        SourceTier::Tier3BgpRir,
        SourceFormat::BgptoolsTable,
        "bgp",
    );
    let parsed_bgp = parse_source_bytes(&src_bgp, bgp_raw, &metadata).unwrap();
    assert_eq!(parsed_bgp.v4.len(), 1);
    assert_eq!(parsed_bgp.v6.len(), 1);
    assert_eq!(
        parsed_bgp.payloads[parsed_bgp.v4[0].payload_id() as usize].asn,
        37963
    );

    // 4. RIR delegated non-power-of-two IPv4 count (768 = /23 + /24) + ASN country delegation
    let rir_raw =
        b"apnic|CN|ipv4|223.5.4.0|768|20200101|allocated\napnic|TW|asn|3462|1|19960101|allocated\n";
    let src_rir = dummy_source(
        "test_rir",
        SourceTier::Tier3BgpRir,
        SourceFormat::RirDelegated,
        "apnic",
    );
    let parsed_rir = parse_source_bytes(&src_rir, rir_raw, &metadata).unwrap();
    assert_eq!(parsed_rir.v4.len(), 1);
    assert_eq!(parsed_rir.v4[0].end - parsed_rir.v4[0].start + 1, 768);
    assert_eq!(
        range_to_ipv4_cidrs(parsed_rir.v4[0].start, parsed_rir.v4[0].end).len(),
        2
    );
    assert_eq!(parsed_rir.asn_meta.len(), 1);
    assert_eq!(parsed_rir.asn_meta[0].asn, 3462);
    assert_eq!(parsed_rir.asn_meta[0].country, Some(IsoCode::TW));

    // 5. Onionoo Tor Exit JSON + Spamhaus DROP (non-adjacent IPs `.1` and `.5`)
    let onion_raw = br#"{"relays":[{"or_addresses":["185.220.101.1:9001","[2a0b:f4c2::1]:9001"],"exit_addresses":["185.220.101.5"]}]}"#;
    let src_tor = dummy_source(
        "test_tor",
        SourceTier::TraitOverlay,
        SourceFormat::OnionooJson,
        "tor",
    );
    let parsed_tor = parse_source_bytes(&src_tor, onion_raw, &metadata).unwrap();
    assert_eq!(parsed_tor.v4.len(), 2);
    assert_eq!(parsed_tor.v6.len(), 1);

    let drop_raw =
        b"{\"cidr\":\"198.51.100.0/24\",\"sblid\":\"SBL123\"}\n203.0.113.0/24 ; SBL456\n";
    let src_drop = dummy_source(
        "test_drop",
        SourceTier::TraitOverlay,
        SourceFormat::SpamhausDrop,
        "drop",
    );
    let parsed_drop = parse_source_bytes(&src_drop, drop_raw, &metadata).unwrap();
    assert_eq!(parsed_drop.v4.len(), 2);

    // 6. BGP.Tools OpenDB ASN-Tag CSV (`AS<num>,<name>`)
    let tag_raw = b"AS174,\"\"\"Cogent Communications\", LLC\"\nAS209,Lumen (ex. Qwest)\n";
    let mut src_tag = dummy_source(
        "test_bgptools_tag",
        SourceTier::TraitOverlay,
        SourceFormat::BgptoolsTagCsv,
        "bgptools_tags",
    );
    src_tag.is_hosting = true;
    let parsed_tag = parse_source_bytes(&src_tag, tag_raw, &metadata).unwrap();
    assert_eq!(parsed_tag.asn_meta.len(), 2);
    assert_eq!(parsed_tag.asn_meta[0].asn, 174);
    assert_eq!(
        parsed_tag.asn_meta[0].organization,
        "Cogent Communications, LLC"
    );
    assert!(
        parsed_tag.asn_meta[0]
            .traits
            .contains(TraitFlags::IS_HOSTING)
    );
}

#[test]
fn parsers_decode_binary_xdb_qqwry_and_ipdb_formats() {
    let (metadata, _, _) = load_real_fixtures();

    // 1. Synthetic IPv4 XDB (256-byte header + vector index + payload + 14-byte segment)
    let mut xdb = vec![0u8; 256 + 256 * 256 * 8];
    xdb[0..2].copy_from_slice(&2u16.to_le_bytes()); // version 2
    xdb[16..18].copy_from_slice(&4u16.to_le_bytes()); // IPv4 (4 bytes)
    let payload_bytes = "中国|0|浙江省|杭州市|电信".as_bytes();
    let data_ptr = xdb.len() as u32;
    xdb.extend_from_slice(payload_bytes);
    let seg_start = xdb.len() as u32;
    let s_ip = u32::from(Ipv4Addr::new(223, 5, 5, 0));
    let e_ip = u32::from(Ipv4Addr::new(223, 5, 5, 255));
    xdb.extend_from_slice(&s_ip.to_le_bytes());
    xdb.extend_from_slice(&e_ip.to_le_bytes());
    xdb.extend_from_slice(&(payload_bytes.len() as u16).to_le_bytes());
    xdb.extend_from_slice(&data_ptr.to_le_bytes());
    let seg_end = (xdb.len() - 14) as u32;
    xdb[8..12].copy_from_slice(&seg_start.to_le_bytes());
    xdb[12..16].copy_from_slice(&seg_end.to_le_bytes());

    let src_xdb = dummy_source("test_xdb", SourceTier::Tier2aCn, SourceFormat::Xdb, "xdb");
    let parsed_xdb = parse_source_bytes(&src_xdb, &xdb, &metadata).unwrap();
    assert_eq!(parsed_xdb.v4.len(), 1);
    let px = &parsed_xdb.payloads[parsed_xdb.v4[0].payload_id() as usize];
    assert_eq!(px.country, Some(IsoCode::CN));
    assert_eq!(parsed_xdb.strings.get(px.subdiv1_en), "Zhejiang");
    assert_eq!(parsed_xdb.strings.get(px.city_en), "Hangzhou");
    assert_eq!(parsed_xdb.strings.get(px.isp), "China Telecom");

    // 1b. Synthetic IPv4 XDB testing HK/MO/TW subdivision hygiene (no "台湾省" leakage)
    let mut xdb_tw = vec![0u8; 256 + 256 * 256 * 8];
    xdb_tw[0..2].copy_from_slice(&2u16.to_le_bytes());
    xdb_tw[16..18].copy_from_slice(&4u16.to_le_bytes());
    let tw_payload = "中国|0|台湾省|台北市|中华电信".as_bytes();
    let tw_ptr = xdb_tw.len() as u32;
    xdb_tw.extend_from_slice(tw_payload);
    let tw_seg_start = xdb_tw.len() as u32;
    let tw_s_ip = u32::from(Ipv4Addr::new(168, 95, 1, 0));
    let tw_e_ip = u32::from(Ipv4Addr::new(168, 95, 1, 255));
    xdb_tw.extend_from_slice(&tw_s_ip.to_le_bytes());
    xdb_tw.extend_from_slice(&tw_e_ip.to_le_bytes());
    xdb_tw.extend_from_slice(&(tw_payload.len() as u16).to_le_bytes());
    xdb_tw.extend_from_slice(&tw_ptr.to_le_bytes());
    let tw_seg_end = (xdb_tw.len() - 14) as u32;
    xdb_tw[8..12].copy_from_slice(&tw_seg_start.to_le_bytes());
    xdb_tw[12..16].copy_from_slice(&tw_seg_end.to_le_bytes());

    let parsed_xdb_tw = parse_source_bytes(&src_xdb, &xdb_tw, &metadata).unwrap();
    let px_tw = &parsed_xdb_tw.payloads[parsed_xdb_tw.v4[0].payload_id() as usize];
    assert_eq!(px_tw.country, Some(IsoCode::TW));
    assert_eq!(parsed_xdb_tw.strings.get(px_tw.subdiv1_zh), "");
    assert_eq!(parsed_xdb_tw.strings.get(px_tw.subdiv1_en), "");
    assert_eq!(parsed_xdb_tw.strings.get(px_tw.city_zh), "台北市");

    // 2. Synthetic QQWry DAT (GB18030 + mode 0x02 redirect)
    let (country_gb, _, _) = GB18030.encode("广东省深圳市");
    let (area_gb, _, _) = GB18030.encode("腾讯云计算");
    let mut qqwry = vec![0u8; 8];
    let shared_country_off = qqwry.len() as u32; // offset 8
    qqwry.extend_from_slice(&country_gb);
    qqwry.push(0);
    let rec_body_off = qqwry.len() as u32;
    qqwry.extend_from_slice(&u32::from(Ipv4Addr::new(182, 254, 118, 255)).to_le_bytes());
    qqwry.push(0x02); // redirect country string to `shared_country_off`
    qqwry.extend_from_slice(&shared_country_off.to_le_bytes()[..3]);
    qqwry.extend_from_slice(&area_gb);
    qqwry.push(0);
    let idx_off = qqwry.len() as u32;
    qqwry.extend_from_slice(&u32::from(Ipv4Addr::new(182, 254, 118, 0)).to_le_bytes());
    qqwry.extend_from_slice(&rec_body_off.to_le_bytes()[..3]);
    qqwry[0..4].copy_from_slice(&idx_off.to_le_bytes());
    qqwry[4..8].copy_from_slice(&idx_off.to_le_bytes());

    let src_qq = dummy_source(
        "test_qq",
        SourceTier::Tier2aCn,
        SourceFormat::QqwryDat,
        "qqwry",
    );
    let parsed_qq = parse_source_bytes(&src_qq, &qqwry, &metadata).unwrap();
    assert_eq!(parsed_qq.v4.len(), 1);
    let pq = &parsed_qq.payloads[parsed_qq.v4[0].payload_id() as usize];
    assert_eq!(pq.country, Some(IsoCode::CN));
    assert_eq!(parsed_qq.strings.get(pq.city_en), "Shenzhen");
    assert_eq!(parsed_qq.strings.get(pq.isp), "Tencent Cloud");

    // 3. Synthetic OpenIPDB `.ipdb` testing exact `tree_base + node_count * 8 + (ptr - node_count)`
    let meta_json = br#"{"build":1700000000,"ip_version":1,"node_count":1,"total_size":100,"fields":["country_name","region_name","city_name","isp_domain"],"languages":{"CN":0}}"#;
    let payload_tab = "中国\t北京市\t北京市\t联通".as_bytes();
    let mut ipdb = Vec::new();
    ipdb.extend_from_slice(&(meta_json.len() as u32).to_be_bytes());
    ipdb.extend_from_slice(meta_json);
    // Single root node (node 0): left -> empty (node_count = 1), right -> data offset 8 (ptr = 1 + 8 = 9)
    // Put 8 padding bytes before our payload so `rel = ptr - node_count = 8` is non-zero!
    let node_count = 1u32;
    let ptr = node_count + 8;
    ipdb.extend_from_slice(&node_count.to_be_bytes()); // left = 1 (empty)
    ipdb.extend_from_slice(&ptr.to_be_bytes()); // right = 9 -> 128.0.0.0/1
    ipdb.extend_from_slice(&[0u8; 8]); // 8-byte padding before record
    ipdb.extend_from_slice(&(payload_tab.len() as u16).to_be_bytes());
    ipdb.extend_from_slice(payload_tab);

    let src_ipdb = dummy_source(
        "test_ipdb",
        SourceTier::Tier2aCn,
        SourceFormat::Ipdb,
        "ipdb",
    );
    let parsed_ipdb = parse_source_bytes(&src_ipdb, &ipdb, &metadata).unwrap();
    assert_eq!(parsed_ipdb.v4.len(), 1);
    let pi = &parsed_ipdb.payloads[parsed_ipdb.v4[0].payload_id() as usize];
    assert_eq!(pi.country, Some(IsoCode::CN));
    assert_eq!(parsed_ipdb.strings.get(pi.subdiv1_en), "Beijing");
    assert_eq!(parsed_ipdb.strings.get(pi.isp), "China Unicom");

    // 4. Synthetic IPFire libloc v1 testing 12-byte `struct loc_database_network_v1` layout
    let mut libloc = vec![0u8; 72];
    libloc[0..7].copy_from_slice(b"LOCDBXX");
    libloc[7] = 1; // version 1
    let pool_bytes = b"\0Example Corp\0";
    let pool_off = libloc.len() as u32;
    libloc.extend_from_slice(pool_bytes);
    let as_off = libloc.len() as u32;
    libloc.extend_from_slice(&64500u32.to_be_bytes());
    libloc.extend_from_slice(&1u32.to_be_bytes()); // offset 1 in pool -> "Example Corp"
    let net_data_off = libloc.len() as u32;
    // 12-byte struct loc_database_network_v1: cc[2]="DE", pad[2]=0, asn=64500, flags=ANYCAST(4), pad[2]=0
    libloc.extend_from_slice(b"DE\0\0");
    libloc.extend_from_slice(&64500u32.to_be_bytes());
    libloc.extend_from_slice(&4u16.to_be_bytes());
    libloc.extend_from_slice(&[0u8; 2]);
    let net_tree_off = libloc.len() as u32;
    // Root node 0 -> `1` branch (8000::/1) goes to node 1; node 1 carries network_idx = 0
    libloc.extend_from_slice(&0u32.to_be_bytes()); // zero
    libloc.extend_from_slice(&1u32.to_be_bytes()); // one -> node 1
    libloc.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    libloc.extend_from_slice(&0u32.to_be_bytes()); // node 1 zero = leaf
    libloc.extend_from_slice(&0u32.to_be_bytes()); // node 1 one = leaf
    libloc.extend_from_slice(&0u32.to_be_bytes()); // network index 0
    libloc[28..32].copy_from_slice(&as_off.to_be_bytes());
    libloc[32..36].copy_from_slice(&8u32.to_be_bytes());
    libloc[36..40].copy_from_slice(&net_data_off.to_be_bytes());
    libloc[40..44].copy_from_slice(&12u32.to_be_bytes());
    libloc[44..48].copy_from_slice(&net_tree_off.to_be_bytes());
    libloc[48..52].copy_from_slice(&24u32.to_be_bytes());
    libloc[60..64].copy_from_slice(&pool_off.to_be_bytes());
    libloc[64..68].copy_from_slice(&(pool_bytes.len() as u32).to_be_bytes());

    let src_libloc = dummy_source(
        "test_libloc",
        SourceTier::Tier2bGlobal,
        SourceFormat::Libloc,
        "ipfire",
    );
    let parsed_libloc = parse_source_bytes(&src_libloc, &libloc, &metadata).unwrap();
    assert_eq!(parsed_libloc.v6.len(), 1);
    let pl = &parsed_libloc.payloads[parsed_libloc.v6[0].payload_id() as usize];
    assert_eq!(pl.country, IsoCode::parse_raw("DE"));
    assert_eq!(pl.asn, 64500);
    assert_eq!(parsed_libloc.strings.get(pl.as_org), "Example Corp");
    assert!(pl.traits.contains(TraitFlags::IS_ANYCAST));
}

#[test]
fn end_to_end_fusion_priority0_lineage_dedup_and_mmdb_verification() {
    let (metadata, _, overrides) = load_real_fixtures();
    let mut arena = GlobalArena::new();

    // Source A..D: 4 mirror clones sharing the SAME lineage ("maxmind_clone") claiming 16.192.0.0/18 is DE
    // AND mistakenly claiming Tailscale `100.64.0.0/10`, Surge Fake-IP `198.18.0.0/15`, and LAN `192.168.0.0/16` are US/CN!
    let mut sources = Vec::new();
    for i in 0..4 {
        let mut sc = dummy_source(
            &format!("mm_clone_{i}"),
            SourceTier::Tier2bGlobal,
            SourceFormat::Rfc8805Csv,
            "maxmind_geolite2",
        );
        sc.country_weight = 86;
        let csv = b"16.192.0.0/18,DE,DE-HE,Frankfurt,\n100.64.0.0/10,US,,,\n198.18.0.0/15,US,,,\n192.168.0.0/16,CN,,,\nfd7a:115c:a1e0::/48,CA,,,\nfd01:db8:1111::/48,US,,,\n223.5.5.0/24,CN,CN-ZJ,Hangzhou,\n168.95.1.0/24,TW,,Taipei,\n203.80.96.0/24,HK,,Hong Kong,\n";
        let parsed = parse_source_bytes(&sc, csv, &metadata).unwrap();
        let (v4, v6) = arena.ingest_parsed_source(parsed, 80);
        sources.push((sc, v4, v6));
    }

    // Source E: Authoritative AWS Geofeed (Tier 1) saying 16.192.0.0/18 is SE (Stockholm)
    let mut aws_sc = dummy_source(
        "aws_official",
        SourceTier::Tier1Geofeed,
        SourceFormat::AwsIpRangesJson,
        "aws_official",
    );
    aws_sc.country_weight = 99;
    aws_sc.city_weight = 96;
    aws_sc.is_hosting = true;
    let aws_json = br#"{"prefixes":[{"ip_prefix":"16.192.0.0/18","region":"eu-north-1","service":"EC2"}],"ipv6_prefixes":[]}"#;
    let parsed_aws = parse_source_bytes(&aws_sc, aws_json, &metadata).unwrap();
    let (v4_aws, v6_aws) = arena.ingest_parsed_source(parsed_aws, 90);
    sources.push((aws_sc, v4_aws, v6_aws));

    // Source F: BGP RIB + ASN metadata
    let mut bgp_sc = dummy_source(
        "bgp_rib",
        SourceTier::Tier3BgpRir,
        SourceFormat::BgptoolsTable,
        "bgp_rib",
    );
    bgp_sc.asn_weight = 98;
    let bgp_raw = b"16.192.0.0/18 AS16509\n223.5.5.0/24 AS37963\n168.95.1.0/24 AS3462\n100.64.0.0/10 AS64512\n2400:3200::/32 AS37963\n";
    let parsed_bgp = parse_source_bytes(&bgp_sc, bgp_raw, &metadata).unwrap();
    let (v4_bgp, v6_bgp) = arena.ingest_parsed_source(parsed_bgp, 98);
    sources.push((bgp_sc, v4_bgp, v6_bgp));

    let fused = run_fusion(&mut arena, &metadata, &overrides, sources);

    let tmp = TempDir::new().unwrap();
    let epoch = 1_763_000_000;
    write_geo_mmdb(
        &tmp.path().join("Country.mmdb"),
        "GeoLite2-City",
        "Test Country DB",
        "测试全球库",
        epoch,
        &fused.country_records,
        &fused.country_v4,
        &fused.country_v6,
        &arena.strings,
        &metadata,
    )
    .unwrap();
    write_country_only_mmdb(
        &tmp.path().join("Country-only.mmdb"),
        epoch,
        &fused.country_records,
        &fused.country_v4,
        &fused.country_v6,
        &metadata,
    )
    .unwrap();
    write_geo_mmdb(
        &tmp.path().join("Country-cn.mmdb"),
        "GeoLite2-Country",
        "Test CN DB",
        "测试中国大陆库",
        epoch,
        &fused.country_records,
        &fused.cn_v4,
        &fused.cn_v6,
        &arena.strings,
        &metadata,
    )
    .unwrap();
    write_asn_mmdb(
        &tmp.path().join("ASN.mmdb"),
        epoch,
        &fused.asn_records,
        &fused.asn_v4,
        &fused.asn_v6,
        &arena.strings,
    )
    .unwrap();

    // Run full special-network verification suite (19 LAN + Fake-IP + Tailscale + Cloudflare Mesh + ZeroTier canaries)
    let report = verify_artifact_dir(tmp.path(), false).unwrap();
    assert_eq!(report.canaries_checked, 19);

    // Check lineage deduplication + Tier-1 Geofeed priority: 16.192.0.1 must resolve to SE (Stockholm), NOT DE!
    let aws_inspect = inspect_ip_in_dir(tmp.path(), "16.192.0.1").unwrap();
    assert_eq!(
        aws_inspect
            .pointer("/Country.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("SE")
    );
    assert_eq!(
        aws_inspect
            .pointer("/Country-only.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("SE")
    );
    assert_eq!(
        aws_inspect
            .get("Country-only.mmdb")
            .and_then(|v| v.as_object())
            .map(|o| o.len()),
        Some(1)
    );
    assert_eq!(
        aws_inspect
            .pointer("/Country.mmdb/city/names/en")
            .and_then(|v| v.as_str()),
        Some("Stockholm")
    );
    assert_eq!(
        aws_inspect
            .pointer("/ASN.mmdb/autonomous_system_number")
            .and_then(|v| v.as_u64()),
        Some(16509)
    );

    // Check HK/TW exclusion from Country-cn.mmdb while CN is included, and Country-only.mmdb fidelity
    let cn_inspect = inspect_ip_in_dir(tmp.path(), "223.5.5.5").unwrap();
    assert_eq!(
        cn_inspect
            .pointer("/Country-cn.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("CN")
    );
    assert_eq!(
        cn_inspect
            .pointer("/Country-only.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("CN")
    );
    assert_eq!(
        cn_inspect
            .get("Country-only.mmdb")
            .and_then(|v| v.as_object())
            .map(|o| o.len()),
        Some(1)
    );
    let tw_inspect = inspect_ip_in_dir(tmp.path(), "168.95.1.1").unwrap();
    assert_eq!(
        tw_inspect
            .pointer("/Country.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("TW")
    );
    assert_eq!(
        tw_inspect
            .pointer("/Country-only.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("TW")
    );
    assert!(tw_inspect.get("Country-cn.mmdb").unwrap().is_null());

    let hk_inspect = inspect_ip_in_dir(tmp.path(), "203.80.96.1").unwrap();
    assert_eq!(
        hk_inspect
            .pointer("/Country.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("HK")
    );
    assert_eq!(
        hk_inspect
            .pointer("/Country-only.mmdb/country/iso_code")
            .and_then(|v| v.as_str()),
        Some("HK")
    );
    assert!(hk_inspect.get("Country-cn.mmdb").unwrap().is_null());

    let mesh_inspect = inspect_ip_in_dir(tmp.path(), "100.64.0.1").unwrap();
    assert!(mesh_inspect.get("Country-only.mmdb").unwrap().is_null());

    // Round-trip `Country.mmdb` back through our own `parsers::mmdb::parse_mmdb`!
    let country_bytes = std::fs::read(tmp.path().join("Country.mmdb")).unwrap();
    let mmdb_sc = dummy_source(
        "rt_mmdb",
        SourceTier::Tier2bGlobal,
        SourceFormat::Mmdb,
        "rt",
    );
    let rt_parsed = parse_source_bytes(&mmdb_sc, &country_bytes, &metadata).unwrap();
    assert!(!rt_parsed.v4.is_empty());
    assert!(!rt_parsed.v6.is_empty());
}

#[test]
fn country_only_mmdb_coalesces_adjacent_spans_and_omits_non_country_fields() {
    let (metadata, _, _) = load_real_fixtures();
    let mut strings = StringPool::new();
    let mut records: IndexSet<ResolvedGeoRecord, FxBuildHasher> =
        IndexSet::with_hasher(FxBuildHasher);

    // Countryless anycast span (should be excluded completely from Country-only.mmdb)
    let anycast_rec = ResolvedGeoRecord {
        country: None,
        traits: TraitFlags(TraitFlags::IS_ANYCAST),
        ..ResolvedGeoRecord::default()
    };
    let (anycast_rid, _) = records.insert_full(anycast_rec);

    // Two adjacent CN /24 blocks differing in city and ASN (should coalesce into one CN /23)
    let hz_rec = ResolvedGeoRecord {
        country: Some(IsoCode::CN),
        registered_country: Some(IsoCode::CN),
        city_en: strings.intern("Hangzhou"),
        asn: 37963,
        as_org: strings.intern("Hangzhou Alibaba Advertising Co."),
        ..ResolvedGeoRecord::default()
    };
    let (hz_rid, _) = records.insert_full(hz_rec);

    let sz_rec = ResolvedGeoRecord {
        country: Some(IsoCode::CN),
        registered_country: Some(IsoCode::CN),
        city_en: strings.intern("Shenzhen"),
        asn: 45102,
        as_org: strings.intern("Alibaba (US) Technology Co."),
        ..ResolvedGeoRecord::default()
    };
    let (sz_rid, _) = records.insert_full(sz_rec);

    let net_any: Ipv4Net = "1.1.1.0/24".parse().unwrap();
    let net_hz: Ipv4Net = "223.5.4.0/24".parse().unwrap();
    let net_sz: Ipv4Net = "223.5.5.0/24".parse().unwrap();
    let v4_spans = vec![
        OutputSpanV4 {
            start: u32::from(net_any.network()),
            end: u32::from(net_any.broadcast()),
            record_id: anycast_rid as u32,
        },
        OutputSpanV4 {
            start: u32::from(net_hz.network()),
            end: u32::from(net_hz.broadcast()),
            record_id: hz_rid as u32,
        },
        OutputSpanV4 {
            start: u32::from(net_sz.network()),
            end: u32::from(net_sz.broadcast()),
            record_id: sz_rid as u32,
        },
    ];

    let tmp = TempDir::new().unwrap();
    let country_path = tmp.path().join("Country.mmdb");
    let country_only_path = tmp.path().join("Country-only.mmdb");

    let country_stats = write_geo_mmdb(
        &country_path,
        "GeoLite2-City",
        "Test Full",
        "测试全量",
        1_763_000_000,
        &records,
        &v4_spans,
        &[],
        &strings,
        &metadata,
    )
    .unwrap();
    let country_only_stats = write_country_only_mmdb(
        &country_only_path,
        1_763_000_000,
        &records,
        &v4_spans,
        &[],
        &metadata,
    )
    .unwrap();

    assert_eq!(country_only_stats.unique_records, 1);
    assert!(
        country_only_stats.node_count < country_stats.node_count,
        "expected coalesced Country-only nodes ({}) < Country nodes ({})",
        country_only_stats.node_count,
        country_stats.node_count
    );

    let reader = maxminddb::Reader::open_readfile(&country_only_path).unwrap();
    let anycast_hit: Option<serde_json::Value> =
        lookup_opt(&reader, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).unwrap();
    assert!(anycast_hit.is_none());

    for ip in [Ipv4Addr::new(223, 5, 4, 1), Ipv4Addr::new(223, 5, 5, 1)] {
        let doc: serde_json::Value = lookup_opt(&reader, IpAddr::V4(ip)).unwrap().unwrap();
        let obj = doc.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("country"));
        assert_eq!(
            doc.pointer("/country/iso_code").and_then(|v| v.as_str()),
            Some("CN")
        );
    }
}

// ============================================================================
// Property-Based Tests (`proptest`)
// ============================================================================

proptest! {
    #[test]
    fn prop_range_to_ipv4_cidrs_exact(a in any::<u32>(), b in any::<u32>()) {
        let (start, end) = if a <= b { (a, b) } else { (b, a) };
        let cidrs = range_to_ipv4_cidrs(start, end);
        prop_assert!(!cidrs.is_empty());

        let first_start = u32::from(cidrs.first().unwrap().network());
        let last_end = u32::from(cidrs.last().unwrap().broadcast());
        prop_assert_eq!(first_start, start);
        prop_assert_eq!(last_end, end);

        for pair in cidrs.windows(2) {
            let left_end = u32::from(pair[0].broadcast());
            let right_start = u32::from(pair[1].network());
            prop_assert_eq!(left_end.checked_add(1), Some(right_start));
        }
    }

    #[test]
    fn prop_range_to_ipv6_cidrs_exact(base in any::<u128>(), span in 0u32..200_000u32) {
        let start = base;
        let end = base.saturating_add(span as u128);
        let cidrs = range_to_ipv6_cidrs(start, end);
        prop_assert!(!cidrs.is_empty());

        let first_start = u128::from(cidrs.first().unwrap().network());
        let last_end = u128::from(cidrs.last().unwrap().broadcast());
        prop_assert_eq!(first_start, start);
        prop_assert_eq!(last_end, end);

        for pair in cidrs.windows(2) {
            let left_end = u128::from(pair[0].broadcast());
            let right_start = u128::from(pair[1].network());
            prop_assert_eq!(left_end.checked_add(1), Some(right_start));
        }
    }

    #[test]
    fn prop_flatten_disjoint_v4_matches_pointwise_oracle(
        raw in prop::collection::vec((0u16..512u16, 0u16..512u16, 8u8..=32u8, 1u32..8u32), 1..40)
    ) {
        // Assign strictly unique `(prefix_len)` or verify against exact oracle when prefix_lens differ
        // Make prefix_len distinct per interval mod 32 or test general case where unique `(start, end, plen)` holds:
        let intervals: Vec<IntervalV4> = raw
            .iter()
            .map(|&(x, y, plen, pid)| {
                let (s, e) = if x <= y { (x as u32, y as u32) } else { (y as u32, x as u32) };
                IntervalV4::new(s, e, pid, plen)
            })
            .collect();

        let flat = flatten_disjoint_v4(intervals.clone());

        // 1. Disjointness + coalesced invariant
        for w in flat.windows(2) {
            prop_assert!(w[0].start <= w[0].end);
            prop_assert!(w[0].end < w[1].start);
            if w[0].end + 1 == w[1].start {
                prop_assert_ne!(w[0].packed, w[1].packed);
            }
        }
        if let Some(last) = flat.last() {
            prop_assert!(last.start <= last.end);
        }

        // 2. Pointwise coverage + max prefix_len invariant across 0..512
        for ip in 0u32..512u32 {
            let covering: Vec<&IntervalV4> = intervals
                .iter()
                .filter(|iv| iv.start <= ip && ip <= iv.end)
                .collect();
            let actual = flat.iter().find(|iv| iv.start <= ip && ip <= iv.end);

            if covering.is_empty() {
                prop_assert!(actual.is_none());
            } else {
                let actual_iv = actual.expect("covered IP must appear in flattened output");
                let max_plen = covering.iter().map(|iv| iv.prefix_len()).max().unwrap();
                prop_assert_eq!(actual_iv.prefix_len(), max_plen);
                // Payload must come from one of the intervals achieving `max_plen`
                let valid_payload = covering
                    .iter()
                    .any(|iv| iv.prefix_len() == max_plen && iv.payload_id() == actual_iv.payload_id());
                prop_assert!(valid_payload);
            }
        }
    }

    #[test]
    fn prop_special_networks_never_leak_under_arbitrary_upstream(
        v4_nets in prop::collection::vec((any::<u32>(), 8u8..=28u8, 0usize..5usize, 1u32..60000u32), 1..25),
        v6_nets in prop::collection::vec((any::<u128>(), 16u8..=64u8, 0usize..5usize, 1u32..60000u32), 1..15),
    ) {
        let (metadata, _, overrides) = load_real_fixtures();
        let isos = [
            IsoCode::CN,
            IsoCode::HK,
            IsoCode::TW,
            IsoCode::parse_raw("US").unwrap(),
            IsoCode::parse_raw("JP").unwrap(),
        ];

        let mut parsed = ParsedSource::new("prop_upstream");
        // Deliberately inject adversarial observations directly on top of LAN, Tailscale, Cloudflare Mesh & Fake-IP
        for adversarial in [
            "10.0.0.0/8",
            "100.64.0.0/10",
            "100.96.0.0/12",
            "192.168.0.0/16",
            "198.18.0.0/15",
        ] {
            let net: Ipv4Net = adversarial.parse().unwrap();
            let pid = parsed
                .intern_payload(ObsPayload {
                    country: Some(IsoCode::CN),
                    registered_country: Some(IsoCode::CN),
                    asn: 4134,
                    ..ObsPayload::default()
                })
                .unwrap();
            parsed.push_ipnet(IpNet::V4(net), pid);
        }
        for adversarial_v6 in ["fd7a:115c:a1e0::/48", "fd01:db8:1111::/48", "fc00::/8", "fe80::/10"] {
            let net: Ipv6Net = adversarial_v6.parse().unwrap();
            let pid = parsed
                .intern_payload(ObsPayload {
                    country: Some(IsoCode::CN),
                    registered_country: Some(IsoCode::CN),
                    asn: 4134,
                    ..ObsPayload::default()
                })
                .unwrap();
            parsed.push_ipnet(IpNet::V6(net), pid);
        }

        for &(ip, plen, iso_idx, asn) in &v4_nets {
            let net = Ipv4Net::new(Ipv4Addr::from(ip), plen).unwrap().trunc();
            let pid = parsed
                .intern_payload(ObsPayload {
                    country: Some(isos[iso_idx]),
                    registered_country: Some(isos[iso_idx]),
                    asn,
                    ..ObsPayload::default()
                })
                .unwrap();
            parsed.push_ipnet(IpNet::V4(net), pid);
        }
        for &(ip, plen, iso_idx, asn) in &v6_nets {
            let net = Ipv6Net::new(Ipv6Addr::from(ip), plen).unwrap().trunc();
            let pid = parsed
                .intern_payload(ObsPayload {
                    country: Some(isos[iso_idx]),
                    registered_country: Some(isos[iso_idx]),
                    asn,
                    ..ObsPayload::default()
                })
                .unwrap();
            parsed.push_ipnet(IpNet::V6(net), pid);
        }
        parsed.finalize();

        let mut arena = GlobalArena::new();
        let sc = dummy_source("prop_src", SourceTier::Tier1Geofeed, SourceFormat::Rfc8805Csv, "prop");
        let (v4, v6) = arena.ingest_parsed_source(parsed, 99);
        let fused = run_fusion(&mut arena, &metadata, &overrides, vec![(sc, v4, v6)]);

        // Every Priority-0 special V4 & V6 IP must have NO country, NO registered_country, NO ASN,
        // and zero overlap with Country-cn or ASN spans!
        let probe_v4 = [
            u32::from(Ipv4Addr::new(10, 1, 2, 3)),
            u32::from(Ipv4Addr::new(100, 64, 5, 6)),
            u32::from(Ipv4Addr::new(100, 100, 100, 100)),
            u32::from(Ipv4Addr::new(100, 96, 1, 1)),
            u32::from(Ipv4Addr::new(192, 168, 1, 1)),
            u32::from(Ipv4Addr::new(198, 18, 0, 2)),
        ];
        for probe in probe_v4 {
            let span = fused
                .country_v4
                .iter()
                .find(|s| s.start <= probe && probe <= s.end)
                .expect("special v4 IP must exist in country_v4");
            let rec = &fused.country_records[span.record_id as usize];
            prop_assert!(rec.country.is_none());
            prop_assert!(rec.registered_country.is_none());
            prop_assert_eq!(rec.asn, 0);
            prop_assert!(rec.traits.contains(TraitFlags::IS_BOGON));
            prop_assert!(fused.cn_v4.iter().all(|s| probe < s.start || probe > s.end));
            prop_assert!(fused.asn_v4.iter().all(|s| probe < s.start || probe > s.end));
        }

        let probe_v6 = [
            u128::from("fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap()),
            u128::from("fd01:db8:1111::1".parse::<Ipv6Addr>().unwrap()),
            u128::from("fc00::1".parse::<Ipv6Addr>().unwrap()),
            u128::from("fe80::1".parse::<Ipv6Addr>().unwrap()),
        ];
        for probe in probe_v6 {
            let span = fused
                .country_v6
                .iter()
                .find(|s| s.start <= probe && probe <= s.end)
                .expect("special v6 IP must exist in country_v6");
            let rec = &fused.country_records[span.record_id as usize];
            prop_assert!(rec.country.is_none());
            prop_assert!(rec.registered_country.is_none());
            prop_assert_eq!(rec.asn, 0);
            prop_assert!(rec.traits.contains(TraitFlags::IS_BOGON));
            prop_assert!(fused.cn_v6.iter().all(|s| probe < s.start || probe > s.end));
            prop_assert!(fused.asn_v6.iter().all(|s| probe < s.start || probe > s.end));
        }
    }

    #[test]
    fn prop_mmdb_dual_stack_roundtrip_fidelity(
        v4_blocks in prop::collection::vec((1u8..220u8, 0u8..255u8, 0usize..4usize, 100u32..65000u32), 1..20),
        v6_blocks in prop::collection::vec((0x2001u16..0x2a10u16, any::<u16>(), 0usize..4usize, 100u32..65000u32), 1..15),
    ) {
        let (metadata, _, _) = load_real_fixtures();
        let isos = [
            IsoCode::CN,
            IsoCode::parse_raw("US").unwrap(),
            IsoCode::parse_raw("SE").unwrap(),
            IsoCode::parse_raw("JP").unwrap(),
        ];

        let mut strings = StringPool::new();
        let mut records: IndexSet<ResolvedGeoRecord, FxBuildHasher> =
            IndexSet::with_hasher(FxBuildHasher);

        // Deduplicate block keys so spans are strictly disjoint
        let mut v4_map = std::collections::BTreeMap::new();
        for &(a, b, iso_i, asn) in &v4_blocks {
            if a == 10 || a == 127 || (a == 100 && (64..=127).contains(&b)) || (a == 192 && b == 168) || (a == 198 && (b == 18 || b == 19)) {
                continue;
            }
            v4_map.insert((a, b), (isos[iso_i], asn));
        }

        let mut v6_map = std::collections::BTreeMap::new();
        for &(seg0, seg1, iso_i, asn) in &v6_blocks {
            v6_map.insert((seg0, seg1), (isos[iso_i], asn));
        }

        let mut v4_spans = Vec::new();
        for (&(a, b), &(iso, asn)) in &v4_map {
            let rec = ResolvedGeoRecord {
                country: Some(iso),
                registered_country: Some(iso),
                city_en: strings.intern("TestCity"),
                asn,
                as_org: strings.intern("TestOrg"),
                latitude_e5: quantize_coord(35.12345),
                longitude_e5: quantize_coord(139.54321),
                accuracy_radius: 20,
                traits: TraitFlags(TraitFlags::IS_CDN),
                ..ResolvedGeoRecord::default()
            };
            let (rid, _) = records.insert_full(rec);
            let net = Ipv4Net::new(Ipv4Addr::new(a, b, 0, 0), 16).unwrap();
            v4_spans.push(OutputSpanV4 {
                start: u32::from(net.network()),
                end: u32::from(net.broadcast()),
                record_id: rid as u32,
            });
        }

        let mut v6_spans = Vec::new();
        for (&(seg0, seg1), &(iso, asn)) in &v6_map {
            let rec = ResolvedGeoRecord {
                country: Some(iso),
                registered_country: None,
                city_en: strings.intern("TestCityV6"),
                asn,
                as_org: strings.intern("TestOrgV6"),
                latitude_e5: COORD_UNSET,
                longitude_e5: COORD_UNSET,
                accuracy_radius: 0,
                traits: TraitFlags::EMPTY,
                ..ResolvedGeoRecord::default()
            };
            let (rid, _) = records.insert_full(rec);
            let addr = Ipv6Addr::new(seg0, seg1, 0, 0, 0, 0, 0, 0);
            let net = Ipv6Net::new(addr, 32).unwrap();
            v6_spans.push(OutputSpanV6 {
                start: u128::from(net.network()),
                end: u128::from(net.broadcast()),
                record_id: rid as u32,
            });
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("prop.mmdb");
        let country_only_path = tmp.path().join("prop-country-only.mmdb");
        write_geo_mmdb(
            &path,
            "GeoLite2-City",
            "Prop Test",
            "属性测试",
            1_763_000_000,
            &records,
            &v4_spans,
            &v6_spans,
            &strings,
            &metadata,
        )
        .unwrap();
        write_country_only_mmdb(
            &country_only_path,
            1_763_000_000,
            &records,
            &v4_spans,
            &v6_spans,
            &metadata,
        )
        .unwrap();

        let reader = maxminddb::Reader::open_readfile(&path).unwrap();
        let country_only_reader = maxminddb::Reader::open_readfile(&country_only_path).unwrap();
        for (&(a, b), &(iso, asn)) in &v4_map {
            let ip_v4 = IpAddr::V4(Ipv4Addr::new(a, b, 42, 9));
            let doc: serde_json::Value = lookup_opt(&reader, ip_v4).unwrap().unwrap();
            prop_assert_eq!(doc.pointer("/country/iso_code").and_then(|v| v.as_str()), Some(iso.as_str()));
            prop_assert_eq!(doc.pointer("/autonomous_system_number").and_then(|v| v.as_u64()), Some(asn as u64));

            let co_doc: serde_json::Value = lookup_opt(&country_only_reader, ip_v4).unwrap().unwrap();
            prop_assert_eq!(co_doc.as_object().map(|o| o.len()), Some(1));
            prop_assert_eq!(co_doc.pointer("/country/iso_code").and_then(|v| v.as_str()), Some(iso.as_str()));
            prop_assert!(co_doc.get("autonomous_system_number").is_none());

            // Also verify IPv4-mapped IPv6 `::ffff:a.b.42.9` resolves identically!
            let mapped = IpAddr::V6(Ipv4Addr::new(a, b, 42, 9).to_ipv6_mapped());
            let doc_mapped: serde_json::Value = lookup_opt(&reader, mapped).unwrap().unwrap();
            prop_assert_eq!(doc_mapped, doc);
            let co_mapped: serde_json::Value = lookup_opt(&country_only_reader, mapped).unwrap().unwrap();
            prop_assert_eq!(co_mapped, co_doc);
        }

        for (&(seg0, seg1), &(iso, asn)) in &v6_map {
            let ip_v6 = IpAddr::V6(Ipv6Addr::new(seg0, seg1, 0, 1, 0, 0, 0, 99));
            let doc: serde_json::Value = lookup_opt(&reader, ip_v6).unwrap().unwrap();
            prop_assert_eq!(doc.pointer("/country/iso_code").and_then(|v| v.as_str()), Some(iso.as_str()));
            prop_assert_eq!(doc.pointer("/autonomous_system_number").and_then(|v| v.as_u64()), Some(asn as u64));

            let co_doc: serde_json::Value = lookup_opt(&country_only_reader, ip_v6).unwrap().unwrap();
            prop_assert_eq!(co_doc.as_object().map(|o| o.len()), Some(1));
            prop_assert_eq!(co_doc.pointer("/country/iso_code").and_then(|v| v.as_str()), Some(iso.as_str()));
            prop_assert!(co_doc.get("autonomous_system_number").is_none());
        }
    }
}

#[test]
fn openproxydb_boolean_columns_filter_broad_webhost_and_cdn_blocks() {
    let (metadata, _, _) = load_real_fixtures();
    let csv_bytes = b"ip,anonblock,proxy,vpn,cdn,public-wifi,rangeblock,school-block,tor,webhost\n\
223.5.0.0/16,False,True,False,False,False,False,False,False,True\n\
1.0.0.0/24,False,True,False,True,False,False,False,False,False\n\
1.0.171.213,False,True,False,False,False,False,False,False,False\n\
192.0.2.1,False,False,False,False,False,False,True,False,False\n";

    let src = dummy_source(
        "test_openproxydb",
        SourceTier::TraitOverlay,
        SourceFormat::OpenproxydbCsv,
        "openproxydb",
    );
    let parsed = parse_source_bytes(&src, csv_bytes, &metadata).unwrap();
    assert_eq!(parsed.v4.len(), 3);

    let find_traits = |octets: [u8; 4]| {
        let ip_u32 = u32::from(Ipv4Addr::from(octets));
        let span = parsed
            .v4
            .iter()
            .find(|s| s.start <= ip_u32 && ip_u32 <= s.end)
            .expect("expected matching span");
        parsed.payloads[span.payload_id() as usize].traits
    };

    let t_ali = find_traits([223, 5, 5, 5]);
    assert!(t_ali.contains(TraitFlags::IS_HOSTING));
    assert!(!t_ali.contains(TraitFlags::IS_ANONYMOUS_PROXY));
    assert!(!t_ali.contains(TraitFlags::IS_VPN));

    let t_cf = find_traits([1, 0, 0, 1]);
    assert!(t_cf.contains(TraitFlags::IS_CDN));
    assert!(!t_cf.contains(TraitFlags::IS_ANONYMOUS_PROXY));
    assert!(!t_cf.contains(TraitFlags::IS_HOSTING));

    let t_proxy = find_traits([1, 0, 171, 213]);
    assert!(t_proxy.contains(TraitFlags::IS_ANONYMOUS_PROXY));
    assert!(!t_proxy.contains(TraitFlags::IS_VPN));
}
