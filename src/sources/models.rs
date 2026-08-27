//! Response shapes of the discovery APIs.
//!
//! Every model flattens itself into a plain set of hostnames through
//! [`IntoSubdomains`], or through an inherent `into_subdomains` when it needs
//! the target to rebuild names from relative labels.
//!
//! Fields are `#[serde(default)]` on purpose: these are third party APIs that
//! add and drop keys without notice, and losing a whole page because one
//! optional field disappeared is worse than working with what arrived.

use {serde::Deserialize, std::collections::HashSet};

/// Flattens an API response into the hostnames it carries.
pub trait IntoSubdomains {
    fn into_subdomains(self) -> HashSet<String>;
}

/// Reports whether more pages are worth requesting.
pub trait Paginated {
    /// `page` is the 1-based number of the page just parsed.
    fn has_more(&self, page: usize) -> bool;
}

/// Several APIs return a field that is sometimes a string and sometimes a
/// list of strings, depending on how many values the record carries.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl Default for OneOrMany {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl OneOrMany {
    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

/// A bare JSON array of hostnames, as returned by Subdomain Center.
impl IntoSubdomains for HashSet<String> {
    #[inline]
    fn into_subdomains(self) -> HashSet<String> {
        self
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct CertSpotterIssuance {
    #[serde(default)]
    pub dns_names: Vec<String>,
}

impl IntoSubdomains for Vec<CertSpotterIssuance> {
    fn into_subdomains(self) -> HashSet<String> {
        self.into_iter()
            .flat_map(|issuance| issuance.dns_names)
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct CrtshEntry {
    #[serde(default)]
    pub name_value: String,
}

impl IntoSubdomains for Vec<CrtshEntry> {
    fn into_subdomains(self) -> HashSet<String> {
        // One certificate covers several names, one per line.
        self.iter()
            .flat_map(|entry| entry.name_value.split('\n'))
            .map(str::to_owned)
            .collect()
    }
}

/// Shape shared by the APIs that wrap a hostname array in a single key.
#[derive(Debug, Default, Deserialize)]
pub struct NamedHostList {
    #[serde(default, alias = "subdomains", alias = "results", alias = "domains")]
    pub hosts: HashSet<String>,
}

impl IntoSubdomains for NamedHostList {
    fn into_subdomains(self) -> HashSet<String> {
        self.hosts
    }
}

/// Shape shared by the services answering with labels relative to the target.
#[derive(Debug, Default, Deserialize)]
pub struct RelativeSubdomains {
    #[serde(default)]
    pub subdomains: Vec<String>,
}

impl RelativeSubdomains {
    #[must_use]
    pub fn into_subdomains(self, target: &str) -> HashSet<String> {
        self.subdomains
            .into_iter()
            .filter(|label| !label.is_empty())
            .map(|label| format!("{label}.{target}"))
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct FacebookResponse {
    #[serde(default)]
    pub data: Vec<FacebookCertificate>,
    #[serde(default)]
    pub paging: FacebookPaging,
}

#[derive(Debug, Default, Deserialize)]
pub struct FacebookCertificate {
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct FacebookPaging {
    #[serde(default)]
    pub next: String,
}

impl IntoSubdomains for FacebookResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .into_iter()
            .flat_map(|certificate| certificate.domains)
            .collect()
    }
}

/// `BufferOver` returns `ip,hostname` pairs.
#[derive(Debug, Default, Deserialize)]
pub struct BufferoverResponse {
    #[serde(default, rename = "Results")]
    pub results: HashSet<String>,
}

impl IntoSubdomains for BufferoverResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .iter()
            .filter_map(|entry| entry.rsplit(',').next())
            .map(str::to_owned)
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct UrlscanResponse {
    #[serde(default)]
    pub results: Vec<UrlscanResult>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct UrlscanResult {
    #[serde(default)]
    pub page: UrlscanPage,
    /// Cursor of this result, echoed back as `search_after` for the next page.
    #[serde(default)]
    pub sort: Vec<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UrlscanPage {
    #[serde(default)]
    pub domain: String,
}

impl UrlscanResponse {
    /// Cursor to resume from, formatted as urlscan expects it.
    #[must_use]
    pub fn cursor(&self) -> Option<String> {
        let sort = &self.results.last()?.sort;
        if sort.is_empty() {
            return None;
        }
        let parts: Vec<String> = sort
            .iter()
            .map(|value| match value {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .collect();
        Some(parts.join(","))
    }
}

impl IntoSubdomains for UrlscanResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .map(|result| result.page.domain)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct C99Response {
    #[serde(default)]
    pub subdomains: Vec<C99Subdomain>,
}

#[derive(Debug, Default, Deserialize)]
pub struct C99Subdomain {
    #[serde(default)]
    pub subdomain: String,
}

impl IntoSubdomains for C99Response {
    fn into_subdomains(self) -> HashSet<String> {
        self.subdomains
            .into_iter()
            .map(|entry| entry.subdomain)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct AlienVaultResponse {
    #[serde(default)]
    pub passive_dns: Vec<AlienVaultRecord>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AlienVaultRecord {
    #[serde(default)]
    pub hostname: String,
}

impl IntoSubdomains for AlienVaultResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.passive_dns
            .into_iter()
            .map(|record| record.hostname)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct MnemonicResponse {
    #[serde(default)]
    pub data: Vec<MnemonicRecord>,
}

#[derive(Debug, Default, Deserialize)]
pub struct MnemonicRecord {
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub answer: String,
    #[serde(default, rename = "rrtype")]
    pub record_type: String,
}

impl IntoSubdomains for MnemonicResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .into_iter()
            .flat_map(|record| {
                // A CNAME answer is a hostname; address records answer with an IP.
                let alias = (record.record_type == "cname").then_some(record.answer);
                [Some(record.query), alias]
            })
            .flatten()
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct LeakixRecord {
    #[serde(default)]
    pub subdomain: String,
}

impl IntoSubdomains for Vec<LeakixRecord> {
    fn into_subdomains(self) -> HashSet<String> {
        self.into_iter()
            .map(|record| record.subdomain)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct MaltiverseResponse {
    #[serde(default)]
    pub hits: MaltiverseHits,
}

#[derive(Debug, Default, Deserialize)]
pub struct MaltiverseHits {
    #[serde(default)]
    pub hits: Vec<MaltiverseHit>,
}

#[derive(Debug, Default, Deserialize)]
pub struct MaltiverseHit {
    #[serde(default, rename = "_source")]
    pub source: MaltiverseSource,
}

#[derive(Debug, Default, Deserialize)]
pub struct MaltiverseSource {
    #[serde(default)]
    pub hostname: String,
}

impl IntoSubdomains for MaltiverseResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.hits
            .hits
            .into_iter()
            .map(|hit| hit.source.hostname)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

impl MaltiverseResponse {
    #[must_use]
    pub fn len(&self) -> usize {
        self.hits.hits.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hits.hits.is_empty()
    }
}

/// `DNSRepo` answers with a bare array of records.
#[derive(Debug, Default, Deserialize)]
pub struct DnsRepoRecord {
    #[serde(default)]
    pub domain: String,
}

impl IntoSubdomains for Vec<DnsRepoRecord> {
    fn into_subdomains(self) -> HashSet<String> {
        self.into_iter()
            .map(|record| record.domain)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct SocRadarResponse {
    #[serde(default)]
    pub data: SocRadarData,
}

#[derive(Debug, Default, Deserialize)]
pub struct SocRadarData {
    #[serde(default)]
    pub subdomains: HashSet<String>,
}

impl IntoSubdomains for SocRadarResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data.subdomains
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct CommonCrawlIndex {
    #[serde(default, rename = "cdx-api")]
    pub cdx_api: String,
}

/// Answer to a `showNumPages=true` query against a `CommonCrawl` index.
#[derive(Debug, Default, Deserialize)]
pub struct CommonCrawlPages {
    #[serde(default)]
    pub pages: usize,
}

/// One line of a CDX index in `output=json` mode.
#[derive(Debug, Default, Deserialize)]
pub struct CdxRecord {
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct BinaryEdgeResponse {
    #[serde(default)]
    pub events: HashSet<String>,
    #[serde(default)]
    pub page: usize,
    #[serde(default)]
    pub total: usize,
    #[serde(default)]
    pub pagesize: usize,
}

impl IntoSubdomains for BinaryEdgeResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.events
    }
}

impl Paginated for BinaryEdgeResponse {
    fn has_more(&self, _page: usize) -> bool {
        // Every operand comes from the API, so the product is saturating.
        self.pagesize != 0 && self.page.saturating_mul(self.pagesize) < self.total
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct DeepinfoResponse {
    #[serde(default)]
    pub results: Vec<DeepinfoRecord>,
    #[serde(default)]
    pub result_count: usize,
}

#[derive(Debug, Default, Deserialize)]
pub struct DeepinfoRecord {
    #[serde(default, alias = "domain", alias = "subdomain")]
    pub punycode: String,
}

impl IntoSubdomains for DeepinfoResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .map(|record| record.punycode)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

impl Paginated for DeepinfoResponse {
    fn has_more(&self, page: usize) -> bool {
        !self.results.is_empty() && self.result_count > DEEPINFO_PAGE_SIZE.saturating_mul(page)
    }
}

/// Records Deepinfo returns per page.
pub const DEEPINFO_PAGE_SIZE: usize = 100;

#[derive(Debug, Default, Deserialize)]
pub struct OnypheResponse {
    #[serde(default)]
    pub results: Vec<OnypheRecord>,
    #[serde(default)]
    pub max_page: usize,
}

#[derive(Debug, Default, Deserialize)]
pub struct OnypheRecord {
    #[serde(default)]
    pub hostname: OneOrMany,
    #[serde(default)]
    pub subdomains: OneOrMany,
    #[serde(default)]
    pub domain: OneOrMany,
}

impl IntoSubdomains for OnypheResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .flat_map(|record| {
                record
                    .hostname
                    .into_vec()
                    .into_iter()
                    .chain(record.subdomains.into_vec())
                    .chain(record.domain.into_vec())
            })
            .filter(|host| !host.is_empty())
            .collect()
    }
}

impl Paginated for OnypheResponse {
    fn has_more(&self, page: usize) -> bool {
        !self.results.is_empty() && page < self.max_page
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct NetlasResponse {
    #[serde(default)]
    pub items: Vec<NetlasItem>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NetlasItem {
    #[serde(default)]
    pub data: NetlasData,
}

#[derive(Debug, Default, Deserialize)]
pub struct NetlasData {
    #[serde(default)]
    pub domain: OneOrMany,
}

impl IntoSubdomains for NetlasResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.items
            .into_iter()
            .flat_map(|item| item.data.domain.into_vec())
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct HunterResponse {
    #[serde(default)]
    pub data: HunterData,
}

#[derive(Debug, Default, Deserialize)]
pub struct HunterData {
    #[serde(default)]
    pub emails: Vec<HunterEmail>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HunterEmail {
    #[serde(default)]
    pub sources: Vec<HunterSource>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HunterSource {
    #[serde(default)]
    pub domain: String,
}

impl IntoSubdomains for HunterResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .emails
            .into_iter()
            .flat_map(|email| email.sources)
            .map(|source| source.domain)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

impl HunterResponse {
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.emails.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.emails.is_empty()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ZetalyticsResponse {
    #[serde(default)]
    pub results: Vec<ZetalyticsRecord>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ZetalyticsRecord {
    #[serde(default, alias = "domain")]
    pub qname: String,
}

impl IntoSubdomains for ZetalyticsResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .map(|record| record.qname)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ThreatBookResponse {
    #[serde(default)]
    pub data: ThreatBookData,
}

#[derive(Debug, Default, Deserialize)]
pub struct ThreatBookData {
    #[serde(default)]
    pub sub_domains: ThreatBookSubdomains,
}

#[derive(Debug, Default, Deserialize)]
pub struct ThreatBookSubdomains {
    #[serde(default)]
    pub data: HashSet<String>,
}

impl IntoSubdomains for ThreatBookResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data.sub_domains.data
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct WhoisXmlResponse {
    #[serde(default)]
    pub result: WhoisXmlResult,
}

#[derive(Debug, Default, Deserialize)]
pub struct WhoisXmlResult {
    #[serde(default)]
    pub records: Vec<WhoisXmlRecord>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WhoisXmlRecord {
    #[serde(default)]
    pub domain: String,
}

impl IntoSubdomains for WhoisXmlResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.result
            .records
            .into_iter()
            .map(|record| record.domain)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ZoomEyeResponse {
    #[serde(default, alias = "list")]
    pub matches: Vec<ZoomEyeMatch>,
    #[serde(default)]
    pub total: usize,
}

#[derive(Debug, Default, Deserialize)]
pub struct ZoomEyeMatch {
    #[serde(default)]
    pub name: String,
}

impl IntoSubdomains for ZoomEyeResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.matches
            .into_iter()
            .map(|entry| entry.name)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

impl Paginated for ZoomEyeResponse {
    fn has_more(&self, page: usize) -> bool {
        !self.matches.is_empty() && page.saturating_mul(self.matches.len()) < self.total
    }
}

/// One line of the `DNSDB` newline delimited stream.
#[derive(Debug, Default, Deserialize)]
pub struct DnsdbLine {
    #[serde(default)]
    pub obj: DnsdbRecord,
}

#[derive(Debug, Default, Deserialize)]
pub struct DnsdbRecord {
    #[serde(default)]
    pub rrname: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct BuiltWithResponse {
    #[serde(default, rename = "Results")]
    pub results: Vec<BuiltWithResult>,
}

#[derive(Debug, Default, Deserialize)]
pub struct BuiltWithResult {
    #[serde(default, rename = "Result")]
    pub result: BuiltWithPaths,
}

#[derive(Debug, Default, Deserialize)]
pub struct BuiltWithPaths {
    #[serde(default, rename = "Paths")]
    pub paths: Vec<BuiltWithPath>,
}

#[derive(Debug, Default, Deserialize)]
pub struct BuiltWithPath {
    #[serde(default, rename = "Domain")]
    pub domain: String,
    #[serde(default, rename = "SubDomain")]
    pub subdomain: String,
}

impl IntoSubdomains for BuiltWithResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .flat_map(|result| result.result.paths)
            .filter(|path| !path.domain.is_empty())
            .map(|path| {
                if path.subdomain.is_empty() {
                    path.domain
                } else {
                    format!("{}.{}", path.subdomain, path.domain)
                }
            })
            .collect()
    }
}

/// One page of `PassiveTotal` subdomains.
#[derive(Debug, Default, Deserialize)]
pub struct PassiveTotalResponse {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub subdomains: Vec<String>,
    /// Cursor for the next page, absent or empty on the last one.
    #[serde(default, rename = "lastId")]
    pub last_id: String,
}

impl PassiveTotalResponse {
    #[must_use]
    pub fn into_subdomains(self, target: &str) -> HashSet<String> {
        self.subdomains
            .into_iter()
            .filter(|label| !label.is_empty())
            .map(|label| format!("{label}.{target}"))
            .collect()
    }
}

/// `CertCentral` wraps its list in a single-element data array.
#[derive(Debug, Default, Deserialize)]
pub struct CertCentralResponse {
    #[serde(default)]
    pub data: Vec<CertCentralEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CertCentralEntry {
    #[serde(default)]
    pub subdomains: HashSet<String>,
}

impl IntoSubdomains for CertCentralResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .into_iter()
            .flat_map(|entry| entry.subdomains)
            .collect()
    }
}

/// Quake reports each service it saw, with the HTTP host when there was one.
#[derive(Debug, Default, Deserialize)]
pub struct QuakeResponse {
    #[serde(default)]
    pub data: Vec<QuakeRecord>,
    #[serde(default)]
    pub meta: QuakeMeta,
}

#[derive(Debug, Default, Deserialize)]
pub struct QuakeRecord {
    #[serde(default)]
    pub service: QuakeService,
}

#[derive(Debug, Default, Deserialize)]
pub struct QuakeService {
    #[serde(default)]
    pub http: QuakeHttp,
}

#[derive(Debug, Default, Deserialize)]
pub struct QuakeHttp {
    #[serde(default)]
    pub host: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct QuakeMeta {
    #[serde(default)]
    pub pagination: QuakePagination,
}

#[derive(Debug, Default, Deserialize)]
pub struct QuakePagination {
    #[serde(default)]
    pub total: usize,
}

impl IntoSubdomains for QuakeResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .into_iter()
            .map(|record| record.service.http.host)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

impl Paginated for QuakeResponse {
    fn has_more(&self, page: usize) -> bool {
        !self.data.is_empty() && page.saturating_mul(self.data.len()) < self.meta.pagination.total
    }
}

/// FOFA answers with rows of the fields that were requested.
#[derive(Debug, Default, Deserialize)]
pub struct FofaResponse {
    #[serde(default)]
    pub results: Vec<OneOrMany>,
    #[serde(default)]
    pub size: usize,
}

impl IntoSubdomains for FofaResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .flat_map(OneOrMany::into_vec)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

/// Spamhaus passive DNS returns the matching resource records.
#[derive(Debug, Default, Deserialize)]
pub struct SpamhausResponse {
    #[serde(default)]
    pub records: Vec<SpamhausRecord>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SpamhausRecord {
    #[serde(default)]
    pub rrname: String,
}

impl IntoSubdomains for SpamhausResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.records
            .into_iter()
            .map(|record| record.rrname.trim_end_matches('.').to_owned())
            .filter(|host| !host.is_empty())
            .collect()
    }
}

/// Ahrefs lists the pages it has crawled; the hostname lives in the URL.
#[derive(Debug, Default, Deserialize)]
pub struct AhrefsResponse {
    #[serde(default)]
    pub pages: Vec<AhrefsPage>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AhrefsPage {
    #[serde(default)]
    pub url: String,
}

/// `DNSlytics` reverse IP data.
#[derive(Debug, Default, Deserialize)]
pub struct DnslyticsResponse {
    #[serde(default)]
    pub data: DnslyticsData,
}

#[derive(Debug, Default, Deserialize)]
pub struct DnslyticsData {
    #[serde(default)]
    pub domains: HashSet<String>,
}

impl IntoSubdomains for DnslyticsResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data.domains
    }
}

/// Pulsedive returns the indicators it knows about.
#[derive(Debug, Default, Deserialize)]
pub struct PulsediveResponse {
    #[serde(default)]
    pub results: Vec<PulsediveIndicator>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PulsediveIndicator {
    #[serde(default)]
    pub indicator: String,
}

impl IntoSubdomains for PulsediveResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .map(|entry| entry.indicator)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

/// `IntelX` phonebook search results.
#[derive(Debug, Default, Deserialize)]
pub struct IntelxResponse {
    #[serde(default)]
    pub selectors: Vec<IntelxSelector>,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: i64,
}

#[derive(Debug, Default, Deserialize)]
pub struct IntelxSelector {
    #[serde(default, alias = "selectorvalue")]
    pub selector_value: String,
}

impl IntoSubdomains for IntelxResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.selectors
            .into_iter()
            .map(|selector| selector.selector_value)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

/// Censys certificate search.
#[derive(Debug, Default, Deserialize)]
pub struct CensysResponse {
    #[serde(default)]
    pub results: Vec<CensysResult>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CensysResult {
    #[serde(default, rename = "parsed.names")]
    pub names: Vec<String>,
}

impl IntoSubdomains for CensysResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.results
            .into_iter()
            .flat_map(|result| result.names)
            .filter(|host| !host.is_empty())
            .collect()
    }
}

/// One line of the CIRCL passive DNS stream.
#[derive(Debug, Default, Deserialize)]
pub struct CirclLine {
    #[serde(default)]
    pub rrname: String,
}

/// Detectify asset listing.
#[derive(Debug, Default, Deserialize)]
pub struct DetectifyAsset {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub token: String,
}

/// `PentestTools` returns rows whose first column is the hostname.
#[derive(Debug, Default, Deserialize)]
pub struct PentestToolsResponse {
    #[serde(default)]
    pub data: PentestToolsData,
}

#[derive(Debug, Default, Deserialize)]
pub struct PentestToolsData {
    #[serde(default)]
    pub output_data: Vec<Vec<String>>,
}

impl IntoSubdomains for PentestToolsResponse {
    fn into_subdomains(self) -> HashSet<String> {
        self.data
            .output_data
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .filter(|host| !host.is_empty())
            .collect()
    }
}

/// 360's passive DNS service.
#[derive(Debug, Default, Deserialize)]
pub struct PassiveDns360Response {
    #[serde(default)]
    pub rrset: Vec<PassiveDns360Record>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PassiveDns360Record {
    #[serde(default)]
    pub rrname: String,
}

impl IntoSubdomains for PassiveDns360Response {
    fn into_subdomains(self) -> HashSet<String> {
        self.rrset
            .into_iter()
            .map(|record| record.rrname.trim_end_matches('.').to_owned())
            .filter(|host| !host.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passivetotal_reports_its_cursor_and_whether_it_worked() {
        let page: PassiveTotalResponse =
            serde_json::from_str(r#"{"success":true,"subdomains":["a","b"],"lastId":"abc123"}"#)
                .expect("valid payload");
        assert!(page.success);
        assert_eq!(page.last_id, "abc123");
        assert_eq!(
            page.into_subdomains("example.com"),
            HashSet::from(["a.example.com".to_owned(), "b.example.com".to_owned()])
        );

        let last: PassiveTotalResponse =
            serde_json::from_str(r#"{"success":true,"subdomains":["c"]}"#).expect("valid payload");
        assert!(last.last_id.is_empty(), "a missing cursor ends the walk");

        let refused: PassiveTotalResponse =
            serde_json::from_str(r#"{"success":false}"#).expect("valid payload");
        assert!(!refused.success);
    }

    fn parse<T: serde::de::DeserializeOwned>(json: &str) -> T {
        serde_json::from_str(json).expect("valid fixture")
    }

    fn sorted(subdomains: HashSet<String>) -> Vec<String> {
        let mut names: Vec<String> = subdomains.into_iter().collect();
        names.sort();
        names
    }

    #[test]
    fn plain_arrays_pass_through() {
        let response: HashSet<String> = parse(r#"["a.example.com","b.example.com"]"#);
        assert_eq!(
            sorted(response.into_subdomains()),
            ["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn certspotter_flattens_every_issuance() {
        let response: Vec<CertSpotterIssuance> = parse(
            r#"[{"dns_names":["a.example.com","*.example.com"]},{"dns_names":["b.example.com"]}]"#,
        );
        assert_eq!(
            sorted(response.into_subdomains()),
            ["*.example.com", "a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn crtsh_splits_multi_name_certificates() {
        let response: Vec<CrtshEntry> = parse(
            r#"[{"name_value":"a.example.com\nb.example.com"},{"name_value":"c.example.com"}]"#,
        );
        assert_eq!(
            sorted(response.into_subdomains()),
            ["a.example.com", "b.example.com", "c.example.com"]
        );
    }

    #[test]
    fn named_host_list_accepts_every_key_variant() {
        for json in [
            r#"{"subdomains":["a.example.com"]}"#,
            r#"{"results":["a.example.com"]}"#,
            r#"{"hosts":["a.example.com"]}"#,
        ] {
            let parsed: NamedHostList = parse(json);
            assert_eq!(sorted(parsed.into_subdomains()), ["a.example.com"]);
        }
    }

    #[test]
    fn relative_labels_are_joined_to_the_target() {
        let response: RelativeSubdomains = parse(r#"{"subdomains":["a","b.c",""]}"#);
        assert_eq!(
            sorted(response.into_subdomains("example.com")),
            ["a.example.com", "b.c.example.com"]
        );
    }

    #[test]
    fn facebook_flattens_certificates_and_exposes_its_cursor() {
        let response: FacebookResponse = parse(
            r#"{"data":[{"domains":["a.example.com","b.example.com"]}],
                "paging":{"next":"https://graph.facebook.com/next"}}"#,
        );
        assert_eq!(response.paging.next, "https://graph.facebook.com/next");
        assert_eq!(
            sorted(response.into_subdomains()),
            ["a.example.com", "b.example.com"]
        );

        let last: FacebookResponse = parse(r#"{"data":[]}"#);
        assert!(last.paging.next.is_empty());
    }

    #[test]
    fn bufferover_keeps_only_the_hostname_half() {
        let response: BufferoverResponse = parse(r#"{"Results":["93.184.216.34,a.example.com"]}"#);
        assert_eq!(sorted(response.into_subdomains()), ["a.example.com"]);
    }

    #[test]
    fn urlscan_reads_domains_and_builds_a_cursor() {
        let response: UrlscanResponse = parse(
            r#"{"results":[{"page":{"domain":"a.example.com"},"sort":[1784883083980,"019f"]}],
                "has_more":true}"#,
        );
        assert!(response.has_more);
        assert_eq!(response.cursor().as_deref(), Some("1784883083980,019f"));
        assert_eq!(sorted(response.into_subdomains()), ["a.example.com"]);
    }

    #[test]
    fn urlscan_without_results_has_no_cursor() {
        let response: UrlscanResponse = parse(r#"{"results":[],"has_more":false}"#);
        assert!(response.cursor().is_none());
    }

    #[test]
    fn mnemonic_keeps_queries_and_cname_answers_only() {
        let response: MnemonicResponse = parse(
            r#"{"data":[{"query":"a.example.com","rrtype":"a","answer":"1.2.3.4"},
                        {"query":"b.example.com","rrtype":"cname","answer":"c.example.com"}]}"#,
        );
        assert_eq!(
            sorted(response.into_subdomains()),
            ["a.example.com", "b.example.com", "c.example.com"]
        );
    }

    #[test]
    fn binaryedge_stops_once_the_total_is_covered() {
        let page: BinaryEdgeResponse =
            parse(r#"{"events":["a.example.com"],"page":1,"total":250,"pagesize":100}"#);
        assert!(page.has_more(1));

        let last: BinaryEdgeResponse =
            parse(r#"{"events":["a.example.com"],"page":3,"total":250,"pagesize":100}"#);
        assert!(!last.has_more(3));

        let broken: BinaryEdgeResponse = parse(r#"{"events":[],"page":1,"total":0,"pagesize":0}"#);
        assert!(!broken.has_more(1));
    }

    #[test]
    fn absurd_pagination_counters_do_not_overflow() {
        // Every operand is attacker or bug controlled. The property under test
        // is that the arithmetic neither panics in debug nor wraps into a wrong
        // answer in release; saturating simply ends the walk.
        let binaryedge: BinaryEdgeResponse = parse(&format!(
            r#"{{"events":["a.example.com"],"page":{max},"total":{max},"pagesize":{max}}}"#,
            max = usize::MAX
        ));
        assert!(!binaryedge.has_more(1));

        let zoomeye: ZoomEyeResponse = parse(&format!(
            r#"{{"matches":[{{"name":"a.example.com"}}],"total":{}}}"#,
            usize::MAX
        ));
        assert!(!zoomeye.has_more(usize::MAX));

        let deepinfo: DeepinfoResponse = parse(&format!(
            r#"{{"results":[{{"punycode":"a.example.com"}}],"result_count":{}}}"#,
            usize::MAX
        ));
        assert!(!deepinfo.has_more(usize::MAX));
    }

    #[test]
    fn realistic_counters_still_drive_pagination() {
        // The saturating guard must not disturb ordinary paging decisions.
        let more: BinaryEdgeResponse =
            parse(r#"{"events":["a.example.com"],"page":1,"total":250,"pagesize":100}"#);
        assert!(more.has_more(1));

        let zoomeye: ZoomEyeResponse =
            parse(r#"{"matches":[{"name":"a.example.com"},{"name":"b.example.com"}],"total":10}"#);
        assert!(zoomeye.has_more(1));
        assert!(!zoomeye.has_more(5));

        let deepinfo: DeepinfoResponse =
            parse(r#"{"results":[{"punycode":"a.example.com"}],"result_count":250}"#);
        assert!(deepinfo.has_more(1));
        assert!(!deepinfo.has_more(3));
    }

    #[test]
    fn onyphe_stops_at_the_last_page() {
        let page: OnypheResponse = parse(
            r#"{"results":[{"hostname":["a.example.com"],"domain":["example.com"]}],"max_page":3}"#,
        );
        assert!(page.has_more(1));
        assert!(!page.has_more(3));
        assert_eq!(
            sorted(page.into_subdomains()),
            ["a.example.com", "example.com"]
        );

        let empty: OnypheResponse = parse(r#"{"results":[],"max_page":3}"#);
        assert!(!empty.has_more(1));
    }

    #[test]
    fn netlas_reads_the_nested_domain_list() {
        let response: NetlasResponse =
            parse(r#"{"items":[{"data":{"domain":["a.example.com","b.example.com"]}}]}"#);
        assert_eq!(
            sorted(response.into_subdomains()),
            ["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn hunter_collects_the_source_domains() {
        let response: HunterResponse = parse(
            r#"{"data":{"emails":[{"sources":[{"domain":"a.example.com"},{"domain":""}]}]}}"#,
        );
        assert_eq!(response.len(), 1);
        assert_eq!(sorted(response.into_subdomains()), ["a.example.com"]);
    }

    #[test]
    fn threatbook_reads_the_nested_subdomain_list() {
        let response: ThreatBookResponse =
            parse(r#"{"data":{"sub_domains":{"total":"1","data":["a.example.com"]}}}"#);
        assert_eq!(sorted(response.into_subdomains()), ["a.example.com"]);
    }

    #[test]
    fn whoisxml_reads_the_record_domains() {
        let response: WhoisXmlResponse =
            parse(r#"{"result":{"count":1,"records":[{"domain":"a.example.com"}]}}"#);
        assert_eq!(sorted(response.into_subdomains()), ["a.example.com"]);
    }

    #[test]
    fn zoomeye_accepts_both_result_keys() {
        let matches: ZoomEyeResponse = parse(r#"{"matches":[{"name":"a.example.com"}],"total":1}"#);
        assert_eq!(sorted(matches.into_subdomains()), ["a.example.com"]);

        let list: ZoomEyeResponse = parse(r#"{"list":[{"name":"b.example.com"}],"total":1}"#);
        assert_eq!(sorted(list.into_subdomains()), ["b.example.com"]);
    }

    #[test]
    fn builtwith_joins_the_subdomain_to_its_domain() {
        let response: BuiltWithResponse = parse(
            r#"{"Results":[{"Result":{"Paths":[
                {"Domain":"example.com","SubDomain":"www"},
                {"Domain":"example.com","SubDomain":""},
                {"Domain":"","SubDomain":"orphan"}]}}]}"#,
        );
        assert_eq!(
            sorted(response.into_subdomains()),
            ["example.com", "www.example.com"]
        );
    }

    #[test]
    fn a_missing_optional_field_does_not_fail_the_parse() {
        // Third party APIs drop keys without warning; partial data still counts.
        let response: AlienVaultResponse =
            parse(r#"{"passive_dns":[{"hostname":"a.example.com"}]}"#);
        assert_eq!(sorted(response.into_subdomains()), ["a.example.com"]);

        let empty: AlienVaultResponse = parse("{}");
        assert!(empty.into_subdomains().is_empty());

        let no_fields: NetlasResponse = parse(r#"{"items":[{}]}"#);
        assert!(no_fields.into_subdomains().is_empty());
    }

    #[test]
    fn dnsdb_lines_expose_the_record_name() {
        let line: DnsdbLine = parse(r#"{"obj":{"rrname":"a.example.com.","rrtype":"A"}}"#);
        assert_eq!(line.obj.rrname, "a.example.com.");
    }

    #[test]
    fn cdx_records_expose_the_url() {
        let record: CdxRecord = parse(r#"{"url":"https://a.example.com/x"}"#);
        assert_eq!(record.url, "https://a.example.com/x");
    }
}
