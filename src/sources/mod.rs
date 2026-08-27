//! Passive discovery sources.
//!
//! Every source parses a documented response format, JSON in almost every
//! case. Sources that would need hostnames scraped out of prose or HTML are
//! deliberately absent: they cost a request, return noise, and break silently
//! whenever the page changes.
//!
//! Paginated APIs are walked to exhaustion through [`paginate`], which keeps
//! whatever earlier pages returned when a later one fails.

pub mod crtsh;
pub mod models;

use {
    crate::{config::Config, utils::random_from},
    models::{
        AhrefsResponse, AlienVaultResponse, BinaryEdgeResponse, BufferoverResponse,
        BuiltWithResponse, C99Response, CdxRecord, CensysResponse, CertCentralResponse,
        CertSpotterIssuance, CirclLine, CommonCrawlIndex, CommonCrawlPages, DeepinfoResponse,
        DetectifyAsset, DnsRepoRecord, DnsdbLine, DnslyticsResponse, FacebookResponse,
        FofaResponse, HunterResponse, IntelxResponse, IntoSubdomains, LeakixRecord,
        MaltiverseResponse, MnemonicResponse, NamedHostList, NetlasResponse, OnypheResponse,
        Paginated, PassiveDns360Response, PassiveTotalResponse, PentestToolsResponse,
        PulsediveResponse, QuakeResponse, RelativeSubdomains, SocRadarResponse, SpamhausResponse,
        ThreatBookResponse, UrlscanResponse, WhoisXmlResponse, ZetalyticsResponse, ZoomEyeResponse,
    },
    reqwest::{
        blocking::{Client, RequestBuilder, Response},
        header::{ACCEPT, AUTHORIZATION, USER_AGENT},
        StatusCode,
    },
    serde::de::DeserializeOwned,
    std::{
        collections::HashSet,
        sync::Arc,
        time::{Duration, Instant},
    },
};

/// Hard ceiling on a single discovery request, whatever the configuration says.
///
/// A source that has been given a whole minute and still has nothing to show is
/// not going to produce anything useful, and sources run in parallel, so the
/// slowest of them is what the run waits for.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on pages fetched from any single source.
const MAX_PAGES: usize = 500;

/// Shared state handed to every source.
#[derive(Clone, Debug)]
pub struct SourceContext {
    client: Client,
    user_agents: Arc<Vec<String>>,
    request_timeout: Duration,
    /// When the discovery phase stops issuing requests, if it is bounded.
    deadline: Option<Instant>,
    /// Tighter allowance for the archive indexes, if they have one.
    archive_budget: Option<Duration>,
    quiet: bool,
    verbose: bool,
}

impl SourceContext {
    /// Builds the context, reusing a single connection pool for all sources.
    ///
    /// The budget clock starts here, so build this immediately before the
    /// sources fan out.
    ///
    /// # Panics
    ///
    /// Panics when the platform TLS backend cannot be initialised.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        let request_timeout = Duration::from_secs(config.sources.timeout).min(REQUEST_TIMEOUT);
        Self {
            client: Client::builder()
                .timeout(request_timeout)
                .build()
                .expect("build the HTTP client"),
            user_agents: Arc::new(config.http.user_agents.clone()),
            request_timeout,
            deadline: (config.sources.budget > 0)
                .then(|| Instant::now() + Duration::from_secs(config.sources.budget)),
            archive_budget: (config.sources.archive_budget > 0)
                .then(|| Duration::from_secs(config.sources.archive_budget)),
            quiet: config.general.quiet,
            verbose: config.general.verbose,
        }
    }

    /// How long the discovery phase may still spend, or `None` when unbounded.
    ///
    /// Returns `Some(ZERO)` once the budget is gone, which callers treat as a
    /// refusal rather than an unlimited wait.
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Returns a view of this context that must be done within `budget`.
    ///
    /// This is how a source that is known to be unable to stop on its own gets
    /// held to a tighter clock than the run as a whole, without shortening the
    /// clock of the sources that page through real results. It only ever
    /// tightens: a run with no budget at all keeps none, which is what makes
    /// `--source-budget 0` mean what it says.
    fn with_budget(&self, budget: Duration) -> Self {
        let Some(deadline) = self.deadline else {
            return self.clone();
        };
        Self {
            deadline: Some(deadline.min(Instant::now() + budget)),
            ..self.clone()
        }
    }

    fn get(&self, url: &str) -> RequestBuilder {
        self.client
            .get(url)
            .header(USER_AGENT, random_from(&self.user_agents))
    }

    fn post(&self, url: &str) -> RequestBuilder {
        self.client
            .post(url)
            .header(USER_AGENT, random_from(&self.user_agents))
    }

    fn announce(&self, api: &str) {
        if !self.quiet {
            println!("Searching in the {api} API... 🔍");
        }
    }

    /// Reports a source failure; silent unless `--verbose` was given.
    fn report(&self, message: &str) {
        if !self.quiet && self.verbose {
            eprintln!("{message}");
        }
    }
}

/// Sends `request`, returning the response only when the server answered 200.
///
/// This is the single gate every source request passes through, so it is also
/// where the discovery budget is enforced: once it is spent no further request
/// goes out, and any request still allowed is capped at what is left. A
/// paginated source therefore stops mid-walk and keeps the pages it already
/// has, because [`paginate`] treats a failed later page as the end of the road.
fn send(context: &SourceContext, api: &str, request: RequestBuilder) -> Option<Response> {
    let request = match context.remaining() {
        Some(Duration::ZERO) => {
            context.report(&format!(
                "Skipping the {api} API: the time budget for the sources is spent."
            ));
            return None;
        }
        Some(left) => request.timeout(left.min(context.request_timeout)),
        None => request,
    };

    let response = match request.send() {
        Ok(response) => response,
        Err(e) => {
            context.report(&format!("❌ Error in {api} API. {e} "));
            return None;
        }
    };

    if response.status() != StatusCode::OK {
        context.report(&format!(
            "The {api} API has failed returning the following HTTP status: {}",
            response.status(),
        ));
        return None;
    }

    Some(response)
}

fn fetch_json<T: DeserializeOwned>(
    context: &SourceContext,
    api: &str,
    request: RequestBuilder,
) -> Option<T> {
    match send(context, api, request)?.json::<T>() {
        Ok(payload) => Some(payload),
        Err(e) => {
            context.report(&format!(
                "❌ An error occurred while parsing the JSON obtained from the {api} API. Error description: {e:?}.",
            ));
            None
        }
    }
}

fn fetch<T: DeserializeOwned + IntoSubdomains>(
    context: &SourceContext,
    api: &str,
    request: RequestBuilder,
) -> Option<HashSet<String>> {
    fetch_json::<T>(context, api, request).map(IntoSubdomains::into_subdomains)
}

fn fetch_text(context: &SourceContext, api: &str, request: RequestBuilder) -> Option<String> {
    match send(context, api, request)?.text() {
        Ok(body) => Some(body),
        Err(e) => {
            context.report(&format!("❌ Error reading the {api} API response. {e}"));
            None
        }
    }
}

/// Parses a newline delimited JSON stream, skipping lines that do not fit.
fn parse_ndjson<T: DeserializeOwned>(body: &str) -> Vec<T> {
    body.lines()
        .filter(|line| !line.trim_start().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Walks a paginated source until it runs out of pages.
///
/// A failure on the first page means the source produced nothing; a failure
/// later on keeps the pages already collected, which is the useful answer from
/// a flaky API.
///
/// Paging stops when the source reports no more pages, returns an empty page,
/// or hands back the exact same page as before. That last guard catches
/// services that ignore the page parameter and keep replying with page one; it
/// deliberately compares whole pages rather than the merged total, so a cursor
/// based source whose distinct pages happen to share hostnames is not cut short.
fn paginate<F>(max_pages: usize, mut next_page: F) -> Option<HashSet<String>>
where
    F: FnMut(usize) -> Option<(HashSet<String>, bool)>,
{
    let mut all: HashSet<String> = HashSet::new();
    let mut previous: Option<HashSet<String>> = None;

    for page in 1..=max_pages.min(MAX_PAGES) {
        match next_page(page) {
            Some((found, has_more)) => {
                if found.is_empty() || previous.as_ref() == Some(&found) {
                    break;
                }
                if !has_more {
                    all.extend(found);
                    break;
                }
                all.extend(found.iter().cloned());
                previous = Some(found);
            }
            None if page == 1 => return None,
            None => break,
        }
    }

    Some(all)
}

/// Fetches one page of a source whose response knows its own pagination state.
fn page_of<T>(
    context: &SourceContext,
    api: &str,
    request: RequestBuilder,
    page: usize,
) -> Option<(HashSet<String>, bool)>
where
    T: DeserializeOwned + IntoSubdomains + Paginated,
{
    let response = fetch_json::<T>(context, api, request)?;
    let has_more = response.has_more(page);
    Some((response.into_subdomains(), has_more))
}

/// Extracts the host part of a URL.
fn host_of(url: &str) -> Option<String> {
    let authority = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Certificate transparency logs, faster with a token.
#[must_use]
pub fn certspotter(context: &SourceContext, target: &str, token: &str) -> Option<HashSet<String>> {
    const API: &str = "CertSpotter";
    context.announce(API);

    let mut request = context.get(&format!(
        "https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
    ));
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    fetch::<Vec<CertSpotterIssuance>>(context, API, request)
}

/// Subdomain Center's aggregated index.
#[must_use]
pub fn subdomain_center(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Subdomain Center";
    context.announce(API);

    let request = context.get(&format!("https://api.subdomain.center/?domain={target}"));
    fetch::<HashSet<String>>(context, API, request)
}

/// `HackerTarget`'s host search, which answers with `hostname,ip` lines.
#[must_use]
pub fn hackertarget(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    const API: &str = "HackerTarget";
    context.announce(API);

    let mut url = format!("https://api.hackertarget.com/hostsearch/?q={target}");
    if !api_key.is_empty() {
        url.push_str("&apikey=");
        url.push_str(api_key);
    }

    let body = fetch_text(context, API, context.get(&url))?;

    // HackerTarget reports a spent quota as prose with a 200 status; its real
    // answer is always `hostname,address`.
    if !body.contains(',') {
        context.report(&format!(
            "The {API} API refused the query: {}",
            body.lines().next().unwrap_or("empty response").trim()
        ));
        return None;
    }

    Some(
        body.lines()
            .filter_map(|line| line.split(',').next())
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Mnemonic's public passive DNS database.
#[must_use]
pub fn mnemonic(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Mnemonic";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.mnemonic.no/pdns/v3/{target}?limit=1000"
    ));
    fetch::<MnemonicResponse>(context, API, request)
}

/// Hits requested per Maltiverse page.
const MALTIVERSE_PAGE_SIZE: usize = 500;

/// Maltiverse's hostname search.
#[must_use]
pub fn maltiverse(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Maltiverse";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let from = (page - 1) * MALTIVERSE_PAGE_SIZE;
        let request = context.get(&format!(
            "https://api.maltiverse.com/search?query=hostname:*.{target}&from={from}&size={MALTIVERSE_PAGE_SIZE}"
        ));
        let response = fetch_json::<MaltiverseResponse>(context, API, request)?;
        let has_more = response.len() >= MALTIVERSE_PAGE_SIZE;
        Some((response.into_subdomains(), has_more))
    })
}

/// Results requested per urlscan page.
const URLSCAN_PAGE_SIZE: usize = 100;

/// Hostnames urlscan.io saw while scanning pages, walked with its cursor.
#[must_use]
pub fn urlscan(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Urlscan.io";
    context.announce(API);

    let mut cursor: Option<String> = None;
    paginate(MAX_PAGES, |_| {
        let mut url =
            format!("https://urlscan.io/api/v1/search/?q=domain:{target}&size={URLSCAN_PAGE_SIZE}");
        if let Some(after) = &cursor {
            url.push_str("&search_after=");
            url.push_str(after);
        }

        let response = fetch_json::<UrlscanResponse>(context, API, context.get(&url))?;
        let has_more = response.has_more;
        cursor = response.cursor();
        Some((response.into_subdomains(), has_more && cursor.is_some()))
    })
}

/// Upper bound on the rows the Wayback index is asked for in one go.
///
/// Its `page` parameter indexes storage blocks, not result rows: a busy domain
/// spreads a handful of matches over hundreds of pages, so walking them costs
/// hundreds of requests for the same data one request already returns.
const WAYBACK_MAX_ROWS: usize = 100_000;

/// Marks a source as an archive index, holding it to `--archive-budget`.
///
/// These are the only sources here that cannot stop on their own. A CDX index
/// is a bulk download of every URL ever archived under a domain, sliced into
/// storage blocks rather than into pages of distinct hostnames, so walking it
/// keeps costing requests long after it has stopped producing names: left
/// alone, `CommonCrawl` spends over two minutes on google.com to return exactly
/// the same hostnames it already had after twenty seconds. Every other source
/// pages through results that differ from each other and is left to finish,
/// which is why this limit is theirs alone rather than the run's.
fn archive(context: &SourceContext) -> SourceContext {
    context
        .archive_budget
        .map_or_else(|| context.clone(), |budget| context.with_budget(budget))
}

/// Reads a CDX index page and turns the archived URLs into hostnames.
///
/// The Wayback server answers `output=json` with an array of arrays whose
/// first row names the columns; `CommonCrawl` answers with one JSON object
/// per line.
fn cdx_page(
    context: &SourceContext,
    api: &str,
    url: &str,
    json_lines: bool,
) -> Option<(HashSet<String>, bool)> {
    let body = fetch_text(context, api, context.get(url))?;

    let urls: Vec<String> = if json_lines {
        parse_ndjson::<CdxRecord>(&body)
            .into_iter()
            .map(|record| record.url)
            .collect()
    } else {
        serde_json::from_str::<Vec<Vec<String>>>(&body)
            .ok()?
            .into_iter()
            .skip(1)
            .filter_map(|row| row.into_iter().next())
            .collect()
    };

    let has_more = !urls.is_empty();
    let found = urls.iter().filter_map(|url| host_of(url)).collect();
    Some((found, has_more))
}

/// URLs the Internet Archive has seen under the target.
#[must_use]
pub fn wayback(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Wayback Machine";
    context.announce(API);
    let context = &archive(context);

    let url = format!(
        "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json\
         &collapse=urlkey&limit={WAYBACK_MAX_ROWS}&url={target}"
    );
    cdx_page(context, API, &url, false).map(|(found, _)| found)
}

/// Newest `CommonCrawl` indexes queried; older ones add little and cost a lot.
const COMMONCRAWL_INDEXES: usize = 3;

/// URLs `CommonCrawl` has seen under the target.
#[must_use]
pub fn commoncrawl(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "CommonCrawl";
    context.announce(API);
    let context = &archive(context);

    let indexes = fetch_json::<Vec<CommonCrawlIndex>>(
        context,
        API,
        context.get("https://index.commoncrawl.org/collinfo.json"),
    )?;

    // One index at a time: the service answers 503 as soon as two requests
    // from the same client overlap. The archive budget bounds the walk.
    let mut subdomains = HashSet::new();
    for api_url in indexes
        .iter()
        .map(|index| index.cdx_api.as_str())
        .filter(|api| !api.is_empty())
        .take(COMMONCRAWL_INDEXES)
    {
        subdomains.extend(commoncrawl_index(context, api_url, target));
    }
    Some(subdomains)
}

/// Walks one `CommonCrawl` index for the hostnames it has seen under `target`.
fn commoncrawl_index(context: &SourceContext, api_url: &str, target: &str) -> HashSet<String> {
    const API: &str = "CommonCrawl";

    // The index reports how many pages the query spans; asking for one
    // beyond that is an error response, not an empty page.
    let pages = fetch_json::<CommonCrawlPages>(
        context,
        API,
        context.get(&format!(
            "{api_url}?output=json&url=*.{target}&showNumPages=true"
        )),
    )
    .map_or(1, |count| count.pages.max(1));

    paginate(pages, |page| {
        let url = format!(
            "{api_url}?output=json&fl=url&page={}&url=*.{target}",
            page - 1
        );
        cdx_page(context, API, &url, true)
    })
    .unwrap_or_default()
}

/// Certificate transparency logs exposed by Facebook, walked with its cursor.
#[must_use]
pub fn facebook(context: &SourceContext, target: &str, token: &str) -> Option<HashSet<String>> {
    const API: &str = "Facebook";
    context.announce(API);

    let mut url = format!(
        "https://graph.facebook.com/certificates?query={target}&fields=domains&limit=1000&access_token={token}"
    );
    paginate(MAX_PAGES, |_| {
        let response = fetch_json::<FacebookResponse>(context, API, context.get(&url))?;
        let has_more = !response.paging.next.is_empty();
        url.clone_from(&response.paging.next);
        Some((response.into_subdomains(), has_more))
    })
}

/// `VirusTotal`'s domain report.
#[must_use]
pub fn virustotal(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Virustotal API using apikey";
    context.announce(API);

    let request = context.get(&format!(
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={target}"
    ));
    fetch::<NamedHostList>(context, API, request)
}

/// `SecurityTrails`, which answers with labels relative to the target.
#[must_use]
pub fn securitytrails(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    const API: &str = "SecurityTrails";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.securitytrails.com/v1/domain/{target}/subdomains?apikey={api_key}"
    ));
    fetch_json::<RelativeSubdomains>(context, API, request)
        .map(|response| response.into_subdomains(target))
}

/// C99's subdomain finder.
#[must_use]
pub fn c99(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "C99";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.c99.nl/subdomainfinder?key={api_key}&domain={target}&json"
    ));
    fetch::<C99Response>(context, API, request)
}

/// `FullHunt`'s attack surface index.
#[must_use]
pub fn fullhunt(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "FullHunt";
    context.announce(API);

    let request = context
        .get(&format!(
            "https://fullhunt.io/api/v1/domain/{target}/subdomains"
        ))
        .header("X-API-KEY", api_key);
    fetch::<NamedHostList>(context, API, request)
}

/// The two `BufferOver` deployments, which differ in URL and authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferoverTier {
    Free,
    Paid,
}

impl BufferoverTier {
    const fn api(self) -> &'static str {
        match self {
            Self::Free => "Bufferover Free",
            Self::Paid => "Bufferover Paid",
        }
    }

    fn url(self, target: &str) -> String {
        match self {
            Self::Free => format!("https://tls.bufferover.run/dns?q={target}"),
            Self::Paid => {
                format!("https://bufferover-run-tls.p.rapidapi.com/ipv4/dns?q={target}")
            }
        }
    }
}

/// Passive DNS data from `BufferOver`.
#[must_use]
pub fn bufferover(
    context: &SourceContext,
    target: &str,
    tier: BufferoverTier,
    api_key: &str,
) -> Option<HashSet<String>> {
    let api = tier.api();
    context.announce(api);

    let mut request = context.get(&tier.url(target)).header("x-api-key", api_key);
    if tier == BufferoverTier::Paid {
        request = request.header("x-rapidapi-host", "bufferover-run-tls.p.rapidapi.com");
    }
    fetch::<BufferoverResponse>(context, api, request)
}

/// Shodan's DNS view of a domain, which answers with bare labels.
#[must_use]
pub fn shodan(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Shodan";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let request = context.get(&format!(
            "https://api.shodan.io/dns/domain/{target}?key={api_key}&page={page}"
        ));
        let response = fetch_json::<RelativeSubdomains>(context, API, request)?;
        let has_more = !response.subdomains.is_empty();
        Some((response.into_subdomains(target), has_more))
    })
}

/// `ProjectDiscovery`'s Chaos dataset, which answers with bare labels.
#[must_use]
pub fn chaos(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Chaos";
    context.announce(API);

    let request = context
        .get(&format!(
            "https://dns.projectdiscovery.io/dns/{target}/subdomains"
        ))
        .header(AUTHORIZATION, api_key);
    fetch_json::<RelativeSubdomains>(context, API, request)
        .map(|response| response.into_subdomains(target))
}

/// `AlienVault` OTX passive DNS.
#[must_use]
pub fn alienvault(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "AlienVault";
    context.announce(API);

    let request = context
        .get(&format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        ))
        .header("X-OTX-API-KEY", api_key);
    fetch::<AlienVaultResponse>(context, API, request)
}

/// `LeakIX`'s subdomain index.
#[must_use]
pub fn leakix(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "LeakIX";
    context.announce(API);

    let request = context
        .get(&format!("https://leakix.net/api/subdomains/{target}"))
        .header(ACCEPT, "application/json")
        .header("api-key", api_key);
    fetch::<Vec<LeakixRecord>>(context, API, request)
}

/// `BeVigil`'s OSINT index.
#[must_use]
pub fn bevigil(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "BeVigil";
    context.announce(API);

    let request = context
        .get(&format!(
            "https://osint.bevigil.com/api/{target}/subdomains/"
        ))
        .header("X-Access-Token", api_key);
    fetch::<NamedHostList>(context, API, request)
}

/// `BinaryEdge`'s subdomain dataset.
#[must_use]
pub fn binaryedge(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "BinaryEdge";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let request = context
            .get(&format!(
                "https://api.binaryedge.io/v2/query/domains/subdomain/{target}?page={page}"
            ))
            .header("X-KEY", api_key);
        page_of::<BinaryEdgeResponse>(context, API, request, page)
    })
}

/// Deepinfo's subdomain finder.
#[must_use]
pub fn deepinfo(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Deepinfo";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let request = context
            .get(&format!(
                "https://api.deepinfo.com/v1/discovery/subdomain-finder?domain={target}&page={page}"
            ))
            .header("apikey", api_key)
            .header(ACCEPT, "application/json");
        page_of::<DeepinfoResponse>(context, API, request, page)
    })
}

const DNSDB_RECORD_TYPES: [&str; 4] = ["A", "AAAA", "CNAME", "NS"];

/// Farsight `DNSDB`, queried once per record type.
#[must_use]
pub fn dnsdb(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "DNSDB";
    context.announce(API);

    let mut subdomains = HashSet::new();
    let mut answered = false;

    for record_type in DNSDB_RECORD_TYPES {
        let request = context
            .get(&format!(
                "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{target}/{record_type}?limit=0"
            ))
            .header("X-API-Key", api_key)
            .header(ACCEPT, "application/x-ndjson");

        let Some(body) = fetch_text(context, API, request) else {
            continue;
        };
        answered = true;
        subdomains.extend(
            parse_ndjson::<DnsdbLine>(&body)
                .into_iter()
                .map(|line| line.obj.rrname.trim_end_matches('.').to_owned())
                .filter(|host| !host.is_empty()),
        );
    }

    answered.then_some(subdomains)
}

/// `DNSRepo`'s passive DNS index.
#[must_use]
pub fn dnsrepo(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "DNSRepo";
    context.announce(API);

    let request = context.get(&format!(
        "https://dnsrepo.noc.org/api/?apikey={api_key}&search={target}&limit=5000"
    ));
    fetch::<Vec<DnsRepoRecord>>(context, API, request)
}

/// Emails requested per Hunter page.
const HUNTER_PAGE_SIZE: usize = 100;

/// Hunter.io's domain search, which names the hosts an address was found on.
#[must_use]
pub fn hunter(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Hunter";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let offset = (page - 1) * HUNTER_PAGE_SIZE;
        let request = context.get(&format!(
            "https://api.hunter.io/v2/domain-search?domain={target}&api_key={api_key}\
             &limit={HUNTER_PAGE_SIZE}&offset={offset}"
        ));
        let response = fetch_json::<HunterResponse>(context, API, request)?;
        let has_more = response.len() >= HUNTER_PAGE_SIZE;
        Some((response.into_subdomains(), has_more))
    })
}

/// Items requested per Netlas page.
const NETLAS_PAGE_SIZE: usize = 100;

/// Netlas' domain index.
#[must_use]
pub fn netlas(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Netlas";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let start = (page - 1) * NETLAS_PAGE_SIZE;
        let request = context
            .get(&format!(
                "https://app.netlas.io/api/domains/?q=*.{target}&start={start}"
            ))
            .header("X-API-Key", api_key)
            .header(ACCEPT, "application/json");
        let response = fetch_json::<NetlasResponse>(context, API, request)?;
        let has_more = response.items.len() >= NETLAS_PAGE_SIZE;
        Some((response.into_subdomains(), has_more))
    })
}

/// ONYPHE's domain summary.
#[must_use]
pub fn onyphe(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "ONYPHE";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let request = context
            .get(&format!(
                "https://www.onyphe.io/api/v2/summary/domain/{target}?page={page}"
            ))
            .header(AUTHORIZATION, format!("apikey {api_key}"));
        page_of::<OnypheResponse>(context, API, request, page)
    })
}

/// `SOCRadar`'s threat analysis endpoint.
#[must_use]
pub fn socradar(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "SOCRadar";
    context.announce(API);

    let request = context.get(&format!(
        "https://platform.socradar.com/api/threat/analysis?key={api_key}&entity={target}"
    ));
    fetch::<SocRadarResponse>(context, API, request)
}

/// `ThreatBook`'s subdomain listing.
#[must_use]
pub fn threatbook(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "ThreatBook";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.threatbook.cn/v3/domain/sub_domains?apikey={api_key}&resource={target}"
    ));
    fetch::<ThreatBookResponse>(context, API, request)
}

/// `WhoisXMLAPI`'s subdomain index.
#[must_use]
pub fn whoisxmlapi(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    const API: &str = "WhoisXMLAPI";
    context.announce(API);

    let request = context.get(&format!(
        "https://subdomains.whoisxmlapi.com/api/v1?apiKey={api_key}&domainName={target}"
    ));
    fetch::<WhoisXmlResponse>(context, API, request)
}

/// `ZETAlytics`' zone data.
#[must_use]
pub fn zetalytics(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "ZETAlytics";
    context.announce(API);

    let request = context.get(&format!(
        "https://zonecruncher.com/api/v1/subdomains?q={target}&token={api_key}"
    ));
    fetch::<ZetalyticsResponse>(context, API, request)
}

/// `ZoomEye`'s domain search.
#[must_use]
pub fn zoomeye(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "ZoomEye";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let request = context
            .get(&format!(
                "https://api.zoomeye.org/domain/search?q={target}&type=1&page={page}"
            ))
            .header("API-KEY", api_key);
        page_of::<ZoomEyeResponse>(context, API, request, page)
    })
}

/// `BuiltWith`'s technology profile, which lists the paths it crawled.
#[must_use]
pub fn builtwith(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "BuiltWith";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.builtwith.com/v21/api.json?KEY={api_key}&LOOKUP={target}"
    ));
    fetch::<BuiltWithResponse>(context, API, request)
}

/// Subdomains previously seen by Sublist3r.
#[must_use]
pub fn sublist3r(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Sublist3r";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.sublist3r.com/search.php?domain={target}"
    ));
    fetch::<HashSet<String>>(context, API, request)
}

/// Passive DNS data from Threatminer.
#[must_use]
pub fn threatminer(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Threatminer";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.threatminer.org/v2/domain.php?q={target}&api=True&rt=5"
    ));
    fetch::<NamedHostList>(context, API, request)
}

/// `AnubisDB`'s subdomain index.
#[must_use]
pub fn anubisdb(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "AnubisDB";
    context.announce(API);

    let request = context.get(&format!("https://jldc.me/anubis/subdomains/{target}"));
    fetch::<HashSet<String>>(context, API, request)
}

/// The UK Web Archive's CDX index.
#[must_use]
pub fn uk_web_archive(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "UK Web Archive";
    context.announce(API);
    let context = &archive(context);

    let url = format!(
        "https://www.webarchive.org.uk/wayback/archive/cdx?matchType=domain&output=json\
         &limit={WAYBACK_MAX_ROWS}&url={target}"
    );
    cdx_page(context, API, &url, false).map(|(found, _)| found)
}

/// Arquivo.pt's CDX index.
///
/// Its older full text endpoint now answers 400 with a pointer to this one.
#[must_use]
pub fn arquivo(context: &SourceContext, target: &str) -> Option<HashSet<String>> {
    const API: &str = "Arquivo";
    context.announce(API);
    let context = &archive(context);

    let url = format!(
        "https://arquivo.pt/wayback/cdx?matchType=domain&output=json\
         &limit={WAYBACK_MAX_ROWS}&url={target}"
    );
    cdx_page(context, API, &url, true).map(|(found, _)| found)
}

/// `PassiveTotal`, which authenticates with an `email:key` pair.
#[must_use]
pub fn passivetotal(
    context: &SourceContext,
    target: &str,
    credentials: &str,
) -> Option<HashSet<String>> {
    const API: &str = "PassiveTotal";
    context.announce(API);

    let (user, secret) = split_credentials(credentials)?;
    let mut cursor = String::new();

    paginate(MAX_PAGES, |_| {
        let mut url = format!("https://api.riskiq.net/pt/v2/enrichment/subdomains?query={target}");
        if !cursor.is_empty() {
            url.push_str("&lastId=");
            url.push_str(&cursor);
        }

        let response = fetch_json::<PassiveTotalResponse>(
            context,
            API,
            context.get(&url).basic_auth(user, Some(secret)),
        )?;
        if !response.success {
            return None;
        }
        cursor = response.last_id.clone();
        let has_more = !cursor.is_empty();
        Some((response.into_subdomains(target), has_more))
    })
}

/// CIRCL passive DNS, which authenticates with a `user:password` pair.
#[must_use]
pub fn circl(context: &SourceContext, target: &str, credentials: &str) -> Option<HashSet<String>> {
    const API: &str = "CIRCL";
    context.announce(API);

    let (user, secret) = split_credentials(credentials)?;
    let request = context
        .get(&format!("https://www.circl.lu/pdns/query/{target}"))
        .basic_auth(user, Some(secret));

    let body = fetch_text(context, API, request)?;
    Some(
        parse_ndjson::<CirclLine>(&body)
            .into_iter()
            .map(|line| line.rrname.trim_end_matches('.').to_owned())
            .filter(|host| !host.is_empty())
            .collect(),
    )
}

/// Censys certificate search, authenticated with an `id:secret` pair.
#[must_use]
pub fn censys(context: &SourceContext, target: &str, credentials: &str) -> Option<HashSet<String>> {
    const API: &str = "Censys";
    context.announce(API);

    let (user, secret) = split_credentials(credentials)?;
    paginate(MAX_PAGES, |page| {
        let request = context
            .post("https://search.censys.io/api/v1/search/certificates")
            .basic_auth(user, Some(secret))
            .json(&serde_json::json!({
                "query": format!("parsed.names: {target}"),
                "page": page,
                "fields": ["parsed.names"],
            }));
        let response = fetch_json::<CensysResponse>(context, API, request)?;
        let has_more = !response.results.is_empty();
        Some((response.into_subdomains(), has_more))
    })
}

/// `DigiCert`'s CertCentral subdomain scan.
#[must_use]
pub fn certcentral(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    const API: &str = "CertCentral";
    context.announce(API);

    let request = context
        .post("https://daas.digicert.com/apicontroller/v1/scan/getSubdomains")
        .header("X-DC-DEVKEY", api_key)
        .json(&serde_json::json!({ "domain": target }));
    fetch::<CertCentralResponse>(context, API, request)
}

/// Quake's service search.
#[must_use]
pub fn quake(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Quake";
    context.announce(API);

    paginate(MAX_PAGES, |page| {
        let request = context
            .post("https://quake.360.cn/api/v3/search/quake_service")
            .header("X-QuakeToken", api_key)
            .json(&serde_json::json!({
                "query": format!("domain:{target}"),
                "start": (page - 1) * QUAKE_PAGE_SIZE,
                "size": QUAKE_PAGE_SIZE,
            }));
        page_of::<QuakeResponse>(context, API, request, page)
    })
}

/// Records requested per Quake page.
const QUAKE_PAGE_SIZE: usize = 100;

/// FOFA's asset search, authenticated with an `email:key` pair.
#[must_use]
pub fn fofa(context: &SourceContext, target: &str, credentials: &str) -> Option<HashSet<String>> {
    const API: &str = "FOFA";
    context.announce(API);

    let (email, key) = split_credentials(credentials)?;
    let query = base64_standard(&format!("domain=\"{target}\""));

    paginate(MAX_PAGES, |page| {
        let request = context.get(&format!(
            "https://fofa.info/api/v1/search/all?email={email}&key={key}\
             &qbase64={query}&fields=host&size={FOFA_PAGE_SIZE}&page={page}"
        ));
        let response = fetch_json::<FofaResponse>(context, API, request)?;
        let has_more = response.size >= FOFA_PAGE_SIZE;
        Some((response.into_subdomains(), has_more))
    })
}

/// Rows requested per FOFA page.
const FOFA_PAGE_SIZE: usize = 1000;

/// Spamhaus passive DNS.
#[must_use]
pub fn spamhaus(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Spamhaus";
    context.announce(API);

    let request = context
        .get(&format!(
            "https://api-pdns.spamhaustech.com/v2/_search/rrset/{target}/ANY"
        ))
        .header(AUTHORIZATION, format!("Bearer {api_key}"))
        .header(ACCEPT, "application/json");
    fetch::<SpamhausResponse>(context, API, request)
}

/// Ahrefs' crawled page index.
#[must_use]
pub fn ahrefs(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Ahrefs";
    context.announce(API);

    let request = context.get(&format!(
        "https://apiv2.ahrefs.com/?token={api_key}&target={target}&mode=domain\
         &output=json&from=pages&limit=1000"
    ));
    let response = fetch_json::<AhrefsResponse>(context, API, request)?;
    Some(
        response
            .pages
            .into_iter()
            .filter_map(|page| host_of(&page.url))
            .collect(),
    )
}

/// `DNSlytics` reverse IP lookup.
#[must_use]
pub fn dnslytics(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "DNSlytics";
    context.announce(API);

    let request = context.get(&format!(
        "https://api.dnslytics.net/v1/reverseip/{target}?apikey={api_key}"
    ));
    fetch::<DnslyticsResponse>(context, API, request)
}

/// Pulsedive's indicator search.
#[must_use]
pub fn pulsedive(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Pulsedive";
    context.announce(API);

    let request = context.get(&format!(
        "https://pulsedive.com/api/explore.php?q=ioc%3D{target}&limit=1000&key={api_key}"
    ));
    fetch::<PulsediveResponse>(context, API, request)
}

/// `IntelX` phonebook search.
#[must_use]
pub fn intelx(context: &SourceContext, target: &str, credentials: &str) -> Option<HashSet<String>> {
    const API: &str = "IntelX";
    context.announce(API);

    // The key may be given on its own or as `host:key` for a private instance.
    let (host, key) = credentials
        .rsplit_once(':')
        .map_or(("2.intelx.io", credentials), |(host, key)| (host, key));

    let request = context
        .post(&format!("https://{host}/phonebook/search"))
        .header("x-key", key)
        .json(&serde_json::json!({
            "term": target,
            "maxresults": 10_000,
            "media": 0,
            "target": 1,
            "timeout": 20,
        }));
    fetch::<IntelxResponse>(context, API, request)
}

/// Detectify's asset inventory.
#[must_use]
pub fn detectify(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "Detectify";
    context.announce(API);

    let assets = fetch_json::<Vec<DetectifyAsset>>(
        context,
        API,
        context
            .get("https://api.detectify.com/rest/v2/assets/")
            .header("X-Detectify-Key", api_key),
    )?;

    let asset = assets
        .into_iter()
        .find(|asset| asset.name.eq_ignore_ascii_case(target))?;
    if asset.token.is_empty() {
        return None;
    }

    let request = context
        .get(&format!(
            "https://api.detectify.com/rest/v2/assets/{}/subdomains/",
            asset.token
        ))
        .header("X-Detectify-Key", api_key);
    fetch_json::<Vec<DetectifyAsset>>(context, API, request).map(|subdomains| {
        subdomains
            .into_iter()
            .map(|entry| entry.name)
            .filter(|host| !host.is_empty())
            .collect()
    })
}

/// `PentestTools`' subdomain scan results.
#[must_use]
pub fn pentesttools(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    const API: &str = "PentestTools";
    context.announce(API);

    let request = context
        .post(&format!("https://pentest-tools.com/api?key={api_key}"))
        .json(&serde_json::json!({
            "op": "start_scan",
            "tool_id": 20,
            "target_name": target,
            "tool_params": { "scan_type": "light" },
        }));
    fetch::<PentestToolsResponse>(context, API, request)
}

/// 360's passive DNS service.
#[must_use]
pub fn passivedns360(
    context: &SourceContext,
    target: &str,
    api_key: &str,
) -> Option<HashSet<String>> {
    const API: &str = "360 PassiveDNS";
    context.announce(API);

    let request = context
        .get(&format!(
            "https://api.passivedns.cn/flint/rrset/*.{target}/"
        ))
        .header("X-AuthToken", api_key)
        .header(ACCEPT, "application/json");
    fetch::<PassiveDns360Response>(context, API, request)
}

/// `PublicWWW`'s source code search, which exports a plain URL list.
#[must_use]
pub fn publicwww(context: &SourceContext, target: &str, api_key: &str) -> Option<HashSet<String>> {
    const API: &str = "PublicWWW";
    context.announce(API);

    let request = context.get(&format!(
        "https://publicwww.com/websites/%22.{target}%22/?export=urls&key={api_key}"
    ));
    let body = fetch_text(context, API, request)?;
    Some(body.lines().filter_map(host_of).collect())
}

/// Splits a `user:secret` credential, reporting nothing when it is malformed.
fn split_credentials(credentials: &str) -> Option<(&str, &str)> {
    let (user, secret) = credentials.split_once(':')?;
    (!user.is_empty() && !secret.is_empty()).then_some((user, secret))
}

/// Encodes `value` as standard base64, which FOFA wants for its query.
fn base64_standard(value: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bufferover_tiers_have_distinct_names_and_endpoints() {
        assert_eq!(BufferoverTier::Free.api(), "Bufferover Free");
        assert_eq!(BufferoverTier::Paid.api(), "Bufferover Paid");
        assert!(BufferoverTier::Free
            .url("example.com")
            .starts_with("https://tls.bufferover.run/"));
        assert!(BufferoverTier::Paid
            .url("example.com")
            .contains("rapidapi.com"));
    }

    #[test]
    fn host_of_strips_everything_around_the_hostname() {
        assert_eq!(
            host_of("https://A.Example.com/x?y=1").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(
            host_of("http://user:pass@a.example.com:8080/x").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(host_of("a.example.com").as_deref(), Some("a.example.com"));
        assert_eq!(host_of("https:///x"), None);
        assert_eq!(host_of(""), None);
    }

    #[test]
    fn base64_matches_the_reference_encoding() {
        // FOFA's qbase64 must be standard base64; a wrong pad breaks the query.
        assert_eq!(
            base64_standard("domain=\"owasp.org\""),
            "ZG9tYWluPSJvd2FzcC5vcmci"
        );
        assert_eq!(base64_standard(""), "");
        assert_eq!(base64_standard("a"), "YQ==");
        assert_eq!(base64_standard("ab"), "YWI=");
        assert_eq!(base64_standard("abc"), "YWJj");
    }

    #[test]
    fn credentials_split_only_on_a_well_formed_pair() {
        assert_eq!(split_credentials("user:secret"), Some(("user", "secret")));
        assert_eq!(split_credentials("a:b:c"), Some(("a", "b:c")));
        assert!(split_credentials("nocolon").is_none());
        assert!(split_credentials(":secret").is_none());
        assert!(split_credentials("user:").is_none());
    }

    use crate::config::Sources;

    /// A context whose discovery budget has already run out.
    fn spent_context() -> SourceContext {
        let mut context = SourceContext::new(&Config::default());
        context.deadline = Some(Instant::now());
        context
    }

    #[test]
    fn a_spent_budget_refuses_the_request_without_reaching_the_network() {
        // 192.0.2.1 is TEST-NET-1 and never answers, so a request that really
        // went out would sit here until the timeout rather than return at once.
        let context = spent_context();
        let started = Instant::now();
        let response = send(
            &context,
            "test",
            context.get("http://192.0.2.1/never-answers"),
        );
        assert!(response.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_spent_budget_ends_a_page_walk_but_keeps_what_it_collected() {
        // The budget is enforced inside send, so a source in the middle of a
        // walk sees a failed page; paginate must treat that as the end of the
        // road rather than throwing away the pages that already arrived.
        let found = paginate(10, |page| match page {
            1 => Some((HashSet::from(["a.example.com".to_owned()]), true)),
            2 => Some((HashSet::from(["b.example.com".to_owned()]), true)),
            _ => None,
        })
        .expect("the first page succeeded");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn an_archive_is_held_to_a_tighter_clock_than_the_run() {
        let context = SourceContext::new(&Config::default());
        let archive = archive(&context);

        let run_left = context.remaining().expect("the run is bounded");
        let archive_left = archive.remaining().expect("the archive is bounded");
        assert!(archive_left < run_left);
        assert!(
            archive_left <= Duration::from_secs(Sources::default().archive_budget),
            "an archive must not get more than its own budget"
        );
    }

    #[test]
    fn a_tighter_clock_never_extends_the_one_it_came_from() {
        let config = Config {
            sources: Sources {
                budget: 5,
                ..Sources::default()
            },
            ..Config::default()
        };
        let context = SourceContext::new(&config);
        let widened = context.with_budget(Duration::from_secs(600));
        assert!(widened.remaining().expect("still bounded") <= Duration::from_secs(5));
    }

    #[test]
    fn a_zero_archive_budget_holds_the_archives_to_the_run() {
        let config = Config {
            sources: Sources {
                budget: 90,
                archive_budget: 0,
                ..Sources::default()
            },
            ..Config::default()
        };
        let context = SourceContext::new(&config);
        let left = archive(&context).remaining().expect("still bounded");
        assert!(left > Duration::from_secs(80), "got {left:?}");
    }

    #[test]
    fn an_unlimited_run_leaves_even_the_archives_unlimited() {
        // This is what makes `--source-budget 0` mean what it says: a user who
        // asks for no limit gets the archives walked to exhaustion too.
        let config = Config {
            sources: Sources {
                budget: 0,
                ..Sources::default()
            },
            ..Config::default()
        };
        let context = SourceContext::new(&config);
        assert!(archive(&context).remaining().is_none());
    }

    #[test]
    fn an_unbounded_budget_leaves_requests_uncapped() {
        let config = Config {
            sources: Sources {
                budget: 0,
                ..Sources::default()
            },
            ..Config::default()
        };
        assert!(SourceContext::new(&config).remaining().is_none());
    }

    #[test]
    fn the_request_timeout_never_exceeds_the_hard_ceiling() {
        let config = Config {
            sources: Sources {
                timeout: 86_400,
                ..Sources::default()
            },
            ..Config::default()
        };
        assert_eq!(SourceContext::new(&config).request_timeout, REQUEST_TIMEOUT);
    }

    #[test]
    fn a_prose_answer_from_hackertarget_is_not_an_empty_result() {
        // Its real answer is CSV; anything without a comma is an error message
        // served with a 200, which must not read as "no subdomains exist".
        assert!(!"API count exceeded - Increase Quota with Membership".contains(','));
        assert!("mail.google.com,142.250.1.18".contains(','));
    }

    #[test]
    fn ndjson_skips_unparseable_lines() {
        let body = "{\"url\":\"https://a.example.com/\"}\nnot json\n\n{\"url\":\"https://b.example.com/\"}";
        let records: Vec<CdxRecord> = parse_ndjson(body);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].url, "https://b.example.com/");
    }

    #[test]
    fn paginate_stops_on_an_empty_page() {
        let mut calls = 0;
        let found = paginate(10, |page| {
            calls += 1;
            let hosts = if page < 3 {
                HashSet::from([format!("host{page}.example.com")])
            } else {
                HashSet::new()
            };
            Some((hosts, true))
        })
        .expect("first page succeeded");

        assert_eq!(calls, 3);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn paginate_stops_when_the_source_says_there_is_no_more() {
        let mut calls = 0;
        let found = paginate(10, |page| {
            calls += 1;
            Some((HashSet::from([format!("host{page}.example.com")]), false))
        })
        .expect("first page succeeded");

        assert_eq!(calls, 1);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn paginate_reports_nothing_when_the_first_page_fails() {
        assert!(paginate(10, |_| None).is_none());
    }

    #[test]
    fn paginate_keeps_what_it_had_when_a_later_page_fails() {
        let found = paginate(10, |page| {
            (page == 1).then(|| (HashSet::from(["a.example.com".to_owned()]), true))
        })
        .expect("first page succeeded");

        assert_eq!(found.len(), 1);
    }

    #[test]
    fn paginate_stops_when_a_source_ignores_the_page_and_repeats() {
        // A broken source returning the same page forever must not loop.
        let mut calls = 0;
        let found = paginate(500, |_| {
            calls += 1;
            Some((HashSet::from(["a.example.com".to_owned()]), true))
        })
        .expect("first page succeeded");

        assert_eq!(calls, 2, "a repeated page ends the walk");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn paginate_keeps_going_when_pages_differ_but_share_hostnames() {
        // Cursor sources (urlscan, facebook) return distinct pages that can map
        // to already-seen hostnames; the walk must not stop on the overlap.
        let pages = [
            HashSet::from(["a.example.com".to_owned(), "b.example.com".to_owned()]),
            HashSet::from(["a.example.com".to_owned(), "c.example.com".to_owned()]),
            HashSet::from(["a.example.com".to_owned(), "d.example.com".to_owned()]),
        ];
        let mut calls = 0;
        let found = paginate(10, |page| {
            calls += 1;
            pages
                .get(page - 1)
                .map(|set| (set.clone(), page < pages.len()))
        })
        .expect("first page succeeded");

        assert_eq!(calls, 3);
        assert_eq!(found.len(), 4, "every distinct hostname is collected");
    }

    #[test]
    fn paginate_honours_the_hard_page_cap() {
        let mut calls = 0;
        paginate(usize::MAX, |page| {
            calls += 1;
            Some((HashSet::from([format!("h{page}.example.com")]), true))
        });
        assert_eq!(calls, MAX_PAGES);
    }
}
