[![Follow on Twitter](https://img.shields.io/twitter/follow/edu4rdshl.svg?logo=twitter)](https://twitter.com/edu4rdshl)
[![Follow on Twitter](https://img.shields.io/twitter/follow/FindomainApp.svg?logo=twitter)](https://twitter.com/FindomainApp)

[![Travis CI Status](https://travis-ci.org/edu4rdshl/findomain.svg?branch=master)](https://travis-ci.org/edu4rdshl/findomain)
[![Appveyor CI Status](https://ci.appveyor.com/api/projects/status/github/edu4rdshl/findomain?branch=master&svg=true)](https://ci.appveyor.com/project/edu4rdshl/findomain)
[![Build status](https://github.com/Edu4rdSHL/findomain/workflows/Github%20Actions/badge.svg)](https://github.com/Edu4rdSHL/findomain/actions)

# Findomain

![Findomain](images/findomain.png)

The complete solution for domain recognition. Supports screenshotting, port scanning, importing data from other tools, subdomain monitoring, and more. Be alerted on your findings through services such as Discord, Slack, and Telegram. Multiple API Keys for sources and much more.

## Chat with us

[![Chat on Discord](https://img.shields.io/discord/697050821057183777.svg?logo=discord)](https://discord.gg/y5JaRbX)

# What Can Findomain Do?

The following table demonstrates features that are available in the premium version (but not the free version) of Findomain. It aims to gives you an idea of why you should use Findomain and what it can do for you. The domain used for the test was aol.com. The details of the [BlackArch](https://blackarch.org) virtual machine used in the test are outlined below:

```
Host: KVM/QEMU (Standard PC (i440FX + PIIX, 1996) pc-i440fx-3.1)
Kernel: 5.2.6-arch1-1-ARCH
CPU: Intel (Skylake, IBRS) (4) @ 2.904GHz
Memory: 139MiB / 3943MiB
```
The tool used to calculate the time was Linux's `time` command.

|Enumeration Tool|Search Time|Total Subdomains Found|CPU Usage|RAM Usage|
|---|---|---|---|---|
|Findomain|real 0m5.515s|84110|Very Low|Very Low|

**Summary:** 84110 subdomains in 5.5 seconds.

# Features

* Subdomains monitoring: put data to Discord, Slack or Telegram webhooks.  See [Subdomains Monitoring](README.md#subdomains-monitoring) for more information.
* Multi-thread support for API querying, it makes that the maximun time that Findomain will take to search subdomains for any target is 15 seconds (in case of API's timeout).
* Parallel support for subdomains resolution, in good network conditions can resolv about 3.5k of subdomains per minute.
* DNS over TLS support.
* Specific IPv4 or IPv6 query support.
* Discover subdomains without brute-force, it tool uses Certificate Transparency Logs and APIs.
* Discover only resolved subdomains.
* Discover subdomains IP for data analysis.
* Read target from user argument (-t) or file (-f).
* Write to one unique output file specified by the user all or only resolved subdomains.
* Write results to automatically named TXT output file(s).
* Hability to query directly the Findomain database created with [Subdomains Monitoring](docs/INSTALLATION.md#subdomains-monitoring) for previous discovered subdomains.
* Hability to import and work data discovered by other tools. See [Working with other tools](README.md#working-with-other-tools).
* Quiet mode to run it silently.
* Cross platform support: Any platform, it's written in Rust and Rust is multiplatform. See [the documentation](docs/INSTALLATION.md#build-for-32-bits-or-another-platform) for instructions.
* Multiple API support.
* Possibility to use as subdomain resolver.
* Subdomain wildcard detection for accurate results. 
* Support for subdomain discover using bruteforce method.
* Support for configuration file in TOML, JSON, INI or YAML format.
* Custom DNS IP addresses for fast subdomains resolving (more than 60 per second by default, adjustable using the `--threads` option.

# Findomain in Depth

See [Subdomains Enumeration: what is, how to do it, monitoring automation using webhooks and centralizing your findings](https://medium.com/@edu4rdshl/subdomains-enumeration-what-is-how-to-do-it-monitoring-automation-using-webhooks-and-5e0a0c6d9127) for a detailed guide, including real-world examples, of how to get the most out of the tool.

# How Does It Work?
Findomain uses Certificate Transparency logs and well-tested APIs to find subdomains. This method makes the tool much faster and more reliable than alternatives. If you want to know more about Certificate Transparency logs, read https://www.certificate-transparency.org/

Findomain queries 54 passive sources. Every one of them parses a documented
data format, JSON in almost every case: there is no HTML scraping anywhere, so a
redesigned web page can never quietly turn results into noise. Paginated APIs are
walked to the last page.

- [360 PassiveDNS](https://passivedns.cn) `**`
- [Ahrefs](https://ahrefs.com/api) `**`
- [AlienVault OTX](https://otx.alienvault.com) `**`
- [AnubisDB](https://jldc.me/anubis/)
- [Arquivo.pt](https://arquivo.pt/api)
- [BeVigil](https://bevigil.com/osint-api) `**`
- [BinaryEdge](https://binaryedge.io) `**`
- [BufferOver (free)](https://tls.bufferover.run) `**`
- [BufferOver (paid)](https://rapidapi.com/bufferover/api/bufferover-run-tls) `**`
- [BuiltWith](https://api.builtwith.com) `**`
- [C99](https://api.c99.nl) `**`
- [Censys](https://search.censys.io) `**`
- [CertSpotter](https://sslmate.com/certspotter/) `*`
- [Chaos](https://chaos.projectdiscovery.io) `**`
- [CIRCL PassiveDNS](https://www.circl.lu/services/passive-dns/) `**`
- [CommonCrawl](https://commoncrawl.org)
- [Crt.sh (database mirror)](https://crt.sh)
- [Deepinfo](https://deepinfo.com) `**`
- [Detectify](https://detectify.com) `**`
- [DigiCert CertCentral](https://daas.digicert.com) `**`
- [DNSlytics](https://dnslytics.com) `**`
- [DNSRepo](https://dnsrepo.noc.org) `**`
- [Facebook CT](https://developers.facebook.com/docs/certificate-transparency) `**`
- [Farsight DNSDB](https://www.domaintools.com/products/farsight-dnsdb/) `**`
- [FOFA](https://fofa.info) `**`
- [FullHunt](https://fullhunt.io) `**`
- [HackerTarget](https://hackertarget.com) `*`
- [Hunter.io](https://hunter.io/api-documentation) `**`
- [IntelX](https://intelx.io) `**`
- [LeakIX](https://leakix.net) `**`
- [Maltiverse](https://maltiverse.com)
- [Mnemonic PassiveDNS](https://docs.mnemonic.no/display/public/API/PassiveDNS+Overview)
- [Netlas](https://netlas.io) `**`
- [ONYPHE](https://www.onyphe.io) `**`
- [PassiveTotal](https://community.riskiq.com) `**`
- [Pentest-Tools](https://pentest-tools.com) `**`
- [PublicWWW](https://publicwww.com) `**`
- [Pulsedive](https://pulsedive.com) `**`
- [Quake](https://quake.360.cn) `**`
- [SecurityTrails](https://docs.securitytrails.com/docs) `**`
- [Shodan](https://www.shodan.io) `**`
- [SOCRadar](https://socradar.io) `**`
- [Spamhaus PassiveDNS](https://www.spamhaus.com) `**`
- [Subdomain Center](https://www.subdomain.center)
- [Sublist3r](https://api.sublist3r.com)
- [ThreatBook](https://threatbook.io) `**`
- [Threatminer](https://www.threatminer.org/api.php)
- [UK Web Archive](https://www.webarchive.org.uk)
- [Urlscan.io](https://urlscan.io/about-api/)
- [VirusTotal](https://www.virustotal.com) `**`
- [Wayback Machine](https://archive.org/help/wayback_api.php)
- [WhoisXMLAPI](https://subdomains.whoisxmlapi.com) `**`
- [ZETAlytics](https://zetalytics.com) `**`
- [ZoomEye](https://www.zoomeye.org) `**`

Any source can be turned off with `--exclude-sources`, for example
`--exclude-sources wayback,commoncrawl`.

**Working with other tools**

Findomain reads the results of any other enumerator through
`--import-subdomains`, which accepts as many files as you care to give it:

```
subfinder -d example.com -silent > subfinder.txt
amass enum -d example.com && amass subs -d example.com -names -show > amass.txt
findomain -t example.com --import-subdomains subfinder.txt amass.txt -r
```

The imported names join the ones Findomain discovers itself, and the whole set
goes through the same resolution, filtering and reporting. Driving those tools
yourself means their own flags, configuration files and API keys apply, which a
wrapper could never express.

**How long the search takes**

Sources are queried in parallel, so the search lasts as long as its slowest
source rather than the sum of all of them. In practice a search settles in
about twenty seconds, and two options bound the cases where it would not:

- `--source-timeout` (default 30) is the number of seconds a single request to
  a source may take.
- `--source-budget` (default 300) is the number of seconds the whole search may
  spend. This is a backstop for a source that hangs, not the thing that decides
  how long a run takes, so a source paging through thousands of real results is
  left to finish. Use `--source-budget 0` to remove the limit entirely.

- `--archive-budget` (default 20) is the number of seconds the archive indexes
  (Wayback, CommonCrawl, UK Web Archive and Arquivo) may spend between them.
  They are the only sources that cannot stop on their own: a CDX index is a bulk
  download of every URL archived under a domain, sliced into storage blocks
  rather than into pages of distinct hostnames, so it keeps costing requests
  long after it has stopped producing new names. Left alone, CommonCrawl spends
  over two minutes on `google.com` to return exactly the hostnames it already
  had after twenty seconds. Raise this if you would rather wait than miss what
  the archives hold on a small domain, use 0 to hold them to `--source-budget`
  like any other source, or `--exclude-sources wayback,commoncrawl` to skip
  them. They are also the slowest sources by a wide margin, so this is the knob
  that decides how long a run takes.

Whenever a limit is reached no new request is made and whatever the source had
already collected is kept, so a cut search returns fewer results, never none.
All three can also be set in `findomain.toml` as `source_timeout`,
`source_budget` and `archive_budget`.

**Notes**

APIs marked with `**`, **require** an access token to work. Search in the [Findomain documentation](docs/INSTALLATION.md#access-tokens-configuration) for help on how to configure and use it.

APIs marked with `*` can *optionally* be used with an access token. Create one if you start experiencing problems with that API. Search in the [Findomain documentation](docs/INSTALLATION.md#access-tokens-configuration) for help on how to configure and use it.

**More APIs?**

If you know other APIs that should be added, comment [here](https://github.com/Edu4rdSHL/findomain/issues/7).

# Installation

We offer ready-to-use binaries for the following platforms (64-bit only):

* [Linux](docs/INSTALLATION.md#installation-in-linux-using-compiled-artifacts)
* [Windows](docs/INSTALLATION.md#installation-windows)
* [MacOS](docs/INSTALLATION.md#installation-macos)
* [Aarch64 (Raspberry Pi)](docs/INSTALLATION.md#installation-aarch64-raspberry-pi)
* [NixOS](docs/INSTALLATION.md#installation-nixos)
* [Docker](docs/INSTALLATION.md#installation-docker)

If you need to run Findomain on another platform, continue reading the documentation.

# Issues and Requests

If you have a problem or a feature request, open an [issue](https://github.com/Edu4rdSHL/findomain/issues).

# Stargazers over Time

[![Stargazers over time](https://starchart.cc/Edu4rdSHL/findomain.svg)](https://starchart.cc/Edu4rdSHL/findomain)

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [See the contributors list](https://github.com/Edu4rdSHL/findomain/graphs/contributors).
