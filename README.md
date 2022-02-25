[![Follow on Twitter](https://img.shields.io/twitter/follow/edu4rdshl.svg?logo=twitter)](https://twitter.com/edu4rdshl)
[![Follow on Twitter](https://img.shields.io/twitter/follow/FindomainApp.svg?logo=twitter)](https://twitter.com/FindomainApp)

[![Travis CI Status](https://travis-ci.org/edu4rdshl/findomain.svg?branch=master)](https://travis-ci.org/edu4rdshl/findomain)
[![Appveyor CI Status](https://ci.appveyor.com/api/projects/status/github/edu4rdshl/findomain?branch=master&svg=true)](https://ci.appveyor.com/project/edu4rdshl/findomain)
[![Build status](https://github.com/Edu4rdSHL/findomain/workflows/Github%20Actions/badge.svg)](https://github.com/Edu4rdSHL/findomain/actions)

# Findomain Monitoring Service

If you don't want to deal with servers and complex configurations for doing recon but also have more features in an integrated solution, Findomain offers [a subdomains monitoring service that provides:](https://findomain.app/#Pricing) **directory fuzzing/ports scan/vulnerabilities discovery (with Nuclei) - and more** that allow you to **monitor your target domains with multiple top tools** (OWASP Amass, Sublist3r, Assetfinder and Subfinder) and send alerts to Discord, Slack, Telegram, Email or Push Notifications (Android/iOS/Smart Watch/Desktop) when new subdomains are found. **The only you need to do is configure a file with your email address (if applicable) or/and webhooks/Telegram chat information and put your domains in another file**, once you have done that you have a full automated subdomains monitoring service that keep you up to date with new subdomains discovered, Host IP, HTTP Status, Screenshots of the HTTP websites, Open Ports, Subdomains CNAME and more. All your data is securely saved in a relational database and you can request a dump of your data whenever you want.

When you finish your payment, you will receive an email with the server credentials and documentation about how to fill the configuration file and other details.

**Note:** Our private version is superior to the public version and you can't achieve the same results using the last one, plus if you use our service you help us to keep the project alive and we will release plus features to this repo every X time.

## Pricing

[**See available plans here.**](https://findomain.app/#Pricing)

# Findomain

![Findomain](images/findomain.png)

The complete solution for domain recognition. Supports screenshoting, port scan, HTTP check, data import from other tools, subdomain monitoring, alerts via Discord, Slack and Telegram, multiple API Keys for sources and much more.

## Chat with us

[![Chat on Discord](https://img.shields.io/discord/697050821057183777.svg?logo=discord)](https://discord.gg/y5JaRbX)

The next table offers you the comparison about what is in Plus version that is not in free version (current repo).

# What Findomain can do?

It table gives you a idea why you should use findomain and what it can do for you. The domain used for the test was aol.com in the following [BlackArch](https://blackarch.org) virtual machine:

```
Host: KVM/QEMU (Standard PC (i440FX + PIIX, 1996) pc-i440fx-3.1)
Kernel: 5.2.6-arch1-1-ARCH
CPU: Intel (Skylake, IBRS) (4) @ 2.904GHz
Memory: 139MiB / 3943MiB
```
The tool used to calculate the time, is the `time` command in Linux.

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
* Hability to import and work data discovered by other tools.
* Quiet mode to run it silently.
* Cross platform support: Any platform, it's written in Rust and Rust is multiplatform. See [the documentation](docs/INSTALLATION.md#build-for-32-bits-or-another-platform) for instructions.
* Multiple API support.
* Possibility to use as subdomain resolver.
* Subdomain wildcard detection for accurate results. 
* Support for subdomain discover using bruteforce method.
* Support for configuration file in TOML, JSON, HJSON, INI or YAML format.
* Custom DNS IP addresses for fast subdomains resolving (more than 60 per second by default, adjustable using the `--threads` option.

# Findomain in depth

See [Subdomains Enumeration: what is, how to do it, monitoring automation using webhooks and centralizing your findings](https://medium.com/@edu4rdshl/subdomains-enumeration-what-is-how-to-do-it-monitoring-automation-using-webhooks-and-5e0a0c6d9127) for a detailed guide including real world examples of how you get the most out of the tool.

# How it works?
It tool doesn't use the common methods for sub(domains) discover, the tool uses Certificate Transparency logs and specific well tested APIs to find subdomains. It method make it tool the most faster and reliable. The tool make use of multiple public available APIs to perform the search. If you want to know more about Certificate Transparency logs, read https://www.certificate-transparency.org/

APIs that we are using at the moment:

- [Certspotter](https://api.certspotter.com/)
- [Crt.sh Database (favorite) or Crt.sh HTTP API](https://crt.sh)
- [Virustotal](https://www.virustotal.com/ui/domains/)
- [Sublist3r](https://api.sublist3r.com/)
- [Facebook](https://developers.facebook.com/docs/certificate-transparency) `**`
- [Spyse (CertDB)](https://certdb.com/apidocs#/Subdomains) `*`
- [Bufferover](http://dns.bufferover.run/)
- [Threatcrowd](https://threatcrowd.org/)
- [Virustotal with apikey](https://www.virustotal.com/) `**`
- [AnubisDB](https://jonlu.ca/anubis/)
- [Urlscan.io](https://urlscan.io/about-api/)
- [SecurityTrails](https://docs.securitytrails.com/docs) `**`
- [Threatminer](https://www.threatminer.org/api.php)
- [C99](https://api.c99.nl/) `**`
- [Archive.org](https://archive.org/)
- [CTSearch](https://ui.ctsearch.entrust.com/ui/ctsearchui)

**Notes**

APIs marked with `**`, **require** an access token to work. Search in the [Findomain documentation](docs/INSTALLATION.md#access-tokens-configuration) how to configure and use it.

APIs marked with `*` can *optionally* be used with an access token, create one if you start experiencing problems with that APIs. Search in the [Findomain documentation](docs/INSTALLATION.md#access-tokens-configuration) how to configure and use it.

**More APIs?**

If you know other APIs that should be added, comment [here](https://github.com/Edu4rdSHL/findomain/issues/7).

# Installation

We offer binarys ready to use for the following platforms (all are for 64 bits only):

* [Linux](docs/INSTALLATION.md#installation-in-linux-using-compiled-artifacts)
* [Windows](docs/INSTALLATION.md#installation-windows)
* [MacOS](docs/INSTALLATION.md#installation-macos)
* [Aarch64 (Raspberry Pi)](docs/INSTALLATION.md#installation-aarch64-raspberry-pi)
* [NixOS](docs/INSTALLATION.md#installation-nixos)
* [Docker](docs/INSTALLATION.md#installation-docker)

If you need to run Findomain in another platform, continue reading the documentation.


# Issues and requests

If you have a problem or a feature request, open an [issue](https://github.com/Edu4rdSHL/findomain/issues).

# Stargazers over time

[![Stargazers over time](https://starchart.cc/Edu4rdSHL/findomain.svg)](https://starchart.cc/Edu4rdSHL/findomain)

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [See the contributors list](https://github.com/Edu4rdSHL/findomain/graphs/contributors).
