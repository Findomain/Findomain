
[![crates.io](https://img.shields.io/crates/v/findomain.svg)](https://crates.io/crates/findomain)
[![Travis CI Status](https://travis-ci.org/edu4rdshl/findomain.svg?branch=master)](https://travis-ci.org/edu4rdshl/findomain)
[![Appveyor CI Status](https://ci.appveyor.com/api/projects/status/github/edu4rdshl/findomain?branch=master&svg=true)](https://ci.appveyor.com/project/edu4rdshl/findomain)
[![Build status](https://github.com/Edu4rdSHL/findomain/workflows/Github%20Actions/badge.svg)](https://github.com/Edu4rdSHL/findomain/actions)

# Findomain Plus version

Findomain has a Plus version that provides additional features, performance improvements and practical ways to configure and get it working.

The next table offers you the comparison about what is in Plus version that is not in free version (current repo).

**Implemented features:**
| Feature  | Plus Version Support | Free Version Support |
| ------------- | ------------- | ------------- |
| [Core features](README.md#features)  | Yes  |Yes|
| Check subdomains HTTP/S status | Yes  |No|
| Check subdomains open ports | Yes  |No|
| Support for posting HOST, IP, HTTP status and open ports to webhook notifications | Yes  |No|
| Support for "light monitoring" mode | Yes  |No|
| Support for configuration file in TOML, JSON, HJSON, INI or YAML format. | Yes  |No|
| Support for automatic detection/read of default configuration file | Yes  |No|
| Save Host, IP, HTTP Status and Open Ports to database  | Yes  |No|
| Option to exclude sources | Yes  |No|
| Filter or exclude subdomains containing specific keywords. | Yes  |No|
| Maximum number of threads 1000 | Yes  |No|
| Force all targets to be lowercase | Yes  |No|
| Port scanner  | Yes  |No|
| Save root domain to database  | Yes  |No|
| Custom user agent configuration | Yes |No |
| Rate limit user configuration | Yes | No |
| Output files written in real-time | Yes | No|
| Output to unique file while monitoring | Yes | No|

**Planned features:**
| Feature  | Plus Version Plans | Free Version Plans |
| ------------- | ------------- | ------------- |
| [Project Sonar](https://www.rapid7.com/research/project-sonar/) integration | Yes  |No|
| Shodan source support  | Yes  |No|
| Elastic search support  | Yes  |No|
| SQLite output  | Yes  |No|
| Email notifications  | Yes  |No|
| Screenshot included in notifications  | Yes  |No|
| Track CNAME for subdomains | Yes | No |

## How to get Findomain Plus?

It so easy, just make a monthly suscription to Patreon using the following button. You will receive the binaries in the email associated to your suscription account.

## Patreon

<a href="https://www.patreon.com/bePatron?u=30383720"><img src="https://c5.patreon.com/external/logo/become_a_patron_button@2x.png" alt="Patreon donate button" /> </a>

## Paypal

**By default donations to Paypal will not give access to the Plus version. If for any reason you want to make your monthly suscription using Paypal instead of Patreon, please reach me out in [Twitter](https://twitter.com/edu4rdshl) and I will send you the binaries. Anyways I recommend that you use Patreon for the Findomain+ suscription.**

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=37K3XKBUD2JJ8)

**Screenshots:**

![Findomain Scan](images/findomain3.png)
![Findomain Database](images/findomain4.jpg)

**Demos:**
[![asciicast](https://asciinema.org/a/YQkHcS5Vsx3vt2gbTPodbTIox.svg)](https://asciinema.org/a/YQkHcS5Vsx3vt2gbTPodbTIox)
[![asciicast](https://asciinema.org/a/3kHnCYTDsOp20ttgNXXgvCRjX.svg)](https://asciinema.org/a/3kHnCYTDsOp20ttgNXXgvCRjX)

[![Follow on Twitter](https://img.shields.io/twitter/follow/edu4rdshl.svg?logo=twitter)](https://twitter.com/edu4rdshl)
[![Follow on Twitter](https://img.shields.io/twitter/follow/sechacklabs.svg?logo=twitter)](https://twitter.com/sechacklabs)

# Findomain

![Findomain](images/findomain.png)

The fastest and cross-platform subdomain enumerator.

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
* Discover subdomains IP for data analisis.
* Read target from user argument (-t) or file (-f).
* Write to one unique output file specified by the user all or only resolved subdomains.
* Write results to automatically named TXT output file(s).
* Hability to query directly the Findomain database created with [Subdomains Monitoring](README.md#subdomains-monitoring) for previous discovered subdomains.
* Hability to import and work data discovered by other tools.
* Quiet mode to run it silently.
* Cross platform support: Any platform, it's written in Rust and Rust is multiplatform. See [the documentation](README.md#build-for-32-bits-or-another-platform) for instructions.
* Multiple API support.
* Possibility to use as subdomain resolver.
* Subdomain wildcard detection for accurate results. 
* Support for subdomain discover using bruteforce method.
* Update checker. Use the `--check-updates` flag.

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

**Notes**

APIs marked with `**`, **require** an access token to work. Search in the [Findomain documentation](README.md#access-tokens-configuration) how to configure and use it.

APIs marked with `*` can *optionally* be used with an access token, create one if you start experiencing problems with that APIs. Search in the [Findomain documentation](README.md#access-tokens-configuration) how to configure and use it.

**More APIs?**

If you know other APIs that should be added, comment [here](https://github.com/Edu4rdSHL/findomain/issues/7).

# Development

In order to make sure Findomain will not be broken on some commit I have created the [develop branch](https://github.com/Edu4rdSHL/findomain/tree/develop) where new features and improvements are pushed before they go to [master branch](https://github.com/Edu4rdSHL/findomain/tree/master). In resume the difference is: **develop branch and beta releases aren't ready for production purposes but testing or development purposes** and **master branch and non-beta releases are ready for production purposes**. If you are a developer or want to be a beta tester of the new features that are added to Findomain then use the develop branch, otherwise always use the master branch. Every new feature is tested before it goes to master by the Findomain beta testers that are only ([@sumgr0](https://github.com/sumgr0)) at the moment, I will appreciate if you join to the testing process, just send me a DM in Twitter ([@edu4rdshl](https://twitter.com/edu4rdshl)).

**If you are a packager of Findomain for X system distribution always go for the master branch if using git or non-beta releases if using releases model**.

**Build the development version:**

You need to have [rust](https://rust-lang.org), [make](http://www.gnu.org/software/make) and [perl](https://www.perl.org/) installed in your system first.

```bash
$ git clone https://github.com/Edu4rdSHL/findomain.git -b develop # Only the develop branch is needed
$ cd findomain
$ cargo build --release
$ ./target/release/findomain
```
To update the repository when new commits are added, just go to the folder where Findomain's develop branch was cloned and excute:

```
$ git pull
$ cargo build --release
$ ./target/release/findomain
```

# Installation

We offer binarys ready to use for the following platforms (all are for 64 bits only):

* [Linux](README.md#installation-in-linux-using-compiled-artifacts)
* [Windows](README.md#installation-windows)
* [MacOS](README.md#installation-macos)
* [Aarch64 (Raspberry Pi)](README.md#installation-aarch64-raspberry-pi)
* [NixOS](README.md#installation-nixos)
* [Docker](README.md#installation-docker)

If you need to run Findomain in another platform, continue reading the documentation.

# Build for 32 bits or another platform

If you want to build the tool for your 32 bits system or another platform, follow it steps:

**Note:** You need to have [rust](https://rust-lang.org), [make](http://www.gnu.org/software/make) and [perl](https://www.perl.org/) installed in your system first.

Using the [crate](https://crates.io/crates/findomain):

1. `cargo install findomain`
2. Execute the tool from `$HOME/.cargo/bin`. See the [cargo-install documentation](https://doc.rust-lang.org/cargo/commands/cargo-install.html).

Using the Github source code:

1. Clone the [repository](https://github.com/Edu4rdSHL/findomain) or download the [release source code](https://github.com/Edu4rdSHL/findomain/releases).
2. Extract the release source code (only needed if you downloaded the compressed file).
3. Go to the folder where the source code is.
4. Execute `cargo build --release`
5. Now your binary is in `target/release/findomain` and you can use it.

# Installation Android (Termux)

Install the [Termux](https://termux.com/) package, open it and follow it commands:

```
$ pkg install rust make perl
$ cargo install findomain
$ cd $HOME/.cargo/bin
$ ./findomain
```

# Installation in Linux using source code
If you want to install it, you can do that manually compiling the source or using the precompiled binary.

**Manually:**
You need to have [rust](https://rust-lang.org), [make](http://www.gnu.org/software/make) and [perl](https://www.perl.org/) installed in your system first.

```bash
$ git clone https://github.com/Edu4rdSHL/findomain.git
$ cd findomain
$ cargo build --release
$ sudo cp target/release/findomain /usr/bin/
$ findomain
```

# Installation in Linux using compiled artifacts

```
$ wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
$ chmod +x findomain-linux
$ ./findomain-linux
```
**If you are using the [ArchLinux](https://archlinux.org) distribution or any ArchLinux-based distro, you just need to use:**

```
$ pacman -S findomain
```
**If you are using the [Pentoo](https://pentoo.ch) distribution, you just need to use:**

```
$ emerge -a findomain
```

# Installation Aarch64 (Raspberry Pi)

```
$ wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-aarch64
$ chmod +x findomain-aarch64
$ ./findomain-aarch64
```

# Installation Windows

Download the binary from https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-windows.exe

Open a CMD shell and go to the dir where findomain-windows.exe was downloaded.

Exec: `findomain-windows` in the CMD shell.


# Installation MacOS

You have two options to install Findomain in MacOS.

**Using Homebrew:**

```
$ brew install findomain
$ findomain
```
**Manually from the repo:**

```
$ wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-osx
$ chmod +x findomain-osx.dms
$ ./findomain-osx.dms
```

# Installation NixOS

```
$ nix-env -i findomain
$ findomain
```

# Installation Docker

You have two options to install Findomain in a docker container.

**Using Dockerhub:**

```
$ docker pull edu4rdshl/findomain:latest
$ docker run -it edu4rdshl/findomain:latest /bin/bash
$ findomain
```

**Building the docker image:**

Please see [the documentation](docker/).

# Updating Findomain to latest version

To update Findomain to latest version, you can be in some scenarios:

1. **You downloaded a precompiled binary:** If you are using a precompiled binary, then you need to download the new binary.
2. **You are using it in ArchLinux or any Arch-based distro:** Just run `pacman -Syu`
3. **You have cloned the repo and compiled it from source:** You just need to go to the folder where the repo is cloned and run: `git pull && cargo build --release`, when finish, you have your executable in `target/release/findomain`.
4. **You downloaded a source code release and compiled it:** You need to download the new source code release and compile it again.
5. **I used cargo install findomain:** then just run `cargo install findomain`.

# Access tokens configuration

In in section you can found the steps about how to configure APIs that need or can be used with access tokens.

# Configuring the Facebook API

**History**

When I added the [Facebook CT API](https://developers.facebook.com/docs/certificate-transparency-api) in the beginning I was providing a [Webhook token](https://developers.facebook.com/docs/certificate-transparency/certificates-webhook) to search in the API, as consequence when a lot of users were using the same token the limit was reached and user can't search in the Facebook API anymore until Facebook unlocked it again. Since Findomain version 0.2.2, users can set their own Facebook Access Token for the webook and pass it to findomain setting the `findomain_fb_token` system variable. The change was introduced [here](https://github.com/Edu4rdSHL/findomain/commit/1716e264e2b15c96c67b692b80b32c78fe9aaf9a). Also since 23/08/2019 I have removed the webhook that was providing that API token and it will not work anymore, if you're using findomain < 0.2.2 you are affected, please use a version >= 0.2.2.

Since Findomain 0.2.4 you don't need to explicity set the `findomain_fb_token` variable in your system, if you don't set that variable then Findomain will use one of our provided access tokens for the Facebook CT API, otherwise, if you set the environment variable then Findomain will use your token. See [it commit](https://github.com/Edu4rdSHL/findomain/commit/226575c370e32979a16fd377dfea1db10ca38f3b). **Please, if you can create your own token, do it. The usage limit of access tokens is reached when a lot of people use it and then the tool will fail.**

**Getting the Webhook token**

The first step is get your Facebook application token. You need to create a Webhook, follow the next steps:

1. Open https://developers.facebook.com/apps/
2. Clic in "Create App", put the name that you want and send the information.
3. In the next screen, select "Configure" in the Webhooks option.
4. Go to "Configuration" -> "Basic" and clic on "Show" in the "App secret key" option.
5. Now open in your browser the following URL: https://graph.facebook.com/oauth/access_token?client_id=your-app-id&client_secret=your-secret-key&grant_type=client_credentials

**Note:** replace `your-app-id` by the number of your webhook identifier and `your-secret-key` for the key that you got in the 4th step.

6. You should have a JSON like:

```json
{
  "access_token": "xxxxxxxxxx|yyyyyyyyyyyyyyyyyyyyyyy",
  "token_type": "bearer"
}
```
7. Save the `access_token` value.

Now you can use that value to set the access token as following:

**Unix based systems (Linux, BSD, MacOS, Android with Termux, etc):**

Put in your terminal:

```
$ findomain_fb_token="YourAccessToken" findomain -(options)
```

**Windows systems:**

Put in the CMD command prompt:

```
> set findomain_fb_token=YourAccessToken && findomain -(options)
```

**Note:** In Windows you need to scape special characters like `|`, add `^` before the special character to scape it and don't quote the token. Example:  `set findomain_fb_token=xxxxxxx^|yyyyyyyy && findomain -(options)`

**Tip:** If you don't want to write the access token everytime that you run findomain, export the `findomain_fb_token` in Unix based systems like putting `export findomain_fb_token="YourAccessToken"` into your `.bashrc` and set the `findomain_fb_token` variable in your Windows system as [described here](https://www.computerhope.com/issues/ch000549.htm).

# Configuring the Spyse API to use with token

1. Open https://account.spyse.com/register and make the registration process (include email verification).
2. Log in into your spyse account and go to https://account.spyse.com/user
3. Search for the "API token" section and clic in "Show".
4. Save that access token.

Now you can use that value to set the access token as following:

**Unix based systems (Linux, BSD, MacOS, Android with Termux, etc):**

Put in your terminal:

```
$ findomain_spyse_token="YourAccessToken" findomain -(options)
```

**Windows systems:**

Put in the CMD command prompt:

```
> set findomain_spyse_token=YourAccessToken && findomain -(options)
```

**Note:** In Windows you need to scape special characters like `|`, add `^` before the special character to scape it and don't quote the token. Example:  `set findomain_spyse_token=xxxxxxx^|yyyyyyyy && findomain -(options)`

**Tip:** If you don't want to write the access token everytime that you run findomain, export the `findomain_spyse_token` in Unix based systems like putting `export findomain_spyse_token="YourAccessToken"` into your `.bashrc` and set the `findomain_spyse_token` variable in your Windows system as [described here](https://www.computerhope.com/issues/ch000549.htm).

# Configuring the Virustotal API to use with token

1. Open https://www.virustotal.com/gui/join-us and make the registration process (include email verification).
2. Log in into your spyse account and go to https://www.virustotal.com/gui/user/YourUsername/apikey
3. Search for the "API key" section.
4. Save that API key.

Now you can use that value to set the access token as following:

**Unix based systems (Linux, BSD, MacOS, Android with Termux, etc):**

Put in your terminal:

```
$ findomain_virustotal_token="YourAccessToken" findomain -(options)
```

**Windows systems:**

Put in the CMD command prompt:

```
> set findomain_virustotal_token=YourAccessToken && findomain -(options)
```

**Note:** In Windows you need to scape special characters like `|`, add `^` before the special character to scape it and don't quote the token. Example:  `set findomain_virustotal_token=xxxxxxx^|yyyyyyyy && findomain -(options)`

**Tip:** If you don't want to write the access token everytime that you run findomain, export the respective system variable in your OS. For Unix based systems it can be done putting `export VariableName="VariableValue"` into your `.bashrc`. For Windows system it can be done as [described here](https://www.computerhope.com/issues/ch000549.htm) or [here](https://www.dowdandassociates.com/blog/content/howto-set-an-environment-variable-in-windows-command-line-and-registry/).

# Configuring the SecurityTrails API

**Getting the API key**

The first step is get your SecurityTrails token.Follow the next steps:

1. Open https://securitytrails.com/
2. Clic in "SIGNUP FOR FREE" (right corner).
3. Fill the requested fields, **you need to put a valid email address, it's needed for verification.**.
4. Select the API Pricing plan of your preference, there's a free plan limited to 50 queries per month. Clic in "Get started".
5. Confirm email address.
6. Select "Credentials" in the left panel, there's the API Key.

Now you can use that value to set the access token as following:

**Unix based systems (Linux, BSD, MacOS, Android with Termux, etc):**

Put in your terminal:

```
$ findomain_securitytrails_token="YourAccessToken" findomain -(options)
```

**Windows systems:**

Put in the CMD command prompt:

```
> set findomain_securitytrails_token=YourAccessToken && findomain -(options)
```

**Note:** In Windows you need to scape special characters like `|`, add `^` before the special character to scape it and don't quote the token. Example:  `set findomain_securitytrails_token=xxxxxxx^|yyyyyyyy && findomain -(options)`

**Tip:** If you don't want to write the access token everytime that you run findomain, export the `findomain_fb_token` in Unix based systems like putting `export findomain_securitytrails_token="YourAccessToken"` into your `.bashrc` and set the `findomain_fb_token` variable in your Windows system as [described here](https://www.computerhope.com/issues/ch000549.htm).


# Subdomains Monitoring

Findomain is capable of monitor a specific domain or a list of domains for new subdomains and send the data to [Slack](https://slack.com/), [Discord](https://discordapp.com) or [Telegram](https://telegram.org) webhooks. All what you need is a server or your computer with  [PostgreSQL](https://www.postgresql.org/) database server installed. Have in mind that you can have only a central server/computer with PostgreSQL installed and connect to it from anywhere to perform the monitoring tasks.

**IMPORTANT NOTE:** Findomain is a subdomains enumeration and monitor tool, not a job scheduler. If you want to run findomain automatically then you need to configure a job scheduler like [systemd-timers](https://wiki.archlinux.org/index.php/Systemd/Timers) or the well known [CRON](https://wiki.archlinux.org/index.php/Cron) in \*NIX systems, Termux in Android or MAC and the [Windows Task Scheduler](https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page) in Windows.

**Options**

You can set the following command line options when using the subdomains monitoring feature:

```
        --postgres-database <postgres-database>    Postgresql database.
        --postgres-host <postgres-host>            Postgresql host.
        --postgres-password <postgres-password>    Postgresql password.
        --postgres-port <postgres-port>            Postgresql port.
        --postgres-user <postgres-user>            Postgresql username.
```

**System variables that can be configured**

Findomain reads system variables to make use of webhooks. Currently Findomain support the following webhooks (click on them to see how to setup the webhooks):

* [Discord](https://support.discordapp.com/hc/en-us/articles/228383668-Intro-to-Webhooks).
* [Slack](https://api.slack.com/incoming-webhooks).
* [Telegram](docs/create_telegram_webhook.md).

The available system variables that you have are:

```
findomain_discord_webhook: Discord webhook URL.
findomain_slack_webhook: Slack webhook URL.
findomain_telegrambot_token: Telegram bot autentication token.
findomain_telegrambot_chat_id: Unique identifier for the target chat or username of the target channel.
```

**Tip:** If you don't want to write the webhook parameters everytime that you run findomain, export the respective system variable in your OS. For Unix based systems it can be done putting `export VariableName="VariableValue"` into your `.bashrc`. For Windows system it can be done as [described here](https://www.computerhope.com/issues/ch000549.htm) or [here](https://www.dowdandassociates.com/blog/content/howto-set-an-environment-variable-in-windows-command-line-and-registry/).

**Default values while connecting to database server**

Findomain have some default values that are used when they are not set. They are listed below:

1) If you only specify the `-m` flag without more arguments or don't specify one of the options Findomain sets:

* Database host: localhost
* Database username: postgres
* Database password: postgres
* Database port: 5432
* Database: [Default PostgreSQL database cluster](https://www.postgresql.org/docs/current/app-initdb.html)

**Subdomains monitoring examples**

1) **Connect to local computer and local PostgreSQL server with specific username, password and database and push the data to both Discord and Slack webhooks**

```
$ findomain_discord_webhook='https://discordapp.com/api/webhooks/XXXXXXXXXXXXXXX' findomain_slack_webhook='https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX' findomain -m -t example.com --postgres-database findomain --postgres-user findomain --postgres-host localhost --postgres-port 5432
```

2) **Connect to remote computer/server and remote PostgreSQL server with specific username, password and database and push the data to both Discord and Slack webhooks**

```
$ findomain_discord_webhook='https://discordapp.com/api/webhooks/XXXXXXXXXXXXXXX' findomain_slack_webhook='https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX' findomain -m -t example.com --postgres-user postgres --postgres-password psql  --postgres-host 192.168.122.130 --postgres-port 5432
```

3) **Connect to remote computer/server and remote PostgreSQL server with specific username, password and database and push the data to Telegram webhook**

```
$ findomain_telegrambot_token="Your_Bot_Token_Here" findomain_telegrambot_chat_id="Your_Chat_ID_Here" findomain -m -t example.com --postgres-user postgres --postgres-password psql  --postgres-host 192.168.122.130 --postgres-port 5432
```

4) **Connect to local computer using the default values**

```
$ findomain_discord_webhook='https://discordapp.com/api/webhooks/XXXXXXXXXXXXXXX' findomain_slack_webhook='https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX' findomain -m -t example.com
```

# Usage

See `findomain -h/--help` to see all the options.

For subdomains monitoring examples [Subdomains Monitoring](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#subdomains-monitoring) for more information.

You can use the tool in two ways, only discovering the domain name or discovering the domain + the IP address.

# Examples

1. Make a simple search of subdomains and print the info in the screen:

`findomain -t example.com`

2. Make a search of subdomains and print the info in the screen:

`findomain -t example.com`

3. Make a search of subdomains and export the data to a output file (the output file name in it case is example.com.txt):

`findomain -t example.com -o`

4. Make a search of subdomains and export the data to a custom output file name:

`findomain -t example.com -u example.txt`

5. Make a search of only resolvable subdomains:

`findomain -t example.com -r`

6. Make a search of only resolvable subdomains, exporting the data to a custom output file.

`findomain -t example.com -r -u example.txt`

7. Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file):

`findomain -f file_with_domains.txt`

8. Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file) and save all the resolved domains into a custom file name:

`findomain -f file_with_domains.txt -r -u multiple_domains.txt`

9. Query the Findomain database created with [Subdomains Monitoring](README.md#subdomains-monitoring).

`findomain -t example.com --query-database`

10. Query the Findomain database created with [Subdomains Monitoring](README.md#subdomains-monitoring) and save results to a custom filename.

`findomain -t example.com --query-database -u subdomains.txt`

11. Import subdomains from several files and work with they in the [Subdomains Monitoring](README.md#subdomains-monitoring) process:

`findomain --import-subdomains file1.txt file2.txt file3.txt -m -t example.com`

# Issues and requests

If you have a problem or a feature request, open an [issue](https://github.com/Edu4rdSHL/findomain/issues).

# Stargazers over time

[![Stargazers over time](https://starchart.cc/Edu4rdSHL/findomain.svg)](https://starchart.cc/Edu4rdSHL/findomain)

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [See the contributors list](https://github.com/Edu4rdSHL/findomain/graphs/contributors).

### Financial Contributors

Become a financial contributor and help us sustain our community.

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=37K3XKBUD2JJ8)

<a href="https://patreon.com/edu4rdshl"><img src="https://c5.patreon.com/external/logo/become_a_patron_button@2x.png" alt="Patreon donate button" /> </a>
