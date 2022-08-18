# Installation

We offer binaries ready to use for the following platforms (all are for 64 bits only):

* [Linux](INSTALLATION.md#installation-in-linux-using-compiled-artifacts)
* [Windows](INSTALLATION.md#installation-windows)
* [MacOS](INSTALLATION.md#installation-macos)
* [Aarch64](INSTALLATION.md#installation-aarch64)
* [ARMv7](INSTALLATION.md#installation-armv7)
* [NixOS](INSTALLATION.md#installation-nixos)
* [Docker](INSTALLATION.md#installation-docker)

If you need to run Findomain in another platform, continue reading the documentation.

Note: You need a utility to unpack the ZIP downloaded artifacts, in Linux you can use [unzip](http://infozip.sourceforge.net/UnZip.html), in Windows you can use [7zip](https://www.7-zip.org/download.html).

## Prerequisites

Findomain requires the following software to be installed:

* Google Chrome or Chromium (for the screenshoting functionality).
* PostgreSQL (for the subdomains monitoring functionality). See [Subdomains Monitoring](INSTALLATION.md#subdomains-monitoring) for more details.

# Build for 32 bits or another platform

## Binaries

The only 32-bit platform with precompiled binaries is Linux since the 4.0.1 release, follow these steps for using the precompiled binaries:


```
$ curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip
$ unzip findomain-linux-i386.zip
$ chmod +x findomain
$ sudo mv findomain /usr/bin/findomain
$ findomain --help
```

If you want to build the tool for your 32 bits system or another platform, follow these steps:

**Note:** You need to have [rust](https://rust-lang.org), [make](http://www.gnu.org/software/make) and [perl](https://www.perl.org/) installed in your system first.

1. Clone the [repository](https://github.com/findomain/findomain) or download the [release source code](https://github.com/findomain/findomain/releases).
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
$ git clone https://github.com/findomain/findomain.git
$ cd findomain
$ cargo build --release
$ sudo cp target/release/findomain /usr/bin/
$ findomain
```

# Installation in Linux using precompiled artifacts

**If you are using [ArchLinux](https://archlinux.org) or any ArchLinux-based distro, you can use the following command:**

```
$ pacman -S findomain
```
**If you are using [Pentoo](https://pentoo.ch), you can use the following command:**

```
$ emerge -a findomain
```

**If you are using [NixOs](https://nixos.org/), you can use the following command:**

```
$ nix-env -iA findomain
```

**If you are using [Homebrew](https://brew.sh/) on your OS, you can use the following command:**

```
$ brew install findomain
```

Otherwise, you can use the following commands:

```
$ curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip}
$ unzip findomain-linux.zip
$ chmod +x findomain
$ sudo mv findomain /usr/bin/findomain
$ findomain --help
```

# Installation Aarch64

```
$ curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64.zip
$ unzip findomain-aarch64.zip
$ chmod +x findomain
$ sudo mv findomain /usr/bin/findomain
$ findomain --help
```

# Installation ARMv7

```
$ curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-armv7.zip
$ unzip findomain-armv7.zip
$ chmod +x findomain
$ sudo mv findomain /usr/bin/findomain
$ findomain --help
```

# Installation Windows

Download the binary from https://github.com/findomain/findomain/releases/latest/download/findomain-windows.exe.zip and extract it.

Open a CMD shell and go to the dir where findomain.exe was downloaded.

Exec: `findomain.exe --help` in the CMD shell.

# Installation MacOS

You have two options to install Findomain in MacOS.

**Using Homebrew:**

```
$ brew install findomain
$ findomain
```
**Manually from the repo:**

```
$ curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-osx.zip
# Extract the ZIP file.
$ chmod +x findomain.dms
$ ./findomain.dms --help
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

When I added the [Facebook CT API](https://developers.facebook.com/docs/certificate-transparency-api) in the beginning I was providing a [Webhook token](https://developers.facebook.com/docs/certificate-transparency/certificates-webhook) to search in the API, as consequence when a lot of users were using the same token the limit was reached and user can't search in the Facebook API anymore until Facebook unlocked it again. Since Findomain version 0.2.2, users can set their own Facebook Access Token for the webook and pass it to findomain setting the `findomain_fb_token` system variable. The change was introduced [here](https://github.com/findomain/findomain/commit/1716e264e2b15c96c67b692b80b32c78fe9aaf9a). Also since 23/08/2019 I have removed the webhook that was providing that API token and it will not work anymore, if you're using findomain < 0.2.2 you are affected, please use a version >= 0.2.2.

Since Findomain 0.2.4 you don't need to explicity set the `findomain_fb_token` variable in your system, if you don't set that variable then Findomain will use one of our provided access tokens for the Facebook CT API, otherwise, if you set the environment variable then Findomain will use your token. See [it commit](https://github.com/findomain/findomain/commit/226575c370e32979a16fd377dfea1db10ca38f3b). **Please, if you can create your own token, do it. The usage limit of access tokens is reached when a lot of people use it and then the tool will fail.**

**Getting the Webhook token**

The first step is get your Facebook application token. You need to create a Webhook, follow the next steps:

1. Open https://developers.facebook.com/apps/
2. Click in "Create App", select "None" and then "Next".
3. Put the "Display name" that you want and click "Next".
4. In the next screen, search for "Webhooks" and click on "Set up".
5. Go to "Configuration" -> "Basic" and click on "Show" in the "App secret key" option.
6. Now open in your browser the following URL: https://graph.facebook.com/oauth/access_token?client_id={your-app-id}&client_secret={your-secret-key}&grant_type=client_credentials

**Note:** replace `{your-app-id}` by the number of your webhook identifier and `{your-secret-key}` for the key that you got in the 4th step.

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
3. Search for the "API token" section and click in "Show".
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
2. Log in into your Virustotal account and go to https://www.virustotal.com/gui/user/YourUsername/apikey
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

**Tip:** If you don't want to write the access token everytime that you run findomain, export the respective system variable in your OS. For Unix based systems it can be done putting `export findomain_virustotal_token=YourAccessToken` into your `.bashrc`. For Windows system it can be done as [described here](https://www.computerhope.com/issues/ch000549.htm) or [here](https://www.dowdandassociates.com/blog/content/howto-set-an-environment-variable-in-windows-command-line-and-registry/).

# Configuring the SecurityTrails API

**Getting the API key**

The first step is get your SecurityTrails token.Follow the next steps:

1. Open https://securitytrails.com/
2. Click in "SIGNUP FOR FREE" (right corner).
3. Fill the requested fields, **you need to put a valid email address, it's needed for verification.**.
4. Select the API Pricing plan of your preference, there's a free plan limited to 50 queries per month. Click on "Get started".
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

Here's an article that covers the process of monitoring your domains with scheduled [CRON](https://wiki.archlinux.org/index.php/Cron) jobs for \*NIX systems - [Automated subdomain scanning with findomain, PostgreSQL and Webhooks](https://medium.com/heck-the-packet/automated-subdomain-scanning-with-findomain-postgresql-and-webhooks-3e74ce9b5372)

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

For subdomains monitoring examples [Subdomains Monitoring](INSTALLATION.md#subdomains-monitoring) for more information.

You can use the tool in two ways, only discovering the domain name or discovering the domain + the IP address.

# Examples

1. Make a search of subdomains and print the info in the screen:

`findomain -t example.com`

2. Make a search of subdomains and export the data to a output file (the output file name in it case is example.com.txt):

`findomain -t example.com -o`

3. Make a search of subdomains and export the data to a custom output file name:

`findomain -t example.com -u example.txt`

4. Make a search of only resolvable subdomains:

`findomain -t example.com -r`

5. Make a search of only resolvable subdomains, exporting the data to a custom output file.

`findomain -t example.com -r -u example.txt`

6. Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file):

`findomain -f file_with_domains.txt`

7. Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file) and save all the resolved domains into a custom file name:

`findomain -f file_with_domains.txt -r -u multiple_domains.txt`

8. Query the Findomain database created with [Subdomains Monitoring](INSTALLATION.md#subdomains-monitoring).

`findomain -t example.com --query-database`

9. Query the Findomain database created with [Subdomains Monitoring](INSTALLATION.md#subdomains-monitoring) and save results to a custom filename.

`findomain -t example.com --query-database -u subdomains.txt`

10. Import subdomains from several files and work with them in the [Subdomains Monitoring](INSTALLATION.md#subdomains-monitoring) process:

`findomain --import-subdomains file1.txt file2.txt file3.txt -m -t example.com`
