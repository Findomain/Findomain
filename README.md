[![Follow on Twitter](https://img.shields.io/twitter/follow/edu4rdshl.svg?logo=twitter)](https://twitter.com/edu4rdshl)
[![Follow on Twitter](https://img.shields.io/twitter/follow/sechacklabs.svg?logo=twitter)](https://twitter.com/sechacklabs)

![alt text](findomain.png "Findomain")

# Mixed feelings with Findomain? Show your love

If you want to support the tool development and make it better, [support us :)](https://opencollective.com/findomain#backer) You will appear here.

# Findomain

[![crates.io](https://img.shields.io/crates/v/findomain.svg)](https://crates.io/crates/findomain)
[![Travis CI Status](https://travis-ci.org/edu4rdshl/findomain.svg?branch=master)](https://travis-ci.org/edu4rdshl/findomain)
[![Appveyor CI Status](https://ci.appveyor.com/api/projects/status/github/edu4rdshl/findomain?branch=master&svg=true)](https://ci.appveyor.com/project/edu4rdshl/findomain)
[![Build status](https://github.com/Edu4rdSHL/findomain/workflows/Github%20Actions/badge.svg)](https://github.com/Edu4rdSHL/findomain/actions)

The fastest and cross-platform subdomain enumerator.

# What Findomain can do?

It table gives you a idea why you should use findomain and what it can do for you. The domain used for the test was google.com in the following [BlackArch](https://blackarch.org) virtual machine:

```
Host: KVM/QEMU (Standard PC (i440FX + PIIX, 1996) pc-i440fx-3.1)
Kernel: 5.2.6-arch1-1-ARCH
CPU: Intel (Skylake, IBRS) (4) @ 2.904GHz
Memory: 139MiB / 3943MiB
```
The tool used to calculate the time, is the `time` command in Linux.

|Enumeration Tool|Serch Time|Total Subdomains Found|CPU Usage|RAM Usage|
|---|---|---|---|---|
|Findomain|real	0m14.790s|27329|Very Low|Very Low|

**Summary:** 27329 subdomains in 14.7 seconds.

# Features

* Multi-thread support, it makes that the maximun time that Findomain will take to search subdomains for any target is 20 seconds.
* Discover subdomains without brute-force, it tool uses Certificate Transparency Logs and APIs.
* Discover subdomains with or without IP address according to user arguments.
* Read target from user argument (-t) or file (-f).
* Discover subdomains with or without IP and also write to output files per-domain if specified by the user, recursively.
* Write output to TXT file.
* Write output to CSV file.
* Write output to JSON file.
* Cross platform support: Any platform, it's written in Rust and Rust is multiplatform. See [the documentation](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#build-for-32-bits-or-another-platform) for instructions.
* Multiple API support.

**Note**: the proxy support is just to proxify APIs requests, the actual implementation to discover IP address of subdomains doesn't support proxyfing and it's made using the host network still if you use the -p option.

# How it works?
It tool doesn't use the common methods for sub(domains) discover, the tool uses Certificate Transparency logs and specific well tested APIs to find subdomains. It method make it tool the most faster and reliable. The tool make use of multiple public available APIs to perform the search. If you want to know more about Certificate Transparency logs, read https://www.certificate-transparency.org/

APIs that we are using at the moment:

- [Certspotter](https://api.certspotter.com/)
- [Crt.sh](https://crt.sh)
- [Virustotal](https://www.virustotal.com/ui/domains/)
- [Sublit3r](https://api.sublist3r.com/)
- [Facebook](https://developers.facebook.com/docs/certificate-transparency) `**`
- [Spyse (CertDB)](https://certdb.com/apidocs#/Subdomains) `*`
- [Bufferover](http://dns.bufferover.run/)
- [Threadcrow](https://threatcrowd.org/)
- [Virustotal with apikey](https://www.virustotal.com/) `**`

**Notes**

APIs marked with `**`, **require** an access token to work. Search in the [Findomain documentation](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#access-tokens-configuration) how to configure and use it.

APIs marked with `*` can *optionally* be used with an access token, create one if you start experiencing problems with that APIs. Search in the [Findomain documentation](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#access-tokens-configuration) how to configure and use it. 

**More APIs?**

If you know other APIs that should be added, comment [here](https://github.com/Edu4rdSHL/findomain/issues/7).

# Supported platforms in our binary releases

All supported platforms in the binarys that we give are 64 bits only and we don't have plans to add support for 32 bits binary releases, if you want to have support for 32 bits follow the [documentation](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#build-for-32-bits-or-another-platform).

* [Linux](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#installation-in-linux-using-compiled-artifacts)
* [Windows](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#installation-windows)
* [MacOS](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#installation-macos)
* [Aarch64 (Raspberry Pi)](https://github.com/Edu4rdSHL/findomain/blob/master/README.md#installation-aarch64-raspberry-pi)

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

```
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
**If you are using the [BlackArch Linux](https://blackarch.org) distribution, you just need to use:**

```
$ sudo pacman -S findomain
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

```
$ wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-osx
$ chmod +x findomain-osx.dms
$ ./findomain-osx.dms
```

# Access tokens configuration

In in section you can found the steps about how to configure APIs that need or can be used with access tokens.

# Configuring the Facebook API

**History**

When I added the [Facebook CT API](https://developers.facebook.com/docs/certificate-transparency-api) in the beginning I was providing a [Webhook token](https://developers.facebook.com/docs/certificate-transparency/certificates-webhook) to search in the API, as consequence when a lot of users were using the same token the limit was reached and user can't search in the Facebook API anymore until Facebook unlocked it again. Since Findomain version 0.2.2, users can set their own Facebook Access Token for the webook and pass it to findomain setting the `findomain_fb_token` system variable. The change was introduced [here](https://github.com/Edu4rdSHL/findomain/commit/1716e264e2b15c96c67b692b80b32c78fe9aaf9a). Also since 23/08/2019 I have removed the webhook that was providing that API token and it will not work anymore, if you're using findomain < 0.2.2 you are affected, please use a version >= 0.2.2.

Since Findomain 0.2.4 you don't need to explicity set the `findomain_fb_token` variable in your system, if you don't set that variable then Findomain will use one of our [five provided access tokens](https://github.com/Edu4rdSHL/findomain/blob/master/findomain_fb_tokens.md) for the Facebook CT API, otherwise, if you set the environment variable then Findomain will use your token. See [it commit](https://github.com/Edu4rdSHL/findomain/commit/226575c370e32979a16fd377dfea1db10ca38f3b). **Please, if you can create your own token, do it. The usage limit of access tokens is reached when a lot of people use it and then the tool will fail.**

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

**Tip:** If you don't want to write the access token everytime that you run findomain, export the `findomain_virustotal_token` in Unix based systems like putting `export findomain_virustotal_token="YourAccessToken"` into your `.bashrc` and set the `findomain_virustotal_token` variable in your Windows system as [described here](https://www.computerhope.com/issues/ch000549.htm).

# Usage

You can use the tool in two ways, only discovering the domain name or discovering the domain + the IP address.

```
findomain 0.2.5
Eduard Tolosa <tolosaeduard@gmail.com>
The fastest and cross-platform subdomain enumerator, don't waste your time.

USAGE:
    findomain [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -i, --get-ip     Return the subdomain list with IP address if resolved.
    -V, --version    Prints version information

OPTIONS:
    -f, --file <file>        Sets the input file to use.
    -o, --output <output>    Write data to output file in the specified format. [possible values: txt, csv, json]
    -t, --target <target>    Target host
```

# Examples

1. Make a simple search of subdomains and print the info in the screen:

`findomain -t example.com`

2. Make a search of subdomains and print the info in the screen:

`findomain -t example.com`

3. Make a search of subdomains and export the data to a CSV file:

`findomain -t example.com -o csv`

4. Make a search of subdomains and resolve the IP address of subdomains (if possible):

`findomain -t example.com -i`

5. Make a search of subdomains and resolve the IP address of subdomains (if possible), exporting the data to a CSV file:

`findomain -t example.com -i -o csv`

6. Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file):

`findomain -f file_with_domains.txt`

# TODO

- [ ] Improve JSON output.
- [ ] Add more APIs (It's longterm because I depend of new requests, at the moment I have not more APIs in the mind).

# Issues and requests

If you have a problem or a feature request, open an [issue](https://github.com/Edu4rdSHL/findomain/issues).

# Stargazers over time

[![Stargazers over time](https://starchart.cc/Edu4rdSHL/findomain.svg)](https://starchart.cc/Edu4rdSHL/findomain)
