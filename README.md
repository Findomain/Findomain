# Findomain
A cross-platform tool that use Certificates Transparency logs to find subdomains. We currently support Linux, Windows and MacOS.

# How it works?
It tool doesn't use the common methods for sub(domains) discover, the tool uses Certificate Transparency logs to find subdomains and it method make it tool very faster and reliable. If you want to know more about Certificate Transparency logs, read https://www.certificate-transparency.org/

# Installation Linux
If you want to install it, you can do that manually compiling the source or using the precompiled binary.

**Manually:**
You need to have [Rust](https://www.rust-lang.org/) installed in your computer first.

```
$ git clone https://github.com/Edu4rdSHL/findomain.git
$ cd findomain
$ cargo build --release
$ sudo cp target/release/findomain /usr/bin/
$ findomain
```

**Using the binary:**

```
$ git clone https://github.com/Edu4rdSHL/findomain.git
$ sudo cp findomain/bin/findomain /usr/bin
$ findomain
```
**If you are using the [BlackArch Linux](https://blackarch.org) distribution, you just need to use:**

```
$ sudo pacman -S findomain
```

# Installation Windows

Download the binary from https://github.com/Edu4rdSHL/findomain/tree/master/bin/windows and use it.

# Installation MacOS

Download the binary from https://github.com/Edu4rdSHL/findomain/tree/master/bin/osx and use it.

# Usage

You can use the tool in two ways, only discovering the domain name or discovering the domain + the IP address.

```
findomain 0.1.3
Eduard Tolosa <tolosaeduard@gmail.com>
A tool that use Certificates Transparency logs to find subdomains.

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
# Features

* Discover subdomains without brute-force, it tool uses Certificate Transparency Logs.
* Discover subdomains with or without IP address according to user arguments.
* Read target from user argument (-t).
* Read a list of targets from file and discover their subdomains with or without IP and also write to output files per-domain if specified by the user, recursively.
* Write output to TXT file.
* Write output to CSV file.
* Write output to JSON file.
* Cross platform support: Linux, Windows, MacOS.

# Issues and requests

If you have a problem or a feature request, open an [issue](https://github.com/Edu4rdSHL/findomain/issues).
