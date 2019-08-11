Follow in Twitter:

* https://twitter.com/sechacklabs (Team)
* https://twitter.com/edu4rdshl (Developer)

![alt text](findomain.png "Findomain")

# Findomain

The fastest and cross-platform subdomain enumerator.

# Comparision

It comparision gives you a idea why you should use findomain instead of another tools. The domain used for the test was microsoft.com in the following [BlackArch](https://blackarch.org) virtual machine:

```
Host: KVM/QEMU (Standard PC (i440FX + PIIX, 1996) pc-i440fx-3.1)
Kernel: 5.2.6-arch1-1-ARCH
CPU: Intel (Skylake, IBRS) (4) @ 2.904GHz
Memory: 139MiB / 3943MiB
```
The tool used to calculate the time, is the `time` command in Linux. You can see all the details of the tests in [it link](https://github.com/Edu4rdSHL/findomain/blob/master/comparision_log.md).

|Enumeration Tool|Serch Time|Total Subdomains Found|CPU Usage|RAM Usage|
|---|---|---|---|---|
|Findomain|real	0m38.701s|5622|Very Low|Very Low|
|assetfinder|real	6m1.117s|4630|Very Low|Very Low|
|Subl1st3r|real	7m14.996s|996|Low|Low|
|Amass*|real 29m20.301s|332|Very Hight|Very Hight|

* I can't wait to the amass test for finish, looks like it will never ends and aditionally the resources usage is very hight.

**Note:** The benchmark was made the 10/08/2019, since it point other tools can improve things and you will got different results.

# Features

* Discover subdomains without brute-force, it tool uses Certificate Transparency Logs.
* Discover subdomains with or without IP address according to user arguments.
* Read target from user argument (-t).
* Read a list of targets from file and discover their subdomains with or without IP and also write to output files per-domain if specified by the user, recursively.
* Write output to TXT file.
* Write output to CSV file.
* Write output to JSON file.
* Cross platform support: Any platform.
* Optional multiple API support.
* Proxy support. 

**Note**: the proxy support is just to proxify APIs requests, the actual implementation to discover IP address of subdomains doesn't support proxyfing and it's made using the host network still if you use the -p option.

# How it works?
It tool doesn't use the common methods for sub(domains) discover, the tool uses Certificate Transparency logs to find subdomains and it method make it tool the most faster and reliable. The tool make use of multiple public available APIs to perform the search. If you want to know more about Certificate Transparency logs, read https://www.certificate-transparency.org/

APIs that we are using at the moment:

- Certspotter: https://api.certspotter.com/
- Crt.sh : https://crt.sh
- Virustotal: https://www.virustotal.com/ui/domains/
- Sublit3r: https://api.sublist3r.com/
- Facebook: https://developers.facebook.com/docs/certificate-transparency

If you know other that should be added, open an issue.

# Supported platforms in our binary releases

All supported platforms in the binarys that we give are 64 bits only and we don't have plans to add support for 32 bits binary releases, if you want to have support for 32 bits follow the [documentation](https://github.com/Edu4rdSHL/findomain#build-for-32-bits-or-another-platform).

* Linux
* Windows
* MacOS
* ARM
* Aarch64

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
You need to have [Rust](https://www.rust-lang.org/) installed in your computer first.

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

# Installation ARM

```
$ wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-arm
$ chmod +x findomain-arm
$ ./findomain-arm
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

# Usage

You can use the tool in two ways, only discovering the domain name or discovering the domain + the IP address.

```
findomain 0.2.0
Eduard Tolosa <tolosaeduard@gmail.com>
A tool that use Certificates Transparency logs to find subdomains.

USAGE:
    findomain [FLAGS] [OPTIONS]

FLAGS:
    -a, --all-apis    Use all the available APIs to perform the search. It take more time but you will have a lot of
                      more results.
    -h, --help        Prints help information
    -i, --get-ip      Return the subdomain list with IP address if resolved.
    -V, --version     Prints version information

OPTIONS:
    -f, --file <file>        Sets the input file to use.
    -o, --output <output>    Write data to output file in the specified format. [possible values: txt, csv, json]
    -p, --proxy <proxy>      Use a proxy to make the requests to the APIs.
    -t, --target <target>    Target host
```

# Examples

1. Make a simple search of subdomains and print the info in the screen:

`findomain -t example.com`

2. Make a simple search of subdomains using all the APIs and print the info in the screen:

`findomain -t example.com -a`

3. Make a search of subdomains and export the data to a CSV file:

`findomain -t example.com -o csv`

4. Make a search of subdomains using all the APIs and export the data to a CSV file:

`findomain -t example.com -a -o csv`

5. Make a search of subdomains and resolve the IP address of subdomains (if possible):

`findomain -t example.com -i`

6. Make a search of subdomains with all the APIs and resolve the IP address of subdomains (if possible):

`findomain -t example.com -i -a`

7. Make a search of subdomains with all the APIs and resolve the IP address of subdomains (if possible), exporting the data to a CSV file:

`findomain -t example.com -i -a -o csv`

8. Make a search of subdomains using a proxy (http://127.0.0.1:8080 in it case, the rest of aguments continue working in the same way, you just need to add the -p flag to the before commands):

`findomain -t example.com -p http://127.0.0.1:8080`

# TODO

- [ ] Improve JSON output.
- [ ] Add more APIs (It's longterm because I depend of new requests, at the moment I have not more APIs in the mind).

# Issues and requests

If you have a problem or a feature request, open an [issue](https://github.com/Edu4rdSHL/findomain/issues).

# Stargazers over time

[![Stargazers over time](https://starchart.cc/Edu4rdSHL/findomain.svg)](https://starchart.cc/Edu4rdSHL/findomain)
