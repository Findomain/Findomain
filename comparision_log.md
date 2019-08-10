**PERFORMANCE TEST RESULTS**


- FINDOMAIN

```
[ blackarch ~ ]# time findomain -t microsoft.com -o txt -a

Target ==> microsoft.com

Searching in the CertSpotter API... 🔍
Searching in the Crtsh API... 🔍
A timeout ⏳ error as occured while processing the request in the Crtsh API. Error description: timed out

Searching in the Virustotal API... 🔍
Searching in the Sublist3r API... 🔍
Searching in the Facebook API... 🔍

A total of 5622 subdomains were found for ==>  microsoft.com 👽

 >> 000dco1l50fe3b.redmond.corp.microsoft.com
 ...snip
 Good luck Hax0r 💀!

>> 📁 Filename for the target microsoft.com was saved in: ./microsoft.com_1239.txt 😀

real	0m38.701s
user	0m0.106s
sys	0m0.079s
[ blackarch ~ ]# cat ./microsoft.com_1239.txt |wc -l
5622
```

- SUBL1ST3R

```
[ blackarch ~ ]# time sublist3r -d microsoft.com -o amazon-sub.txt

                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|

                # Coded By Ahmed Aboul-Ela - @aboul3la
    
[-] Enumerating subdomains now for microsoft.com
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Ask..
[-] Searching now in Netcraft..
[-] Searching now in DNSdumpster..
[-] Searching now in Virustotal..
[-] Searching now in ThreatCrowd..
[-] Searching now in SSL Certificates..
[-] Searching now in PassiveDNS..
[-] Saving results to file: amazon-sub.txt
[-] Total Unique Subdomains Found: 996
www.microsoft.com
1501.microsoft.com
3rdpartysource.microsoft.com
a.microsoft.com
...snip

real	7m14.996s
user	0m2.722s
sys	0m0.388s
[ blackarch ~ ]# cat /usr/share/sublist3r/amazon-sub.txt |wc -l
996
```

- AMASS

```
[ blackarch ~ ]# time amass enum -d microsoft.com
Average DNS queries performed: 1276/sec, DNS names remaining: 4004
wwwco2test78.microsoft.com
...snip
Average DNS queries performed: 1454/sec, DNS names remaining: 26043
bmsuc01.manage-beta.microsoft.com
vh54.virtuallab.microsoft.com
^C
OWASP Amass v3.0.3                                https://github.com/OWASP/Amass
--------------------------------------------------------------------------------
332 names discovered - api: 316, scrape: 16
--------------------------------------------------------------------------------
ASN: 1103 - SURFNET-NL SURFnet, The Netherlands, NL
	2002::/16         	1    Subdomain Name(s)
ASN: 6584 - MICROSOFT-GP-AS - Microsoft Corporation, US
	194.69.126.0/23   	1    Subdomain Name(s)
ASN: 30148 - SUCURI-SEC - Sucuri, US
	192.124.249.0/24  	1    Subdomain Name(s)
ASN: 8075 - MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
	134.170.0.0/16    	56   Subdomain Name(s)
	13.64.0.0/11      	11   Subdomain Name(s)
	94.245.64.0/18    	4    Subdomain Name(s)
	23.96.0.0/14      	3    Subdomain Name(s)
	111.221.16.0/20   	1    Subdomain Name(s)
	64.4.0.0/18       	8    Subdomain Name(s)
	191.232.0.0/13    	2    Subdomain Name(s)
	70.37.128.0/18    	2    Subdomain Name(s)
	207.46.48.0/20    	3    Subdomain Name(s)
	207.46.128.0/17   	19   Subdomain Name(s)
	147.243.0.0/16    	1    Subdomain Name(s)
	207.46.0.0/19     	7    Subdomain Name(s)
	207.46.64.0/18    	6    Subdomain Name(s)
	40.64.0.0/10      	8    Subdomain Name(s)
	23.103.128.0/17   	7    Subdomain Name(s)
	20.184.0.0/13     	1    Subdomain Name(s)
	52.160.0.0/11     	13   Subdomain Name(s)
	23.100.0.0/15     	3    Subdomain Name(s)
	207.68.128.0/18   	4    Subdomain Name(s)
	20.40.0.0/13      	1    Subdomain Name(s)
	65.52.0.0/14      	33   Subdomain Name(s)
	104.40.0.0/13     	2    Subdomain Name(s)
	52.224.0.0/11     	5    Subdomain Name(s)
	204.79.195.0/24   	1    Subdomain Name(s)
	104.208.0.0/13    	8    Subdomain Name(s)
	168.62.0.0/15     	1    Subdomain Name(s)
	157.56.0.0/16     	12   Subdomain Name(s)
	157.55.0.0/16     	2    Subdomain Name(s)
	213.199.128.0/18  	3    Subdomain Name(s)
ASN: 1221 - ASN-TELSTRA Telstra Corporation Ltd, AU
	203.40.0.0/13     	2    Subdomain Name(s)
ASN: 22606 - EXACT-7 - ExactTarget, Inc., US
	136.147.186.0/24  	23   Subdomain Name(s)
ASN: 20940 - AKAMAI-ASN1, US
	104.86.110.0/23   	8    Subdomain Name(s)
	104.84.152.0/23   	3    Subdomain Name(s)
	95.101.142.0/24   	6    Subdomain Name(s)
	104.123.68.0/24   	1    Subdomain Name(s)
	92.123.155.0/24   	8    Subdomain Name(s)
	23.60.69.0/24     	4    Subdomain Name(s)
ASN: 5511 - OPENTRANSIT, FR
	88.221.128.0/21   	2    Subdomain Name(s)
ASN: 3598 - MICROSOFT-CORP-AS - Microsoft Corporation, US
	131.107.0.0/16    	48   Subdomain Name(s)
	167.220.0.0/16    	11   Subdomain Name(s)
	157.58.0.0/16     	2    Subdomain Name(s)
ASN: 11855 - ASN-INTERNAP-BLK - Internap Corporation, US
	70.42.224.0/21    	1    Subdomain Name(s)

real	29m20.301s
user	7m6.331s
sys	3m46.000s
```

- ASSETFINDER

```
[ blackarch ~ ]# time assetfinder -subs-only microsoft.com
office2010.microsoft.com
downloadoffice2010.microsoft.com
www20.downloadoffice2010.microsoft.com
...snip
ebis.one.microsoft.com

real	6m1.117s
user	0m0.113s
sys	0m0.042s

# I copied and pasted the results into a TXT file and then did a:
sechacklabs@SecHackLabs /tmp> cat subdomains-assetfinder.txt |wc -l
4630
```
