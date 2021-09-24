```pr0xh4ck © 2021```

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
    - [Wordlists](#wordlists)
    - [Miscellaneous](#miscellaneous)
    - [Log File Analyze](#log-file-analyze)
    - [Public programs](#programs)
    - [Burp Suite Extension](#burp-suite-extesion)





---


## recon
### ip-test
 - [centralops](https://centralops.net/co/)
 - [spyonweb](https://spyonweb.com/)
 - [viewdns](https://viewdns.info/)
 - [shodan cli](https://cli.shodan.io/)
 
 
### dns
 - [dnsrecon](https://github.com/darkoperator/dnsrecon)
 - [host linux tool](https://tools.kali.org/)
 - [nslookup](https://www.nslookup.io/)
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


### internet-search-engine-discovery
  - [shodan.io](https://www.shodan.io/)
  - [spyse](https://spyse.com/)
  - [censys](https://censys.io/ipv4)
  - [fofa](https://fofa.so/)
  - [binary edge](https://www.binaryedge.io/)


### subdomain-enumeration
 - [certificate.transparency](https://certificate.transparency.dev/)
 - [crt.sh](https://crt.sh/)
 - [crtfinder](https://github.com/eslam3kl/crtfinder) - Fast tool to extract all subdomains from crt.sh website. Output will be up to sub.sub.sub.subdomain.com with standard and advanced search techniques
 - [amass](https://github.com/OWASP/Amass)
 - [subfinder](https://github.com/projectdiscovery/subfinder)
 - [dnsdumpster](https://dnsdumpster.com/)
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

> Exception(web) subdomain enumeration
 - [dns](https://dns.bufferover.run/dns?q=)
 - [tls](https://tls.bufferover.run/dns?q=)

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
 - [udork.sh](https://github.com/m3n0sd0n4ld/uDork)
 - [fav-up](https://github.com/pielco11/fav-up)
 - [testssl](https://github.com/drwetter/testssl.sh)
 - [bbtz](https://github.com/m4ll0k/BBTz)
 - [sonar search](https://github.com/Cgboal/SonarSearch)
 - [notify](https://github.com/projectdiscovery/notify)
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
 


### http-probing
 - [httprobe](https://github.com/tomnomnom/httprobe)
 - [httpx](https://github.com/projectdiscovery/httpx)


#### subdomain-takeover
 - [subjack](https://github.com/haccer/subjack) - Subdomain Takeover tool written in Go
 - [SubOver](https://github.com/Ice3man543/SubOver) - A Powerful Subdomain Takeover Tool
 - [autoSubTakeover](https://github.com/JordyZomer/autoSubTakeover) - A tool used to check if a CNAME resolves to the scope address. If the CNAME resolves to a non-scope address it might be worth checking out if subdomain takeover is possible.
 - [NSBrute](https://github.com/shivsahni/NSBrute) - Python utility to takeover domains vulnerable to AWS NS Takeover
 - [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - "Can I take over XYZ?" — a list of services and how to claim (sub)domains with dangling DNS records.
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
 - [cmseek](https://github.com/Tuhinshubhra/CMSeeK)
 - [webanlyze](https://github.com/rverton/webanalyze)
 - [whatweb](https://github.com/urbanadventurer/WhatWeb)
 - [wappalyzer](https://www.wappalyzer.com/)
 - [wappalyzer cli](https://github.com/AliasIO)
 - [build with](https://builtwith.com/)
 - [build with cli](https://github.com/claymation/python-builtwith)
 - [backlinkwatch](http://backlinkwatch.com/index.php)
 - [retirejs](https://github.com/RetireJS/retire.js)


### automation
- [wapiti-scanner](https://github.com/wapiti-scanner) - Scan your website 
- [nuclei](https://github.com/projectdiscovery/nuclei) - Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use.
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
- 

> wordpress
   - [wpscan](https://github.com/wpscanteam/wpscan)
> joomla
   - [joomscan](https://github.com/OWASP/joomscan)


### cloud-enumeration
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
 
> Git
- [GitTools](https://github.com/internetwache/GitTools) - A repository with 3 tools for pwn'ing websites with .git repositories available
- [gitjacker](https://github.com/liamg/gitjacker) - Leak git repositories from misconfigured websites
- [git-dumper](https://github.com/arthaud/git-dumper) - A tool to dump a git repository from a website
- [GitHunter](https://github.com/digininja/GitHunter) - A tool for searching a Git repository for interesting content
- [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG...


### email-hunting 
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
 - [waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch all the URLs that the Wayback Machine knows about for a domain
 - [gau](https://github.com/lc/gau) - Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl. 
 - [gauplus](https://github.com/bp0lr/gauplus) - A modified version of gau
 - [waybackpy](https://github.com/akamhy/waybackpy) - Wayback Machine API Python interfaces and CLI tool. 
 
> Find reflected params
 - [gxss](https://github.com/KathanP19/Gxss) - A tool to check a bunch of URLs that contain reflecting params. 
 - []()
 
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
 - [brokenlinkhijacker](https://github.com/MayankPandey01/BrokenLinkHijacker)
 - [jsa](https://github.com/w9w/JSA)
 
 
### parameter-finder
- [paramspider](https://github.com/devanshbatham/ParamSpider) - Mining parameters from dark corners of Web Archives 
- [parameth](https://github.com/maK-/parameth) - This tool can be used to brute discover GET and POST parameters
- [param-miner](https://github.com/PortSwigger/param-miner) - This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.
- [ParamPamPam](https://github.com/Bo0oM/ParamPamPam) - This tool for brute discover GET and POST parameters.
- [Arjun](https://github.com/s0md3v/Arjun) - HTTP parameter discovery suite.

### bypass-forbidder-directory
 - [dirdar](https://github.com/M4DM0e/DirDar) - DirDar is a tool that searches for (403-Forbidden) directories to break it and get dir listing on it 


### wordlists
  - [seclists](https://github.com/danielmiessler/SecLists)
  - [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings)
  - [assetnote](https://wordlists.assetnote.io/)
  - [samlists](https://github.com/the-xentropy/samlists)
  - [all in one](https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt)
  - [fuzz](https://github.com/Bo0oM/fuzz.txt)


### miscellaneous
  - [hack-tools](https://github.com/edoardottt/lit-bb-hack-tools)
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
  - [reconftw.sh](https://github.com/six2dez/reconftw/blob/main/reconftw.sh)
  - [radamsa](https://gitlab.com/akihe/radamsa)
  - [reconmaster](https://github.com/YouGina/reconmaster/)
  - [unicode-converter](https://www.branah.com/unicode-converter) - Unicode Converter  Decimal, text, URL, and unicode converter
  - [breport](https://buer.haus/breport/) - Bounty report genarator


> Uncategorized
- [JSONBee](https://github.com/zigoo0/JSONBee) - A ready to use JSONP endpoints/payloads to help bypass content security policy (CSP) of different websites.
- [CyberChef](https://github.com/gchq/CyberChef) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis
- [bountyplz](https://github.com/fransr/bountyplz) - Automated security reporting from markdown templates (HackerOne and Bugcrowd are currently the platforms supported)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads and bypass for Web Application Security and Pentest/CTF 
- [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) - This repo contains hourly-updated data dumps of bug bounty platform scopes (like Hackerone/Bugcrowd/Intigriti/etc) that are eligible for reports
- [android-security-awesome](https://github.com/ashishb/android-security-awesome) - A collection of android security related resources
- [awesome-mobile-security](https://github.com/vaib25vicky/awesome-mobile-security) - An effort to build a single place for all useful android and iOS security related stuff.
- [awesome-vulnerable-apps](https://github.com/vavkamil/awesome-vulnerable-apps) - Awesome Vulnerable Applications
- [XFFenum](https://github.com/vavkamil/XFFenum) - X-Forwarded-For [403 forbidden] enumeration

### log-file-analyze
- [Dialog](https://github.com/SxNade/DiaLog)

### programs
- [disclose](https://github.com/disclose)
- [bug bounty dork](https://github.com/sushiwushi/bug-bounty-dorks)
- [crunchbase](https://www.crunchbase.com/) - Discover innovative companies and the people behind them
- [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) - This repo contains hourly-updated data dumps of bug bounty platform scopes (like Hackerone/Bugcrowd/Intigriti/etc) that are eligible for reports
- 


### burp-suite-extesion
   - [Active scan ++]()
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



















