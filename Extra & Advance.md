### Tips 1
```
Found an #ElasticSearch instance while doing #recon?

Hit these endpoints -

https://elastic.host/_cat/api
(More in the thread, add your own as well)
/_cat/aliases
/_cat/aliases/{alias}
/_cat/thread_pool
/_cat/thread_pool/{thread_pools}
/_cat/plugins
/_cat/fielddata
/_cat/fielddata/{fields}
/_cat/nodeattrs
/_cat/repositories
/_cat/snapshots/{repository}
/_cat/templates
/_cat/allocation
/_cat/shards
/_cat/shards/{index}
/_cat/master
/_cat/nodes
/_cat/tasks
/_cat/indices
/_cat/indices/{index}
/_cat/segments
/_cat/segments/{index}
/_cat/count
/_cat/count/{index}
/_cat/recovery
/_cat/recovery/{index}
/_cat/health
/_cat/pending_tasks
/_mapping
```

### Tips 2
```
Shodan dorks:
kibana content-length:217

Google dorks:
inurl:app/kibana
inurl:app/kibana intext:Loading Kibana
inurl::5601/app/kibana
```

### Tips 3
```
In a cloud test if you find a .cspkg file its a gold mine, 
its a zip file with all the compiled code and config files.
```

### Tips 4
```
Want to find employees of a company on github? 
Use this: https://github.com/search?q={COMPANY_NAME}-&type=Users. 
This will help to find any users who have "company_name-" in their name. 
Most of the time these accounts are employee accounts or is company owned.
```

### Tips 5
```
If you want to know the name of inside-site s3 bucket - just put %c0 into url
```

### Tips 6
```
Here's my favourite way to reliably bruteforce subdomains: 
cat SecLists/Discovery/DNS/dns-Jhaddix.txt | subgen -d DOMAIN.TLD | zdns A --name-servers 1.1.1.1 --threads 500 | jq -r "select(.data.answers[0].name) | .name"
```

### Tips 7
```
on github for http://target.com
take a look and check 

http://target.okta.com password
http://target.onelogin.com password
target.service-now password
http://target.atlassian.net password
http://target.jfrog.io password
http://target.sharepoint.com password
```

### Tips 8
```
Wordpress juicy endpoints (beginners)
1) wp-includes [directory]
2) index.php
3) wp-login.php
4) wp-links-opml.php
5) wp-activate.php
6) wp-blog-header.php
7) wp-cron.php
8) wp-links.php
9) wp-mail.php
10) xmlrpc.php
11) wp-settings.php
12) wp-trackback.php
```

### Tips 9
```
1- find subdomain with http://crt.sh
2- see interesting url
3- full port scan
4- port 3001 | open
5- grafana admin portal
6- use default credentials admin:admin
7- success login to admin portal
```

### Tips 10 recon 1
```
Bypass SSL Pinning Of Mobile - Desktop
two Use Nmap - Nuclei - FFUF - Burp Suite
Manage Axiom Tool e.g. 200 Instances On Your VPS ≈ 1000 - 2000 Banknote with dollar sign / Month
Understand VHost , SSRF , Path Traversal , IDOR
Hunt 8 - 12 Hours / Day
Patient Man
```

### Tips 11 recon 2
```
Create a Team 3 - 4 Members
2 - 3 Months Of Hunting On Large-Scale
Scan Entire Internet --top-ports 3328 + Grap TLS-Certificates
Deep Dive Into Specific Third-Party Target
Maybe More If The Members Will Share Other Plans 
```

### Tips 12
```
Tips: I never miss dir fuzzing
ffuf -recursion -mc all -ac -c -e .htm,.shtml,.php,.html,.js,.txt,.zip,.bak,.asp,.aspx,.xml,.sql,.old,.at,.inc -w path -u https://target.com/FUZZ -t 5000
```

### Tips 13
```
inurl:/axis2/axis2-web/HappyAxis.jsp 
Thank me later :) 
```

### Tips 14
```
If you found a GitLab instance, try to login as root/admin with those credentials:-

Username: root & pass: 5iveL!fe
Username: admin & Pass: 5iveL!fe

You can find it with #shodan :

org:"Target" http.title:"GitLab"
```

### Tips 15
```
Another hit by Github recon.
SwagRed heart+bounty $$$

Github dorks:-

"Target" "LdapUsername":
"Target" "ConnectionStrings":
"Target" string _password = 
```

### Tips 16
```

```































































































































