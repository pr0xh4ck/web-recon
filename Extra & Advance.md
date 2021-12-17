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

















































































































































