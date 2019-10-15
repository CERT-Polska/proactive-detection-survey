## Network Intrusion Detection System
+ Snort
+ Suricata
+ Bro/Zeek
+ RITA (https://github.com/activecm/rita)
+ AIEngine 

## Network flow monitoring
+ NFSen
+ pmacctd
+ vflow
+ Ntopng
+ nfdump & nfcapd
+ SiLK
+ GoFlow
+ Yaf
+ Argus
+ fprobe
+ Joy (https://github.com/cisco/joy)
+ ipt_NETFLOW 

## Full packet capture
+ Moloch
+ OpenFPC
+ Stenographer https://github.com/google/stenographer
+ PcapDB https://github.com/dirtbags/pcapdb

## Sinkholing
+ generic web server (Apache, Ngnix, etc.)

## Monitoring of internet routing
+ BGPalerter
+ bgp-watcher

## Passive monitoring of unused IP space (network telescope/darknet)
+ one of the network flow monitoring or full packet capture tools above

## Systems for aggregation, correlation and visualization of logs and other event data
+ MozDef
+ OSSEC
+ HIDS
+ OSSIM
+ Maltrail - https://github.com/stamparm/maltrail
+ Malcolm - https://github.com/idaholab/Malcolm
+ Hunting ELK - https://github.com/Cyb3rWard0g/HELK
+ ELK

## Monitoring specific to industrial control systems (ICS/SCADA)
+ GRASSMARLIN - https://github.com/nsacyber/GRASSMARLIN
+ Splonebox - https://github.com/splone/splonebox-core

## Monitoring of cloud services
+ Scout Suite - https://github.com/nccgroup/ScoutSuite
+ Security Monkey - https://github.com/Netflix/security_monkey

## Passive DNS
+ https://github.com/gamelinux/passivedns - self hosted
+ Circl.lu - service https://www.circl.lu/services/passive-dns/
+ https://www.dnsdb.info/ - FairSight - commercial
+ Passivetotal - commercial
+ Cisco Umbrella Investigate - commercial
+ D4 Passive DNS backend and analyzer - analyzer-d4-passivedns

## DNS request monitoring (monitoring of how often and when certain domain names were queried and by which addresses)
+ Local resolver logs
+ Cisco Umbrella Investigate

## Other DNS monitoring (monitoring of DNS ecosystem other than Passive DNS and request monitoring. It includes, for example, monitoring of new domain names in search of phishing sites)
+ Zone files + regexes
+ Centralized Zone Data Service (CZDS)

## Endpoint monitoring
+ osquery - https://github.com/osquery/osquery
+ Sysmon
+ OSSEC
+ Wazuh - https://github.com/wazuh/wazuh
+ Weakforced - https://github.com/PowerDNS/weakforced
+ StreamAlert - https://github.com/airbnb/streamalert
+ Zentral - https://github.com/zentralopensource/zentral

## X.509 certificates monitoring
+ CIRCL Passive SSL (online)
+ crt.sh (online)
+ Cert Spotter
+ D4 project's sensor-d4-tls-fingerprinting

## Vulnerability scanning
+ OpenVAS - https://github.com/greenbone/openvas
+ Unfetter - https://nsacyber.github.io/unfetter/
+ ZMap
+ nmap
+ masscan
+ Metasploit

## Automated spam collection
+ Spamscope

## Sandbox (automated systems for behavioral analysis)
+ Cuckoo
+ Online free:
    + app any run
    + Cuckoo CERT-EE
    + Hybrid analysis
    + CAPE Sandbox (hosted + online)

## Automated mobile malware analysis
+ androguard
+ androwarn
+ Koodous (online)

## Automated static malware analysis (for example: extraction of indicators from binaries or memory dumps, YARA signature matching)
+ CAPE Sandbox
+ RATDecoders / malwareconfig / malconf
+ https://malwareconfig.com/ (online)
+ MalConfScan
+ malduck / roach

## Leak monitoring
+ AIL
+ Pastebins monitoring
+ Repository monitoring (secrets, passwords) - https://github.com/awslabs/git-secrets
+ https://github.com/tleyden/keynuker

## Media/news monitoring
+ Social media monitoring
+ Blogs
+ EMM (European Media Monitor - CERT-EU) 
 
