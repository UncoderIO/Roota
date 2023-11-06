# RootA Specification
* Version 1.0.0
* Release date 2023-10-06

# Contents
- [Format](#format)
- [Structure](#structure)
- [Fields](#fields)
  - [name](#name)
  - [details](#details)
  - [author](#author)
  - [severity](#severity)
  - [type](#type)
  - [class](#class)
  - [date](#date)
  - [mitre-attack](#mitre-attack)
  - [timeline](#timeline)
  - [logsource](#logsource)
    - [product](#product)
    - [log_name](#log_name)
    - [class_name](#class_name)
    - [category](#category)
    - [service](#service)
    - [audit](#audit)
      - [source](#source)
      - [enable](#enable)
  - [detection](#detection)
    - [language](#language)
    - [body](#body)
  - [references](#references)
  - [tags](#tags)
  - [license](#license)
  - [version](#version)
  - [uuid](#uuid)
  - [correlation](#correlation)
  - [response](#response)

# Format
RootA is structured in the YAML format

# Structure
```
name: Rule Name
details: Rule description
author: Rule author
severity: high
type: query 
class: behaviour
date: 2020-05-24
mitre-attack: t1003.001
timeline:     # for Actors and campaigns only
    2022-04-01 - 2022-08-08: Bumblebee
    2022-07-27: KNOTWEED
    2022-12-04: UAC-0082, CERT-UA#4435
logsource:
    product: Windows                # Sigma or OCSF products
    log_name: Security              # OCSF log names
    class_name: Process Activity    # OCSF classes
    #category:                      # Sigma categories
    #service:                       # Sigma services
    audit:
        source: Windows Security Event Log 
        enable: Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process
detection:
    language: splunk-spl-query # elastic-lucene-query, logscale-lql-query, mde-kql-query
    body: index=* ((((process="*comsvcs*") AND (process="*MiniDump*")) OR ((process="*comsvcs*") AND (process="*#24*"))) OR ((process="*comsvcs*") AND (process="*full*")))
references: 
    - https://badoption.eu/blog/2023/06/21/dumpit.html
tags: Bumblebee, UAC-0082, CERT-UA#4435, KNOTWEED, Comsvcs, cir_ttps, ContentlistEndpoint
license: DRL 1.1
version: 1
uuid: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
#correlation: [] # extended format
#response: []    # extended format
```

# Fields

## name
Format: `text (max 1024 characters)`

Required: *mandatory*

Description: The name of the rule which reflects the goal and the method used in the rule

Example: name: `Possible Credential Dumping using comsvcs.dll`


## details
Format: `text (max 8192 characters)`

Required: *optional*

Description: A short description of the rule that should give more context to the detection and threats that can be detected with this rule

Example: `details: Adversaries can use the built-in library comsvcs.dll to dump credentials on a compromised host.`


## author
Format: `text (max 256 characters)`

Required: *optional*

Description: The name of the creator. It is recommended to use the same name for all your rules. Comma-separated value. 

Example: `author: SOC Prime Team`


## severity

Format: `text (max 16 characters)`

Required: *optional*

Description: The severity of the rule which indicates the level of the rule's importance and investigation priority.

Possible Values: 
- `critical` - When critical severity rules are triggered, immediate action is required. Critical rules have a very low probability of false positives, or are highly sensitive actions that must always be deconflicted.
- `high` - When high severity rules are triggered, an investigation/case should be created and completed with a high priority. Low probability of false positives after minimal tuning. 
- `medium` - Medium severity rules will likely require tuning in an average environment. After tuning, when medium security rules are triggered, a case should be generated with medium priority. 
- `low` - Low severity rules should be used as part of correlations, or to support triage and enrich the analysis environment. Some of these rules may be used as case generators after a significant amount of tuning.

Example: `severity: medium`


## type
Format: `text (max 16 characters)`

Required: *optional*

Description: The type of the rule that indicates whether the rule is intended as a threat hunting 'query' (may generate false positives) or a real-time detection 'alert' (rarely generates false positives).
An alert can be defined as a rule that in the majority of environments will cause a low false positive or true positive - benign rate. For instance, if a rule requires for someone to add domain controllers to filter out benign events, it would NOT be considered an alert.
A query can be defined as any rule that can be expected to require tuning in most environments.

Possible Values: 
- `query`
- `alert`

Example: `type: query`

## class

Format: `text (max 128 characters)`

Required: *optional*

Possible Values: 
- `campaign`
- `behavioral`
- `tool`
- `generic`
- `exploit`
- `ioc`

Description:
- `Exploit Rules`
  These are rules meant to identify the exploitation or probing of a vulnerability (e.g. CVE, General SQL-I / XSS Rules). Many of these rules would qualify as "alerts". An example would be a rule built for Log4J detection. These rules are useful indefinitely.

- `Behavioral Rules`
  These rules are meant to identify behaviors that may match an adversary's behavior based on known reporting. Many of these rules would qualify as "queries". An example of a behavioral rule would be a rule that identifies a remote login of a local administrator account. These rules will NOT include information specific to a campaign. These rules are useful retroactively, and on average have a 12+ month expectancy of usefulness.

- `Campaign Rules`
  These rules would be tied to a specific campaign. Many of these rules would qualify as "alerts". For instance, a rule that identifies a campaign by the name of the service that is installed on a Windows host. These rules should help customers identify if they have been the target of a specific campaign. These rules are useful retroactively, and have on average a 3-12 month expectancy of usefulness. 

- `Tool Rules`
  These rules identify the usage of a specific tool (offensive, or living off the land). For instance, a rule meant to identify psexec specifically would be a "tool" rule. A rule meant to identify psexec and any similar tool, without explicitly identifying attributes that are unique to those tools would be considered a behavioral rule.

 - `IOC Rule`
  Rules that are created for urgent adversary activity that has little to no other detection measures (e.g. wannacry, notpetya, mass & urgent exploitation). Mostly for IOCs like domains, IPs, hashes, URLs.

- `Generic Rules`
  These rules are meant to identify potential weaknesses in an environment. For instance, a rule that identifies weak encryption in Kerberos (RC4_HMAC_MD5). Rules that provide only information that has a very small chance of being a true-positive but is good for customers to keep an eye on. For instance, the root user account of AWS being utilized.

Example: `class: campaign`


## date

Format: `YYYY-MM-DD`

Required: *optional*

Description: The date of rule creation.

Example: date: `2022-10-31`


## mitre-attack

Format: `text (max 1024 characters)`

Required: *optional*

Description: Comma-separated MITRE ATT&CK (r) Techniques, Subtechniques, Groups, Software IDs. All IDs should be in lowercase.

Example: `mitre-attack: t1136.003, t1087.004, t1069`


## timeline

Format: 

```
YYYY-MM-DD - YYYY-MM-DD: Actor1, Actor2, TLP:CLEAR
YYYY-MM-DD: Actor1, Actor3, TLP:GREEN
```

Required: *optional*

Description: Has to include the name of the actor, TLP:key, and dates when the behavior described in the RootA rule was used by the Actor. On the contrary to indicators of compromise, which are Actor specific, behaviors are constant while Actor is a variable. If the TLP:key is not defined, it is perceived as TLP:CLEAR. The period can be defined with two dates (first and last seen) or with one date.

Example: 
```
timeline:
    2023-01-01 - 2023-03-06: Ducktail, MerlinAgent
    2023-02-04: Lazarus
```


## logsource

Required: *optional*

Description: This section describes log sources required for the rule. It is optional but could be necessary in some cases when the detection logic doesn’t describe which log sources are required. 


### product

Format: `text (max 128 characters)`

Required: *optional*

Description: The product that reported the event.

Example: `product: windows`


### log_name

Format: `text (max 128 characters)`

Required: *optional*

Description: The event log name. For example, syslog file name or Windows logging subsystem: Security.

Example: `log_name: Security`


### class_name

Format: `text (max 128 characters)`

Required: *optional*

Description: The OCSF event classes. Details: [https://schema.ocsf.io/1.0.0/classes](https://schema.ocsf.io/1.0.0/classes)

Example: `class_name: Process Activity`

### category

Format: `text (max 128 characters)`

Required: *optional*

Description: ?????

Example: `category: process_creation`


### service

Format: `text (max 128 characters)`

Required: *optional*

Description: ?????

Example: `service: apache`


## audit

Required: *optional*

Description: ?????


### source

Format: `text (max 128 characters)`

Required: *optional*

Description: ?????

Example: `source: Microsoft-Windows-PowerShell/Operational`


### enable

Format: `text (max 2048 characters)`

Required: *optional*

Description: ?????

Example: `enable: 'Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation'`


## detection

Required: *mandatory*

Description: 


### language

Format: `text (max 128 characters)`

Required: *mandatory*

Description: The field should specify the name of the SIEM/EDR/XDR in the appropriate format. See the list of supported platforms in the Possible Values section.

Possible Values: 

- `sentinel-kql-query`
- `sentinel-kql-rule`
- `splunk-spl-query`
- `splunk-spl-rule`
- `crowdstrike-spl-query`
- `elastic-lucene-query`
- `elastic-lucene-rule`
- `opensearch-lucene-query`
- `logscale-lql-query`
- `logscale-lql-rule`
- `mde-kql-query`
- `qradar-aql-query`
- `sigma-yml-rule`
- `athena-sql-query`
- `chronicle-yaral-query`
- `chronicle-yaral-rule`
  
Example: `language: splunk-spl-query`


### body

Format: `text (max 8192 characters)`

Required: *mandatory*

Description: This section should contain the rule's logic. It should be a SIEM/EDR/XDR query in the native format. The query should be in one line. In case you have a multiline query, you should join lines before adding it to the RootA rule. 

Example: `index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com")`


## references

Format: `text (max 2048 characters)`

Required: *optional*

Description: Links to articles in the media, posts, or other sources that describe the threat, exploit, behavior, etc. that the rule detects.

Example: 
```
references: 
    - https://badoption.eu/blog/2023/06/21/dumpit.html
    - 
```


## tags

Format: `text (max 1024 characters)`

Required: *optional*

Description: Comma-separated short words that can label RootA rule for keyword search.   

Example: `tags: MerlinAgent, UAC-0173, UAC-0006, Ducktail, CERT-UA#4753`


## license
Format: `text (max 256 characters)`

Required: *optional*

Description: The license of the rule. It can also contain a link to the license file.

Example: `license: DRL 1.1`


## version
Format: `X.X (major.minor version number)`

Required: *optional*

Description: The unique version number of the rule. 

Example: `version: 0.1`


## uuid
Format: `text (32 characters)`

Required: *optional*

Description: Unique ID of the rule. UUID version 4 is recommended for use. 

Example: 009a001b-1623-4320-8369-95bf0d651e8e

## correlation
Reserved for future

## response
Reserved for future
