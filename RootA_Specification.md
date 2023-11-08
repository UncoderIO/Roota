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
  - [detection](#detection)
    - [language](#language)
    - [body](#body)
  - [logsource](#logsource)
    - [product](#product)
    - [log_name](#log_name)
    - [class_name](#class_name)
    - [category](#category)
    - [service](#service)
    - [audit](#audit)
      - [source](#source)
      - [enable](#enable)
  - [timeline](#timeline)
  - [references](#references)
  - [tags](#tags)
  - [license](#license)
  - [version](#version)
  - [uuid](#uuid)
  - [correlation](#correlation)
    - [timeframe](#timeframe)
    - [functions](#functions)
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
mitre-attack:
    - t1003.001
    - t1136.003
detection:
    language: splunk-spl-query # elastic-lucene-query, logscale-lql-query, mde-kql-query
    body: index=* ((((process="*comsvcs*") AND (process="*MiniDump*")) OR ((process="*comsvcs*") AND (process="*#24*"))) OR ((process="*comsvcs*") AND (process="*full*")))
logsource:
    product: Windows                # Sigma or OCSF products
    log_name: Security              # OCSF log names
    class_name: Process Activity    # OCSF classes
    #category:                      # Sigma categories
    #service:                       # Sigma services
    audit:
        source: Windows Security Event Log 
        enable: Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process
timeline:     # for Actors and campaigns only
    2022-04-01 - 2022-08-08: Bumblebee
    2022-07-27: KNOTWEED
    2022-12-04: UAC-0082, CERT-UA#4435
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

Description: The name of the rule which reflects the goal and the method used in the rule.

Example: `name: Possible Credential Dumping using comsvcs.dll`


## details
Format: `text (max 8192 characters)`

Required: *optional*

Description: A short description of the rule that should give more context to the detection and threats that can be detected with this rule.

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

Example: `date: 2022-10-31`


## mitre-attack

Format: `text (max 1024 characters)`

Required: *optional*

Description: List of MITRE ATT&CK (r) Techniques, Subtechniques, Groups, Software IDs. All IDs should be in lowercase.

Example: 
```
mitre-attack:
    - t1136.003
    - t1087.004
    - t1069
```


## detection

Required: *mandatory*

Description: This section contains the fields that specify the detection logic and the language used to express it. See the specifications of the fields below.


### language

Format: `text (max 128 characters)`

Required: *mandatory*

Description: The field should specify the name of the SIEM/EDR/XDR in the appropriate format. See the list of supported platforms in the Possible Values section.

Possible Values: 

- `sentinel-kql-query` for Microsoft Sentinel Query
- `splunk-spl-query` for Splunk Query
- `crowdstrike-spl-query` for CrowdStrike Query
- `elastic-lucene-query` for Elasticsearch Query
- `opensearch-lucene-query` for AWS OpenSearch Query
- `logscale-lql-query` for Falcon LogScale Query
- `mde-kql-query` for Microsoft Defender for Endpoint Query
- `qradar-aql-query` for IBM QRadar Query
- `sigma-yml-rule` for Sigma Rule
- `athena-sql-query` for AWS Athena Query (Security Lake)
- `chronicle-yaral-query` for Chronicle Security Query
  
Example: `language: splunk-spl-query`


### body

Format: `text (max 8192 characters)`

Required: *mandatory*

Description: This section should contain the rule's logic. It should be a SIEM/EDR/XDR query in the native format. The query should be in one line. In case you have a multiline query, you should join lines before adding it to the RootA rule. 

Example: `index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com")`


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

Description: A category is used when disparate data sources provide the same type of event logging. For instance, Microsoft Windows 4688 & Sysmon Event ID 1 both provide process creation logs and share many of the same fields. Therefore, we can write and consume rules written generally for "process_creation" instead of rules written specifically for exact data sources. The same goes for most firewalls, proxies, etc.

Example: `category: process_creation`


### service

Format: `text (max 128 characters)`

Required: *optional*

Description: A service is used when a distinct data source exists for the relevant event logs. As an example, Amazon Cloudtrail eventing is specific to AWS. You generally cannot use a rule made for one service against another data source.

Example: `service: apache`


## audit

Required: *optional*

Description: This section describes in detail what logging service should be enabled to have the logs required for the rule.


### source

Format: `text (max 128 characters)`

Required: *optional*

Description: The full name of the logging provider or logging service that logged the event. For example, Microsoft-Windows-Security-Auditing.

Example: `source: Microsoft-Windows-PowerShell/Operational`


### enable

Format: `text (max 2048 characters)`

Required: *optional*

Description: This section provides detailed instructions on how to enable the required log audit in the source system.

Example: `enable: 'Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation'`


## timeline

Format: 

```
YYYY-MM-DD - YYYY-MM-DD: Actor1, Actor2, TLP:CLEAR
YYYY-MM-DD: Actor1, Actor3, TLP:GREEN
```

Required: *optional*

Description: It has to include the name of the actor, TLP:key, and dates when the behavior described in the RootA rule was used by the Actor. On the contrary to indicators of compromise, which are Actor specific, behaviors are constant while Actor is a variable. If the TLP:key is not defined, it is perceived as TLP:CLEAR. The period can be defined with two dates (first and last seen) or with one date.

Example: 
```
timeline:
    2023-01-01 - 2023-03-06: Ducktail, MerlinAgent
    2023-02-04: Lazarus
```


## references

Format: `text (max 2048 characters)`

Required: *optional*

Description: Links to articles in the media, posts, or other sources that describe the threat, exploit, behavior, etc. that the rule detects.

Example: 
```
references: 
    - https://badoption.eu/blog/2023/06/21/dumpit.html
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

Example: `uuid: 009a001b-1623-4320-8369-95bf0d651e8e`

## correlation
Required: *optional*

Description: The correlation section is responsible for the correlation of query results. 

Example:
```
correlation: 
    timeframe: 1m
    functions: count() > 10
```

### timeframe
Format: `text (8 characters)`

Required: *optional*

Description: A time frame for the functions, which is defined as a span of seconds (s), minutes (m), hours (h), days (d), and weeks(w). 

Example: `timeframe: 1m`

### functions
Format: `text (128 characters)`

Required: *optional*

Description: Functions can be used for correlation of query results, for example, to trigger only in case certain thresholds of certain fields are met. This is still under development. First functions to be released:

- `count()` - count of field values
- `by` - group by field
- `dcount` - unique field values
Example: `functions: count() > 10`


## response
Reserved for future
