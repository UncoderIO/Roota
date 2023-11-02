# RootA Specification
* Version 1.0.0
* Release date 2023-10-02

# Contents
- [Format](#format)
- [Structure](#structure)
- [Fields](#fields)
  - [name](#name)
  - [uuid](#uuid)
  - [details](#details)
  - [author](#author)
  - [version](#version)
  - [license](#license)
  - [type](#type)
  - [classes](#classes)
  - [severity](#severity)
  - [date](#date)
  - [timeline](#timeline)
  - [mitre-attack](#mitre-attack)
  - [tags](#tags)
  - [logsource](#logsource)
    - [layer](#layer)
    - [vendor](#vendor)
    - [product](#product)
    - [category](#category)
    - [source](#source)
    - [enable](#enable)
  - [detection](#detection)
    - [language](#language)
    - [schema](#schema)
    - [body](#body)
  - [response](#response)

# Format
RootA is structured in the YAML format

# Structure
```
name: Rule Name
uuid: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
details: Rule description
author: SOC Prime Team
version: 1.0
license: DRL 1.1
type: query
class: campagin
severity: medium
date: 01-01-2023
timeline:
    2023-01-01 - 2023-03-06: Ducktail, MerlinAgent
    2023-02-04: Lazarus
mitre-attack: t1136.003, t1087.004, t1069
tags: MerlinAgent, UAC-0173, UAC-0006, Ducktail, CERT-UA#4753, CERT-UA#5909, CERT-UA#7183
references:
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html
    - https://lolbas-project.github.io/lolbas/Binaries/msedgewebview2/
logsource:
    layer: host 
    vendor: microsoft
    product: windows
    category: process_creation
    source: Microsoft-Windows-PowerShell/Operational
    enable: 'Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation'
detection:
    language: splunk #microsoft-defender, elastic-lucene, elastic-eql, splunk
    schema: cim
    body: index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com" OR Image="*.scr") 
response:
    #actions:
    #    Preparation:
```

# Fields

## name
Format: `text (max 1024 characters)`
Required: mandatory
Description: Name of the rule which reflects the goal and the method used in the rule
Example: name: `Possible Credential Dumping using comsvcs.dll`

## uuid
Format: `text (32 characters)`
Required: optional
Description: Unique ID of the rule. UUID version 4 is recommended to use. 
Example: 009a001b-1623-4320-8369-95bf0d651e8e

## details
Format: `text (max 8192 characters)`
Required: optional
Description: A short description of the rule that should give more context to the detection and threats that can be detected with this rule
Example: `details: Adversaries can use the built-in library comsvcs.dll to dump credentials on a compromised host.`

## author
Format: `text (max 256 characters)`
Required: optional
Description: Name of the creator. It is recommended to use the same name for all your rules. Coma-separated value. 
Example: `author: SOC Prime Team`

## version
Format: `X.X (major.minor version number)`
Required: optional
Description: The unique version number of the rule. 
Example: `version: 0.1`

## license
Format: `text (max 256 characters)`
Required: optional
Description: The license of the rule. It can also contain a link to the license file.
Example: `license: DRL 1.1`

## type
Format: `text (max 16 characters)`
Required: optional
Description: The type of the rule that indicates whether the rule is intended for threat hunting ‘query’ (may generate false positives) or for real-time detection ‘alert’ (rarely generate false positives). 
Possible Values: 
- `query`
- `alert`
Example: `type: query`

## classes
Format: `text (max 128 characters)`
Required: optional
Description: ??????
Possible Values: 
- `campaign`
- `behavioral`
- `tool`
- `informational`
- `cve`
- `ioc`
Example: `class: campaign #behavioral, tool, informational, cve, ioc`

## severity
Format: `text (max 16 characters)`
Required: optional
Description: Severity of the rule which indicates the level of rule importance and investigation priority.
Possible Values: 
- `critical` - in case the rule is triggered, immediate action is required. Very low probability of false positives.
- `high` - investigation with a high priority should be in place. Low probability of false positives.
- `medium` - ?????
- `low` - ?????
Example: `severity: medium`

## date
Format: `YYYY-MM-DD`
Required: optional
Description: The date of rule creation.
Example: date: `2022-10-31`

## timeline
Format: 
`YYYY-MM-DD - YYYY-MM-DD: Actor1, Actor2, TLP:CLEAR`
`YYYY-MM-DD: Actor1, Actor3, TLP:GREEN`
Required: optional
Description: Has to include the name of the actor, TLP:key, and dates when behavior described in the RootA rule was used by the Actor. On the contrary to indicators of compromise, which are Actor specific, behaviors are constant while Actor is a variable. If the TLP:key is not defined, it is perceived as TLP:CLEAR. Period can be defined with two dates (first and last seen) or with one date.
Example: 
`timeline:`
`    2023-01-01 - 2023-03-06: Ducktail, MerlinAgent`
`    2023-02-04: Lazarus`

## mitre-attack
Format: `text (max 1024 characters)`
Required: optional
Description: Coma-separated MITRE ATT&CK Techniques, Subtechnique, Groups, Software IDs. All IDs should be in lowercase.
Example: `mitre-attack: t1136.003, t1087.004, t1069`

## tags
Format: `text (max 1024 characters)`
Required: optional
Description: Coma-separated short words that can label RootA rule for keyword search. Tags should be in lowercase, with no spaces. 
Example: `tags: MerlinAgent, UAC-0173, UAC-0006, Ducktail, CERT-UA#4753`

## logsource
Required: optional
Description: Section that describes needed log sources for the rule. It is optional but could be necessary in some cases when the detection logic doesn’t describe which log sources are required. 

### layer
Format: `text (max 128 characters)`
Required: optional
Description: ?????
Possible Values: 
- `host`
- `network`
- `cloud`
- `container`
- `application`
Example: `layer: host`

### vendor
Format: `text (max 128 characters)`
Required: optional
Description: ?????
Example: `vendor: microsoft`

### product
Format: `text (max 128 characters)`
Required: optional
Description: ?????
Example: `product: windows`

### category
Format: `text (max 128 characters)`
Required: optional
Description: ?????
Example: `category: process_creation`

### source
Format: `text (max 128 characters)`
Required: optional
Description: ?????
Example: `source: Microsoft-Windows-PowerShell/Operational`

### enable
Format: `text (max 2048 characters)`
Required: optional
Description: ?????
Example: `enable: 'Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation'`

## detection
Required: mandatory
Description: 

### language
Format: `text (max 128 characters)`
Required: mandatory
Description: The field should specify the name of the SIEM/EDR/XDR in the appropriate format. See the list of supported platforms in the Possible Values section.
Possible Values: 
- `splunk`
- `microsoft-defender`
- `elastic-lucene`
- `elastic-eql`
- `splunk`
.....
Example: `language: splunk`

### schema
Format: `text (max 128 characters)`
Required: mandatory
Description: 
Example: `schema: ocsf`

### body
Format: `text (max 8192 characters)`
Required: mandatory
Description: The section should contain a rule logic. It should be a SIEM/EDR/XDR query in the native format. The query should be in one line. In case you have a multiline query, you should join lines before adding it to the RootA rule. 
Example: `index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com")`

## response
Reserved for future
