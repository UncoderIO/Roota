![Logo](images/roota_logo.png)
# RootA, the Open-Source Language for Collective Cyber Defence
## Welcome to RootA
Welcome to the RootA repository, a place that connects cybersecurity enthusiasts who are eager to collaborate on RootA rules and help evolve RootA as an open-source language for collective cyber defense. Despite all cyber defenders having a common goal, they tend to speak different languages. Driven by a common mission to bridge this gap and industry collaboration, we’ve created this open-source RootA project.

**Table Of Contents:**

- [What Is RootA](#what-is-roota)
- [Why RootA](#why_roota)
- [Writing RootA Rules](#writing-roota-rules)
- [How to Contribute](#how-to-contribute)
- [Questions & Feedback](#questions--feedback)
- [Maintainers](#maintainers)
- [Credits](#credits)
- [Licenses](#licenses)
- [Resources & Useful Links](#resources--useful-links)
  
## What Is RootA
RootA is a public-domain language for collective cyber defense, created to make threat detection, incident response, and actor attribution simple. It acts as an open-source wrapper on top of most of the existing SIEM, EDR, XDR, and Data Lake query languages. If you learn the basics of RootA, you will be able to contribute to collective defense. And if you have mastered a specific SIEM language, with RootA and Uncoder.IO you can speak them all.

## Why RootA
The objective of RootA is to accelerate the global cyber industry collaboration. You can easily start performing Detection Engineering tasks, having any background in writing SIEM or EDR detection rules. Alternatively, if you are good with generic languages like Sigma or Yara, then RootA will look like the next logical step forward.

### Enabling Cross-Platform Query Translation
With RootA acting as a wrapper, cyber defenders can take a native rule or query and augment it with metadata to automatically translate the code into other SIEM, EDR, XDR, and Data Lake languages without the need to learn new technology:

- **Simple universal format.** RootA is expressed using YAML, a wide-spread, easy-to-write and human-readable format.
- **Keeping the full power of your query.** RootA lets you capture all the native SIEM functions, including aggregations, correlations, and using multiple log sources. This way, your complex detection logic can later be rendered in other languages.
- **Flexibility.** Depending on your SIEM, you can rely on log sources explicitly or implicitly defined in the native query itself or in the customizable `logsource` field.
- **No need to learn a new technology.** To capture detection with RootA, you don't have to learn a new query language. The detection logic is specified in the native language of your SIEM, EDR, XDR, or Data Lake technology.

### CTI and Metadata Enrichment
RootA includes fields to define relevant cyber threat intelligence and metadata to create a self-sufficient document capturing the whole use case rather than mere detection logic:

- **Mapping to TTPs.** Link detection logic to related tactics, techniques, and procedures in terms of MITRE ATT&CK®. Use custom tags to make the mapping even more tailored and detailed.
- **Timeline.** Ensure a clear understanding of the adversary's behavior over the course of an attack. Specify when a particular actor, tool, or threat was detected.
- **Triage facilitation.** Define the severity of a potential hit to help in its prioritization. Be mindful of SOC operators who are sometimes overwhelmed with alerts.
- **Author and license.** Writing a rule requires a great deal of effort and expertise. Ensure the credit is on the right person and define the license for use.
- **Details.** Well, that's where the devil is. Describe how the detection logic works and provide anything that may be useful to understand the code or use it properly.
- **Response.** Define response recommendations for cases where the detection produces hits. Refer to best practices or provide specific instructions.
  
### Community Collaboration
- **Use Case Documentation.** Relying on the RootA language, cyber defenders can seamlessly document and share their threat research in a universal format describing the whole use case enriched with CTI, ATT&CK tagging, and other relevant fields.
- **Knowledge Sharing.** RootA enables defenders to share vendor-agnostic use cases enriched with comprehensive metadata rather than mere detection logic to foster global information exchange among industry peers.
- **Collective Cyber Defense.** Despite all cyber defenders having a common goal, they tend to speak different languages. To bridge this gap, we’ve created RootA, a single language for threat detection and response. 

## Writing RootA Rules
This guide helps you create a RootA rule. You can start writing RootA rules in any code editor that supports YAML. We recommend using Uncoder which aggregates built-in RootA templates to streamline your detection engineering process. 

RootA is designed with broad customization opportunities. Use the RootA minimal template if you just need to capture seamless cross-platform query translation into any SIEM, EDR, or XDR native format. Alternatively, apply full or short RootA templates to document your security use case in detail and share the research with peers.

RootA is meant to be a highly flexible format with only two required fields: `name` and `detection`. All other fields are optional. 

### RootA Rule Templates
You can get started by using one of the available rule templates, including full, short, or minimum based on your current needs. 

#### Minimal RootA rule example:
```
name: Possible Credential Dumping using comsvcs.dll
detection:
    language: splunk 
    body: index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com" OR Image="*.scr")
```
#### Short RootA rule example:
```
name: Possible Credential Dumping using comsvcs.dll
details: Adversaries can use built-in library comsvcs.dll to dump credentials on a compromised host.
author: SOC Prime Team
severity: medium
references:
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html
    - https://lolbas-project.github.io/lolbas/Binaries/msedgewebview2/
logsource:
    vendor: microsoft
    product: windows
    category: process_creation
detection:
    language: splunk
    body: index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com" OR Image="*.scr")
```
#### Full RootA rule example:
```
name: Possible Credential Dumping using comsvcs.dll
uuid: 009a001b-1623-4320-8369-95bf0d651e8e
details: Adversaries can use the built-in library comsvcs.dll to dump credentials on a compromised host.
author: SOC Prime Team, SOC Prime Team2
version: 0.1
license: DRL 1.1
type: query
class: campaign 
severity: medium
date: 01-01-2023
timeline:
    01-01-2023: Ducktail, MerlinAgent
    04-02-2023: Lazarus
    06-03-2023: cve-2023-1337, Ducktail
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
    source: Windows Security Event Log
    enable: 'Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process 
detection:
    language: splunk
    schema: cim
    body: index=* source="WinEventLog:*" AND (Image="*.exe" OR Image="*.com" OR Image="*.scr")
response:
    #actions:
    #    Preparation:
    #        - Make personnel report suspicious activity.
    #    Identification:
    #        - List of hosts communicated with internal domain.
```

### Fields
[This specification](local url) includes the list of all fields that can be used to write a RootA rule.

## How to Contribute
Thank you for your interest in the RootA open-source project! Your contribution really matters in evolving the project and helping us make the RootA language even more useful for the global cyber defender community.

To submit your pull request with your ideas or suggestions for changes, take the following steps:

1. Fork the [RootA repository](#) and clone your fork to your local environment.
2. Create a new feature branch in which you’re going to make your changes.
3. Then commit your changes to your newly created feature branch.
4. Push the changes to your fork.
5. Create a new Pull Request  
    a. Clicking the New Pull Request button.  
    b. Select your fork along with a feature branch.  
    c. Provide a title and a description of your changes. Make sure they are both clear and informative.  
    d. Finally, submit your Pull Request and wait for its approval.  

Thank you for your contribution to the RootA project!

## Questions & Feedback
Please submit your technical feedback and suggestions to support@socprime.com or a RootA channel in [SOC Prime’s Discord](https://discord.gg/socprime). Also, refer to the guidance for contributors to support the RootA project or simply report issues.

## Maintainers
Driving the idea of establishing a unified language and toolkit for threat detection and response since 2015, SOC Prime team has developed RootA from the ground up, with major contributions to the project made by:
- Roman Ranskyi
- Alex Bredikhin
- Ruslan Mikhalov
- Andrii Bezverkhyi

## Credits
We are genuinely grateful to security professionals who contribute their time, expertise, and creativity to evolve the RootA open-source project.

## Licenses
The contents of this repo, along with RootA specifications, are in the public domain.

## Resources & Useful Links
[RootA.IO](https://roota.io/) - the main website page of the single language for threat detection & response  
[Uncoder.IO](https://uncoder.io/) - free online translation engine for RootA, Sigma, and IOC-based queries  
[Uncoder AI](https://tdm.socprime.com/uncoder-ai) - SaaS version of Uncoder acting as advanced IDE for detection engineering  
[SOC Prime Platform](https://tdm.socprime.com/login) - the industry-first platform for collective cyber defense  
[About SOC Prime](https://socprime.com/) 
