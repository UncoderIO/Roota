<p align="left">
  <img src="images/roota_logo_double.png" width="228" height="58">
</p>

# An Open-Source Language for Collective Cyber Defence

RootA is a public-domain language for collective cyber defense, created to make threat detection, incident response, and actor attribution simple. It acts as an open-source wrapper on top of most of the existing SIEM, EDR, XDR, and Data Lake query languages. If you learn the basics of RootA, you will be able to contribute to collective defense. And if you have mastered a specific SIEM language, with RootA and Uncoder.IO you can speak them all.

**Table Of Contents:**

- [Why RootA](#why_roota)
- [Writing RootA Rules](#writing-roota-rules)
- [How to Contribute](#how-to-contribute)
- [Maintainers](#maintainers)
- [Credits](#credits)
- [Licenses](#licenses)
- [Resources & Useful Links](#resources--useful-links)
  
## :smiling_face_with_three_hearts: Why RootA
The objective of RootA is to accelerate the global cyber industry collaboration. With RootA acting as a wrapper, cyber defenders can take a native rule or query and augment it with metadata to automatically translate the code into other SIEM, EDR, XDR, and Data Lake languages. Inspired by success of Yara and Sigma rules, RootA is focused on a broader applicability by a larger community of defenders.

- RootA is expressed using **YAML**, a wide-spread, easy-to-write and human-readable format.
- **Use any query language** for detection, Uncoder.IO will take care of the translation.
- **Correlation support.** Common correlations are supported by RootA in order to make detection logic harder to bypass by the attackers, more compute efficient and future proof.
- **Log sources** can be explicitly or implicitly defined in the native query itself or in the customizable `logsource` field.
- RootA syntax fully accommodates **OCSF** and **Sigma** as taxonomy, making it fast to learn, easy to read and share, and providing maximum compatibility for Detection Engineers.
- **Threat Actor Timeline.** While Actors change, behaviours often stay the same. RootA supports an additional threat intelligence layer for CERTs, NCSCs, ISACs, MDRs, and Defence Agencies, to coordinate defence faster and with greater precision.
- **Mapping to TTPs.** Link detection logic to related tactics, techniques, and procedures in terms of MITRE ATT&CK®. Use custom tags to make the mapping even more tailored and detailed.
- **Response as Code.** With enough community members and industry adoption, the next step after detection is sharing the code to automate response.
  
## :mage: Writing RootA Rules
You can start writing RootA rules in any code editor that supports YAML. 
To translate RootA rules to other languages use Uncoder.IO by building it from source https://github.com/UncoderIO/UncoderIO or hosted online privately by SOC Prime since 2018 at https://uncoder.io

### RootA Rule Templates
RootA Rule format has minimal, full and extended templates.

**Minimal** template is for keeping rules simple, requiring only a name, description, author, severity, date, MITRE ATT&CK tags, detection query in any specific language, reference and license.

**Full** template is for adding alerting context, threat actor campaign timeline, specific log source attributes defined based on Sigma Rules or AWS OCSF taxonomy, and cross-platform correlation section.

**Extended** template is currently reserved for adding response as code and experimental features.

#### Minimal RootA rule example:
```
name: Possible Credential Dumping Using Comsvcs.dll (via cmdline)
details: Adversaries can use built-in library comsvcs.dll to dump credentials on a compromised host.
author: SOC Prime Team
severity: high
date: 2020-05-24
mitre-attack:
    - t1003.001
    - t1136.003
detection:
    language: splunk-spl-query # elastic-lucene-query, logscale-lql-query, mde-kql-query
    body: index=* ((((process="*comsvcs*") AND (process="*MiniDump*")) OR ((process="*comsvcs*") AND (process="*#24*"))) OR ((process="*comsvcs*") AND (process="*full*")))
references: 
    - https://badoption.eu/blog/2023/06/21/dumpit.html
license: DRL 1.1
```

#### Full RootA rule example:
```
name: Possible Credential Dumping Using Comsvcs.dll (via cmdline)
details: Adversaries can use built-in library comsvcs.dll to dump credentials on a compromised host.
author: SOC Prime Team
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
timeline:
    2022-04-01 - 2022-08-08: Bumblebee
    2022-07-27: KNOTWEED
    2022-12-04: UAC-0082, CERT-UA#4435
references: 
    - https://badoption.eu/blog/2023/06/21/dumpit.html
tags: Bumblebee, UAC-0082, CERT-UA#4435, KNOTWEED, Comsvcs, cir_ttps, ContentlistEndpoint
license: DRL 1.1
version: 1
uuid: 151fbb45-0048-497a-95ec-2fa733bb15dc
correlation: 
    timeframe: 1m
    functions: count() > 3
#response: []    # extended format
```

### Fields
[RootA specification](https://github.com/UncoderIO/RootA/blob/main/RootA_Specification.md) includes the list of all fields that can be used to write a RootA rule.

## :cookie: How to Contribute
Your contribution really matters in evolving the project and helping us make the RootA language even more useful for the global cyber defender community.

To submit your pull request with your ideas or suggestions for changes, take the following steps:

1. Fork the [RootA repository](https://github.com/UncoderIO/RootA/tree/main) and clone your fork to your local environment.
2. Create a new feature branch in which you’re going to make your changes.
3. Then commit your changes to your newly created feature branch.
4. Push the changes to your fork.
5. Create a new Pull Request  
    a. Clicking the New Pull Request button.  
    b. Select your fork along with a feature branch.  
    c. Provide a title and a description of your changes. Make sure they are both clear and informative.  
    d. Finally, submit your Pull Request and wait for its approval.  

Thank you for your contribution to the RootA project!

## :smile_cat: Maintainers
- [Roman Ranskyi](https://www.linkedin.com/in/roman-966b91b5/)
- [Alex Bredikhin](https://www.linkedin.com/in/bredikhin/)
- [Adam Swan](https://github.com/acalarch/)
- [Ruslan Mikhalov](https://www.linkedin.com/in/rmikhalov/)
- [Andrii Bezverkhyi](https://www.linkedin.com/in/andriimb/)

## :clap: Credits
We are genuinely grateful to security professionals who contribute their time, expertise, and creativity to evolve the RootA open-source project.

## :globe_with_meridians: Licenses
The contents of this repo, along with RootA specifications, are in the public domain.

## :book: Resources & Useful Links
- [RootA.IO](https://roota.io/) the main website page of the RootA project 
- [Uncoder.IO](https://github.com/UncoderIO/UncoderIO/) source code for translation engine Uncoder.IO which supports RootA, Sigma and IOC packaging into specific SIEM, EDR and Data Lake query formats
- [Uncoder.IO](https://uncoder.io/) private hosted version of Uncoder.IO since 2018, operated by SOC Prime, does not track you, does not see your code
- [RootA Discord Channel](https://tdm.socprime.com/zeptolink/5IAokHui2iWUHaB8/) Discord channel to network with RootA enthusiasts
