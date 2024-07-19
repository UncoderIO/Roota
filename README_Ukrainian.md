<p align="left">
  <img src="images/roota_logo_double.png" width="228" height="58">
</p>

# Мова з відкритим кодом для колективного кіберзахисту

:earth_americas: [English](README.md) | [Українська](README_Ukrainian.md) | [Español](README_Spanish.md)  

Roota – це вільно розповсюджувана мова для колективного кіберзахисту, створена, щоб спростити виявлення загроз, реагування на інциденти та атрибуцію кібератак. Вона виступає обгорткою для мов запитів, що використовуються в різноманітних системах SIEM, EDR, XDR та Data Lake. Вивчивши основи Roota, ви зможете вносити свій вклад у колективний кіберзахист. Володіючи мовою одного SIEM, за допомогою Roota й Uncoder IO ви зможете говорити мовами всіх інших.

**Зміст:**

- [Ключові переваги Roota](#smiling_face_with_three_hearts-ключові-переваги-roota)
- [Як писати правила на Roota](#mage-як-писати-правила-на-roota)
- [Як долучитися до проєкту](#cookie-як-долучитися-до-проєкту)
- [Хто веде проєкт](#smile_cat-хто-веде-проєкт)
- [Учасники](#clap-учасники)
- [Ліцензії](#globe_with_meridians-ліцензії)
- [Ресурси та корисні посилання](#book-ресурси-та-корисні-посилання)
  
## :smiling_face_with_three_hearts: Ключові переваги Roota
Мова Roota створена з метою пришвидшити глобальну співпрацю в галузі кібербезпеки. Використовуючи Roota як обгортку, спеціалісти з кібербезпеки можуть взяти нативне правило або запит і доповнити його метаданими, щоб потім автоматично перекласти код на мови інших систем SIEM, EDR, XDR та Data Lake. На створення мови Roota надихнув успіх правил на Yara та Sigma, але ця мова має ширшу сферу застосування й більшу потенційну аудиторію, для якої вона може бути корисною.

- Для запису Roota використовується **YAML**, поширений формат, який легко читається людиною та зручний у використанні.
- Код для детектування загроз **можна писати будь-якою мовою** – Uncoder IO згенерує автоматичний переклад.
- **Підтримка кореляції.** Roota підтримує поширені функції кореляції, завдяки яким логіку детектування стає важче обійти, вона потребує менше обчислювальних ресурсів, а також не втрачає актуальності з часом.
- **Джерела логів** можуть визначатися самим запитом нативною мовою або зазначатися окремо в полі `logsource`.
- Синтаксис Roota повністю підтримує **OCSF** та **Sigma** як таксономію, завдяки чому цю мову швидко вчити, легко читати і просто використовувати для обміну знаннями, в якому б форматі інженер не писав алгоритми детектування.
- **Хронологія дій зловмисників.** Зловмисники змінюються, але їхні методи часто залишаються такими, як і раніше. Roota підтримує додатковий рівень інформації про загрозу, що допомагає командам реагування на комп'ютерні надзвичайні події (CERT), національним центрам з кібербезпеки (NCSC), центрам обміну й аналізу інформації (ISAC), постачальникам послуг з виявлення та реагування на загрози (MDR) та різноманітним агенціям із кіберзахисту швидше й точніше координувати захисні заходи.
- **Співставлення з тактиками, техніками та процедурами (TTP).** Прив'язуйте алгоритми детектування до відповідних тактик, технік та процедур по системі MITRE ATT&CK®. Використовуйте кастомні теги, щоб робити унікальні прив'язки.
- **Реагування як код.** Коли спільнота виросте й з'явиться галузеве визнання, наступним кроком після алгоритмів детектування буде обмін кодом для автоматизації реагування на кіберзагрози.
  
## :mage: Як писати правила на Roota
Писати правила на мові Roota можна в будь-якому редакторі коду, який підтримує YAML. 
Для перекладу правил Roota на інші мови, використовуйте Uncoder IO. Ви можете встановити його локально звідси: https://github.com/UncoderIO/UncoderIO або скористатися онлайн-версією, яку компанія SOC Prime пропонує з 2018 року, за адресою https://uncoder.io

### Шаблони правил Roota
Для написання правила на Roota можна взяти мінімальний, повний або розширений шаблон.

**Мінімальний** шаблон призначений для написання простих правил, де вказуються лише назва, опис, автор, рівень критичності, дата, теги MITRE ATT&CK, запит для детектування нативною мовою, посилання та ліцензія.

**Повний** шаблон додатково містить поля для того, щоб вказати контекст, необхідний для аналізу сповіщення про загрозу, та хронологію кампанії кіберзловмисників, описати джерела логів за допомогою такономії Sigma або OCSF, а також додати кросплатформенні кореліції.

**Розширений** шаблон наразі зарезервовано для додавання "реагування як коду" та експериментальних можливостей.

#### Мінімальний шаблон правила Roota:
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

#### Повний шаблон правила Roota:
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

### Поля
[Специфікація мови Roota](https://github.com/UncoderIO/Roota/blob/main/Roota_Specification_Ukrainian.md) описує всі поля, які можна використовувати в цій мові.

## :cookie: Як долучитися до проєкту
Ми вдячні кожному, хто допомагає розвивати цей проєкт і робити мову Roota більш корисною для глобальної спільноти спеціалістів з кіберзахисту.

Щоб зробити пул-реквест з ідеями або пропозиціями, виконайте такі дії:

1. Зробіть форк [репозиторія Roota](https://github.com/UncoderIO/Roota/tree/main) і створіть його локальну копію.
2. Створіть гілку, в якій ви вноситимете зміни.
3. Зробіть коміт зі внесеними змінами в створену вами гілку.
4. Відправте зміни у свій форк.
5. Створіть пул-реквест.  
    a. Натисніть кнопку New Pull Request (Новий пул-реквест).  
    b. Виберіть свій форк з гілкою, яка містить зміни.  
    c. Зазначте назву та опис змін. Вони мать бути чіткими й інформативними.  
    d. Відправте пул-реквест і очікуйте на його схвалення.  

Дякуємо за ваш внесок в проєкт Roota!

## :smile_cat: Хто веде проєкт
- [Roman Ranskyi](https://www.linkedin.com/in/roman-966b91b5/)
- [Alex Bredikhin](https://www.linkedin.com/in/bredikhin/)
- [Adam Swan](https://github.com/acalarch/)
- [Ruslan Mikhalov](https://www.linkedin.com/in/rmikhalov/)
- [Andrii Bezverkhyi](https://www.linkedin.com/in/andriimb/)

## :clap: Учасники
Ми щиро вдячні всім спеціалістам з кіберзахисту, які застосовують свої знання, проявляють кмітливість і докладають час для розвитку відкритого проєкту Roota.

## :globe_with_meridians: Ліцензії
Вміст цього репозиторія, зокрема специфікація мови Roota, є суспільним надбанням (public domain).

## :book: Ресурси та корисні посилання
- [Roota.IO](https://roota.io/) основна вебсторінка проєкту Roota
- [Uncoder.IO](https://github.com/UncoderIO/UncoderIO/) вихідний код рушія перекладів Uncoder IO, який підтримує автоматичний переклад Roota й Sigma, а також генерацію запитів з індикаторами компрометації (IOC) на мовах різних SIEM, EDR та Data Lake
- [Uncoder.IO](https://uncoder.io/) онлайн-версія Uncoder IO, яка з 2018 року підтримується компанією SOC Prime і надає повну приватність: ніхто не відстежує ні ваші дії, ні ваш код
- [Канал Roota в Discord](https://tdm.socprime.com/zeptolink/5IAokHui2iWUHaB8/) для спілкування з іншими, кого цікавить і надихає Roota
