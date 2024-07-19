<p align="left">
  <img src="images/roota_logo_double.png" width="228" height="58">
</p>

# Un lenguaje de código abierto para la ciberdefensa colectiva
:earth_americas: [English](README.md) | [Українська](README_Ukrainian.md) | [Español](README_Spanish.md)  

Roota es un lenguaje de dominio público que contribuye a la ciberdefensa colectiva, creado para simplificar la detección de amenazas, la respuesta a incidentes y la atribución de adversarios. Actúa como un contenedor de código abierto sobre la mayoría de los lenguajes de consulta SIEM, EDR, XDR y Data Lake existentes. Si aprendes los conceptos básicos de Roota, podrás contribuir a la defensa colectiva. Y si dominas un idioma SIEM específico, con Roota y Uncoder IO, podrás manejarlos todos.

**Tabla de Contenidos:**

- [Porqué Roota](#smiling_face_with_three_hearts-porqué-roota)
- [Escribir reglas Roota](#mage-escribir-reglas-roota)
- [Cómo contribuir](#cookie-cómo-contribuir)
- [Mantenedores](#smile_cat-mantenedores)
- [Créditos](#clap-créditos)
- [Licencias](#globe_with_meridians-licencias)
- [Recursos y link útiles](#book-recursos-y-link-útiles)
  
## :smiling_face_with_three_hearts: Por qué Roota?
El objetivo de Roota es acelerar la colaboración global en la industria de la ciberseguridad. Con Roota actuando como contenedor, los ciber defensores pueden tomar una regla o consulta nativa y potenciarla con metadatos para traducir automáticamente el código a otros lenguajes SIEM, EDR, XDR y Data Lake. Inspirado por el éxito de las reglas de Yara y Sigma, Roota se centra en una aplicabilidad más amplia por parte de una gran comunidad de defensores.

- Roota se expresa mediante **YAML**, un formato ampliamente difundido, fácil de escribir y legible por humanos.
- **Utilice cualquier lenguaje** de consulta de detección, Uncoder IO se encargará de la traducción.
- **Soporte de correlación.** Roota admite correlaciones comunes para hacer que la lógica de detección sea más difícil de eludir por parte de los atacantes, una alta eficiencia de procesamiento y con durabilidad a largo plazo.
- Las **fuentes de registro** se pueden definir explícita o implícitamente en la propia consulta nativa o en el campo de fuente de registro personalizable.
- La sintaxis de Roota se adapta completamente a **OCSF** y **Sigma** como taxonomía, lo que la hace rápida de aprender, fácil de leer y compartir, y brinda máxima compatibilidad para los ingenieros de detección.
- **Cronología del actor de amenazas.** Si bien los actores cambian, los comportamientos suelen permanecer iguales. Roota admite una capa adicional de inteligencia sobre amenazas para CERT, NCSC, ISAC, MDR y agencias de defensa, para coordinar la defensa más rápido y con mayor precisión.
- **Mapeo a TTP.** Vincular la lógica de detección con tácticas, técnicas y procedimientos relacionados en términos de MITRE ATT&CK®. Utilice etiquetas personalizadas para que el mapeo sea aún más personalizado y detallado.
- **Respuesta como código.** Con una participación suficiente de la comunidad y una aceptación generalizada en la industria, el siguiente paso después de la detección es compartir el código para automatizar la respuesta.
  
## :mage: Escribir reglas Roota
Puedes comenzar a escribir reglas Roota en cualquier editor de código que admita YAML. Para traducir las reglas de Roota a otros lenguajes, utiliza Uncoder IO compilándolo desde la fuente https://github.com/UncoderIO/UncoderIO o alojado en línea de forma privada por SOC Prime desde 2018 en https://uncoder.io

### Plantillas de reglas Roota
El formato de regla Roota tiene plantillas mínimas, completas y extendidas.

La plantilla **mínima** sirve para mantener las reglas simples y solo requiere un nombre, descripción, autor, gravedad, fecha, etiquetas MITRE ATT&CK, consulta de detección en cualquier idioma específico, referencia y licencia.

La plantilla **completa** sirve para agregar contexto de alerta, cronograma de campaña de actores de amenazas, atributos de origen de registro específicos definidos en función de las reglas Sigma o la taxonomía de OCSF y una sección de correlación multiplataforma.

Actualmente, la plantilla **extendida** está reservada para agregar respuestas como código y funciones experimentales.

#### Ejemplo de regla mínima Roota:
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

#### Ejemplo de regla completa Roota:
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

### Campos
La [especificación Roota](https://github.com/UncoderIO/Roota/blob/main/Roota_Specification.md) incluye la lista de todos los campos que se pueden utilizar para escribir una regla Roota.

## :cookie: Cómo contribuir
Tu contribución es realmente importante para hacer evolucionar el proyecto y ayudarnos a hacer que el lenguaje Roota sea aún más útil para la comunidad global de ciber defensores.

Para enviar tu pull request con tus ideas o sugerencias de cambios, sigue los siguientes pasos:

1. Realiza un Fork del repositorio [repositorio Roota](https://github.com/UncoderIO/Roota/tree/main) y clona la misma en tu entorno local.
2. Crea un nuevo Feature Branch en el que realizarán los cambios.
3. Luego, confirma tus cambios en el recién creado Feature Branch.
4. Haz un push de los cambios a tu Fork.
5. Crea un nuevo Pull Request 
    a. Al hacer clic en el botón New Pull Request.  
    b. Selecciona tu Fork junto con tu Feature Branch.  
    c. Proporciona un título y una descripción de tus cambios. Asegúrate de que sean claros e informativos. 
    d. Finalmente, envía tu Pull Request y espera su aprobación. 

Gracias por tu contribución al proyecto Roota!

## :smile_cat: Mantenedores
- [Roman Ranskyi](https://www.linkedin.com/in/roman-966b91b5/)
- [Alex Bredikhin](https://www.linkedin.com/in/bredikhin/)
- [Adam Swan](https://github.com/acalarch/)
- [Ruslan Mikhalov](https://www.linkedin.com/in/rmikhalov/)
- [Andrii Bezverkhyi](https://www.linkedin.com/in/andriimb/)

## :clap: Créditos
Estamos sinceramente agradecidos con los profesionales de la seguridad que aportan su tiempo, experiencia y creatividad para hacer evolucionar el proyecto de código abierto Roota.

## :globe_with_meridians: Licencias
El contenido de este repositorio, junto con las especificaciones de Roota, son de dominio público.

## :book: Recursos y link útiles
- [Roota.IO](https://roota.io/) la página web principal del proyecto Roota
- [Uncoder.IO](https://github.com/UncoderIO/UncoderIO/) Código fuente para el motor de traducción Uncoder IO que admite el empaquetado Roota, Sigma e IOC en formatos de consulta específicos SIEM, EDR y Data Lake
- [Uncoder.IO](https://uncoder.io/) versión alojada privada de Uncoder.IO desde 2018, operada por SOC Prime, no te rastrea, no ve tu código
- [Canal de Discord Roota](https://tdm.socprime.com/zeptolink/5IAokHui2iWUHaB8/) Canal de Discord para establecer contactos con entusiastas de Roota
