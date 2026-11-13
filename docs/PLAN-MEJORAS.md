# Plan de mejoras 0.7.0: más detecciones y exclusiones

Rama: `mejoras-deteccion`, partiendo de `main` (0.6.0). Sin push hasta que Bryan lo apruebe.

## Reglas generales (para todas las fases)

- **Cero dependencias nuevas obligatorias.** Solo biblioteca estándar. Python ≥ 3.9 (no hay `tomllib`).
- **Todo en español**: mensajes, resúmenes de hallazgos, claves de `evidence`, ayuda de la CLI, docstrings. Mismo estilo que las reglas actuales.
- **No romper la API pública**: `from winlog_hunter.rules import RULES, Config, run_rules` debe seguir funcionando, igual que los IDs WLH-001 a WLH-021.
- **Commits sin atribución a ninguna IA** (ni Co-Authored-By, ni menciones). Autor: el configurado en git.
- **Tests con `unittest`** (no pytest): `python -m unittest discover -s tests`. Deben seguir en verde tras cada fase.
- **Medición**: `python tools/benchmark_evtx.py D:\Claude\datasets\EVTX-ATTACK-SAMPLES --json salida.json --detalle`.
  Línea base de la 0.6.0: **58/278**. El dataset NO se copia al repo.

### Contra el sobreajuste (muy importante)

El objetivo es detectar **técnicas**, no ficheros del dataset. Cada regla nueva:

1. Se basa en lógica pública y conocida de la técnica (SigmaHQ, documentación de ATT&CK, Microsoft). Nada de comparar nombres de fichero, nombres de equipo, usuarios, IPs ni hashes del dataset.
2. Tiene en `tests/` al menos **un caso positivo y un caso negativo** (un evento legítimo parecido que NO debe saltar), construidos con `helpers.ev()` / `helpers.sysmon()`.
3. Gradúa la severidad según el contexto, como WLH-006/007: lo ruidoso sale en *low/medium*, lo inequívoco en *high/critical*.
4. Prefiere listas de binarios/claves/permisos concretos frente a patrones genéricos que salten con software normal (actualizadores, antivirus, Office, navegadores, Visual Studio, Windows Update).

## Fase 0: reorganizar `rules.py` (sin cambios de comportamiento)

`rules.py` tiene 1.100 líneas y va a duplicarse. Convertirlo en paquete:

```
src/winlog_hunter/rules/
  __init__.py        # re-exporta RULES, Config, Hit, Rule, rule, run_rules, decode_powershell
  base.py            # Config, Hit, Rule, RULES, rule(), run_rules(), utilidades comunes (_bursts, _exe, _truncate, _is_sysmon, _processes...)
  credenciales.py    # WLH-001-003, 013-016, ...
  movimiento.py      # WLH-004, 017, 018, ...
  persistencia.py    # WLH-006-009, 019, 020, ...
  ejecucion.py       # WLH-010-012, 021, ...
  evasion.py         # WLH-005, ...
  escalada.py        # nuevas
  descubrimiento.py  # nuevas
```

El orden de registro de `RULES` debe seguir siendo por ID (ordena `RULES` al final de `__init__` si hace falta). Criterio de aceptación: tests en verde y benchmark idéntico (58/278, mismo JSON por fichero). Commit propio.

## Fase 1: reglas nuevas y ampliaciones

Objetivo orientativo: **≥ 110/278** sin romper la regla anti-sobreajuste. Si una técnica no se puede detectar de forma genérica, se deja fuera y se documenta.

Numeración: nuevas desde **WLH-022**. Lo que encaje en una regla existente se añade ahí (mismo ID) en vez de crear otra.

### 1a. Procesos (Sysmon 1 / 4688): la bolsa más grande

- **WLH-022 Bypass de UAC** (T1548.002). Señales, cualquiera basta:
  - Registro (Sysmon 12/13): secuestro de `HKCU\Software\Classes\{ms-settings,mscfile,exefile,Folder,Launcher.SystemSettings}\shell\open\command` (incluido `DelegateExecute`), `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\*`, variables `windir`/`SystemRoot` en `HKCU\Environment`.
  - Proceso hijo de binarios autoelevables (fodhelper, computerdefaults, eventvwr, sdclt, slui, wsreset, compmgmtlauncher, changepk, cmstp, perfmon, mmc con .msc raro…) que lanza shells/scripts o binarios fuera de System32.
  - Sysmon 7: binario autoelevable de System32 (sysprep, cliconfg, migwiz, mcx2prov, …) cargando una DLL **no firmada** o desde una ruta fuera de `System32/SysWOW64/WinSxS`.
  - Sysmon 11: ficheros creados en directorios de binarios autoelevables (`System32\sysprep\`, …) o en carpetas que imitan a Windows (`C:\Windows \System32\`, con espacio).
  - `cmstp.exe` con `/s` o `/au` y un `.inf`.
- **WLH-011 LOLBins (ampliar)**: pcalua `-a`, msxsl, desktopimgdownldr `/lockscreenurl`, `ftp -s:`, hh.exe con .chm remoto o que lanza hijos, wuauclt `/RunHandlerComServer`, rundll32 con `advpack`/`zipfldr RouteTheCall`/`pcwutl LaunchApplication`/`shell32 ShellExec_RunDLL`/`.cpl`, regsvr32 `scrobj`, vshadow `-exec`, msiexec con URL o `/y`, wmic `/format:` con XSL, control.exe con `.cpl` fuera de System32.
- **WLH-023 Binario renombrado o disfrazado** (T1036.003, T1036.005): `OriginalFileName` de Sysmon 1 que no coincide con el nombre del ejecutable para binarios conocidos (cmd, powershell, psexec, rundll32, regsvr32, certutil, mshta, wmic, procdump…); procesos con nombre de sistema (svchost, lsass, services, csrss, winlogon, smss, explorer, wermgr…) ejecutados fuera de su ruta; accesibilidad (sethc, osk, utilman, magnify, narrator) cuyo `OriginalFileName` es una shell.
- **WLH-024 Shell lanzada por un servidor o servicio** (T1505.003, T1190, T1021.003): shells/LOLBins hijos de w3wp, httpd, tomcat, php-cgi, nginx, sqlservr (xp_cmdshell), mmc/explorer/excel lanzados por DCOM (`-Embedding`), smss (fuera de autochk), msiexec con hijos de shell, spoolsv, wsmprovhost (si no lo cubre ya WLH-018: amplía WLH-018 en ese caso). Revisa solapes con WLH-012 y WLH-018 para no duplicar hallazgos.
- **WLH-025 Evasión e inhibición de recuperación por comandos** (T1490, T1562.001, T1562.004, T1564.001, T1070): `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete`, `bcdedit /set … recoveryenabled no|bootstatuspolicy`, `wevtutil cl|sl /e:false`, `auditpol /clear|/remove|/set … /success:disable`, `netsh advfirewall set … state off`, `netsh interface portproxy add`, `Set-MpPreference -Disable*`/`Add-MpPreference -ExclusionPath`, `attrib +h +s`, parada del servicio EventLog (`net stop eventlog`, `taskkill` sobre el svchost del EventLog, `sc config eventlog start= disabled`).

### 1b. Otros eventos de Sysmon

- **WLH-026 Inyección de código** (T1055): Sysmon 8 (CreateRemoteThread) excluyendo orígenes legítimos habituales (csrss, System, wininit, svchost→services del sistema, antivirus conocidos, el propio Sysmon); Sysmon 10 a procesos que no sean lsass (lsass ya es WLH-013) con `GrantedAccess` que incluya escritura de memoria + creación de hilos (0x1F0FFF, 0x1FFFFF, 0x143A, 0x1F3FFF, 0x0800…) desde imágenes en rutas de usuario; `CallTrace` con `UNKNOWN` (memoria sin respaldar) en cualquier destino → alta. Sysmon 25 (ProcessTampering) → alta.
- **WLH-027 Carga de DLL sospechosa / sideloading** (T1574.001, T1574.002): Sysmon 7 donde un binario firmado de Microsoft o en una carpeta de sistema carga una DLL **no firmada** desde fuera de `System32/SysWOW64/WinSxS/Program Files`; DLLs típicas de hijacking cargadas desde rutas raras (lista corta y conocida: wwlib, version, dbghelp, cdpsshims, wlbsctrl, …). Ojo al ruido: muchas apps cargan DLLs propias sin firma desde su carpeta de `Program Files`: eso no salta.
- **WLH-028 Named pipes de herramientas ofensivas** (T1021.002, T1559, T1134): Sysmon 17/18 con nombres conocidos de PsExec y clones (psexesvc, remcom, paexec, csexec), Cobalt Strike por defecto (`msagent_*`, `postex_*`, `status_*`, `MSSE-*-server`), Meterpreter/potatoes (nombres que contienen `\pipe\` dentro, `spoolss` creado por algo que no es spoolsv), kekeo/tsssp; y `cmd /c echo … > \\.\pipe\…` en Sysmon 1 o 7045 (getsystem).
- **WLH-019 Persistencia en el registro (ampliar)**: shims (`AppCompatFlags\Custom`, `InstalledSDB`), `BootExecute`/`SetupExecute` (+ Sysmon 1 con padre smss), Winsock (`WinSock2\Parameters\Protocol_Catalog9`), proveedores de red (`NetworkProvider\Order`), `NullSessionPipes`, monitores de impresión, Netsh helpers, `ServiceDll`, GPO pendientes, AccessVBOM. Si una clave es de **evasión** y no de persistencia, va a WLH-029.
- **WLH-029 Desactivación de defensas en el registro** (T1562.001, T1112): Sysmon 12/13 que pone `EnableLUA=0`, `EnableScriptBlockLogging=0`, `ExecutionPolicy` Bypass/Unrestricted, `__PSLockdownPolicy` (CLM), Defender (`DisableAntiSpyware`, `DisableRealtimeMonitoring`, exclusiones), `UseLogonCredential=1` (WDigest), `RunAsPPL=0`, `fDenyTSConnections=0` y cambio de `PortNumber` de RDP, `PortProxy`, firewall deshabilitado, borrado de MRU.
- **WLH-030 Ficheros sospechosos** (T1547.001, T1003, T1574.009): Sysmon 11 en carpetas de Inicio (`\Start Menu\Programs\Startup\`) por procesos que no son instaladores conocidos; volcados `.dmp` creados por lsass/rdrleakdiag/procesos que no son WerFault; `mimilsa.log` (memssp); ejecutables en rutas de servicio sin comillas (`C:\Program.exe`, `C:\Program Files\X.exe` sin carpeta); escritura en `System32\spool\drivers` por procesos que no son spoolsv; cambios de fecha (Sysmon 2) de ejecutables o scripts en rutas de usuario.
- **WLH-031 Conexiones de red de shells y LOLBins** (T1059, T1105, T1572): Sysmon 3 iniciadas por powershell, cmd, mshta, rundll32, regsvr32, wscript, cscript, msbuild, certutil, bitsadmin, notepad, … hacia direcciones no locales → media; túnel RDP (conexión a 3389 en 127.0.0.1/::1 o desde un proceso que no es mstsc/svchost) → alta. También 5156 con destino 127.0.0.1:3389 si el origen no es el sistema.

### 1c. Security y otros canales

- **WLH-032 Ataques a Kerberos y NTLM** (T1558.004, T1110.003, T1550.002): AS-REP roasting (4768 con `PreAuthType` 0); spraying por Kerberos (4771 `0x18` o 4768 fallidos de muchas cuentas desde un origen; puede ampliar WLH-002 en vez de crear regla); pass-the-hash (4624 tipo 9 con `LogonProcessName` seclogo, o tipo 3 NTLM con `KeyLength` 0 y cuenta no anónima); logon anónimo de tipo 3 seguido de 4742 del DC (Zerologon).
- **WLH-033 Cambios peligrosos en el Directorio Activo** (T1098, T1207, T1134.005, T1222.001): 5136 que añade derechos de replicación (los GUID de DCSync en `nTSecurityDescriptor`), `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), `servicePrincipalName` en cuentas de usuario, `msDS-KeyCredentialLink` (shadow credentials); 4742 con SPN de GC/DRS (DCShadow) o renombrado de `sAMAccountName` sin `$` (CVE-2021-42278); 4765/4766 SID History; 4794 contraseña DSRM; 4724 reseteo de contraseña de cuenta privilegiada.
- **WLH-034 Privilegios y ajustes del sistema** (T1134, T1553.006, T1562): 4703 o 4673 activando `SeDebugPrivilege`/`SeTcbPrivilege`/`SeImpersonatePrivilege` por procesos no del sistema; 4826 con depuración de kernel o test signing; 4719 que quita auditoría (`AuditPolicyChanges` con "Success removed"/"Failure removed"); 7036/7040 del servicio EventLog parado o deshabilitado; 4985 (transacciones NTFS, doppelgänging) solo en combinación.
- **WLH-035 Reconocimiento remoto** (T1087, T1069, T1135, T1018): 4799/4798 consultadas por un proceso que no es del sistema (mmc, explorer, svchost legítimos fuera); 4661 a `Domain Admins`/`SAM_GROUP`; un mismo origen accediendo por 5145 a ≥ 3 pipes de enumeración distintos (`srvsvc`, `samr`, `lsarpc`, `winreg`, `wkssvc`) en la ventana → BloodHound/SharpHound, PsLoggedOn; Sysmon 1 con `net user|group|localgroup /domain`, `nltest /dclist|/domain_trusts`, `dsquery`, `AdFind` (ráfaga de ≥ 3 comandos de reconocimiento → media).
- **WLH-036 Antivirus y BITS** (T1562.001, T1197): Defender (`Microsoft-Windows-Windows Defender/Operational`) 1116/1117/1006/1015 malware detectado → alta; 5001 protección en tiempo real desactivada, 5007 cambio de config que añade exclusiones → alta. BITS (`Microsoft-Windows-Bits-Client/Operational`) 3/59/60 creando trabajos que descargan de URLs externas o ejecutables → media.
- **WLH-021 PowerShell (ampliar)**: tratar también 4103 (`Payload`/`ContextInfo`) y 800 del log clásico `Windows PowerShell` (`HostApplication`, detalles del pipeline), con los mismos indicadores más ofuscación típica (`-join`, `[char]` en cadena, `iex` sobre descargas, `Invoke-Item` de ejecutables en `%TEMP%`, `New-Object Net.WebClient … DownloadFile`).
- **Aplicaciones**: MSSQL 15457 `xp_cmdshell` activado, 18456 fallos repetidos (ráfaga, amplía WLH-001), 33205 con `xp_cmdshell`; Application 3001 (SilentProcessExit de lsass); Application 325/326/327 de ESENT creando `ntds.dit` fuera de `NTDS\` (volcado con ntdsutil); 1040/1042 de MsiInstaller con un paquete desde URL. Repartir en las reglas que tengan sentido (credenciales, ejecución), sin crear una regla por evento.

### Integración

- **Exportación local** (`local.py`, `LOGS`): añadir `Windows PowerShell`, `Microsoft-Windows-Windows Defender/Operational`, `Microsoft-Windows-Bits-Client/Operational`, `Microsoft-Windows-TaskScheduler/Operational` y `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` si las usan las reglas. Un canal que no exista en el equipo debe dar un aviso, no un error (ya pasa con los actuales; compruébalo).
- **Sysmon** (`data/sysmon.xml`): confirmar que la config propia registra los eventos que usan las reglas nuevas (7, 8, 10, 11, 12/13, 17/18, 25) sin disparar el volumen: si hay que incluir algo, que sea filtrado.
- **Sigma**: un fichero `sigma/wlh-0xx_*.yml` por regla nueva (el test `test_sigma.py` lo exige), con las mismas convenciones que los actuales; actualizar `sigma/README.md` (número de reglas).
- **README**: tabla de detecciones con las nuevas, tabla de resultados regenerada con `tools/benchmark_evtx.py`, quitar el párrafo de "puntos débiles" o reescribirlo con lo que siga sin cubrirse. Sin ejemplos inventados.

### Criterio de aceptación de la fase 1

- Tests en verde, con positivo y negativo por regla nueva.
- Benchmark ≥ 110/278 (orientativo) y **ningún fichero que antes se detectaba deja de detectarse**.
- `winlog-hunter analyze samples/escenario_ataque.jsonl` no explota en hallazgos nuevos sin sentido.
- Un commit por sub-bloque (1a, 1b, 1c, integración).

## Fase 2: exclusiones (menos falsos positivos)

### Formato: `exclusiones.json` (JSON, sin dependencias)

```json
{
  "version": 1,
  "exclusiones": [
    {
      "motivo": "Tarea legítima del antivirus corporativo",
      "reglas": ["WLH-007"],
      "equipos": ["PC-*"],
      "campos": {"tarea": "\\Antivirus\\*"},
      "caduca": "2027-06-30"
    },
    {
      "motivo": "Cuenta de copias de seguridad",
      "reglas": ["WLH-004", "WLH-017"],
      "texto": "svc_backup"
    }
  ]
}
```

- `motivo` es **obligatorio** (buena práctica de SOC: toda exclusión se justifica).
- Criterios opcionales, se combinan con Y; dentro de una lista, con O:
  - `reglas`: IDs o comodín `*` (si falta, se aplica a todas).
  - `equipos`: comodines tipo `fnmatch`, sin distinguir mayúsculas.
  - `campos`: `{clave_de_evidence: patrón}` sobre los valores de `Finding.evidence` (si el valor es una lista, basta que coincida un elemento). Comodines `fnmatch`, sin distinguir mayúsculas.
  - `texto`: subcadena buscada en el resumen y en todos los valores de `evidence`.
  - `severidad_maxima`: solo excluye hallazgos de esa severidad o menos (para no silenciar un crítico por error).
  - `caduca`: fecha ISO; pasada la fecha la exclusión deja de aplicarse y se avisa.
- Una exclusión sin ningún criterio (solo `motivo`) es un error: no se permite silenciarlo todo.
- Validación estricta con mensajes claros en español (clave desconocida, regla inexistente, fecha mala…), con la ruta del elemento (`exclusiones[2].campos`).

### Implementación

- Módulo nuevo `src/winlog_hunter/exclusiones.py`: `cargar(path) -> list[Exclusion]`, `aplicar(findings, exclusiones, hoy) -> (visibles, excluidos)` y la validación. Se aplica **después** de `run_rules`, sin tocar las reglas.
- CLI:
  - `analyze --exclusiones FICHERO` y `--sin-exclusiones`.
  - `equipo` y `programar` usan por defecto `%ProgramData%\winlog-hunter\exclusiones.json` si existe (la tarea diaria corre como SYSTEM).
  - Comando nuevo `exclusiones` con `--plantilla` (imprime un ejemplo comentado en el README, no en el JSON) y `--validar FICHERO`. Añadirlo a la ayuda y al test `test_help_is_in_spanish_and_lists_every_command`.
- Informes (consola, HTML, JSON, CSV o los que haya): indicar cuántos hallazgos se ocultaron y por qué exclusión (motivo); en JSON, una lista `excluidos` con `rule_id`, `summary` y `motivo`. Nunca se ocultan en silencio.
- Tests: validación (cada error), cada criterio, combinación Y/O, comodines, caducidad, `severidad_maxima`, y que `equipo`/`programar` cogen el fichero por defecto (con ruta inyectable para el test).
- README: sección "Falsos positivos y exclusiones" con el formato y un ejemplo realista breve.

## Fase 3: cierre (la hace el arquitecto)

- Revisión del código de Codex, benchmark final, prueba de falsos positivos con los logs reales del PC de Bryan (`winlog-hunter equipo`, lo ejecuta él como administrador) antes y después.
- Versión 0.7.0 en `pyproject.toml`, `__init__.py` e insignia del README. Push y release solo cuando Bryan lo diga.
