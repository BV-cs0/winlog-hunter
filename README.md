# winlog-hunter

Analizador de logs de Windows para blue team. Lee eventos de **Security**, **System** y **Sysmon**, detecta actividad sospechosa y genera un informe con cada hallazgo mapeado a **MITRE ATT&CK**.

## Instalación

Necesitas Python 3.9 o superior y git.

```bash
git clone https://github.com/BV-cs0/winlog-hunter.git
cd winlog-hunter
python -m pip install .
```

## Uso

Abre PowerShell **como administrador** (sin administrador no se puede leer el log Security), entra en la carpeta del proyecto y:

```powershell
# EJECUTA esto para iniciar el informe
powershell -ExecutionPolicy Bypass -File .\scripts\analisis-diario.ps1
```

Analiza los logs de las últimas 24 horas de tu equipo. Al terminar verás:

```text
Informe: C:\Users\<tu-usuario>\Documents\winlog-hunter\informe_<fecha>.html
```

Tu informe se ha guardado en **`Documentos\winlog-hunter`**: ábrelo con doble clic. Para analizar más horas añade `-Horas 72`.

## Cómo sacar los logs de un equipo Windows manualmente

Para analizar otro equipo, o un log concreto, expórtalo y pásaselo a winlog-hunter:

```powershell
# 1. Exportar los logs (Security requiere administrador)
wevtutil epl Security C:\temp\Security.evtx
wevtutil epl System C:\temp\System.evtx

# 2. Analizarlos y guardar el informe
winlog-hunter analyze C:\temp\Security.evtx C:\temp\System.evtx -o informe.html
```

El formato del informe se elige por la extensión: `.html`, `.md` o `.json`. También acepta `.xml` de `wevtutil qe` y JSON de Winlogbeat o de un SIEM. En Linux/macOS, para leer `.evtx` instala antes `python3 -m pip install ".[evtx]"`.

## Análisis automático diario del propio equipo (Windows)

Para que el informe se genere solo cada día, en PowerShell **como administrador**:

```powershell
# Programarlo cada día a las 09:00
powershell -ExecutionPolicy Bypass -File .\scripts\instalar-tarea.ps1

# A otra hora
powershell -ExecutionPolicy Bypass -File .\scripts\instalar-tarea.ps1 -Hora 21:30

# Lanzarlo ahora sin esperar
Start-ScheduledTask -TaskName 'winlog-hunter diario'

# Quitarlo
powershell -ExecutionPolicy Bypass -File .\scripts\instalar-tarea.ps1 -Desinstalar
```

- Los informes se guardan en `Documentos\winlog-hunter` y los de más de 30 días se borran solos.
- `ejecuciones.log`, en la misma carpeta, guarda un resumen de cada ejecución.
- Si el equipo está apagado a la hora programada, se ejecuta al encenderlo.
- Si mueves la carpeta del proyecto, vuelve a ejecutar el instalador.

## Seguridad del propio analizador

Los logs pueden contener datos controlados por un atacante (nombres de usuario, líneas de comandos, nombres de tareas), así que la herramienta los trata como entrada hostil:

- **HTML.** Todo el contenido se escapa y el informe lleva una **Content-Security-Policy** que bloquea cualquier script.
- **Consola.** Se eliminan los caracteres de control, para que una secuencia ANSI dentro de un log no pueda manipular la terminal.
- **XML.** Se rechazan los documentos con `DOCTYPE` (protección frente a XXE y billion laughs).
- **Markdown.** Se escapan los caracteres especiales.

## Estructura

```text
src/winlog_hunter/
  parsers.py   lectura de EVTX / XML / JSON y normalización de eventos
  rules.py     reglas de detección mapeadas a MITRE ATT&CK
  report.py    informe en consola, HTML, Markdown y JSON
  cli.py       comando winlog-hunter
scripts/
  analisis-diario.ps1   exporta los logs del equipo y genera el informe
  instalar-tarea.ps1    programa el análisis diario
samples/       datos sintéticos que usan los tests
tests/         tests automáticos
```

Úsalo solo con logs de equipos que tengas autorización para analizar. Licencia MIT.
