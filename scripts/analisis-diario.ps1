<#
.SYNOPSIS
    Exporta los logs reales de este equipo, los analiza con winlog-hunter y guarda el informe.

.DESCRIPTION
    Exporta Security, System, PowerShell y Sysmon (si está instalado) de las últimas N horas con wevtutil,
    los analiza con winlog-hunter y deja un informe HTML y otro JSON con la fecha en el nombre.
    Los .evtx exportados se borran al terminar: solo se guardan los informes.

    Security solo se puede exportar como administrador. Sin permisos se omite y se analiza el resto.

.EXAMPLE
    .\scripts\analisis-diario.ps1
    .\scripts\analisis-diario.ps1 -Horas 72 -Salida D:\informes
#>
[CmdletBinding()]
param(
    # Cuántas horas hacia atrás se analizan.
    [ValidateRange(1, 8760)]
    [int]$Horas = 24,

    # Carpeta donde se guardan los informes.
    [string]$Salida = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'winlog-hunter'),

    # Ejecutable de winlog-hunter. La tarea programada pasa la ruta completa.
    [string]$WinlogHunter = 'winlog-hunter',

    # Los informes más antiguos que esto se borran.
    [ValidateRange(1, 3650)]
    [int]$ConservarDias = 30,

    # Muestra un aviso en pantalla si hay hallazgos de esta severidad o mayor.
    [ValidateSet('critical', 'high', 'medium', 'low')]
    [string]$AvisarDesde = 'critical',

    # No muestra ningún aviso en pantalla.
    [switch]$SinAviso
)

$ErrorActionPreference = 'Continue'
$fecha = Get-Date -Format 'yyyy-MM-dd_HHmm'
New-Item -ItemType Directory -Force -Path $Salida | Out-Null
$registro = Join-Path $Salida 'ejecuciones.log'

function Escribir([string]$mensaje) {
    $linea = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $mensaje
    Write-Host $linea
    Add-Content -Path $registro -Value $linea -Encoding UTF8
}

$temporal = Join-Path ([IO.Path]::GetTempPath()) ('winlog-hunter-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temporal | Out-Null

try {
    Escribir "Inicio: análisis de las últimas $Horas h"

    $milisegundos = [int64]$Horas * 3600 * 1000
    $consulta = "*[System[TimeCreated[timediff(@SystemTime) <= $milisegundos]]]"
    $registros = 'Security', 'System', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational'
    $exportados = @()
    # wevtutil el lista los registros sin necesitar permisos (Get-WinEvent -ListLog falla con Security).
    $existentes = & wevtutil.exe el

    foreach ($nombre in $registros) {
        if ($existentes -notcontains $nombre) {
            Escribir "  Omitido ${nombre}: no existe en este equipo"
            continue
        }
        $archivo = Join-Path $temporal (($nombre -replace '[\\/]', '_') + '.evtx')
        $error_wevtutil = & wevtutil.exe epl $nombre $archivo "/q:$consulta" 2>&1
        if ($LASTEXITCODE -ne 0) {
            $motivo = (($error_wevtutil | ForEach-Object { $_.ToString().Trim() }) -join ' ').Trim()
            if ($nombre -eq 'Security') { $motivo += ' (Security necesita ejecutarse como administrador)' }
            Escribir "  Omitido ${nombre}: $motivo"
            continue
        }
        $exportados += $archivo
        Escribir "  Exportado $nombre"
    }

    if ($exportados.Count -eq 0) {
        Escribir 'ERROR: no se pudo exportar ningún registro'
        exit 2
    }

    $html = Join-Path $Salida "informe_$fecha.html"
    $json = Join-Path $Salida "informe_$fecha.json"
    & $WinlogHunter analyze @exportados -o $html 2>&1 | Out-Null
    $codigo_html = $LASTEXITCODE
    & $WinlogHunter analyze @exportados -o $json 2>&1 | Out-Null
    if ($codigo_html -ne 0 -or $LASTEXITCODE -ne 0 -or -not (Test-Path $json)) {
        Escribir "ERROR: winlog-hunter falló (código $LASTEXITCODE). ¿Está instalado? Ruta usada: $WinlogHunter"
        exit 3
    }

    $datos = Get-Content -Raw -Encoding UTF8 $json | ConvertFrom-Json
    $s = $datos.stats.findings_by_severity
    $total = @($datos.findings).Count
    Escribir ("  {0} eventos · {1} hallazgos (crítica {2} · alta {3} · media {4} · baja {5})" -f `
        $datos.stats.events, $total, [int]$s.critical, [int]$s.high, [int]$s.medium, [int]$s.low)
    Escribir "  Informe: $html"

    $limite = (Get-Date).AddDays(-$ConservarDias)
    Get-ChildItem -Path $Salida -Filter 'informe_*' -File |
        Where-Object { $_.LastWriteTime -lt $limite } |
        Remove-Item -Force

    $orden = 'low', 'medium', 'high', 'critical'
    $minimo = [array]::IndexOf($orden, $AvisarDesde)
    $graves = @($datos.findings | Where-Object { [array]::IndexOf($orden, $_.severity) -ge $minimo })
    if ($graves.Count -gt 0 -and -not $SinAviso) {
        $etiquetas = @{ critical = 'CRÍTICA'; high = 'ALTA'; medium = 'MEDIA'; low = 'BAJA' }
        $lineas = $graves | Select-Object -First 5 | ForEach-Object { "[{0}] {1}" -f $etiquetas[$_.severity], $_.summary }
        $texto = "winlog-hunter: {0} hallazgo(s) importantes en {1}`n`n{2}`n`nInforme: {3}" -f `
            $graves.Count, $env:COMPUTERNAME, ($lineas -join "`n"), $html
        # msg.exe llega al escritorio del usuario aunque la tarea se ejecute como SYSTEM.
        & msg.exe * /TIME:43200 $texto 2>&1 | Out-Null
        Escribir "  Aviso mostrado en pantalla ($($graves.Count) hallazgo(s))"
    }

    if ([int]$s.critical -gt 0) { exit 1 }
    exit 0
}
finally {
    Remove-Item -Recurse -Force -Path $temporal -ErrorAction SilentlyContinue
}
