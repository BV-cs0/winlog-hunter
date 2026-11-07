<#
.SYNOPSIS
    Programa analisis-diario.ps1 para que se ejecute solo cada día.

.DESCRIPTION
    Crea la tarea programada "winlog-hunter diario", que se ejecuta como SYSTEM (para poder leer
    el registro Security) a la hora indicada. Si el equipo estaba apagado a esa hora, se ejecuta
    en cuanto se encienda. Los informes se guardan en Documentos\winlog-hunter del usuario que
    instala la tarea.

    Hay que ejecutarlo en una consola de PowerShell abierta como administrador.

.EXAMPLE
    .\scripts\instalar-tarea.ps1
    .\scripts\instalar-tarea.ps1 -Hora 21:30
    .\scripts\instalar-tarea.ps1 -Desinstalar
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Hora del día a la que se ejecuta (formato HH:mm).
    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$Hora = '09:00',

    # Horas de logs que se analizan en cada ejecución.
    [ValidateRange(1, 8760)]
    [int]$Horas = 24,

    # Carpeta de los informes.
    [string]$Salida = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'winlog-hunter'),

    # Borra la tarea en lugar de crearla.
    [switch]$Desinstalar
)

$ErrorActionPreference = 'Stop'
$nombreTarea = 'winlog-hunter diario'

if ($Desinstalar) {
    if (Get-ScheduledTask -TaskName $nombreTarea -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $nombreTarea -Confirm:$false
        Write-Host "Tarea '$nombreTarea' eliminada. Los informes siguen en $Salida"
    } else {
        Write-Host "La tarea '$nombreTarea' no existe."
    }
    return
}

$comando = Get-Command winlog-hunter -ErrorAction SilentlyContinue
if (-not $comando) {
    throw 'No encuentro winlog-hunter. Instálalo primero con: python -m pip install .'
}
$exe = $comando.Source
$script = Join-Path $PSScriptRoot 'analisis-diario.ps1'
if (-not (Test-Path $script)) { throw "No encuentro $script" }

New-Item -ItemType Directory -Force -Path $Salida | Out-Null

$argumentos = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Horas {1} -Salida "{2}" -WinlogHunter "{3}"' -f `
    $script, $Horas, $Salida, $exe

$accion = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argumentos
$disparador = New-ScheduledTaskTrigger -Daily -At $Hora
$usuario = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $nombreTarea -Action $accion -Trigger $disparador -Principal $usuario `
    -Settings $ajustes -Description 'Analiza los logs de Windows con winlog-hunter y guarda un informe diario.' `
    -Force | Out-Null

Write-Host "Tarea '$nombreTarea' creada: cada día a las $Hora, últimas $Horas h."
Write-Host "Informes en: $Salida"
Write-Host "Para probarla ahora:  Start-ScheduledTask -TaskName '$nombreTarea'"
Write-Host "Para quitarla:        .\scripts\instalar-tarea.ps1 -Desinstalar"
