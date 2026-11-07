# Reglas Sigma

Las 21 detecciones de winlog-hunter en formato [Sigma](https://sigmahq.io/), el estándar para compartir detecciones entre SIEM. Cada fichero lleva al final la regla de winlog-hunter a la que corresponde (`# winlog-hunter: WLH-0xx`).

- **WLH-001 a WLH-004** son correlaciones (Sigma 2): una regla base de un evento más una regla que cuenta eventos o valores distintos en una ventana de tiempo.
- **El resto** son reglas de un solo evento.
- Las etiquetas siguen **MITRE ATT&CK v20**.

Todas pasan `sigma check` sin errores ni avisos y se convierten a Splunk.

## Convertirlas a tu SIEM

```bash
python -m pip install sigma-cli
sigma plugin install splunk        # o elasticsearch, microsoft365defender, qradar...

sigma convert -t splunk -p windows-audit -p splunk_windows sigma/
```

## Diferencias con winlog-hunter

Sigma describe qué eventos buscar, pero no toda la lógica del analizador. Estas reglas son una aproximación:

- **Severidad según el contexto.** winlog-hunter baja a *baja* un servicio o una tarea normales. En Sigma, WLH-006 y WLH-007 solo incluyen los casos sospechosos.
- **WLH-003.** Sigma comprueba que haya fallos y un éxito de la misma cuenta en 30 minutos. winlog-hunter además exige 5 fallos y que el éxito llegue después.
- **Decodificación.** winlog-hunter decodifica `-EncodedCommand` y busca dentro. Sigma solo ve la línea de comandos.
