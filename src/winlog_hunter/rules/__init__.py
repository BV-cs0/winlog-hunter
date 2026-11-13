"""Reglas de detección mapeadas a MITRE ATT&CK."""

from .base import RULES, Config, Hit, Rule, rule, run_rules, decode_powershell
from . import credenciales, movimiento, persistencia, ejecucion, evasion, escalada, descubrimiento

RULES.sort(key=lambda regla: regla.id)
