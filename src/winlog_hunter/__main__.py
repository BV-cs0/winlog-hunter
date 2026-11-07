from .cli import main
from .pathfix import ensure_command_available

ensure_command_available()
raise SystemExit(main())
