"""Allow running as `python -m audit_tool`."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
