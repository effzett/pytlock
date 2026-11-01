import sys

if len(sys.argv) > 1:
    from pytlock.cli import main
else:
    from pytlock.gui.app import main

raise SystemExit(main())
