# APD port scanner
Simple TCP port scanner created in Python

Usage:
```apd.py [-T 8 -t 1.0 -f filename.out -pS 1 -pE 65535 -v/-vv --show-progress --no-logo] [host to scan]```

## Options:

**-T [int]** - Thread count (default: 8)

**-t [float]** - connection timeout (default: 1.0)

**-f [filename]** - output results to file (port numbers separated with spaces)

**-pS [int from 1-65535]** - beginning of the port range to scan* (default: 1)

**-pE [int from 1-65535]** - end of the port range to scan* (default: 65535)**

**-v/-vv** - show more info (default: OFF)

**--show-progress** - show current percentage of a port scan

**--no-logo** - disable ASCII-art at startup
