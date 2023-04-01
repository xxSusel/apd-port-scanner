# APD port scanner
![header](/images/head.png?raw=true)

This is a simple Python script that can be used to scan for open TCP ports made mainly for educational purposes.

## Requirements
The only requirement of APD port scanner is Python 3.

## Usage
`python3 apd.py <options> <target host>`

For example, to scan the ports 1 to 100 on the host at IP address 192.168.1.1 and output results to file results.txt, you would run:

`python3 apd.py -pS 1 -pE 100 -f results.txt 192.168.1.1`

### Options:

**-T \<int\>** - thread count (default: 8)

**-t \<float\>** - connection timeout in seconds (default: 1.0)

**-f \<filename\>** - output results to file (port numbers separated with spaces)

**-pS \<int from 1-65535\>** - beginning of the port range to scan (default: 1)

**-pE \<int from 1-65535\>** - end of the port range to scan (default: 65535)

**-v/-vv** - shows verbose / debug information

**--show-progress** - shows the current percentage of a port scan

**--no-logo** - disables ASCII-art at startup



## License
This project is licensed under the MIT License - see the LICENSE file for details.