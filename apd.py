#!/usr/bin/python
import sys
import time
import argparse
from datetime import datetime
import socket
import multiprocessing
 
THREADS_NUMBER = 8

args = {}

startupMessages = []

#TODO: This is an example list, read this from a file later
services = {
	22: 'SSH',
	80: 'HTTP',
	443: 'HTTPS'
}

def splitChunks(a, n): 
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

def argparser():
	global args
	global startupMessages
	# TODO: Full options like --timeout, --file
	parser = argparse.ArgumentParser(description='APD port scanner')
	parser.add_argument('TargetAdress', type=str, help='Target address')
	parser.add_argument('-T', type=int, help='Thread count (default: 8)', default=8)
	parser.add_argument('-t', type=float, help='Connection timeout (default: 1.0s)', default=1)
	parser.add_argument('-f', type=str, help='Output to filename', default='')
	parser.add_argument('-pS', type=int, help='Beginning of the port range to scan (default: 1)', default=1)
	parser.add_argument('-pE', type=int, help='Upper end of the port range to scan (default: 65535)', default=65535)
	parser.add_argument('-v', action=argparse.BooleanOptionalAction, help='Show verbose information')
	parser.add_argument('-vv', action=argparse.BooleanOptionalAction, help='Show debug information')
	parser.add_argument('--show-progress', default=False, action='store_true', help='Show progress')
	parser.add_argument('--no-logo', default=False, action='store_true', help='Disable ASCII-art at startup')
	args = parser.parse_args()

	startupMessages.append('[I] Connection timeout: {}s'.format(str(args.t)))
	if args.T != 8:
		startupMessages.append('[I] Thread count: {}'.format(str(args.T)))
	if args.f != '':
		startupMessages.append('[I] Outputting results to file: {}'.format(args.f))
	if(args.v or args.vv) and args.show_progress:
		startupMessages.append("[!] Verbose / debug options (-v or -vv) and --show-progress aren't supported together. Progress is disabled.")
		args.show_progress = False
	if(args.pS < 1) or (args.pE > 65535):
		print("[-] Port range has to be within 1-65535. Cannot continue - exiting...")
		sys.exit()
	elif (args.pS > args.pE):
		print("[-} Beginning of the port range has to be lower or equal to upper end of the port range - exiting...")
		sys.exit()
	elif (args.pS != 1) and (args.pE != 65535): #Default values
		startupMessages.append('[I] Port range to scan: {}-{}'.format(str(args.pS),str(args.pE)))

def verbprint(text):
	if args.v or args.vv:
		print(text)

def debugprint(text):
	if args.vv:
		print(text)

def printProgress(finishedPort, rangeBeginning, rangeEnding):
	if args.show_progress:
		currentIndex = finishedPort - rangeBeginning
		length = rangeEnding - rangeBeginning+1
		print("Progress: {}%".format(str(int(float((currentIndex / length))*100))), end='\r') #TODO: This is one of the worst ways to calculate percentage

def scan(addr, portRange, queue, isFirst):
	global args
	openports_thread = []
	rangeBeginning = portRange[0]
	rangeEnding = portRange[-1]
	try:
		for port in portRange:
			debugprint("[D] Initializing socket")
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			debugprint("[D] Setting socket timeout")
			# Sets timeout to option specified in arguments
			soc.settimeout(args.t)

			debugprint("[D] Connecting to port {}".format(str(port)))
			result = soc.connect_ex((addr,port))
			if result == 0:
				openports_thread.append(port)
				if port in services:
					print("[*] Port {} is open - {} ".format(str(port), services[port]))
					if isFirst:
						printProgress(port, rangeBeginning, rangeEnding)
				else:
					print("[*] Port {} is open ".format(str(port))) #Whitespace because of the progress message length
					if isFirst:
						printProgress(port, rangeBeginning, rangeEnding)
			else:
				if isFirst:
					printProgress(port, rangeBeginning, rangeEnding)
				verbprint("[!] Port {} is closed - {}".format(str(port), str(result))) 
		queue.put(openports_thread)
	except socket.gaierror: #FIXME: It prints this message once for every thread
		print("[-] Cannot resolve hostname: {}".format(str(addr)))
		sys.exit()
	except KeyboardInterrupt:
		pass

def main():
	openports = []
	global startupMessages
	argparser()
	if not args.no_logo:
		print("                   __\n  ____ _____  ____/ /\n / __ `/ __ \/ __  / \n/ /_/ / /_/ / /_/ /  \n\__,_/ .___/\__,_/   \n    /_/              ")
	try:
		if startupMessages:
			for message in startupMessages:
				print(message)
			# 1s delay allowing user to read messages even if verbose or debug mode is enabled
			time.sleep(1)
		allPortsRanges = splitChunks(range(args.pS, args.pE+1), args.T)
		print("[*] Starting TCP scan on {} at {}".format(args.TargetAdress, str(datetime.now())))
		jobs = []
		queue = multiprocessing.Queue()
		isFirst = True
		for portRange in allPortsRanges:
			if list(portRange) == []:
				if(args.T != 8): #Hardcoded value to prevent from warning with default thread count
					print("[!] Ignoring user thread count: cannot start more threads than ports count")
				break
			if isFirst:
				jobs.append(multiprocessing.Process(target=scan, args=(args.TargetAdress, portRange, queue, True)))
				isFirst = False
			else:
				jobs.append(multiprocessing.Process(target=scan, args=(args.TargetAdress, portRange, queue, False)))
			jobs[-1].start()
		for job in jobs:
			job.join() # If job is already finished, .join() will return instantly
			openports = openports + list(queue.get())

		print("[+] Port scan on {} finished at {}".format(args.TargetAdress, str(datetime.now())))
		text_openports = " ".join(str(openport) for openport in openports)

		print("[+] All open ports: {}".format(text_openports))

		if args.f != '':
			try:
				output_file = open(args.f, "w")
				output_file.write(args.TargetAdress + ': ' + text_openports)
				print("[+] Output written to file: {}".format(args.f))
			except Exception as e:
				print("[-] Cannot write output to file {}: {}".format(args.f, e))
	except KeyboardInterrupt:
		print("\r[-] Cancelling scan: keyboard interrupt")
		sys.exit()

if __name__ == "__main__":
	main()
