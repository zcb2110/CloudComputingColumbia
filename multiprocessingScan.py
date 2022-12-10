''' Scan all ports and addresses on the network and record them on a csv (database keys)'''

import nmap
import time
import csv
from time import sleep
from multiprocessing import Process

def iterateScans(ip_range, fractions, ports, ports_list, flag, deepScanRate, file):
	'''
	Main function to cycle through ALL IP addresses
	INPUTS: 
		- ip_range : range of ip addresses to scan, calls deep/shallow scan for writing 
		- fractions : input number of fractions to break the nmaps into (lower fraction = higher iterations)
		- ports : if ports are specified only scan from that range of top limit (from 0)
		- ports list : if a ports_list is specified, then use the most common ports for efficiency
		- flag : determines whether ports or ports list should be used
		- deepScanRate : gives time rating for deepScan vs. shallowScan to try all ports again

	OUTPUTS: 
		- None : Simply iterates and updates main dictionary and database with periodic inputs of how long
				 unitl next scans, and total time updates
	'''
	deepScanClk = time.time()

	# Flag = True is ports list
	if flag:
		# if ready for deepscan
		if False: #time.time() - deepScanClk >= deepScanRate:
			iterations = len(ip_range)
			for i in range(iterations):
				start = time.time()
				print("Starting deep scan of IP address: {} ({} of {} addresses)".format(ip_range[i], i, iterations))

				# Make multiprocessing list
				processes = [Process(target=deepScanPortsList, args=(ip_range[i], 
								ports_list[k])) for k in range(len(ports_list))]

				# Start processes
				for process in processes:
					process.start()
				# Wait for ending
				for process in processes:
					process.join()

				end = time.time()
				est = (end-start)*(iterations-i)
				est_hr = int(est/3600)
				est_min = int(est/60 - est_hr*60)
				est_s = int(est - est_min*60)
				print("Estimated Time Remaining: {}:{}:{}".format(
						est_hr, est_min, est_s))
				print("Dictionary len is now: {}".format(len(addr)))
				sleep(1)

			print("Finished Deep Scan of {} IP addresses, only {} remain in addr dict".format(iterations, len(addr)))

		# else do a shallow scan
		else:
			# Determine range of hosts in multiprocessing manner
			addresses = []
			morningside2 = '160.39'
			for i in range(256):
				# Breaking into 3 fractions
				addresses.append(morningside2 + "." + str(i) + "." + "0-100")
				addresses.append(morningside2 + "." + str(i) + "." + "101-200")
				addresses.append(morningside2 + "." + str(i) + "." + "201-255")

			batches = int(len(addresses) / 20)
			for i in range(batches):
				batched_addr_list = addresses[i*20:(i+1)*20]
				
				start = time.time()
				processes = []
				for k in range(len(batched_addr_list)):
					ip = batched_addr_list[k]
					processes.append(Process(target=shallowScanPortsList, args=([ip, file])))

				# Start processes
				for process in processes:
					process.start()
				# Wait for ending
				for process in processes:
					process.join()

				end = time.time()
				est = (end-start)*(batches-i)
				est_hr = int(est/3600)
				est_min = int(est/60 - est_hr*60)
				est_s = int(est - est_min*60)
				print("Estimated Time Remaining: {}:{}:{}".format(
						est_hr, est_min, est_s))
				sleep(0.5)
				

			# For the remainder after the batches finish
			remainder = addresses[20*(i+1):]
			processes = []
			for k in range(len(remainder)):
				ip = remainder[k]
				processes.append(Process(target=shallowScanPortsList, args=([ip])))

			# Start processes
			for process in processes:
				process.start()
			# Wait for ending
			for process in processes:
				process.join()

	else:
		pass


def deepScanPortsList(ip, port):
	'''
	Deep scan - including all ports in the list or ports total 
	INPUTS: 
		- ip : current IP address
		- ports : if ports are specified only scan from that range of top limit (from 0)

	OUTPUTS: 
		- None : Writes to CSV
	'''

	nm = nmap.PortScanner()

	timeup = time.localtime()
	timestamp = time.strftime('%Y-%m-%d %H:%M:%S', timeup)

	# Call nmap
	s = nm.scan(ip, port)
	try:
		state = s['scan'][ip]['tcp'][int(port)]['state']

	except:
		return

	# Update dictionary and write entry to database
	if state == 'open':
		if ip in addr:
			addr[ip]['count'] += 1
		else:
			addr[ip] = {'count': 1, 'time': timestamp}

		writeCSV('NA', addr)

def shallowScanPortsList(ip_list, file):
	'''
	Multiprocessing version of scallow scan
	INPUTS: 
		- ip_list : range of IPs
		- file : filename

	OUTPUTS: 
		- None : Writes to CSV
	'''
	timeup = time.localtime()
	timestamp = time.strftime('%Y-%m-%d %H:%M:%S', timeup)
	print("Scanning IPs: ", ip_list)
	nm = nmap.PortScanner()

	nm.scan(hosts=ip_list, arguments='-n -sP -PE')
	addr = dict()
	for item in nm.all_hosts():
		addr[item] = {'count': 1, 'time': timestamp}

	print("Addresses to write: ", len(addr))
	writeCSV(file, addr)

'''Helper function to write to CSV'''
def writeCSV(file, d):
	'''
	Writes to CSV
	INPUTS: 
		- file : filename
		- d : dictionary to write

	OUTPUTS: 
		- None : The CSV
	'''
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/{}.csv'.format(filename)
	f = open(CSV_PATH, 'a')
	writer = csv.writer(f)
	for item in d:
		field = [str(d[item]['time']), str(item), str(d[item]['count'])]
		writer.writerow(field)
	f.close()

	return

if __name__=="__main__":
	# Ip range for MORNINGSIDE HEIGHTS campus are:
	# 128.59.0.0 - 128.59.255.255
	# 160.39.0.0 - 160.39.255.255
	# Total of 131k possible hosts to scan in real-time
	filename = "addr11"
	# Initial write headers
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/{}.csv'.format(filename)
	f = open(CSV_PATH, 'w')
	header = ['Time Stamp', 'IP Address', "Count"]
	writer = csv.writer(f)
	writer.writerow(header)
	f.close()

	# Determine total ip addresses
	testing_addresses = []
	morningside = '128.59'
	morningside2 = '160.39'
	for i in range(256):
		for j in range(256):
		#testing_addresses.append(morningside + "." + str(i) + "." + "1")
			testing_addresses.append(morningside2 + "." + str(i) + "." + str(j))

	print("Initial number of addresses to test: {}".format(len(testing_addresses)))

	frac = 256
	ports = 65535
	# Based on most common ports to increase efficiency
	ports_list = ['80', '22', '5000', '7000' '139', '443', '21', '22', '110', '995', '143', '993', 
				'25', '26', '587', '3306', '2082', '2083', '2086', '2087', '2095', '2096', 
				'2077', '2078', '20', '23', '119', '123', '161']

	# Print intitial time calculations
	'''
	print("Based on fractal division, total time to scan using DeepScan and {} ports is {} seconds".format(
			ports, len(testing_addresses)*5*ports/frac))
	print("If using ports_list, total time for DeepScan and {} ports is {} seconds".format(
			len(ports_list), len(testing_addresses)))
	'''
	# Using known access point list, scan only those routers for output instead, will be much better timing
	iterateScans(testing_addresses, frac, ports, ports_list, True, 0, filename)


