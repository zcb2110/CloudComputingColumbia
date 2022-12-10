''' Scan all ports and addresses on the network and record them on a csv (database keys)'''

import nmap
import time
import csv

# GLOBAL DICT
addr = dict()

def iterateScans(ip_range, fractions, ports, ports_list, flag, deepScanRate):
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
		if True: #time.time() - deepScanClk >= deepScanRate:
			iterations = len(ip_range)
			for i in range(iterations):
				start = time.time()
				print("Starting deep scan of IP address: {} ({} of {} addresses)".format(ip_range[i], i, iterations))
				deepScanPortsList(ip_range[i], ports_list)
				end = time.time()
				est = (end-start)*(iterations-i)
				est_hr = int(est/3600)
				est_min = int(est/60 - est_hr*60)
				est_s = int(est - est_min*60)
				print("Estimated Time Remaining: {}:{}:{}".format(
						est_hr, est_min, est_s))
				print("Dictionary len is now: {}".format(len(addr)))

			print("Finished Deep Scan of {} IP addresses, only {} remain in addr dict".format(iterations, len(addr)))

		# else do a shallow scan
		else:
			iterations = len(ip_range)
			for i in range(iterations):
				start = time.time()
				print("Starting shallow scan of IP address: {} ({} of {} addresses)".format(ip_range[i], i, iterations))



	else:
		pass


'''Have an ip_range to scan and a list of fractions that will divide up the nmap processes into different 
sections for ease of results at a certain time'''
def deepScanPorts(ip, fractions, ports):
	nm = nmap.PortScanner()
	iterations = int(ports / fractions)
	extra = ports - iterations*fractions
	print("Deep Scan started on IP {} with {} fractions for {} iterations".format(ip, fractions, iterations))

	for i in range(iterations):
		print("Current iteration {} out of {}".format(i, iterations))

		timeup = time.localtime()
		timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', timeup)

		# Determine fractal iteration
		begin = i*fractions
		end = begin+fractions

		begin = str(begin)
		end = str(end)

		# Call nmap
		nm.scan(ip, str(begin + "-" + end))
		try:
			count = len(list(nm[ip]['tcp'].keys()))

			# Update dictionary and write entry to database
			addr[ip_range] = {'count': count, 'time': timestamp}
			writeCSV('NA', addr)
		except:
			continue

	# For the reminder
	print("Final extra iteration")

	timeup = time.localtime()
	timestamp = time.strftime('%Y-%m-%d %H:%M:%S', timeup)

	# Determine fractal iteration
	begin = i*fractions
	end = extra

	begin = str(begin)
	end = str(end)

	# Call nmap
	nm.scan(ip_range, str(begin + "-" + end))
	try:
		count = len(list(nm[ip]['tcp'].keys()))

		# Update dictionary and write entry to database
		addr[ip_range] = {'count': count, 'time': timestamp}
		writeCSV('NA', addr)
	except:
		pass


def deepScanPortsList(ip, ports_list):
	nm = nmap.PortScanner()
	iterations = len(ports_list)
	print("Deep Scan started on IP {} with {} iterations".format(ip, iterations))

	for i in range(iterations):
		print("Current iteration {} out of {}".format(i, iterations))

		timeup = time.localtime()
		timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', timeup)

		# Call nmap
		nm.scan(ip, ports_list[i])
		try:
			count = len(list(nm[ip]['tcp'].keys()))

			# Update dictionary and write entry to database
			addr[ip_range] = {'count': count, 'time': timestamp}
			writeCSV('NA', addr)
		except:
			continue


'''deepScan will scan ALL ports on an hourly basis (usually takes a few hours to process) and a shallow
scan will scan all hosts without ports in order to determine if they are up and associating hosts are up'''
def shallowScan(ip_range, fractions, ports):
	pass


'''Helper function to write to CSV'''
def writeCSV(file, d):
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/addr.csv'
	f = open(CSV_PATH, 'a')
	writer = csv.writer(f)
	for item in addr:
		field = [str(addr[item]['time']), str(item), str(addr[item]['count'])]
		print(field)
		writer.writerow(field)
	f.close()


'''Helper function that will update a list of current ip addresses and ports associated that are up, along 
with time stamps and locations'''
def updateDict(d):
	pass

if __name__=="__main__":
	# Ip range for MORNINGSIDE HEIGHTS campus are:
	# 128.59.0.0 - 128.59.255.255
	# 160.39.0.0 - 160.39.255.255
	# Total of 131k possible hosts to scan in real-time

	# Initial write headers
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/addr.csv'
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
			testing_addresses.append(morningside + "." + str(i) + "." + str(j))
			testing_addresses.append(morningside2 + "." + str(i) + "." + str(j))

	print("Initial number of addresses to test: {}".format(len(testing_addresses)))

	frac = 500
	ports = 65535
	# Based on most common ports to increase efficiency
	ports_list = ['80', '139', '443', '21', '22', '110', '995', '143', '993', '25', '26', '587', '3306', '2082', 
				'2083', '2086', '2087', '2095', '2096', '2077', '2078', '20', '23', '119', '123', '161']

	# Print intitial time calculations
	print("Based on fractal division, total time to scan using DeepScan and {} ports is {} seconds".format(
			ports, len(testing_addresses)*5*ports/frac))
	print("If using ports_list, total time for DeepScan and {} ports is {} seconds".format(
			len(ports_list), len(testing_addresses)))

	# Using known access point list, scan only those routers for output instead, will be much better timing
	iterateScans(testing_addresses, frac, ports, ports_list, True, 0)

	#deepScan(ip, frac, ports)
	print("End")

