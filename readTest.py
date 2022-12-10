from CreateMap import formatDict
import csv

def populateDict(file):
	'''
	Populate dictionaries from the CSV
	INPUTS: 
		- file : filename

	OUTPUTS: 
		- addr_detailed : detailed values for time, count, ip
		- addr_loc : total count per AP
	'''
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/{}.csv'.format(file)
	f = open(CSV_PATH, 'r')
	addr_detailed = dict()
	addr_loc = dict()

	# Synthesize different paths
	i = 0
	for line in f:
		if i == 0:
			# break header off
			i+=1
			continue
		data = line.strip().split(',')
		time = data[0]
		ip = data[1]
		count = int(data[2])

		addr_detailed[ip] = {'timestamp': time, 'count': count}

		# Use mapping of (--- . --- . XXX . ---) <-- to find location of access point
		pieces = ip.split('.')
		location = ('.').join(pieces[0:3]) + '.1'

		if location in addr_loc:
			addr_loc[location]['count'] += count
		else:
			addr_loc[location] = {'count': count, 'timestamp': time}

	f.close()

	return addr_detailed, addr_loc

def geoLocate(addr, data):
	'''
	Collates a whole new dictionary
	INPUTS: 
		- addr : the addresses collected
		- data : the base dictionary for mapping static locations

	OUTPUTS: 
		- None : Writes to CSV
	'''
	final_dict = dict()

	for item in addr:
		if item in data:
			final_dict[item] = {'count': addr[item]['count'], \
								'timestamp': addr[item]['timestamp'], \
								'GPS': data[item]['GPS'], \
								'Division Number': data[item]['Division Number'], \
								'Building Name': data[item]['Building Name']}

	# write CSV
	writeCSV('full_addr_10', final_dict)


def writeCSV(filename, d):
	''' Write to final CSV '''
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/{}.csv'.format(filename)
	f = open(CSV_PATH, 'w')
	writer = csv.writer(f)
	header = ["IP Address", "Device Count", "Time Stamp", "GPS_LAT", "GPS_LONG", "Building Name"]
	writer.writerow(header)
	f.close()
	
	CSV_PATH = '/Users/zacharyburpee/GitHub/CloudComputing/{}.csv'.format(filename)
	f = open(CSV_PATH, 'a')
	writer = csv.writer(f)
	for item in d:
		field = [item, d[item]['count'], d[item]['timestamp'], \
				d[item]['GPS'][0], d[item]['GPS'][1], d[item]['Building Name']]
		writer.writerow(field)
	f.close()
	

	return

def augmentCount(addr):
	''' Function to test count '''
	l = []
	for item in addr:
		l.append([addr[item]['count'], item])
	l = sorted(l, reverse=True)
	for i in l:
		print(i)
	return sorted(l, reverse=True)

if __name__=="__main__":
	addr_detailed, addr_loc = populateDict("addr10")
	total = 0
	for item in addr_loc:
		total += addr_loc[item]['count']
		#print(item, addr_loc[item]['count'])
	#print(total)

	#augmentCount(addr_loc)

	referenceDict = formatDict()
	geoLocate(addr_loc, referenceDict)

