
#python ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt

#!/usr/bin/python

from datetime import datetime
from collections import defaultdict
import sys

class HTMLCodes:
	UNAUTHORIZED = '401'
	FORBIDDEN = '403'

class Interval:
	def __init__(self, logTime):
		self.startTime = logTime
		self.next = None 

class LinkedList:
	def __init__(self):
		self.head = None

	def AppendNode(self, startTime):
		newInterval = Interval(startTime)
		if (self.head == None):
			self.head = newInterval
		elif (self.head != None) and (self.head.startTime == newInterval.startTime):
			print 'exists in head .. add the resources'
		else:
			self.head.next = newInterval
			self.head = newInterval


	

def main(argv):
	
	logAttempts = defaultdict(int)

	if len(sys.argv) is not 6:
		print 'python ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt'
		sys.exit(2);
	
	#read the input file
	logFile = sys.argv[1]
	blockedFile = sys.argv[5]

	#reading a large file without explicitly closing it	
	with open(logFile, 'rb') as logInput, open(blockedFile, 'w') as blockedOutput:
		for logLine in logInput:
			logData = logLine.split(" ")

			#ignore invalid lines
			if len(logData) is not 10:
				continue
				

			#feature 4: Detect patterns of three failed login attempts 
			#from the same IP address over 20 seconds so that all further 
			#attempts to the site can be blocked for 5 minutes. 	
			#Log those possible security breaches.

			#get the timestamp
			logStamp = logData[3].lstrip('[')
			#ex: 01/Jul/1995:00:00:12-0400
			logStamp = datetime.strptime(logStamp,'%d/%b/%Y:%H:%M:%S')
		
			hostAttempts = logData[0]+':Attempts'
			hostFirst = logData[0]+':First' 
			hostForbiddenTime = logData[0]+':ForbiddenTime'

			#after three failed attempts under 20 seconds
			#the host will be forbidden for next five minutes (300 seconds)
		
			if hostAttempts in logAttempts and hostForbiddenTime in logAttempts:
				if logAttempts[hostAttempts] >= 3 and (logStamp-logAttempts[hostForbiddenTime]).total_seconds() <= 300:
					continue

			if logData[8] in (HTMLCodes.UNAUTHORIZED,HTMLCodes.FORBIDDEN):
				if hostFirst in logAttempts:
					#if it is a second/thired failed attempt under 20 seconds	
                    			if (logStamp-logAttempts[hostFirst]).total_seconds() <= 20: 
						logAttempts[hostAttempts] += 1
						logAttempts[hostForbiddenTime] = logStamp 
                        			continue
					else:                                     
						#if it is a first failed
						logAttempts[hostAttempts] = 1
						logAttempts[hostFirst] = logStamp
						continue
				else:
					#if it is a first failed
					logAttempts[hostAttempts] = 1
					logAttempts[hostFirst] = logStamp
					continue
			else:
				logAttempts[hostAttempts] = 0


if __name__=="__main__":
    main(sys.argv[1:])


