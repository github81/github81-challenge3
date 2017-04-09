
#python ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt

#!/usr/bin/python

from datetime import datetime, timedelta
from collections import defaultdict
from itertools import groupby
import sys
import operator

class HTTPCodes:
	UNAUTHORIZED = '401'
	FORBIDDEN = '403'

class TimeStamp:
	
	def __init__(self, currentTimeStamp, totalHosts):
		self.currentTimeStamp = currentTimeStamp 
		self.next = None
		self.totalHosts = totalHosts

	def getTimeStamp(self):
		return self.currentTimeStamp

	def getNext(self):
		return self.next

	def setNext(self, nextTimeStamp):
		self.next = nextTimeStamp

	def setTotalHosts(self, totalHosts):
		self.totalHosts = totalHosts

	def getTotalHosts(self):
		return self.totalHosts	


class TimeLog:
	
	def __init__(self):
		self.head = None
		self.tail = None
		self.startTime = None
		self.startTimePlusSixtyMinutes = None
		self.totalHosts = 0
		self.sixtyMinutePeriods = defaultdict(int)
	
	def addSixtyMinutePeriod(self, startTime, totalTraffic):
		self.sixtyMinutePeriod[startTime] = totalTraffic
	
	def insert(self, logTime, host, resource, bytes):	

		isNewTimeStamp = False

		#increate the total number of hosts (total traffic)
		#encountered so far
		self.totalHosts += 1

		#create a new time log node
		newTimeStamp = TimeStamp(logTime, self.totalHosts)

		# if it is the first time log
		# create the first node
		if self.head == None:
			self.head = newTimeStamp
			#set the initial timestamp
			self.startTime = logTime
		# if the time log already exists
		# append the host and resource
		elif self.head != None and self.head.getTimeStamp() == logTime:
			self.head.setTotalHosts(self.totalHosts)
		# if it is a new time log
		# create a new node	
		elif self.tail == None:
			self.head.setNext(newTimeStamp)
			self.tail = newTimeStamp
		# if the time log exists
		# append the host and resource
		elif self.tail != None and self.tail.getTimeStamp() == logTime:
			self.tail.setTotalHosts(self.totalHosts)
		# create the new tail		
		else:
			self.tail.setNext(newTimeStamp)
			self.tail = newTimeStamp


def checkFailedLoginAttempts(host, attempTime, attemptCode, twentySecondLogAttempts):
        loginAttemptCode = 0
        hostAttempts = host+':Attempts'
        hostFirstAttempTime = host+':First'
        hostForbiddenTime = host+':ForbiddenTime'

        #For example, if the third consecutive failed login attempt within a 20 second window occurred on 01/Aug/1995:00:00:08,
        #all access to the website for that IP address would be blocked for the next 5 minutes
        if hostAttempts in twentySecondLogAttempts and hostForbiddenTime in twentySecondLogAttempts:
                if twentySecondLogAttempts[hostAttempts] >= 3 and (attempTime-twentySecondLogAttempts[hostForbiddenTime]).total_seconds() <= 300:
                        loginAttemptCode = -1
                        return loginAttemptCode

        if attemptCode in (HTTPCodes.UNAUTHORIZED,HTTPCodes.FORBIDDEN):
                if hostFirstAttempTime in twentySecondLogAttempts:
                        #if it is a second/third failed attempt under 20 seconds
                        if (attempTime-twentySecondLogAttempts[hostFirstAttempTime]).total_seconds() <= 20:
                                twentySecondLogAttempts[hostAttempts] += 1
                                twentySecondLogAttempts[hostForbiddenTime] = attempTime
                        else:
                                #reset the attempt counter after less than three attempts and after 20 seconds
                                twentySecondLogAttempts[hostAttempts] = 1
                                twentySecondLogAttempts[hostFirstAttempTime] = attempTime
                                twentySecondLogAttempts[hostForbiddenTime] = attempTime
                else:
                        #log the first attempt
                        twentySecondLogAttempts[hostAttempts] = 1
                        twentySecondLogAttempts[hostFirstAttempTime] = attempTime
                        twentySecondLogAttempts[hostForbiddenTime] = attempTime
        else:
                #restore/give full access
                if hostAttempts in twentySecondLogAttempts:
                        del twentySecondLogAttempts[hostAttempts]
                if hostFirstAttempTime in twentySecondLogAttempts:
                        del twentySecondLogAttempts[hostFirstAttempTime]
                if hostForbiddenTime in twentySecondLogAttempts:
                        del twentySecondLogAttempts[hostForbiddenTime]

        return loginAttemptCode
	

def writeToOutputFiles(fileName, dataDictionary, justKey=0):
	with open(fileName, 'w') as writeHandler:
		for a, b in sorted(dataDictionary.iteritems(), key=lambda item: item[1], reverse=True)[:10]:
			if justKey == 1:
				writeHandler.write(a)
			else:
				writeHandler.write("%s,%s" %(a,b))
			writeHandler.write("\n")
			
def main(argv):
	#feature 1
	#dictionary to store all hosts information
	allHosts = defaultdict(int)
	
	#feature 2
	#dictionary to store all resources information
	allResources = defaultdict(int)

	#feature 3
	timeLogList = TimeLog()
	
	#feature 4
	#dictionary to keep track of 20-second log attempts
	twentySecondLogAttempts = defaultdict(int)
	
	if len(sys.argv) is not 6:
		print 'python ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt'
		sys.exit(2);
	
	#read the input file
	logFile = sys.argv[1]

	#output files
	blockedFile = sys.argv[5]
	hostsFile = sys.argv[2]
	hoursFile = sys.argv[3]
	resourcesFile = sys.argv[4]

	#get the very first timestamp in the timelog
	isFirstTimeStamp = True 

	count = 0

	#reading a large file without explicitly closing it
	with open(logFile, 'rb') as logInput, open(blockedFile, 'w') as blockedHandler:
		for logLine in logInput:

			#split by space character
			logData = logLine.split(" ")

			#ideal situation
			#resource has three phrases
			if len(logData) == 10:
				host = logData[0]
				logTimeStamp = logData[3]
				timeZone = logData[4]
				resource = logData[5] + logData[6] + logData[7]
				httpCode = logData[8]
				bytes = logData[9]
			#if resource is of two phrases	
			elif len(logData) == 9:
				host = logData[0]
				logTimeStamp = logData[3]
				timeZone = logData[4]
				resource = logData[5] + logData[6]
				httpCode = logData[7]
				bytes = logData[8]
			#400 and 404 situations	
			elif len(logData) == 8:
				host = logData[0]
				logTimeStamp = logData[3]
				timeZone = logData[4]
				resource = logData[5]
				httpCode = logData[6]
				bytes = logData[7]
			#else ignore the line	
			else:
				continue
			
			#get the timestamp on the current log
			logTimeStamp = logTimeStamp.lstrip('[')
			logTimeStamp = datetime.strptime(logTimeStamp,'%d/%b/%Y:%H:%M:%S')

			#remove the newline character on bytes
			#this is for logs 400 and 404
			bytes = bytes.rstrip('\n')
			if bytes in ('-'):
				bytes = 0

			#feature 4
			if checkFailedLoginAttempts(host, logTimeStamp, httpCode, twentySecondLogAttempts) == -1:
				#this attempt should blocked and logged
				blockedHandler.write(logLine)
				
			#feature 1
			if host in allHosts:
				allHosts[host] += 1
			else:
				allHosts[host] = 1
				
			#feature 2
			if resource in allResources:
				allResources[resource] += int(bytes)
			else:
				allResources[resource] = int(bytes)

			#feature 3
			timeLogList.insert(logTimeStamp, host, resource, int(bytes))
			
	#write total hosts
	writeToOutputFiles(hostsFile,allHosts)
	#write resources
	writeToOutputFiles(resourcesFile,allResources,1)

if __name__=="__main__":
    main(sys.argv[1:])


