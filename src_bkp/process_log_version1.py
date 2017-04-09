
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
	
	def __init__(self, nTimeStamp=None):
		self.nTimeStamp = nTimeStamp 
		self.next = None
		self.hosts = defaultdict(int)
		self.resources = defaultdict(int) 

	def getTimeStamp(self):
		return self.nTimeStamp

	def getNext(self):
		if self.next:
			 self.next
		else:
			return None

	def setNext(self, newNext):
		self.next = newNext

	def addHosts(self,host):
		if host in self.hosts:
			self.hosts[host] += 1
		else:
			self.hosts[host] = 1 

	def addResources(self,resource,bytes):
		if resource in self.resources:
			self.resources[resource] += bytes
		else:
			self.resources[resource] = bytes 

	def getHosts(self):
		return self.hosts
	
	def getResources(self):
		return self.resources

	def getTotalHosts(self):
		return sum(self.hosts.values())

	def getTotalResources(self):
		return sum(self.resources.values())

	def printHosts(self):
		print self.hosts

	def printResources(self):
		print self.resources

class TimeLog:
	
	def __init__(self, startTime=None, head=None):
		self.head = head
		self.tail = None
		self.lastTimeLogReached = False
		self.traffic = 0
		self.startTime=startTime
	
	def isLastTimeLogReached(self):
		return self.lastTimeLogReached
	
	def insert(self, logTime, host, resource, bytes):
		# only make a sixty minute period list
		if self.head is not None:
			if (logTime - self.startTime).total_seconds() > 3600:
				self.lastTimeLogReached = True
				return
	
		#update the traffic
		self.traffic += 1
	
		#create a new time log node
		newTimeStamp = TimeStamp(logTime)
		newTimeStamp.addHosts(host)
		newTimeStamp.addResources(resource,bytes)
		
		# if it is the first time log
		# create the first node
		if self.head == None:
			self.head = newTimeStamp
		# if the time log already exists
		# append the host and resource
		elif self.head != None and self.head.getTimeStamp() == logTime:
			self.head.addHosts(host)
			self.head.addResources(resource,bytes)
		# if it is a new time log
		# create a new node	
		elif self.tail == None:
			self.head.setNext(newTimeStamp)
			self.tail = newTimeStamp
		# if the time log exists
		# append the host and resource
		elif self.tail != None and self.tail.getTimeStamp() == logTime:
			self.tail.addHosts(host)	
			self.tail.addResources(resource,bytes)	
		elif self.tail != None:
			self.tail.setNext(newTimeStamp)
			self.tail = newTimeStamp
	
	def getCurrentTraffic(self):
		return self.traffic
			
	def printTimeLogs(self):
		lst = []
		current = self.head
		while current:
			lst.append(str(current.getTimeStamp()))
			current = current.getNext()
		print('->'.join(lst))

def writeToOutputFiles(fileName, dataDictionary, justKey=0):
	with open(fileName, 'w') as writeHandler:
		for a, b in sorted(dataDictionary.iteritems(), key=lambda item: item[1], reverse=True)[:10]:
			if justKey == 1:
				writeHandler.write(a)
			else:
				writeHandler.write("%s,%s" %(a,b))
			writeHandler.write("\n")

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

def createSixtyMinutePeriods(logTimeStamp,host,resource,bytes,oneHourTimeLogs,completedTimeLogs,sixtyMinutePeriods):

	#convert timestamp to string
	logTimeStampStr = logTimeStamp.strftime('%d/%b/%Y:%H:%M:%S')

	#Through the linked lists of 60-minute open time periods
	for timeStampKey, timeStampFlag in completedTimeLogs.iteritems():
		#get an open 60-minute period
		incompleteTimeLog = oneHourTimeLogs[timeStampKey]
		#insert the time log
		incompleteTimeLog.insert(logTimeStamp,host,resource,int(bytes))
		#update the total number hosts in a 60-minute period
		sixtyMinutePeriods[timeStampKey] = incompleteTimeLog.getCurrentTraffic()
		#update if 60-minute period has ended
		#if the 60-minute period is completed this will be updated to True
		completedTimeLogs[timeStampKey] = incompleteTimeLog.isLastTimeLogReached()
			
	#create a linked list for the new 60-minute time period
	if logTimeStampStr not in oneHourTimeLogs:
		#start a 60-minute period
		newTimeLog = TimeLog(logTimeStamp)
		#insert the time log
		newTimeLog.insert(logTimeStamp,host,resource,int(bytes))
		#update the total number hosts in a 60-minute period
		sixtyMinutePeriods[logTimeStampStr] = newTimeLog.getCurrentTraffic()
		#update if 60-minute period has ended
		completedTimeLogs[logTimeStampStr] = newTimeLog.isLastTimeLogReached()
		#store the timelog
		oneHourTimeLogs[logTimeStampStr] = newTimeLog
			
def main(argv):
	#feature 1
	#dictionary to store all hosts information
	allHosts = defaultdict(int)
	
	#feature 2
	#dictionary to store all resources information
	allResources = defaultdict(int)
	
	#feature 3
	#dictionary to store all the 60-period time logs
	oneHourTimeLogs = defaultdict(TimeLog)
	#dictionary to store the flags (True/False) for completed/non completed time logs
	completedTimeLogs = defaultdict(bool)
	#dictionary for total number of hosts 
	sixtyMinutePeriods = defaultdict(int)

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

			#print "processing feature 3"
			#feature 3
			#start the 60-minute period from the very first timestamp
			#and add a second on every new log	
			#convert the datetime object to string
			#as datetime objects are not iterable
			#Iterate only through the periods which did not reach the 60-minute mark
			#completedTimeLogs = dict((k,v) for k,v in completedTimeLogs.iteritems() if v == False)
			#createSixtyMinutePeriods(logTimeStamp,host,resource,bytes,oneHourTimeLogs,completedTimeLogs,sixtyMinutePeriods)
			
	#write total hosts
	writeToOutputFiles(hostsFile,allHosts)
	#write resources
	writeToOutputFiles(resourcesFile,allResources,1)
	#write 60-minute periods
	writeToOutputFiles(hoursFile,sixtyMinutePeriods)

if __name__=="__main__":
    main(sys.argv[1:])


