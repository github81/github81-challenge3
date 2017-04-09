
#python ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt

#!/usr/bin/python

from datetime import datetime, timedelta
from collections import defaultdict, Counter
from itertools import groupby
import sys
import operator

class HTTPCodes:
	UNAUTHORIZED = '401'
	FORBIDDEN = '403'

class Interval:
	
	def __init__(self, startTime):
		self.startTime = startTime
		self.endTime = startTime + timedelta(hours=1) 
		self.next = None
		self.traffic = Counter()

	def getStartTime(self):
		return self.startTime

	def getEndTime(self):
		return self.endTime

	def getNext(self):
		return self.next

	def setNext(self, nextInterval):
		self.next = nextInterval

	def addTraffic(self, newTimeStamp):
		self.traffic[newTimeStamp] += 1

	#get the overlapping traffic
	def mergeTraffic(self, periodStartTime, lastIntervalTraffic):
		self.traffic = Counter({k: c for k, c in lastIntervalTraffic.items() if k >= periodStartTime})

	def getTraffic(self):
		return self.traffic	

	#get total number of hosts
	def getTrafficCount(self):
		return sum(self.traffic.values())	

class TimeLog:
	
	def __init__(self):
		self.head = None
		self.tail = None
		self.sixtyMinutePeriods = defaultdict(int)
		self.allHosts = Counter()
		self.allResources = Counter()
	
	def addSixtyMinutePeriods(self, periodStartTime, totalTraffic):
		self.sixtyMinutePeriods[periodStartTime] = totalTraffic

	def getSixtyMinutePeriods(self):
		return self.sixtyMinutePeriods	
	
	def addHosts(self, host):
		self.allHosts[host] += 1

	def addResources(self, resource, bytes):
		self.allResources[resource] += bytes

	def getHosts(self):
		return self.allHosts

	def getResources(self):
		return self.allResources			

	def insert(self, logTimeStamp, host, resource, bytes):	

		sixtyMinutePeriodStartTime = None
		sixtyMinutePeriodTotalTraffic = 0

		#insert host and resource
		self.addHosts(host)
		self.addResources(resource,bytes)

		# if it is the first time log
		if self.head == None:
			#create a new time log node
			newInterval = Interval(logTimeStamp)
			newInterval.addTraffic(logTimeStamp)
			self.head = newInterval
			sixtyMinutePeriodStartTime = self.head.getStartTime()
			sixtyMinutePeriodTotalTraffic = self.head.getTrafficCount()
		# if the time log already exists
		elif self.head != None and (logTimeStamp >= self.head.getStartTime() and logTimeStamp <= self.head.getEndTime()):
			self.head.addTraffic(logTimeStamp)
			sixtyMinutePeriodStartTime = self.head.getStartTime()
			sixtyMinutePeriodTotalTraffic = self.head.getTrafficCount()
		# if it is a new time log
		elif self.tail == None:
			newIntervalStartTime = logTimeStamp + timedelta(hours=-1)
			newInterval = Interval(newIntervalStartTime)
			newInterval.mergeTraffic(newIntervalStartTime, self.head.getTraffic())
			newInterval.addTraffic(logTimeStamp)
			self.head.setNext(newInterval)
			self.tail = newInterval
			sixtyMinutePeriodStartTime = self.tail.getStartTime()
			sixtyMinutePeriodTotalTraffic = self.tail.getTrafficCount()
		# if the time log exists
		elif self.tail != None and (logTimeStamp >= self.tail.getStartTime() and logTimeStamp <= self.tail.getEndTime()):
			self.tail.addTraffic(logTimeStamp)
			sixtyMinutePeriodStartTime = self.tail.getStartTime()
			sixtyMinutePeriodTotalTraffic = self.tail.getTrafficCount()
		# create the new tail		
		else:
			#get the next interval end date and create a new interval
			newIntervalStartTime = logTimeStamp + timedelta(hours=-1)
			newInterval = Interval(newIntervalStartTime)
			newInterval.mergeTraffic(newIntervalStartTime, self.tail.getTraffic())
			newInterval.addTraffic(logTimeStamp)
			self.tail.setNext(newInterval)
			self.tail = newInterval
			sixtyMinutePeriodStartTime = self.tail.getStartTime()
			sixtyMinutePeriodTotalTraffic = self.tail.getTrafficCount()

		#update the total traffic in that particular period
		self.addSixtyMinutePeriods(sixtyMinutePeriodStartTime, sixtyMinutePeriodTotalTraffic)

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

	#feature 3
	timeLog = TimeLog()
	
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
				blockedHandler.write(logLine)
			
			#feature 3
			#create sliding windows of 60-minute periods
			#the first window start time will be the first log time
			#the following window start time will be log time - 60 minutes
			timeLog.insert(logTimeStamp, host, resource, int(bytes))

			
	#write total hosts
	writeToOutputFiles(hostsFile,timeLog.getHosts())
	#write resources
	writeToOutputFiles(resourcesFile,timeLog.getResources(),1)
	#write hours
	writeToOutputFiles(hoursFile,timeLog.getSixtyMinutePeriods())

if __name__=="__main__":
    main(sys.argv[1:])


