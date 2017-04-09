#!/usr/bin/python

from collections import Counter
from datetime import datetime 

dt1 = datetime.strptime('01/Jul/1995:00:00:11','%d/%b/%Y:%H:%M:%S') 
dt2 = datetime.strptime('01/Jul/1995:00:00:12','%d/%b/%Y:%H:%M:%S') 
dt3 = datetime.strptime('01/Jul/1995:00:00:13','%d/%b/%Y:%H:%M:%S') 
dt4 = datetime.strptime('01/Jul/1995:00:00:14','%d/%b/%Y:%H:%M:%S') 
dc = Counter()

dc[dt1] = 1
dc[dt2] = 1
dc[dt3] = 1
dc[dt4] = 1

dtnew = datetime.strptime('01/Jul/1995:00:00:12','%d/%b/%Y:%H:%M:%S') 

print dc
dcnew = Counter({k: c for k, c in dc.items() if k >= dtnew})
print dcnew
