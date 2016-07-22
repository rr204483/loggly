#!/usr/bin/env python2.7
# logaggregator takes a set of logs and merge them chronologically based on the 
#timestamp
import fileinput
import re
import sys
import argparse
import os
from datetime import datetime
from datetime import date
import subprocess
import gzip

class Validator (object):
	def __init__(self, t_arg=None, T_arg=None, e_arg=None):
		self.t_arg=t_arg
		self.T_arg=T_arg
		self.e_arg=e_arg

class Line(object):
	# http://www.saltycrane.com/blog/2008/06/how-to-get-current-date-and-time-in/
	mydict={"^[a-zA-Z]{3} [a-zA-Z]{3}[\s]{1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}" :"%a %b %d %H:%M:%S %Y",
				   "^[a-zA-Z]{3}[\s]{1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}":"%a %d %H:%M:%S:%Y",
				   "^\d{4} [a-zA-Z]{3}[\s]{1,2}\d{1,2} \d{2}:\d{2}:\d{2}":"%Y %b %d %H:%M:%S",
				   "^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}":"%Y-%m-%d %H:%M:%S",
				   "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}":"%Y-%m-%dT%H:%M:%S",
				   "^\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2}":"%d/%b/%Y:%H:%M:%S",
		   "[a-zA-Z]{3}[\s]{1,2}\d{1,2} \d{2}:\d{2}:\d{2}":"%b %d %H:%M:%S"
					}
	def __init__(self, fname=None, linedatetime=None, datetimeformat=None, text=None):
		self.fname=fname
		self.linedatetime=linedatetime
		self.datetimeformat=datetimeformat;
		self.text=text

	def isDateFound(self, line):
		for key, value in self.mydict.iteritems():
			match=re.search(key,line)
			if match :
				return match

	# this menthod called for each line
	def parse_line(self, path, line, myvalidator):
		for key, value in self.mydict.iteritems():
			try :
				match=re.search(key,line)
				if match :
				       # some of the txt files like system.sys &
				       # debug.sys will have "\n" at the end, use -1 to
				       # ignore those
					if line[-1] == '\n':
						text=line[match.end()+1:-1].lstrip()
					else:
						text=line[match.end()+1:].lstrip()

					fname=os.path.split(path)[1]
					   # display nothing if it is a empty line with just date/timestamp on it
					if not text:
					   return False
				   	# if there is date/timestamp without year, add an year
					# for handling system.sys and debug.sys formats
					# Feb 06 13:44:50
					if value=="%b %d %H:%M:%S":
					   now = datetime.now()
					   #newdate=match.group(0)+':'+str(date.today().year)
					   newdate=match.group(0)+':'+str(now.year)
					   linedate=datetime.strptime(newdate, "%b %d %H:%M:%S:%Y")
					   if (now.month < linedate.month):
						   newdate=match.group(0)+':'+str(now.year-1)
						   linedate=datetime.strptime(newdate, "%b %d %H:%M:%S:%Y")
					else :
					  linedate=datetime.strptime(match.group(0), value)

					if ( ((myvalidator) and (check_timestamps(myvalidator, linedate))) or
						   (not myvalidator) ):
					   self.set(fname,linedate, value, text)
					   return True
					else :
					   return False
			except ValueError,err:
				 print err
				 return False

		return False

	def outputMsg(self, displayFileName, keeplogtimestamp, max_filename_len=0, max_date_len=0):

		if keeplogtimestamp:
			datetimeformat=self.datetimeformat
		else :
			datetimeformat="%b %d %H:%M:%S:%Y"
		if (self.faketime):
			faked='~'
		else :
			faked=' '
		if (displayFileName) and (keeplogtimestamp) :
			msg='{0:<{w}}: {1:<{w1}}:{2}{3}'.format(self.fname,
													  self.linedatetime.strftime(datetimeformat),
													  faked,
													  self.text,
										  w=max_filename_len,
													  w1=max_date_len)
		elif (not displayFileName) and (keeplogtimestamp) :
			msg='{0:<{w1}}:{1}{2}'.format(self.linedatetime.strftime(datetimeformat),
											self.text, faked, w1=max_date_len)
		elif (displayFileName):
			msg='{0:<{w}}: {1}:{2}{3}'.format(self.fname,
												  self.linedatetime.strftime(datetimeformat),
												  faked,
												  self.text, w=max_filename_len)
		elif (keeplogtimestamp):
			msg='{0}: {1:<{w1}}:{2}{3}'.format(self.fname,
												   self.linedatetime.strftime(datetimeformat),
												   faked,
												   self.text,w1=max_date_len)
		else:
			msg='{0}:{1}{2}'.format(self.linedatetime.strftime(datetimeformat), faked, self.text)

		return msg

		#print self.linedatetime.strftime(self.datetimeformat)

		#print '{0}:{1}:{2}'.format(self.fname, self.linedatetime,self.text)


	def set(self, fname, linedatetime, datetimeformat, text, fake=False):
		self.fname=fname
		self.linedatetime=linedatetime
		self.datetimeformat=datetimeformat
		self.text=text
		self.faketime=fake

''' common routines '''
def check_timestamps(myvalidator, linedate):
	if (myvalidator.e_arg):
		datewithouttime=datetime.strptime(linedate.strftime("%b%d%Y"), "%b%d%Y")
		if ((diff_dates(myvalidator.e_arg, datewithouttime)) == 0):
			return True
	elif (myvalidator.t_arg) and (myvalidator.T_arg) :
		if ((diff_dates(myvalidator.t_arg, linedate) <= 0) and
			(diff_dates(myvalidator.T_arg, linedate) > 0) ):
				return True
	elif ( (myvalidator.t_arg) and (diff_dates(myvalidator.t_arg, linedate) <=0) ):
				return True
	elif( (myvalidator.T_arg) and (diff_dates(myvalidator.T_arg, linedate) >0 ) ):
				return True

	return False

def validate_date(value):
	# Acceptable Formats :
	# 23jan2014, 23-jan-2014, 23012014, 23-01-2014, 23/01/2014
	# %d%b%Y, %d-%b-%Y, %d%m%Y, %d-%m-%Y, %d/%m/%Y
	dateformats=['%d%b%Y', '%d-%b-%Y', '%d%m%Y', '%d-%m-%Y', '%d/%m/%Y', '%b%d%Y']
	sampledates="ddmonyyyy, dd-mon-yyyy, ddmmyyyy, dd-mm-yyyy, dd/mm/yyyy, monddyyyy, ddmon, mondd"
	'''special date formats, if dates are passed without an year.
	like 08feb or feb08 '''
	mydict={"^[a-zA-Z]{3}\d{1,2}$":"%b%d%Y",
			"^\d{1,2}[a-zA-Z]{3}$":"%d%b%Y"
			}

	for dateformat in dateformats:
		try :
			mydate=datetime.strptime(value, dateformat)
			return mydate
		except ValueError:
			continue

	for  key, dictdateformats in mydict.iteritems():
		try :
			match=re.match(key,value)
			if match:
			   newdate=match.group(0)+str(date.today().year)
			   linedate=datetime.strptime(newdate, dictdateformats)
			   return linedate
		except ValueError:
		   continue

	raise Exception("Invalid date value:{0}. Valid formats are : {1}".format(value, sampledates))

def diff_dates(mydate, linedate):
	#print "mydate:{0}, linedate:{1}, diff:{2}".format(mydate, linedate, mydate-linedate)
	if mydate > linedate:
		return 1
	elif mydate < linedate:
		return -1
	elif mydate == linedate:
		return 0

def list_files(dirpath):
   filesInDir=[]
   for fname in os.listdir(dirpath):
	   absolutePath=os.path.join(dirpath, fname)
	   if os.path.isfile(absolutePath):
		   filesInDir.append(absolutePath)
	   elif os.path.isdir(absolutePath):
		  filesInDir.extend(list_files(absolutePath))
   return filesInDir

def check_filetype(file):
	try:
		filetype='txt'
		#file is absolute path name
		fname=file.split('/')[-1]
		fileextension=fname.split(".")[-1]

		if fileextension == "txt":
		   filetype='txt'
		elif re.match('^[\w]+.ak[.\d]*.gz', fname):
		   filetype='akgz'
		elif re.match ('^[\w]+.ak[.\d]*',fname):
		   filetype='ak'
		elif fileextension == "gz":
		   filetype='gz'

		return filetype
	except ValueError, err:
			filetype='txt'
			return filetype

def read_lines_ak(file, myvalidator):
	akLines=[]
	parsedLines=[]
	#run aklog command
	p = subprocess.Popen("aklog --tool-version beta -s "+file, stdout=subprocess.PIPE, shell=True)
	'''Talk with date command i.e. read data from stdout and stderr. Store this info in tuple ##
Interact with process: Send data to stdin. Read data from stdout and stderr,
until end-of-file is reached. Wait for process to terminate. The optional input
argument should be a string to be sent to the child process, or None, if no data
should be sent to the child.'''

	(output, err) = p.communicate()
	## Wait for aklog to terminate. Get return returncode ##
	p_status = p.wait()

	if p_status == 0:
		akLines=output.split("\n")
		#parse each line and create lineObj
		for line in akLines:
			lineObj=Line()
			if (lineObj.parse_line(file, line, myvalidator)):
				parsedLines.append(lineObj)
	return parsedLines

def read_lines(file, myvalidator):
	Lines=[]
	try :
		prevvalue="%Y %b %d %H:%M:%S"
		prevdate=datetime.strptime("1970 Jan 01 00:00:00", prevvalue)
		for line in fileinput.hook_compressed(file, "r"):
			line_obj=Line()
			if (line_obj.isDateFound(line)):
				if(line_obj.parse_line(file,line, myvalidator)):
					prevdate=line_obj.linedatetime
					prevvalue=line_obj.datetimeformat
					Lines.append(line_obj)
			else :
				# for handling the lines without date, eg: smf files
				fname=os.path.split(file)[1]
				#print prevdate, prevvalue, line, fname
				line_obj.set(fname, prevdate, prevvalue, line[:-1].lstrip(), fake=True)
				#Lines[-1].text=Lines[-1].text+"\n"+line
				Lines.append(line_obj)

		return Lines
	except IOError :
		raise Exception(fname+": File is not found. Ignoring this file ")

def read_lines_old(file, myvalidator):
       Lines=[]
       try :
               for line in fileinput.hook_compressed(file, "r"):
                       line_obj=Line()
                       if(line_obj.parse_line(file,line, myvalidator)):
                               Lines.append(line_obj)
               return Lines
       except IOError :
               raise Exception(fname+": File is not found. Ignoring this file ")

def read_files(files, myvalidator):
	allLines=[]
	for file in files:
		try:
			if not (os.path.exists(file)):
			   raise Exception(file+": File is not found. Ignoring this file ")

			fileType=check_filetype(file)
			if fileType == "ak" or fileType == "akgz":
				allLines.extend(read_lines_ak(file, myvalidator))
				continue

			''' call this for other type of files '''
			allLines.extend(read_lines(file, myvalidator))

		except Exception, err:
			''' file is not found and continue with next file '''
			print err
			continue

	return allLines

def print_output(allSortedLines, searchstrs, ignorestrs,
		output,displayFileName, keeplogtimestamp):

	max_filename_len=0
	max_date_len=0
	if allSortedLines:
		if displayFileName :
			max_filename_len=max(len(Line.fname) for Line in allSortedLines)
		if keeplogtimestamp:
			max_date_len=max(len((Line.linedatetime).strftime(Line.datetimeformat)) for Line in allSortedLines)
	if output:
		fp=open(output, "w")
	for line in allSortedLines:
		msg=None
		if ((searchstrs) or (ignorestrs)):
			#if ((searchstrs) and (search_string_all(line, searchstrs))):
			if ((searchstrs) and (search_string(line,searchstrs))):
				msg=line.outputMsg(displayFileName,
						keeplogtimestamp,
						max_filename_len, max_date_len)
			if ignorestrs :
				if (ignore_string(line, ignorestrs)):
					msg=line.outputMsg(displayFileName,
							keeplogtimestamp,
							max_filename_len,max_date_len)
				else:
					msg=None
		else :
			msg=line.outputMsg(displayFileName, keeplogtimestamp,
					max_filename_len, max_date_len)

		if msg :
			if output:
				fp.write(msg+"\n")
			else:
				print msg
	if output:
		fp.close()


def search_string(line, searchstrs):
	for searchstr in searchstrs:
		if (re.search(searchstr, line.text, re.IGNORECASE)):
			return 1
	#no match found
	return 0

#this fun is not used now. it may be used in the futuer to
# have a RE supported in the future

def search_string_all(line, searchstrs):
	strsearch=''.join(searchstrs)

	#if (strsearch.find('&') == -1) :
	#	print "& is not found"
	#else:
	#	strsearchtoken=strsearch.split('&')

	for searchstr in strsearch:
		#print searchstr
		if (re.search(searchstr, line.text, re.IGNORECASE)):
			#print "match is found"
			continue
		else:
			#print "match is not found , return 0"
			return 0
	#print "match found , return 1"
	return 1

def ignore_string(line, ignorestrs):
	for ignorestr in ignorestrs:
		if (re.search(ignorestr, line.text, re.IGNORECASE)):
			#string is found , so throw away the string
			return 0
	#the string is not found
	return 1

def sortKey(line):
	return line.linedatetime

def returnError(errstr, exit=0):
	sys.stderr.write("%s\n" % errstr)
	if exit:
		sys.exit(1)

def parse_args():
		   parser = argparse.ArgumentParser(description='Aggregates multiple file content in a chronological order. Files can be in text, ak or gzip format.')
	   #
	   # store_true option automatically creates a default value of False.
	   # Likewise, store_false will default to True when the command-line argument is not present.
	   #
		   parser.add_argument('-n', dest='displayFileName', action='store_false',
				help='suppress filename')

		   parser.add_argument('-k', dest='keeplogtimestamp', action='store_true',
				help='keep logs date format')

		   parser.add_argument('-p', metavar='search-pattern',
								dest='pattern', action='append',
								help='text pattern to search for')

		   parser.add_argument('-i', metavar='ignore-pattern',
								dest='ignorepattern', action='append',
								help='text pattern to ignore for')

		   parser.add_argument('-t', metavar='from-date',  dest='fromdate',
								 action='store', help='select events that occurred after the specified date')

		   parser.add_argument('-e', metavar='exact-date',  dest='exactdate',
								 action='store', help='select events that occurred on the specified date')

		   parser.add_argument('-T', metavar='until-date', dest='untildate',
								action='store', help='select events that occurred before the specified date')

		   parser.add_argument('-o', metavar='filename', dest='outfile', action='store',
								help='output file')
		   parser.add_argument(dest='filenames',metavar='file | directory', nargs='+')

		   args = parser.parse_args()
		   return args

def main():

	args=parse_args()
	files=[]
	allLines=[]
	sortedLines=[]

	if ((args.fromdate) or (args.untildate)) and (args.exactdate):
			returnError("can not have both -t/-T and -e. These are mutually exclusive options", 1)

	for path in args.filenames:
		if os.path.isdir(path):
		   files.extend(list_files(path))
		elif os.path.isfile(path):
			files.append(os.path.abspath(path))
		else :
			returnError(path+": No such file or directory", 0)

	myvalidator=Validator()

	if (args.fromdate) or (args.untildate) or (args.exactdate):
		try:
			if args.fromdate:
				myvalidator.t_arg=validate_date(args.fromdate)
			if args.untildate:
				myvalidator.T_arg=validate_date(args.untildate)
			if args.exactdate:
				myvalidator.e_arg=validate_date(args.exactdate)
		except Exception, err:
			    returnError(err)
	else :
		myvalidator=None

	allLines.extend(read_files(files,myvalidator))
	sortedLines=sorted(allLines, key=sortKey)

	print_output(sortedLines, args.pattern, args.ignorepattern,
			args.outfile, args.displayFileName, args.keeplogtimestamp);

if __name__ == "__main__":
	try :
		main()
	except KeyboardInterrupt:
		print 'Interrupted...exiting'
	except Exception,err :
		print err
		pass
	try:
		sys.exit(0)
	except SystemExit:
		os._exit(0)
#sys.exit(0)

