#! /usr/bin/env python
#  Copyright (C) 2009  Sebastian Garcia
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Author:
# Sebastian Garcia eldraco@gmail.com
#
# Based on code from Twisted examples.
# Copyright (c) Twisted Matrix Laboratories.

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
#
# CHANGELOG
# 0.7
#  - Commands with the .. characters are not executed. We avoid path traversal attacks from the server to the client.  (thanks to disclosure@d1b.org)
#  - We do not move nmap output files any more, we just store them correctly.
#  - If the servers sends us an output file name with /, we replace the / with a -
# 0.6
#  - Added some more chars to the command injection prevention.
#  - Clients decide the nmap scanning rate.
#  - If the server sends a --min-rate parameter, we now delete it. WE control the scan speed.
#  - Clients decide the nmap scanning rate.
#  - Exit if nmap is not installed
#  - Stop sending the euid, it was a privacy violation. Now we just say if we are root or not.
#
# TODO
# - privileges on nmap?
#  - Detect when you don't have enought permission in the directory
#

try:
	from OpenSSL import SSL
except:
	print 'You need openssl libs for python. apt-get install python-openssl'
	exit(-1)

import sys

try:
	from twisted.internet.protocol import ClientFactory, ReconnectingClientFactory
	from twisted.protocols.basic import LineReceiver
	from twisted.internet import ssl, reactor
except:
	print 'You need twisted libs for python. apt-get install python-twisted'
	exit(-1)


import time, getopt, shlex
from subprocess import Popen
from subprocess import PIPE
import os
import random

# Global variables
server_ip = False
server_port = 46001 
vernum = '0.7'
# Your name alias defaults to anonymous
alias='Anonymous'
debug=False
# Do not use a max rate by default
maxrate = False
# End global variables


# Print version information and exit
def version():
  print "+----------------------------------------------------------------------+"
  print "| dnmap Client Version "+ vernum +"                                             |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| www.mateslab.com.ar                                                  |"
  print "+----------------------------------------------------------------------+"
  print


# Print help information and exit:
def usage():
  print "+----------------------------------------------------------------------+"
  print "| dnmap Client Version "+ vernum +"                                             |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| www.mateslab.com.ar                                                  |"
  print "+----------------------------------------------------------------------+"
  print "\nusage: %s <options>" % sys.argv[0]
  print "options:"
  print "  -s, --server-ip        IP address of dnmap server."
  print "  -p, --server-port      Port of dnmap server. Dnmap port defaults to 46001"
  print "  -a, --alias      Your name alias so we can give credit to you for your help. Optional"
  print "  -d, --debug      Debuging."
  print "  -m, --max-rate      Force nmaps commands to use at most this rate. Useful to slow nmap down. Adds the --max-rate parameter."
  print
  sys.exit(1)



def check_clean(line):
	""" Check if the received line is clear """
	global debug
	try:
		# Check for unwanted chars in the whole command
		outbound_chars = [';', '#', '`', '..']
		#ret = True
		for char in outbound_chars:
			if char in line:
				#ret = False
				return False

		# Check if the nmap output file name has any strange chars on it..., including the /
		outbound_filename_chars = [';', '#', '`', '..', '/']
		temp_vect = shlex.split(line)

		try:
			oA_index = temp_vect.index(' -o')
			nmap_output_filename = temp_vect[oA_index+1:oA_index+2]
			#if debug:
			#	print ' -- nmap_output_filename = {}'.format(nmap_output_filename)

			for char in outbound_filename_chars:
				if char in nmap_output_filename:
					return False
		except ValueError:
			# The -o is not on the list.
			pass

		# We only get here if there is nothing bad...
		return True

	except Exception as inst:
		print 'Problem in check_clean function'
		print type(inst)
		print inst.args
		print inst





class NmapClient(LineReceiver):
	def connectionMade(self):
		global client_id
		global alias
		global debug
		print 'Client connected succesfully...'
		print 'Waiting for more commands....'
		if debug:
			print ' -- Your client ID is: {0} , and your alias is: {1}'.format(str(client_id), str(alias))

		euid = os.geteuid()

		# Do not send the euid, just tell if we are root or not.
		if euid==0:
			# True
			iamroot = 1
		else:
			# False
			iamroot = 0

		# 'Client ID' text must be sent to receive another command
		line = 'Starts the Client ID:{0}:Alias:{1}:Version:{2}:ImRoot:{3}'.format(str(client_id),str(alias),vernum,iamroot)
		if debug:
			print ' -- Line sent: {0}'.format(line)
		self.sendLine(line)

		#line = 'Send more commands to Client ID:{0}:Alias:{1}:\0'.format(str(client_id),str(alias))
		line = 'Send more commands'
		if debug:
			print ' -- Line sent: {0}'.format(line)
		self.sendLine(line)

	

	def dataReceived(self, line):
		global debug
		global client_id
		global alias


		# If a wait is received. just wait.
		if 'Wait' in line:
			sleeptime = int(line.split(':')[1])
			time.sleep(sleeptime)

			# Ask for more
			#line = 'Send more commands to Client ID:{0}:Alias:{1}:'.format(str(client_id),str(alias))
			line = 'Send more commands'
			if debug:
				print ' -- Line sent: {0}'.format(line)
			self.sendLine(line)



		else:
			# dataReceived does not wait for end of lines or CR nor LF
			if debug:
				print "\tCommand Received: {0}".format(line.strip('\n').strip('\r'))
		
			# Check for a little bit of protection from the server

			if check_clean(line):

				# Vectorize the string received

				# Store the nmap output file so we can send it to the server later
				try:
					# The problem is that in the check_clean() we can not strip /, because the target uses them. 
					# But the output_file_name should not have any /. So we check it here.
					#nmap_output_file = line.split('-oA ')[1].split(' ')[0].strip(' ').replace('/','-')
					# We should shlex the line after the if chech, so we can replace the original nmap output file with the sanitized one
					#temp_vect = shlex.split(line)
					nmap_output_file = line.split('-oA ')[1].split(' ')[0].strip(' ')
					#oA_index = temp_vect.index(' -o')

					#nmap_command = temp_vect[0:word_index] + temp_vect[word_index + 1:]
					# Should we re-create the string?????
				except IndexError:
					random_file_name = str(random.randrange(0, 100000000, 1))
					print '+ No -oA given. We add it anyway so we do not lose the results. Added -oA '+random_file_name
					line = line + '-oA '+random_file_name
					nmap_output_file = line.split('-oA ')[1].split(' ')[0].strip(' ')

				try:
					nmap_returncode = -1

					# Check for rate commands
					# Verfiy that the server is NOT trying to force us to be faster. NMAP PARAMETER DEPENDACE
					
					if 'min-rate' in line:
						temp_vect = shlex.split(line)
						word_index = temp_vect.index('--min-rate')
						# Just delete the --min-rate parameter with its value
						#nmap_command = temp_vect[0:word_index] + temp_vect[word_index + 1:]
						nmap_command = temp_vect[0:word_index] + temp_vect[word_index + 2:]
					else:
						nmap_command = shlex.split(line)

					# Do we have to add a max-rate parameter?
					if maxrate:
						nmap_command.append('--max-rate')
						nmap_command.append(str((maxrate)))

					# Strip the command, so we can controll that only nmap is executed really. Improved version thanks to Paulino Calderon paulino.calderon@gmail.com
					if nmap_command[0] != "nmap":
						nmap_command[0] = 'nmap'


					# Rebuild the final nmap command, so we can show it correctly.
					nmap_command_string = ''
					for i in nmap_command:
						nmap_command_string = nmap_command_string + i + ' '
					print "\tCommand Executed: {0}".format(nmap_command_string)

					#
					# Execute nmap in the output directory directly
					#
					nmap_process = Popen(nmap_command,stdout=PIPE,cwd='nmap_output')
					raw_nmap_output = nmap_process.communicate()[0]
					nmap_returncode = nmap_process.returncode
					
				except OSError:
					print 'You don\'t have nmap installed. You can install it with apt-get install nmap'
					print 'Or you don\'t have enough permissions to create the output directory.'
					exit(-1)

				except ValueError:
					raw_nmap_output = 'Invalid nmap arguments.'
					print raw_nmap_output


				except Exception as inst:
					print 'Problem in dataReceived function'
					print type(inst)
					print inst.args
					print inst



				# Check if nmap ended ok
				if nmap_returncode >= 0:
					# Nmap ended ok

					# Tell the server that we are sending the nmap output
					print '\tSending output to the server...'
					#line = 'Nmap Output File:{0}:{1}:{2}:'.format(nmap_output_file.strip('\n').strip('\r'),str(client_id),str(alias))
					sendline = 'Nmap Output File:{0}:'.format(nmap_output_file.strip('\n').strip('\r'))
					if debug:
						print ' -- Line sent: {0}'.format(sendline)
					self.sendLine(sendline)
					self.sendLine(raw_nmap_output)
					#line = 'Nmap Output Finished:{0}:{1}:{2}:'.format(nmap_output_file.strip('\n').strip('\r'),str(client_id),str(alias))
					#We should return nmap outputZZ
					sendline = 'Nmap Output Finished:{0}:'.format(nmap_output_file.strip('\n').strip('\r'))
					if debug:
						print ' -- Line sent: {0}'.format(sendline)
					self.sendLine(sendline)

					# Ask for another command.
					# 'Client ID' text must be sent to receive another command
					print 'Waiting for more commands....'
					#line = 'Send more commands to Client ID:{0}:Alias:{1}:'.format(str(client_id),str(alias))
					sendline = 'Send more commands'
					if debug:
						print ' -- Line sent: {0}'.format(sendline)
					self.sendLine(sendline)
			else:
				# Something strange was sent to us...
				print
				# the line variable used in the next line is the string command, but now we have a vector...
				#print 'WARNING! Ignoring some strange command that was sent to us: {0}'.format(line)
				print 'WARNING! Ignoring some strange command that was sent to us'
				sendline = 'Send more commands'
				if debug:
					print ' -- Line sent: {0}'.format(sendline)
				self.sendLine(sendline)




class NmapClientFactory(ReconnectingClientFactory):
	try:
		protocol = NmapClient

		def startedConnecting(self, connector):
			print 'Starting connection...'

		def clientConnectionFailed(self, connector, reason):
			print 'Connection failed:', reason.getErrorMessage()
			# Try to reconnect
			print 'Trying to reconnect. Please wait...'
			ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

		def clientConnectionLost(self, connector, reason):
			print 'Connection lost. Reason: {0}'.format(reason.getErrorMessage())
			# Try to reconnect
			print 'Trying to reconnect in 10 secs. Please wait...'
			ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
	except Exception as inst:
		print 'Problem in NmapClientFactory'
		print type(inst)
		print inst.args
		print inst




def process_commands():
	global server_ip
	global server_port
	global client_id
	global factory
	try:

		print 'Client Started...'

		# Generate the client unique ID
		client_id = str(random.randrange(0, 100000000, 1))

		# Create the output directory
		print 'Nmap output files stored in \'nmap_output\' directory...'
		os.system('mkdir nmap_output > /dev/null 2>&1')

		factory = NmapClientFactory()
		# Do not wait more that 10 seconds between reconnections
		factory.maxDelay = 10

		reactor.connectSSL(str(server_ip), int(server_port), factory, ssl.ClientContextFactory())
		#reactor.addSystemEventTrigger('before','shutdown',myCleanUpFunction)
		reactor.run()
	except Exception as inst:
		print 'Problem in process_commands function'
		print type(inst)
		print inst.args
		print inst



def main():
	global server_ip
	global server_port
	global alias
	global debug
	global maxrate

	try:
		opts, args = getopt.getopt(sys.argv[1:], "a:dm:p:s:", ["server-ip=","server-port","max-rate","alias=","debug"])
	except getopt.GetoptError: usage()

	for opt, arg in opts:
	    if opt in ("-s", "--server-ip"): server_ip=str(arg)
	    if opt in ("-p", "--server-port"): server_port=arg
	    if opt in ("-a", "--alias"): alias=str(arg).strip('\n').strip('\r').strip(' ')
	    if opt in ("-d", "--debug"): debug=True
	    if opt in ("-m", "--max-rate"): maxrate=str(arg)

	try:

		if server_ip and server_port:

			version()

			# Start connecting
			process_commands()

		else:
			usage()


	except KeyboardInterrupt:
		# CTRL-C pretty handling.
		print "Keyboard Interruption!. Exiting."
		sys.exit(1)


if __name__ == '__main__':
    main()
