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
# CHANGELOG
# 0.7, first version
#
#
# What does it do?
#
# dnmap.py is a program to automatically queue nmap commands for distribution. The idea is that
# you execute dnmap.py like you use nmap. The command will be automatically distributed using
# dnmap_server to all the dnamp_clients
# This way, you can just execute dnmap.py instead of nmap and have everything working fine!
#

import sys
import time, getopt, shlex
import os

# Global variables
vernum = '0.7'
verbose_level = 2
nmap_commands_file = ''
nmap_commands = []
# End global variables


# Print version information and exit
def version():
  print "+----------------------------------------------------------------------+"
  print "| dnmap Version "+ vernum +"                                                    |"
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
  print "| dnmap Version "+ vernum +"                                                    |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| www.mateslab.com.ar                                                  |"
  print "+----------------------------------------------------------------------+"
  print "\nusage: %s nmap command " % sys.argv[0]
  print 'Example:'
  print 'dnmap.py -sS -F -A -n -v -d 192.168.1.0/24'
  print
  sys.exit(1)


def read_conf():
	""" Read the dnmap configuration file and store the values in the correct variables. If the conf file does not exists, we create it.  """
	global nmap_commands_file

	try:

		# Try to read /etc/dnmap/dnmap.conf
		try:
			os.stat('/etc/dnmap/dnmap.conf')
			# It exist
			conf_file = '/etc/dnmap/dnmap.conf'
		except OSError:
			# It does not exist. Try with ./dnmap.conf
			try:
				os.stat('./dnmap.conf')
				# It exist
				conf_file = './dnmap.conf'
			except OSError:
				# It does not exist. Deal with it...

				print 'WARNING.'
				print 'No configuration file was found on /etc/dnmap/dnmap.conf nor ./dnmap.conf. We are going to create a new one in ./dnmap.conf'
				print 'We suggest you to move it to /etc/dnmap/dnmap.conf if you want to access it from any directory with dnmap.py later'
				print
				conf_file = './dnmap.conf'
				print 'Please enter the full path of the NMAP commands file, e.g.: /home/test/dnmap/nmap_commands.txt'
				nmap_commands_file = raw_input()
				f = open(conf_file,'w')
				f.writelines('# Dnmap automatic created configuration file\n')
				# No sanitization of nmap_commands_file?
				f.writelines('nmap_commands_file = '+nmap_commands_file+'\n')
				f.close

		print 'Using configuration file '+conf_file
		# Open and read the conf file.
		fi = open(conf_file,'r')
		line = fi.readline()
		# Read the conf lines
		while line:
			# Avoid commentaries
			if '#' in line.strip(' ').strip('\t'):
				# just a comment, go on
				line = fi.readline()
				continue
			try:
				variable_name = line.replace(' ','').replace('\t','').split('=')[0].strip('\n')
				value = line.replace(' ','').replace('\t','').split('=')[1].strip('\n')
			except:
				print 'Some syntax error was detected in the configuration file. Perhaps the = is missing?'
				exit(-1)

			# Store the values in the proper variable name.
			# So far only nmap_commands_file is used

			# Nmap command file name
			if 'nmap_commands_file' == variable_name:
				nmap_commands_file = value

			line = fi.readline()
		fi.close()


	except Exception as inst:
		print 'Problem in read_conf function'
		print type(inst)
		print inst.args
		print inst





def generate_nmap_commands(given_nmap_command_vect):
	""" Generate the final nmap commands list  """
	global nmap_commands

	given_nmap_command = ''
	new_commands_list = []
	try:
		if verbose_level > 1:
			print 'Generating the nmap commands...'

		# Put everything together
		for part in given_nmap_command_vect:
			given_nmap_command = given_nmap_command + ' ' + str(part) 

		given_nmap_command = 'nmap' + given_nmap_command


		# Process the commands, and split big networks...
		new_commands_list.append(given_nmap_command)

		
		# Store every new command in a vector
		for command in new_commands_list:
			nmap_commands.append(command)

	except Exception as inst:
		print 'Problem in generate_nmap_commands function'
		print type(inst)
		print inst.args
		print inst



def store_nmap_commands():
	""" Store the nmap commands in the file"""
	global nmap_commands_file
	global nmap_commands

	try:
	
		if verbose_level > 1:
			print 'Storing the nmap commands...'

		fil = open(nmap_commands_file,'a')
		for command in nmap_commands:
			fil.writelines(command+'\n')

		fil.flush()
		fil.close()

		if verbose_level > 1:
			print 'Done.'

	except Exception as inst:
		print 'Problem in store_nmap_commands function'
		print type(inst)
		print inst.args
		print inst


def main():
	global nmap_commands_file

	try:
		version()
		
		if len(sys.argv) == 1:
			print 'No nmap command given.'
			print 'Example: '+sys.argv[0]+' -sS -A -n -v -d x.x.x.x -oA x.x.x.x-sS'
			exit(-1)

		# Read the conf
		read_conf()

		# Generate the final nmap command list
		generate_nmap_commands(sys.argv[1:])

		# Store the commands
		store_nmap_commands()


	except KeyboardInterrupt:
		# CTRL-C pretty handling.
		print "Keyboard Interruption!. Exiting."
		sys.exit(1)


if __name__ == '__main__':
    main()
