#!/usr/bin/env python
# -*- coding: utf8 -*-

import re
import subprocess
import sys
import xml.dom.minidom
import shlex


class PortScanner:
	"""
	PortScanner allows to use nmap from python
	"""

	def __init__(self):
		self._scan_result = {}
		self._nmap_version_number = 0       # nmap version number
		self._nmap_subversion_number = 0    # nmap subversion number
		self._nmap_last_output = ''  # last full ascii nmap output
		# is_nmap_found = False       # true if we have found nmap
		# self.__process = None

	def ipscan(self, hosts='127.0.0.1'):
		assert isinstance(hosts, str), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
		self.scan(hosts, arguments='-sP')
		return self.all_hosts()

	def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV'):
		assert isinstance(hosts, str), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
		assert ports is None or isinstance(ports, str), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
		assert isinstance(arguments, str), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

		f_args = shlex.split(arguments)

		# Launch scan
		args = ['nmap', '-oX', '-', hosts] + ['-p', ports] * (ports is not None) + f_args

		p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		# wait until finished
		# get output
		(self._nmap_last_output, nmap_err) = p.communicate()
		nmap_err = nmap_err.decode("UTF-8", "ignore") if isinstance(nmap_err, bytes) else str(nmap_err)
		self._nmap_last_output = self._nmap_last_output.decode("UTF-8", "ignore") if isinstance(self._nmap_last_output, bytes) else str(self._nmap_last_output)

		# If there was something on stderr, there was a problem so abort...
		if len(nmap_err) > 0:
			regex_warning = re.compile('^Warning: .*')
			for line in nmap_err.split('\n'):
				if len(line) > 0:
					rgw = regex_warning.search(line)
					if rgw is not None:
						sys.stderr.write(line + '\n')
					else:
						raise Exception(nmap_err)

		# nmap xml output looks like :
		#  <host starttime="1267974521" endtime="1267974522">
		#  <status state="up" reason="user-set"/>
		#  <address addr="192.168.1.1" addrtype="ipv4" />
		#  <hostnames><hostname name="neufbox" type="PTR" /></hostnames>
		#  <ports>
		#    <port protocol="tcp" portid="22">
		#      <state state="filtered" reason="no-response" reason_ttl="0"/>
		#      <service name="ssh" method="table" conf="3" />
		#    </port>
		#    <port protocol="tcp" portid="25">
		#      <state state="filtered" reason="no-response" reason_ttl="0"/>
		#      <service name="smtp" method="table" conf="3" />
		#    </port>
		#  </ports>
		#  <times srtt="-1" rttvar="-1" to="1000000" />
		#  </host>

		dom = xml.dom.minidom.parseString(self._nmap_last_output)
		scan_result = []
		for dhost in dom.getElementsByTagName('host'):
			# host ip
			host = ''
			hostname = ''
			host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
			for dhostname in dhost.getElementsByTagName('hostname'):
				hostname = dhostname.getAttributeNode('name').value
				hostname = hostname.split('.')
				hostname = hostname[0]
				host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
				scan_result.append(['host', str(hostname).upper(), str(host), '00:00:00:00:00:00'])
		self._scan_result = scan_result  # store for later use
		return scan_result

	def __getitem__(self, host):
		assert isinstance(host, str), 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
		return self._scan_result['scan'][host]

	def all_hosts(self):
		listh = self._scan_result
		listh.sort()
		return listh
