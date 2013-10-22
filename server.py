#!/bin/env python
# -*- coding: utf8 -*-

"""
#http_port 3128 transparent

icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Authenticated-User
icap_preview_enable on
icap_preview_size 1024
#icap_service service_req reqmod_precache bypass=1 icap://127.0.0.1:13440/squidclamav
#adaptation_access service_req allow all
icap_service service_resp respmod_precache bypass=1 icap://127.0.0.1:13440/example
adaptation_access service_resp allow all
"""

import random
import SocketServer

from pyicap import *

import StringIO
import gzip
import re

class ThreadingSimpleServer(SocketServer.ThreadingMixIn, ICAPServer):
	pass

class ICAPHandler(BaseICAPRequestHandler):

	def example_OPTIONS(self):
		self.set_icap_response(200)
		self.set_icap_header('Methods', 'RESPMOD')
		self.set_icap_header('Service', 'PyICAP Server 1.0')
		self.set_icap_header('Preview', '0')
		self.set_icap_header('Transfer-Preview', '*')
		self.set_icap_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv')
		self.set_icap_header('Transfer-Complete', 'html,htm')
		self.set_icap_header('Max-Connections', '100')
		self.set_icap_header('Options-TTL', '3600')
		self.send_headers(False)

	def example_RESPMOD(self):
		self.set_icap_response(200)

		self.set_enc_status(' '.join(self.enc_res_status))
		for h in self.enc_res_headers:
			for v in self.enc_res_headers[h]:
				self.set_enc_header(h, v)

		analysis_flag = False
		content_encoding = None
		if 'content-type' in self.enc_res_headers: 
			for v in self.enc_res_headers['content-type']:
				if v[:9] == 'text/html':
					analysis_flag = True
			if 'content-encoding' in self.enc_res_headers:
				for v in self.enc_res_headers['content-encoding']:
					content_encoding = v

		if not self.has_body:
			self.send_headers(False)
			return
		if self.preview:
			prevbuf = ''
			while True:
				chunk = self.read_chunk()
				if chunk == '':
					break
				prevbuf += chunk
			if self.ieof:
				self.send_headers(True)
				if len(prevbuf) > 0:
					self.write_chunk(prevbuf)
				self.write_chunk('')
				return
			self.cont()
			self.send_headers(True)
			if len(prevbuf) > 0:
				self.write_chunk(prevbuf)
			while True:
				chunk = self.read_chunk()
				self.write_chunk(chunk)
				if chunk == '':
					break
		elif analysis_flag:
			self.send_headers(True)
			raw = ''
			while True:
				chunk = self.read_chunk()
				if chunk == '':
					break
				raw = raw + chunk
			need_output = True
			try:
				orig_data = ''
				if content_encoding in ('gzip', 'x-gzip', 'deflate'):
					if content_encoding == 'deflate':
						data = StringIO.StringIO(zlib.decompress(raw))
					else:
						data = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(raw))
						orig_data = data.read()
					
						#formated_out = orig_data.replace( "<body>", """
						formated_out = re.sub(r"(<body[^>]*>)", """
<body>
	<!-- src from: http://zh-yue.wikipedia.org/wiki/%E4%B8%96%E7%95%8C%E4%B8%89%E5%A4%A7%E5%A4%9C%E6%99%AF -->
	<center><img src="http://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Victoria_Harbour_around_Chinese_New_Year_Night_with_Fireworks_and_Laser_Show.jpg/1024px-Victoria_Harbour_around_Chinese_New_Year_Night_with_Fireworks_and_Laser_Show.jpg" /></center>
	""", orig_data )

						data = StringIO.StringIO()
						f = gzip.GzipFile(fileobj=data, mode='w')
						f.write(formated_out)
						f.close()

						self.write_chunk( data.getvalue() )
						
						need_output = False

			except Exception, e:
				print e

			if need_output:
				self.write_chunk(raw)
		else:
			self.send_headers(True)
			while True:
				chunk = self.read_chunk()
				self.write_chunk(chunk)
				if chunk == '':
					break

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
	while 1:
		server.handle_request()
except KeyboardInterrupt:
	print "Finished"
