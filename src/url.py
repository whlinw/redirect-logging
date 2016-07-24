#!/usr/bin/env python
# -*- coding: utf-8 -*-
import httplib
import sys, json
import collections
import time
from urltools import follow_redirect

path_urls = '../in/top-1m.csv'
# headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:45.0) Gecko/20100101 Firefox/45.0'}
headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive'}
errdata = collections.OrderedDict([('req', ''), ('rank', -1), ('rdr_num', -1), ('rdr_dest', ''), ('rdr_path', []), ('rdr_prot', []), ('rdr_hsts', []), ('rdr_hsts_type', []), ('rdr_resp', []), ('time', '-1'), ('mesg', '')])

def read_alexa(s, e):
	s -= 1
	list = []
	with open(path_urls) as f:
		for i in range(e):
			l = f.readline()
			if i < s:
				continue
			list.append(l.split(',')[1][:-1])
	return list

def get_prot(url):
	p, h, u = parse_url(url)
	return p

def get_host(url):
	p, h, u = parse_url(url)
	return h

def get_headers(list):
	headers = {}
	for h in list:
		headers[h[0]] = h[1]
	return headers

def main(s, e):
	l = read_alexa(s, e)
	sys.stdout = open('../log/%d-%d.log' % (s, e), 'w')
	path_out = '../out/out_%d-%d.json' % (s, e)
	with open(path_out, 'w') as f:
		f.write('[')
		for i, u in enumerate(l):
			res = follow_redirect(u, rank=s+i)
			# print res
			if i > 0:
				f.write(', ')
			try:
				f.write(json.dumps(res))
			except Exception as e:
				errdata['req'] = u
				errdata['rank'] = s+i
				errdata['time'] = res['time']
				errdata['mesg'] = str(e)
				f.write(json.dumps(errdata))
		f.write(']')

if __name__ == '__main__':
	s = int(sys.argv[1])
	e = int(sys.argv[2])
	main(s, e)

