#!/usr/bin/env python
# -*- coding: utf-8 -*-
import httplib
import sys
import collections
import json
import time
# import requests.packages.urllib3.util.ssl_
# requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0', 'Cookie': ''}
errdata = collections.OrderedDict([('req', ''), ('rank', -1), ('rdr_num', -1), ('rdr_dest', ''), ('rdr_path', []), ('rdr_prot', []), ('rdr_hsts', []), ('rdr_hsts_type', []), ('rdr_resp', []), ('time', '-1'), ('mesg', '')])

def get_resp_body(url):
	p, h, u = parse_url(url)
	if p == 'https':
		conn = httplib.HTTPSConnection(h)
	else:
		conn = httplib.HTTPConnection(h)
	conn.request('GET', u, None, headers)
	res = conn.getresponse()
	body = res.read()
	return body

def hsts_type(protocol, hsts):
	if protocol.lower() == 'http':
		if hsts == True:
			return 2
		return 1
	elif protocol.lower() == 'https':
		if hsts == True:
			return 4
		return 3

def add_cookie_dict(cdict, cookies):
	for c in cookies:
		if c.find(' GMT') > -1:
			continue
		rules = c.split(';')
		domain = ''
		for r in rules:
			if r[:r.find('=')] == 'domain':
				domain = r[r.find('=')+1:]
				break
		cdict[domain][rules[0][:rules[0].find('=')].strip()] = rules[0][rules[0].find('=')+1:].strip()
	return

def follow_redirect(url, rank=-1, category='unk'):
	t_s = time.time()
	print rank, 'Checking',  url, '...',
	sys.stdout.flush()

	cookiedict = collections.defaultdict(dict)	# record cookies and domains
	hstslist = []	# record hsts
	
	result = collections.OrderedDict([('req', url), ('rank', rank), ('rdr_num', 1), ('rdr_dest', ''), ('rdr_path', []), ('rdr_prot', []), ('rdr_hsts', []), ('rdr_hsts_type', []), ('rdr_resp', []), ('time', '-1'), ('mesg', '')])
	res = get(url, num=result['rdr_num'])
	
	result['rdr_path'].append(res['meta']['dest'])
	result['rdr_prot'].append(res['meta']['protocol'])
	result['rdr_hsts'].append(res['meta']['hsts'])
	result['rdr_hsts_type'].append(hsts_type(res['meta']['protocol'], res['meta']['hsts'])) # 0: http/non-hsts, 1: http/hsts, 2: https/non-hsts, 3: https/hsts
	result['rdr_resp'].append(res)
	result['mesg'] = res['reason']

	if res['meta']['hsts'] == True:
		if res['headers']['strict-transport-security'].find('max-age=0') == -1:
			hstslist.append(res['meta']['host'])

	while int(res['status'])/100 == 3:
		# handle unusuals
		if result['rdr_num'] == 20:
			result['mesg'] = 'Warning: Redirect exceed limit'
			print 'Warning: Redirect exceed limit'
			break
		elif res['headers']['location'] == url and res['cookie'] == None:
			result['mesg'] = 'Warning: Location same as destination'
			print 'Warning: Location same as destination'
			break 
		
		result['rdr_num'] += 1
		if len(res['headers']['location']) == 0:
			errdata['req'] = url
			errdata['rank'] = rank
			errdata['time'] = '%.2f' % (time.time() - t_s)
			errdata['mesg'] = 'Error: empty location'
			print errdata['mesg'],
			print 't=' + errdata['time']
			return errdata
		elif res['headers']['location'][0] == '/' and (len(res['headers']['location']) == 1 or res['headers']['location'][1] != '/'):
			p, h, u = parse_url(url)
			url = p + '://' + h + res['headers']['location']
		else:
			url = res['headers']['location']
		p, h, u = parse_url(url)

		# cookie feature
		headers['Cookie'] = ''
		if res['cookie'] != None:
			add_cookie_dict(cookiedict, res['cookie'].split(','))

			for key in cookiedict:
				if h.find(key) > -1:
					for key, value in cookiedict[key].iteritems():
						headers['Cookie'] += (key + '=' + value + ';')
					headers['Cookie'] = headers['Cookie'][:-1]

		# hsts feature
		if h in hstslist:
			url = 'https://' + h + u

		# send request
		res = get(url, num=result['rdr_num'])

		result['rdr_path'].append(res['meta']['dest'])
		result['rdr_prot'].append(res['meta']['protocol'])
		result['rdr_hsts'].append(res['meta']['hsts'])
		result['rdr_hsts_type'].append(hsts_type(res['meta']['protocol'], res['meta']['hsts']))
		result['rdr_resp'].append(res)
		result['mesg'] = res['reason']

		if res['meta']['hsts'] == True:
			if res['headers']['strict-transport-security'].find('max-age=0') == -1:
				hstslist.append(res['meta']['host'])

	result['rdr_dest'] = res['meta']['dest']
	t_e = time.time()
	result['time'] = '%.2f' % (t_e - t_s)
	print 't=' + result['time']
	# print result['mesg']
	return result

def get(url, num=-1):
	# print 'GET', url
	resp = collections.OrderedDict([('meta', collections.OrderedDict())])
	p, h, u = parse_url(url)
	dest = p + '://' + h + u

	resp['meta']['req'] = url
	resp['meta']['dest'] = dest
	resp['meta']['req_cookie'] = headers['Cookie']
	resp['meta']['protocol'] = p
	resp['meta']['host'] = h
	resp['meta']['path'] = u
	# resp['meta']['rank'] = rank
	resp['meta']['rdr_num'] = num
	resp['meta']['hsts'] = False

	if p == 'https':
		conn = httplib.HTTPSConnection(h, timeout=180)
	else:
		conn = httplib.HTTPConnection(h, timeout=180)
	
	try:
		conn.request('GET', u, None, headers)
		res = conn.getresponse()
	except Exception as e:
		print 'Exception:', str(e)
		resp['status'] = '404'
		resp['reason'] = str(e)
		return resp

	if res.getheader('Strict-Transport-Security') != None:
		resp['meta']['hsts'] = True

	resp['status'] = res.status
	resp['reason'] = res.reason
	resp['headers'] = {k:v for k,v in res.getheaders()}
	resp['cookie'] = res.getheader('Set-Cookie')
	
	# resp['body'] = res.read()
	# print 'Resp:', resp
	return resp

def parse_url(addr):
	addr = addr.lstrip('//')	# some location start with "//"

	if addr.find('://') != -1:
		protocol = addr[0:addr.find('://')]
		url = addr[addr.find('://')+3:]
	else:
		protocol = 'http'
		url = addr

	if url.find('/') != -1:
		host = url[:url.find('/')]
		path = url[url.find('/'):]
	else:
		host = url
		path = '/'

	return protocol, host, path

def main():
	return

if __name__ == '__main__':
	url = sys.argv[1]
	with open('./test.json', 'w') as f:
		f.write(json.dumps(follow_redirect(url)))
