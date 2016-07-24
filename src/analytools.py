import sys
import json, csv
import collections

directory = ''
raw = 'out_1-10000.csv'
valid = 'out_1-10000_valid.csv'
keys = ['req', 'rank', 'num', 'dest_type', 'init_hsts', 'dest_hsts', 'rdr_http']
errors = {'[Errno -2]': [], '[Errno -5]': [], '[Errno 1]': [], '[Errno 104]': [], '[Errno 110]': [], '[Errno 111]': [], '[Errno 8]': [], '[SSL: CERTIFICATE_VERIFY_FAILED]': [], 'Bad Gateway': [], 'Bad Request': [], 'Forbidden': [], 'doesn\'t match': [], 'Gateway Time-out': [], 'Internal Server Error': [], 'Not Found': [], 'Redirect exceed limit': [], 'Unknown': [], 'Precondition Failed': [], 'Service Temporarily Unavailable': [], 'timed out': [], 'Origin': [], 'Bad Behavior': [], 'Total': 0}

def dict_to_csv_1(d):
	with open('dict.csv', 'w') as f:
		f.write(','.join(d.keys()) + ',\n')
		for k in d.keys():
			f.write(str(d[k]) + ',')
	return

def dict_to_csv_2(d, name, key, value):
	with open(name + '.csv', 'w') as f:
		f.write(key + ',' + value + '\n')
		for k in d.keys():
			f.write(k + ',' + str(d[k]) + '\n')
	return

def dict_to_json(d, name):
	with open(name + '.json', 'w') as f:
		f.write(json.dumps(d))
	return

def read_csv(path):
	with open(path) as f:
		init_types = [0, 0, 0, 0]
		dest_types = [0, 0, 0, 0]
		downgrades = collections.defaultdict(int)
		paths = collections.defaultdict(list)
		ete_path = collections.OrderedDict([('11', 0), ('12', 0), ('13', 0), ('14', 0), ('21', 0), ('22', 0), ('23', 0), ('24', 0), ('31', 0), ('32', 0), ('33', 0), ('34', 0), ('41', 0), ('42', 0), ('43', 0), ('44', 0)])
		# ete_path = {'11': 0, '12': 0, '13': 0, '14': 0, '21': 0, '22': 0, '23': 0, '24': 0, '31': 0, '32': 0, '33': 0, '34': 0, '41': 0, '42': 0, '43': 0, '44': 0 }
		downgrade = 0
		rdr_nonhsts = 0
		f.readline()
		lines = f.readlines()
		for l in lines:
			arr = l.split(',')
			num = int(arr[2])
			dict = {'req': arr[0], 'rank': int(arr[1]), 'num': num, 'dest_hsts': False, 'init_hsts': False, 'downgrade': False, 'rdr_nonhsts': False}
			types = arr[3][1:-1].split('  ')
			if num != -1:
				paths[''.join(types)].append(dict['req']) # += 1
				init_types[int(types[0])-1] += 1
				dest_types[int(types[num-1])-1] += 1
				dict['dest_type'] = types[num-1]
				ete_path[types[0]+types[-1]] += 1
				if types[num-1] == '4':
					dict['dest_hsts'] = True
				if types[0] == '2' or types[0] == '4':
					dict['init_hsts'] = True
				for i in range(num):
					if i + 1 < num:
						if types[i] == '1' or types[i] == '3':
							dict['rdr_nonhsts'] = True
						downgrades[types[i]+types[i+1]] += 1
						if types[i] == '4' and types[i+1] == '1':
							# print '41: ' + str(dict['rank']) + ' ' + dict['req']
							dict['downgrade'] = True
						elif types[i] == '3' and types[i+1] == '1':
							dict['downgrade'] = True
						elif types[i] == '2' and types[i+1] == '1':
							dict['downgrade'] = True
							# print '21: ' + str(dict['rank'])
						elif types[i] == '4' and types[i+1] == '3':
							dict['downgrade'] = True
						elif types[i] == '4' and types[i+1] == '2':
							dict['downgrade'] = True
							
				if dict['downgrade'] == True:
					downgrade += 1
				if dict['dest_hsts'] == True and dict['rdr_nonhsts'] == True:
					rdr_nonhsts += 1

		print 'init_types:',
		print init_types
		print 'dest_types:',
		print dest_types
		print 'downgrade: %d' % downgrade
		print downgrades
		print 'redirect non-hsts: %d' % rdr_nonhsts
		# print 'paths:'
		# print paths
		dict_to_json(paths, 'paths')
		# print ete_path
		# dict_to_csv_2(paths, 'paths', 'path', 'num')
		dict_to_csv_2(ete_path, 'ete_path', 'End-to-end', 'num')
	return

def rm_invalid(path):
	with open(path) as f, open(valid, 'w') as o:
		o.write(f.readline())
		lines = f.readlines()
		for l in lines:
			err = False
			for k in errors.keys():
				if l.find(k) > -1:
					err = True
					errors[k] += 1
					errors['Total'] += 1
					break
			if err == False:
				o.write(l)
	with open('err.json', 'w') as e:
		e.write(json.dumps(errors))
	return

def ana_error(path):
	with open(path) as f, open('err.json', 'w') as e:
		lines = f.readlines()
		for l in lines:
			err = False
			for k in errors.keys():
				if l.find(k) > -1:
					err = True
					l = l.split(',')
					errors[k].append(l[1] + ' ' + l[0])
					errors['Total'] += 1
					break
		e.write(json.dumps(errors))
	return

if __name__ == '__main__':
	# read_csv(valid)
	# rm_invalid()
	ana_error(raw)
