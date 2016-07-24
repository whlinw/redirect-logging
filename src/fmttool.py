import sys
import json, csv

out_path = '../out/'

def json_load_byteified(file_handle):
	return _byteify(json.load(file_handle, object_hook=_byteify), ignore_dicts=True)

def json_loads_byteified(json_text):
	return _byteify(json.loads(json_text, object_hook=_byteify), ignore_dicts=True)

def _byteify(data, ignore_dicts = False):
	# if this is a unicode string, return its string representation
	if isinstance(data, unicode):
		return data.encode('utf-8')
	# if this is a list of values, return list of byteified values
	if isinstance(data, list):
		return [ _byteify(item, ignore_dicts=True) for item in data ]
	# if this is a dictionary, return dictionary of byteified keys and values
	# but only if we haven't already byteified it
	if isinstance(data, dict) and not ignore_dicts:
		return {
			_byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
			for key, value in data.iteritems()
		}
	# if it's anything else, return it in its original form
	return data

def json_to_csv(files):
	with open(out_path + 'out.csv', 'wb+') as o:
		keys = ['req', 'rank', 'rdr_num', 'rdr_hsts_type', 'rdr_prot', 'rdr_dest', 'rdr_hsts','rdr_path', 'mesg']
		o.write(','.join(keys) + '\n')
		for file in files:
			with open(out_path + file + '.json') as f:
				data = json_load_byteified(f)
				for i in range(len(data)):
					for k in keys:
						tmp = ' '.join(str(data[i][k]).split(','))
						if k == keys[len(keys)-1]:
							o.write(tmp + '\n')
						else:
							o.write(tmp + ',')
	return

if __name__ == '__main__':
	file = sys.argv[1:]
	json_to_csv(file)