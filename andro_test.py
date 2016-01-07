import re
import pprint
import argparse
import multiprocessing

from os import listdir
from os.path import isfile, join

from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis


BLACKLIST_FILETYPES = [
	"jpg",
	"jet",
	"css",
	"js",
	"ttf"]

def is_blacklist_filetype(file):
	exten = file.split('.')[-1]
	for b_extenion in BLACKLIST_FILETYPES:
		if exten == b_extenion:
			return True
	return False

def get_asset_files(a):
	started = False
	# break once we are at the end of assets, get_files is alphabetical.
	ret = []
	for file in a.get_files():
		if file[:7] == 'assets/':
			started = True
			if not is_blacklist_filetype(file):
				ret.append(file)

		elif started == True:
			break
	return ret

def regex_apk_files(a, files, pat):
	results = []
	for file in files:
		data = a.get_file(file)
		found = re.findall(pat, data)
		for find in found:
			results.append([find, file])
	return results

def regex_dvm_strings(d, pat):
	results = []
	for str_d in d.get_string_data_item():
		data = str_d.get()
		found = re.findall(pat, data)
		for find in found:
			results.append([find, str_d])
	return results

def _find_in_list(data, list_data):
	blob = str(list_data)
	if blob.find(data) != -1:
		return True

	# HACKS
	try:
		if re.search("%s" % data, blob, re.IGNORECASE):
			return True
	except:
		print "BAD REGEX"
		pass
	return False


def is_sec_fp(a, d, data):
	if data[:5] == "/com/":
		return True
	elif data[:9] == "Landroid/":
		return True
	elif data[:5] == "Lcom/":
		return True
	elif data[:6] == "Ljava/":
		return True
	elif data == "ABCDEFGHJKLMNPQRSTXY": # placeholder AWS_ID
		return True
	elif data == "DROPPEDSESSIONLENGTH":
		return True
	elif data == "LAUNCHESAFTERUPGRADE":
		return True
	elif data == "COMPROMISEDLIBRARIES":
		return True
	elif data == "========================================": # derp
		return True
	elif data == "3i2ndDfv2rTHiSisAbouNdArYfORhtTPEefj3q2f": # MIME boundry
		return True
	elif data == "5e8f16062ea3cd2c4a0d547876baa6f38cabf625": # FB hash
		return True
	elif data == "8a3c4b262d721acd49a4bf97d5213199c86fa2b9": # FB hash
		return True
	elif data == "a4b7452e2ed8f5f191058ca7bbfd26b0d3214bfc": # FB hash
		return True
	elif data == "bca6990fc3c15a8105800c0673517a4b579634a1": # X-CRASHLYTICS-DEVELOPER-TOKEN
		return True
	elif data == "registerOnSharedPreferenceChangeListener": # nfc why this is not found
		return True
	elif data == "setJavaScriptCanOpenWindowsAutomatically":
		return True
	elif data == "startAppWidgetConfigureActivityForResult":
		return True
	elif _find_in_list(data, d.get_classes_names()):
		# print "DROPING CLASS:\t%s" % data
		return True
	elif d.get_method(data):
		return True
	else:
		return False


AWS_ID_PAT = "(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"
AWS_SEC_PAT = "(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=;$])"
AWS_KEY_C = re.compile(AWS_ID_PAT + "|" + AWS_SEC_PAT)


def get_files_in_dir(dir_path):
	return [f for f in listdir(dir_path) if isfile(join(dir_path, f))]

class Logger():
	def __init__(self):
		self.LOG = ""
	def log(self, data):
		self.LOG += "%s\n" % data
	def data(self):
		return self.LOG


def analyzer(args, queue, lock):
	log = Logger()
	while True:
		if queue.empty():
			return
		else:
			apk_file = queue.get()

			file_path = args.in_dir + "/" + apk_file
			log.log("Checking: %s\n" % file_path)
			a = apk.APK(file_path)
			
			assets = get_asset_files(a)
			found = regex_apk_files(a, assets, AWS_KEY_C)

			log.log("asset KEYS:")
			for data, file in found:
				log.log("%s: %s" % (file, data))

			log.log("Disassembling Dalvik code")
			d = dvm.DalvikVMFormat(a.get_dex())

			log.log("Searching for keys in dalvik code")
			found = regex_dvm_strings(d, AWS_KEY_C)

			log.log("Dalvik keys:")
			# I need to figure out how to take a raw str -> file origin.
			for data, str_d in found:
				if not is_sec_fp(a, d, data):
					log.log("%s" % (data))

			log.log("\n\n")
			# flush to log_file
			lock.acquire()
			with open(args.log_file, "wa") as fd:
				fd.write(log.data())
			lock.release()

			# cleaning?
			a = None
			d = None

	# dx = analysis.newVMAnalysis(d)

def main():
	parser = argparse.ArgumentParser(description='analyzer of APKs')
	parser.add_argument("-i", "--in_dir", type=str,
						help="directory of apk files to analyze", required=True)
	parser.add_argument("-o", "--log_file", type=str,
						help="log file to write to", default="OUTPUT.log")
	parser.add_argument("-c", "--cores", type=int,
						help="force a number of cores to use")
	args = parser.parse_args()


	if args.cores:
		cores = arg.cores
	else:
		cores = multiprocessing.cpu_count()
	# cores -= 1

	print "Started with %d cores, log file: %s" % (cores, args.log_file)
	apk_files = get_files_in_dir(args.in_dir)

	lock = multiprocessing.Lock()
	q = multiprocessing.Queue()
	for apk in apk_files:
		q.put(apk)

	for i in xrange(0,cores):
		p = multiprocessing.Process(target=analyzer, args=(args,q,lock,))
		p.start()
	p.join()

	# analyzer(args, apk_files)
	
if __name__ == '__main__':
	main()