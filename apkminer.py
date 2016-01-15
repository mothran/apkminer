import re
import sys
import time
import pprint
import signal
import logging
import argparse
import traceback
import cStringIO
import multiprocessing as mp


from elftools.elf.elffile import ELFFile

import os
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
	"ttf",
	"fbstr",
	"svg",
	"png",
	"otf",
	"mp3"]

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

class FPDetect():
	def __init__(self, a, d):
		self.a = a
		self.d = d
		# create blob of data to regex, kinda a hack but faster than multiple calls to re.*
		self.classes_str = str(self.d.get_classes_names())

	def _find_in_classes(self, data):
		if self.classes_str.find(data) != -1:
			return True

		# fall back to case insensitive search. 
		if re.search(".%s." % data, self.classes_str, re.IGNORECASE):
			return True
		return False

	def is_sec_fp(self, data):
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
		elif self._find_in_classes(data):     # is this string a method
			return True
		elif self.d.get_method(data): # is this string a class
			return True
		else:
			return False

	def is_xref_fp(self, data):
		if data[:14] == "Lmono/android/":
			return True
		elif data[:25] == "Lcom/twitter/sdk/android/":
			return True
		elif data[:12] == "Lcom/amazon/":
			return True
		elif data[:20] == "Lcom/google/android/":
			return True
		else:
			return False


AWS_ID_PAT = "(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"
AWS_SEC_PAT = "(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=;$])"
AWS_KEY_C = re.compile(AWS_ID_PAT + "|" + AWS_SEC_PAT)


def get_files_in_dir(dir_path):
	return [f for f in listdir(dir_path) if isfile(join(dir_path, f))]

class Logger():
	def __init__(self, file, res_queue):
		self.file = file
		self.LOG = ""
		self.res_queue = res_queue
	def log(self, data):
		self.LOG += "%s\n" % data
	def flush(self):
		self.res_queue.put(self.LOG)
		self.LOG = ""
	def clean(self):
		self.LOG = ""

def logger_runner(log_file, res_queue):
	print "started logger"
	fd = open(log_file, "a")
	while True:
		res_queue.get(True)
		log_data = res_queue.get()
		fd.write(log_data)
		fd.flush()

def file_checker(args, queue, res_queue):
	log = Logger(args.log_file, res_queue)
	while True:
		if queue.empty():
			return
		else:
			apk_file = queue.get()

			file_path = args.in_dir + "/" + apk_file
			log.log("Checking: %s\n" % file_path)
			a = apk.APK(file_path)

			so_files = []
			for file in a.get_files():
				exten = file.split('.')[-1]
				if exten == "so":
					so_files.append(file)

			if len(so_files) == 0:
				continue

			log.log("Found %d .so files" % len(so_files))

			for so_file in so_files:
				elf_data = a.get_file(so_file)
				elf_stream = cStringIO.StringIO(elf_data)
				try:
					elf = ELFFile(elf_stream)
				except:
					log.log("ERROR: bad elf file")
					log.flush()
					continue

				log.log("  File: %s" % so_file)
				log.log("  Elf sections:")
				for section in elf.iter_sections():
					log.log("\t%s" % section.name)
					if section.name == ".comment" or section.name == ".conststring":
						log.log("\t\t%s" % section.data().replace("\x00", "\n"))

			log.log("\n\n")
			log.flush()

def private_key(args, queue, res_queue):
	log = Logger(args.log_file, res_queue)
	while True:
		if queue.empty():
			return
		else:
			apk_file = queue.get()

			file_path = args.in_dir + "/" + apk_file
			log.log("Checking: %s\n" % file_path)
			a = apk.APK(file_path)

			for file in a.get_files():
				file_data = a.get_file(file)
				if re.search(".PRIVATE KEY-----", file_data):
					log.log(u"  FOUND  %s:\n%s" % (file, file_data))

			log.log("\n\n")
			log.flush()


def amazon_finder(args, queue, res_queue):
	log = Logger(args.log_file, res_queue)
	while True:
		if queue.empty():
			return
		else:
			apk_file = queue.get()
			file_path = args.in_dir + "/" + apk_file
			log.log("Checking: %s\n" % file_path)

			try:
				a = apk.APK(file_path)
			except:
				log.log("ERROR parsing apk\n")
				log.flush()
				continue

			found_aws = False
			main_act = a.get_main_activity()
			if not main_act:
				log.log("NO ACTIVITY: %s" % file_path)
				# fall back to just the apk file name
				main_act = apk_file

			# try and skip any com.amazon.* apps
			if re.search(".com.amazon.", main_act):
				log.log("skipping: %s\n" % main_act)
				log.flush()
				continue

			d = dvm.DalvikVMFormat(a.get_dex())

			for current_class in d.get_classes():
				# log.log(current_class.get_name())
				if re.search(".amazon.", current_class.get_name(), re.IGNORECASE):
					found_aws = True
					break

			if found_aws:
				assets = get_asset_files(a)
				found = regex_apk_files(a, assets, AWS_KEY_C)

				log.log("asset KEYS:")
				for data, file in found:
					log.log("  %s: %s" % (file, data))


				d = dvm.DalvikVMFormat(a.get_dex())
				dx = analysis.newVMAnalysis( d )
				d.set_vmanalysis( dx )
				dx.create_xref()


				fp_detect = FPDetect(a,d)

				log.log("\nDalvik keys:")
				for str_val, ref_obj in dx.get_strings_analysis().iteritems():
					found_key = re.findall(AWS_KEY_C, str_val)

					for res in found_key:
						#bail out on FP hits
						if fp_detect.is_sec_fp(res):
							continue
						
						log.log("  %s" % res)
						for ref_class, ref_method in ref_obj.get_xref_from():
							if fp_detect.is_xref_fp(ref_method.get_class_name()):
								continue

							log.log("    REF: %s->%s%s" % (ref_method.get_class_name(), 
														   ref_method.get_name(),
														   ref_method.get_descriptor()))
						
			log.log("\n")
			log.flush()

def silverpush(args, queue, res_queue):
	log = Logger(args.log_file, res_queue)
	while True:
		if queue.empty():
			return
		else:
			apk_file = queue.get()

			file_path = args.in_dir + "/" + apk_file
			log.log("Checking: %s\n" % file_path)

			try:
				a = apk.APK(file_path)
			except:
				log.log("ERROR parsing apk\n")
				log.flush()
				continue

			record_perm = "android.permission.RECORD_AUDIO" in a.get_permissions()

			try:
				if "com.silverpush.sdk.android.SPService" in a.get_services() or "com.silverpush.sdk.android.BR_CallState" in a.get_receivers():
					log.log("found silverpush, can record: %s" % str(record_perm))
					log.flush()
					continue
			except:
				log.log("BAD APK DATA: %s" % apk_file)

			log.log("\n")
			log.flush()

def runner(func, args, queue, res_queue):
	try:
		func(args, queue, res_queue)
	except:
		raise Exception("".join(traceback.format_exception(*sys.exc_info())))

def init_worker():
	signal.signal(signal.SIGINT, signal.SIG_IGN)

def main():
	parser = argparse.ArgumentParser(description='analyzer of APKs')
	parser.add_argument("-i", "--in_dir", type=str,
						help="directory of apk files to analyze", default=None)
	parser.add_argument("-o", "--log_file", type=str,
						help="log file to write to", default="OUTPUT.log")
	parser.add_argument("-c", "--cores", type=int,
						help="force a number of cores to use")
	parser.add_argument("-a", "--analyzer", type=str,
						help="Select the analyzer you want to use.", default="file_checker")
	parser.add_argument("-l", "--list_analyzers", action="store_true",
						help="List the possible analyzers")

	args = parser.parse_args()

	# Complete listing of possible analyzers
	analyzer_funcs = {'file_checker':file_checker,
					  'private_key':private_key,
					  'amazon_finder':amazon_finder,
					  'silverpush':silverpush}

	if args.list_analyzers:
		print "Analyzers:"
		for func_name, func in analyzer_funcs.iteritems():
			print "  %s" % func_name
		return

	if not args.in_dir:
		print "Please provide a input directory with -i"
		return

	selected_analyzer = None
	for func_name, func in analyzer_funcs.iteritems():
		if func_name == args.analyzer:
			selected_analyzer = func
			break
	if not selected_analyzer:
		print "You selected a bad analyzer [%s]" % args.analyzer
		print "Analyzers:"
		for func_name, func in analyzer_funcs.iteritems():
			print "  %s" % func_name

		return

	if args.cores:
		cores = arg.cores
	else:
		cores = mp.cpu_count()

	print "Started '%s' analyzer with %d cores, log file: %s" % (selected_analyzer.__name__, cores, args.log_file)
	apk_files = get_files_in_dir(args.in_dir)

	# Enable for debugging info.
	# mp.log_to_stderr(logging.DEBUG)
	manager = mp.Manager()
	pool = mp.Pool(cores + 2, init_worker)

	queue = manager.Queue()
	res_queue = manager.Queue()
	lock = manager.Lock()

	for apk in apk_files:
		queue.put(apk)

	try:
		# TODO: make the runner handle multiple arg lists?
		log_result = pool.apply_async(logger_runner, (args.log_file, res_queue))
		
		worker_results = []
		for i in xrange(0, cores):
			worker_results.append(pool.apply_async(runner, (selected_analyzer, args, queue, res_queue)))
		pool.close()

		for res in worker_results:
			result = res.get()
			if not res.successful():
				print "one of the workers failed"


		print "completed all work"
		pool.terminate()
		pool.join()

	except KeyboardInterrupt:
		print "Exiting!"
		pool.terminate()
		pool.join()
	
if __name__ == '__main__':
	main()