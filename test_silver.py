import re
import sys
import argparse

from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

# allow for copy + pasting from the main codebase
class Log():
	def log(self,data):
		print data
	def flush(self):
		pass

log = Log()

parser = argparse.ArgumentParser(description='analyzer of APKs')
parser.add_argument("-i", "--in_apk", type=str,
					help="apk file to analyze", required=True)
args = parser.parse_args()
apk_file = file_path = args.in_apk


for one in xrange(0,1):
	log.log("Checking: %s\n" % file_path)
	a = apk.APK(file_path)

	record_perm = "android.permission.RECORD_AUDIO" in a.get_permissions()

	if "com.silverpush.sdk.android.SPService" in a.get_services() or "com.silverpush.sdk.android.BR_CallState" in a.get_receivers():
		log.log("found silverpush, can record: %s" % str(record_perm))
		log.flush()
		# continue

	# elif
	if record_perm:
		dex_files = list(a.get_all_dex())
		if not dex_files:
			log.log("no dex files")
			continue

		for dex in dex_files:
			d = dvm.DalvikVMFormat(dex)
			for data in d.get_strings():
				print data.replace("\x00", "")
				# if re.search("\"silverpush\"", data, re.IGNORECASE):
				# 	print data
				# 	break