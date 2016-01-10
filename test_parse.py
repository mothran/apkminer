import re
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
	a = apk.APK(file_path)
	found = False
	main_act = a.get_main_activity()

	if main_act == None:
		log.log("NO ACTIVITY: %s" % file_path)
		log.flush()
		continue
	if re.search("\"com.amazon\"", main_act):
		log.log("skipping: %s\n\n" % main_act)
		log.flush()
		continue

	d = dvm.DalvikVMFormat(a.get_dex())

	amzn_classes = []
	for current_class in d.get_classes():
		if current_class.get_name().find("amazon") != -1:
			amzn_classes.append(current_class)
			found = True
			break



	if found:
		log.log("FOUND: %s\n\t%s" % (file_path, main_act))
		for cls in amzn_classes:
			log.log("\t%s\t->\t%s" % (cls, cls.get_name()))

	log.log("\n\n")
	log.flush()