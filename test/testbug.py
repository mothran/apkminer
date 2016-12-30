import re
import sys
import argparse

from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

# allow for copy + pasting from the main codebase
class Log():
	def log(self,data):
		print(data)
	def flush(self):
		pass

log = Log()

parser = argparse.ArgumentParser(description='analyzer of APKs')
parser.add_argument("-i", "--in_apk", type=str,
					help="apk file to analyze", required=True)
args = parser.parse_args()
apk_file = file_path = args.in_apk


def find_call(dx, class_name, func_name):
	for name, cur_class in dx.classes.items():
		for method in cur_class.get_methods():
			xref_from = method.get_xref_to()
			
			for ref_class, ref_method, offset in xref_from:
				ref_class_name = ref_class.orig_class
				# WTF
				if type(ref_class_name) == analysis.ExternalClass:
					ref_class_name = ref_class_name.name

				ref_method_name = ref_method.get_name()

				if ref_class_name == class_name and ref_method_name == func_name:
					log.log("%s.%s  calls  %s.%s()" % (name, method.method.name, class_name, func_name))
					log.log("")

def find_implements(dx, srch_class_name):
	for name, cur_class in dx.classes.items():
		class_name = cur_class.orig_class
		if type(class_name) == analysis.ExternalClass:
			class_name = class_name.name

		# log.log("%s implements: %s" % (name, class_name))
		if class_name == srch_class_name:
			log.log("%s implements: %s" % (name, class_name))

def find_methods(dx, methods):
	for name, cur_class in dx.classes.items():

		# ipdb> p cur_class.orig_class.get_interfaces()
		# ['Ljavax/net/ssl/X509TrustManager;']

		if name == "Lo/md;":
			import ipdb; ipdb.set_trace();

		for method in cur_class.get_methods():
			if "checkServerTrusted" in method.method.name:
				log.log("%s inplements: %s" % (name, "checkServerTrusted"))


for one in xrange(0,1):
	log.log("Checking: %s\n" % file_path)

	try:
		a = apk.APK(file_path)
	except:
		log.log("ERROR parsing apk\n")
		log.flush()
		continue
	log.log("Parsed APK")

	d = dvm.DalvikVMFormat(a.get_dex())
	log.log("Parsed Dalvik")

	dx = analysis.newVMAnalysis(d)
	d.set_vmanalysis(dx)
	dx.create_xref()
	log.log("Completed VM analysis")
	

	# Check for WebView
	find_call(dx, "Landroid/webkit/WebView;", "addJavascriptInterface")

	# Check for Runtime.exec()
	find_call(dx, "Ljava/lang/Runtime;", "exec")

	# Check for pinning
	find_implements(dx, "Ljavax/net/ssl/X509TrustManager;")

	find_methods(dx, ["checkServerTrusted"])

	log.log("\n")
	log.flush()
