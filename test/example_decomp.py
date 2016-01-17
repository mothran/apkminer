import re
import pprint
import argparse


from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

from androguard.decompiler.decompiler import *


# allow for copy + pasting from the main codebase
class Log():
	def log(self,data):
		print data
	def flush(self):
		pass

log = Log()

pp = pprint.PrettyPrinter(indent=4)

parser = argparse.ArgumentParser(description='analyzer of APKs')
parser.add_argument("-i", "--in_apk", type=str,
					help="apk file to analyze", required=True)
args = parser.parse_args()
apk_file = file_path = args.in_apk

for one in xrange(0,1):
	log.log("starting analysis of %s" % apk_file)
	
	try:
		a = apk.APK(file_path)
	except Exception as err:
		log.log("ERROR parsing apk: %s\n" % err)
		log.flush()
		continue

	PRIV_KEY_PAT = ".PRIVATE KEY-----"
	dex_files = []
	for file in a.get_files():
		file_data = a.get_file(file)
		if re.search(PRIV_KEY_PAT, file_data):
			log.log("  FOUND %s" % file)
			if file[-4:] == ".dex":
				dex_files.append(file)

	for dex_file in dex_files:
		d = dvm.DalvikVMFormat(a.get_file(dex_file))
		dx = analysis.newVMAnalysis( d )
		d.set_vmanalysis( dx )
		dx.create_xref()

		d.set_decompiler(DecompilerDAD(d, dx))
		d.set_vmanalysis(dx)

		for str_val, ref_obj in dx.get_strings_analysis().iteritems():
			found_key = re.findall(PRIV_KEY_PAT, str_val)

			for res in found_key:
				log.log("  %s" % str_val)
				for ref_class, ref_method in ref_obj.get_xref_from():
					log.log("    REF: %s->%s%s" % (ref_method.get_class_name(), 
												   ref_method.get_name(),
												   ref_method.get_descriptor()))


				current_class = d.get_class(ref_method.get_class_name())
				if current_class != None:
					print current_class.get_source()
				else:
					print "ref'd class not found"

				xmethod = dx.get_method_analysis_by_name(ref_method.get_class_name(),ref_method.get_name(), ref_method.get_descriptor())

				for xref_class, xref_method, xoffset in xmethod.get_xref_from():
					log.log("    REF: %s->%s%s\n" % (xref_method.get_class_name(), 
												   xref_method.get_name(),
												   xref_method.get_descriptor()))

				current_class = d.get_class(xref_method.get_class_name())
				if current_class != None:
					print current_class.get_source()
				else:
					print "ref'd class not found"
