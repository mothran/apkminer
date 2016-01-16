import re
import pprint
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

pp = pprint.PrettyPrinter(indent=4)

parser = argparse.ArgumentParser(description='analyzer of APKs')
parser.add_argument("-i", "--in_apk", type=str,
					help="apk file to analyze", required=True)
args = parser.parse_args()
apk_file = file_path = args.in_apk

for one in xrange(0,1):
	log.log("starting analysis of %s" % apk_file)
	
	a = apk.APK(file_path)
	d = dvm.DalvikVMFormat(a.get_dex())

	log.log("completed base analysis")

	for method in d.get_methods():
		print method


	dx = analysis.newVMAnalysis( d )
	d.set_vmanalysis( dx )

	log.log("creating xrefs")
	dx.create_xref()

	class_name = "Ljava/lang/Runtime;"
	func_name = "exec"
	func_proto = "(Ljava/lang/String;)V"
	# method = dx.get_method_by_name(class_name, func_name, func_proto)

	break

	# print dir()
	# for class_str, class_obj in dx.classes.iteritems():
	# 	print class_str

	# print dir(method)
	# print method



	for key, val in dx.get_strings_analysis().iteritems():
		if key == "logcat -d -f ":
			print "FOUND: %s " % key

			for ref_class, ref_method in val.get_xref_from():
				print type(ref_method)
				pp.pprint(dir(ref_method))
				print type(ref_class)
				pp.pprint(dir(ref_class))

				for classobj, class_set in ref_class.get_xref_to().iteritems():
					class_list = list(class_set)
					
					print classobj.orig_class
					for obj in class_list:
						print obj[1].get_name()




					# import pdb; pdb.set_trace()

				# import pdb; pdb.set_trace()
				# print ref_method.class_name
				# print ref_method.proto
				# print ref_method.get_name()

				# print dir(ref_method)
				# print dir(ref_class)
				# # ref_method.show()

			break