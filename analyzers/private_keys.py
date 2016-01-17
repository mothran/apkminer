from utils import *

def analyze(args, apk_queue, res_queue):
	log = Logger(args.log_file, res_queue)
	while True:
		if apk_queue.empty():
			return
		else:
			apk_file = apk_queue.get()
			file_path = args.in_dir + "/" + apk_file
			log.log("Checking: %s\n" % file_path)

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
					#log.log("  FOUND  %s:\n%s" % (file.decode('utf-8', 'ignore'), file_data.decode('utf-8', 'ignore')))

			for dex_file in dex_files:
				d = dvm.DalvikVMFormat(a.get_file(dex_file))
				dx = analysis.newVMAnalysis( d )
				d.set_vmanalysis( dx )
				dx.create_xref()

				for str_val, ref_obj in dx.get_strings_analysis().iteritems():
					found_key = re.findall(PRIV_KEY_PAT, str_val)

					for res in found_key:
						log.log("  %s" % str_val)
						for ref_class, ref_method in ref_obj.get_xref_from():
							log.log("    REF: %s->%s%s" % (ref_method.get_class_name(), 
														   ref_method.get_name(),
														   ref_method.get_descriptor()))

			log.log("\n\n")
			log.flush()
