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
