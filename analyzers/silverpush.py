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
