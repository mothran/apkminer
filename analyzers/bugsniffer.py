from utils import *

def analyze(args, apk_queue, res_queue, output_data):
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
			log.log("Parsed APK")

			d = dvm.DalvikVMFormat(a.get_dex())
			log.log("Parsed Dalvik")

			dx = analysis.newVMAnalysis(d)
			d.set_vmanalysis(dx)
			dx.create_xref()
			log.log("Completed VM analysis")

			# Check for WebView
			find_call(dx, log, "Landroid/webkit/WebView;", "addJavascriptInterface")

			# # Check for Runtime.exec()
			find_call(dx, log, "Ljava/lang/Runtime;", "exec")

			# Check for pinning
			find_implements(dx, log, "Ljavax/net/ssl/X509TrustManager;")

			find_methods(dx, log, ["checkServerTrusted"])

			log.log("\n")
			log.flush()
