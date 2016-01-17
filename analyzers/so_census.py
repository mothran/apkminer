import hashlib

from utils import *

def output_results(output_data):
	for so_file in output_data:
		print "%s,%d,%s,%s" % (so_file["name"], so_file["count"], so_file["sha_hashes"], so_file["apk_files"])


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

			so_files = []
			for file in a.get_files():
				exten = file.split('.')[-1]
				if exten == "so":
					so_files.append(file)

			if len(so_files) == 0:
				continue

			log.log("Found %d .so files" % len(so_files))

			for elf_file in so_files:
				cur_hash = hashlib.sha1(a.get_file(elf_file)).hexdigest()

				if elf_file.find("/") != -1:
					base_name = elf_file.split("/")[-1]
				else:
					base_name = elf_file
				
				found = False
				for i, so_obj in enumerate(output_data):
					if so_obj["name"] == base_name:
						log.log("found so file: %s" % base_name)
						so_obj["count"] += 1
						so_obj["sha_hashes"].append(cur_hash)
						so_obj["apk_files"].append(apk_file)
						output_data[i] = so_obj

						found = True
						break;
				if not found:
					output_data.append({"name": base_name, "count": 1, "sha_hashes": [cur_hash], "apk_files": [apk_file]})

			log.log("\n\n")
			log.flush()
