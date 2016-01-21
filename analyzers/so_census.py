import hashlib

from utils import *

try:
   import cPickle as pickle
except:
   import pickle

def get_base_name(elf_file):
	if elf_file.find("/") != -1:
		return elf_file.split("/")[-1]
	else:
		return elf_file


def output_results(output_data):
	final_data = {}
	for element in output_data:
		cur_name = element["name"]
		if cur_name in final_data:
			final_data[cur_name]["count"] += 1
			final_data[cur_name]["sha_hashes"].append(element["sha_hash"])
			final_data[cur_name]["apk_files"].append(element["apk_file"])
		else:
			final_data[cur_name] = {}
			final_data[cur_name]["count"] = 1
			final_data[cur_name]["sha_hashes"] = [element["sha_hash"]]
			final_data[cur_name]["apk_files"] = [element["apk_file"]]

	# fd = open("output.pick", "wb")
	# pickle.dump(final_data, fd )
	# fd.close()

	for name, obj in final_data.iteritems():
		print "  %s, %d, %s, %s" % (name, obj["count"], str(obj["sha_hashes"]), str(obj["apk_files"]))

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

				base_name = get_base_name(elf_file)
				
				output_data.put({"name": base_name, "sha_hash": cur_hash, "apk_file": apk_file})

			log.log("\n\n")
			log.flush()
