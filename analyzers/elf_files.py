from elftools.elf.elffile import ELFFile

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
			a = apk.APK(file_path)

			so_files = []
			for file in a.get_files():
				exten = file.split('.')[-1]
				if exten == "so":
					so_files.append(file)

			if len(so_files) == 0:
				continue

			log.log("Found %d .so files" % len(so_files))

			for so_file in so_files:
				elf_data = a.get_file(so_file)
				elf_stream = cStringIO.StringIO(elf_data)
				try:
					elf = ELFFile(elf_stream)
				except:
					log.log("ERROR: bad elf file")
					log.flush()
					continue

				log.log("  File: %s" % so_file)
				log.log("  Elf sections:")
				for section in elf.iter_sections():
					log.log("\t%s" % section.name)
					if section.name == ".comment" or section.name == ".conststring":
						log.log("\t\t%s" % section.data().replace("\x00", "\n"))

			log.log("\n\n")
			log.flush()

