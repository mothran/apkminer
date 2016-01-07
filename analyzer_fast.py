import zipfile
import argparse
import subprocess

import shutil
import os

from os import listdir, makedirs
from os.path import isfile, join


def get_files_in_dir(dir_path):
	return [f for f in listdir(dir_path) if isfile(join(dir_path, f))]

def simple_grep(pattern, path, options):
	process = subprocess.Popen(['grep', options, pattern, path], stdout=subprocess.PIPE)
	stdout, stderr = process.communicate()
	return stdout

def print_not_matches(data, patterns):
	if not len(data) > 0:
		return
	# SLOW
	for line in data.splitlines():
		found = False
		for pat in patterns:
			# print pat
			# print line
			# print line.find(pat)
			# raw_input(">")
			if line.find(pat) > -1:
				found = True
				break
		if not found:
			print line

def main():
	parser = argparse.ArgumentParser(description='analyzer of APKs')
	parser.add_argument("-i", "--in_dir", type=str,
						help="directory of apk files to analyze")
	parser.add_argument("-o", "--out_dir", type=str,
						help="directory of apk files to analyze")
	parser.add_argument("-s", "--skip_extract", action="store_true",
						help="NOT WORKING")
	parser.add_argument("-f", "--full_decomp", action="store_true",
						help="skip creating .java files (smali will sill be created)")
	args = parser.parse_args()


	apk_files = get_files_in_dir(args.in_dir)

	found_apks = []
	if not args.skip_extract:
		if not os.path.exists(args.out_dir):
			os.makedirs(args.out_dir)

		aws_pat = [
			"Binary file",
			"Lorg/codehaus/jackson/map/JsonSerializer",
			"Lorg/codehaus/jackson/type/TypeReference",
			"Lcom/amazonaws/internal/config/JsonIndex",
			"Lorg/apache/commons/lang3/text/StrLookup",
			"smali/assets/languagePacks.json",
			"/com/amazon/",
			"smali/res/values/",
			"/com/google/common/",
			"com/amazon/identity/auth/device/framework/",
			"ABCDEFGHJKLMNPQRSTXY",
			"original/META-INF/MANIFEST.MF:Name:",
			"/xerces/util/EncodingMap.smali:"]

		# print apk_files
		for apk_file in apk_files:
			out_dir = args.out_dir + "/%s" % apk_file
			os.makedirs(out_dir)

			# STEP 1
			# extract the apk and grep both the file name and contents for interesting strings

			extract_dir = out_dir + "/extracted/"
			os.makedirs(extract_dir)
			
			with zipfile.ZipFile(args.in_dir + "/" + apk_file, "r") as z:
				z.extractall(extract_dir)

			print "extracted %s to %s" % (apk_file, extract_dir)


			print "GREP: %s\n" % apk_file
			# print "apiKey:"
			# print simple_grep("apiKey", extract_dir, "-ri")
			
			found_id = found_key = False
			out = simple_grep("ACCESS_KEY_ID", extract_dir, "-ri")
			if len(out) > 0:
				# print "AWS_ID:"
				# print out
				found_id = True
			out = simple_grep("SECRET_ACCESS_KEY", extract_dir, "-ri")
			if len(out) > 0:
				# print "AWS_SEC:"
				# print out
				found_key = True
			
			if found_key or found_id:
				found_apks.append(apk_file)

				files = get_files_in_dir(extract_dir)

				dex_files = []
				for file in files:
					# todo: replace with regex
					if file.find(".dex") != -1:
						dex_files.append(file)

				if len(dex_files) == 0:
					print "No .dex files found in root of: %s" % extract_dir
					continue


				# apktool makes the dir for you.
				smali_dir = out_dir + "/smali/"

				if args.full_decomp:
					jar_dir = out_dir + "/jars/"
					os.makedirs(jar_dir)

					java_dir = out_dir + "/java/"
					os.makedirs(java_dir)

					dex2jar_err_dir = jar_dir + "dex2jar_errors/" 
					os.makedirs(dex2jar_err_dir)

					for idx, dex_file in enumerate(dex_files):
						cur_apk_filename = apk_file + "%d.jar" % idx

						output = subprocess.check_output(['dex2jar',
														'-o', jar_dir + cur_apk_filename,
														'-e', dex2jar_err_dir + cur_apk_filename,
														extract_dir + "/" + dex_file])
						output = subprocess.check_output(['jd-cmd',
														'-od', java_dir,
														jar_dir + cur_apk_filename])

				output = subprocess.check_output(['apktool',
												'd',
												'-o', smali_dir,
												args.in_dir + "/" + apk_file])

				print "AWS_ID val:"
				aws_id_res = simple_grep("(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", smali_dir, "-RP")
				print_not_matches(aws_id_res, aws_pat)
				print "\nAWS_SEC val:"		
				# print simple_grep("(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", extract_dir, "-RP")
				aws_sec_res = simple_grep("""(?<![A-Za-z0-9/+])[="\s][A-Za-z0-9/+=]{40}["\s](?![A-Za-z0-9/+=;$])""", smali_dir, "-RP")
				print_not_matches(aws_sec_res, aws_pat)

			
			else:
				shutil.rmtree(out_dir)

			print "\n\n"
			# raw_input("> ")
if __name__ == '__main__':
	main()