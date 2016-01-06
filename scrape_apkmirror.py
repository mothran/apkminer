import json
import argparse
import urlparse
from httpshit import HttpShit

def main():

	parser = argparse.ArgumentParser(description='downloader of APKs, indexes are reversed in order')
	parser.add_argument("-o", "--out_dir", type=str,
						help="output directory to put all the apks in")
	parser.add_argument("-s", "--start_idx", type=int,
						help="index to start at")
	parser.add_argument("-e", "--end_idx", type=int,
						help="index to end at")



	args = parser.parse_args()

	http = HttpShit()

	# most recent upload on jan 2, 2015
	#   http://www.apkmirror.com/wp-content/themes/APKMirror/download.php?id=53391
	for idx in reversed(xrange(args.end_idx, args.start_idx)):
		url = "http://www.apkmirror.com/wp-content/themes/APKMirror/download.php?id=%d" % idx


		print url
		data = http.send(url)
		if not data:
			print "failed on URL1"
			return

		if data.find("<!DOCTYPE", 0, 15) == 0:
			print "no apk at id=%d" % idx
			continue

		apk_name =  http.last_url.split("/")[-1]

		output_file = "%s/%s" % (args.out_dir, apk_name)
		with open(output_file, "wb") as fd:
			fd.write(data)

		print "downloaded to: %s" % output_file

	print "DONE!"
if __name__ == '__main__':
	main()