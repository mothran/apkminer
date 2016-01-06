import json
import argparse
from httpshit import HttpShit

def find_by_next_line(data=None, line_srch=None, count=1):
	found = False

	split_data = data.splitlines()
	for line in split_data:
		if found:
			index = split_data.index(line)
			return split_data[index + count]
		
		if line.find(line_srch) != -1:
			found = True
			continue
	return False

def main():

	parser = argparse.ArgumentParser(description='downloader of APKs')
	parser.add_argument("-a", "--app_name", type=str,
						help="apk name, example: com.redphx.deviceid")
	parser.add_argument("-o", "--out_dir", type=str,
						help="output directory to put all the apks in")
	parser.add_argument("-i", "--input_file", type=str,
						help="input file of app names")

	args = parser.parse_args()

	http = HttpShit()

	app_names = []
	if args.input_file:
		with open(args.input_file, "r") as fd:
			app_names = fd.read().splitlines()
			print app_names

	else:
		app_names.append(args.app_name)

	for app_name in app_names:
		url_1 = "http://apps.evozi.com/apk-downloader/?id=%s" % app_name
		print url_1

		data = http.send(url_1)
		if not data:
			print "failed on URL1"
			return

		apk_key = "bdfbcdbadec"
		key_key = "efccfabcece"
		key_val = None
		t_val = None

		key_val = find_by_next_line(data, "var packageguide =", 0)

		if not key_val:
			print "failed to find key_val"
			return
		key_val = key_val.split("'")[1]
		print key_val


		json_data = find_by_next_line(data, "span class=\"android android_holder\"", 2)

		if not json_data:
			print "failed to find json_data"
			return
		json_data = json_data.replace("$('#forceRefetch').is(':checked')", "false")

		json_data = json_data.split("   =   ")[1]

		for elm in json_data[1:-2].split(", "):
			sub_elms = elm.split(": ")
			if sub_elms[0] == "t":
				t_val = sub_elms[1]

		post_args = {
			apk_key: app_name,
			"t": t_val,
			key_key: key_val,
			"fetch": False
		}

		url_2 = "http://api-apk-3.evozi.com/download"

		data2 = http.send(url_2, post_args)
		if not data2:
			print "failed to retrive POST data"
			return

		json_post_data = json.loads(data2)
		try:
			print json_post_data["url"]
		except KeyError:
			print data2

		url_dl = "http:%s" % json_post_data["url"]

		blob_data = http.send(url_dl)
		if not blob_data:
			print "failed to DL file"
			return

		output_file = "%s/%s.apk" % (args.out_dir, app_name)
		with open(output_file, "wb") as fd:
			fd.write(blob_data)

		print "downloaded to: %s" % output_file

	print "DONE!"
if __name__ == '__main__':
	main()