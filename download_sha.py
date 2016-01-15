import hashlib
import json
import argparse
import urlparse
from httpshit import HttpShit

from os import listdir
from os.path import isfile, join

from lxml import html

def get_files_in_dir(dir_path):
	return [f for f in listdir(dir_path) if isfile(join(dir_path, f))]

def main():

	parser = argparse.ArgumentParser(description='downloader of APKs, indexes are reversed in order')
	parser.add_argument("-o", "--out_dir", type=str,
						help="output directory to put all the apks in")

	args = parser.parse_args()
	http = HttpShit()

	current_apks = get_files_in_dir(args.out_dir)

	apk_hashes = []
	for apk in current_apks:
		with open(args.out_dir + "/" + apk, "r") as fd:
			cur_hash = hashlib.sha1(fd.read()).hexdigest()
			apk_hashes.append({"apk": apk, "sha1": cur_hash})

	for apk in apk_hashes:
		print "%s: %s" % (apk["apk"], apk["sha1"])

	url_index = "https://apkpure.com/app?sort=download&page=%d&ajax=1"

	for i in xrange(1,21):
		url_1 = url_index % i
		data = http.send(url_1)
		if data == None:
			print "bad url: %s" % url_1
			continue

		apk_fulls = []

		tree = html.fromstring(data)
		tree.make_links_absolute(url_1)
		for el in tree.cssselect('div.category-template-img a'):
			apk_fulls.append(el.get("href"))

		for url in apk_fulls:
			data = http.send(url)
			if data is None:
				print "failed to get %s" % url
				continue

			tree = html.fromstring(data)
			for el in tree.cssselect("div.faq_cat dl dd"):
				attributes = el.cssselect("p")
				
				cur_link = None
				cur_hash = None
				for attr in attributes:

					strong = attr.find("strong")
					if strong == None:
						link = attr.find("a")
						cur_link = link.get("href")
						continue

					cur_attrib = strong.text_content()
					if cur_attrib[:11] == "File SHA1: ":
						cur_hash = attr.text_content().split("File SHA1: ")[1]

				# print cur_link
				# print cur_hash

				if not cur_hash in apk_hashes:
					url_params = urlparse.urlparse(cur_link).query
					for param in url_params.split("&"):
						splited = param.split("=")
						key = splited[0]
						value = splited[1]

						if key == "fn":
							file_name = value
							break

					dl_data = http.send(cur_link)
					if not dl_data:
						print "failed on dl_data: %s" % cur_link
						continue

					
					output_file = args.out_dir + '/' + file_name
					with open(output_file, "wb") as fd:
						fd.write(dl_data)
					print "downloaded to: %s" % output_file
					
					apk_hashes.append(cur_hash)

				else:
					print "skipping existing"
		break

if __name__ == '__main__':
	main()