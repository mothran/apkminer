import re

BLACKLIST_FILETYPES = [
	"jpg",
	"jet",
	"css",
	"js",
	"ttf",
	"fbstr",
	"svg",
	"png",
	"otf",
	"mp3"]


AWS_ID_PAT = "(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"
AWS_SEC_PAT = "(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=;$])"
AWS_KEY_C = re.compile(AWS_ID_PAT + "|" + AWS_SEC_PAT)

class Logger():
	def __init__(self, file, res_queue):
		self.file = file
		self.LOG = ""
		self.res_queue = res_queue
	def log(self, data):
		self.LOG += "%s\n" % data
	def flush(self):
		self.res_queue.put(self.LOG)
		self.LOG = ""
	def clean(self):
		self.LOG = ""

def is_blacklist_filetype(file):
	exten = file.split('.')[-1]
	for b_extenion in BLACKLIST_FILETYPES:
		if exten == b_extenion:
			return True
	return False

def get_asset_files(a):
	started = False
	# break once we are at the end of assets, get_files is alphabetical.
	ret = []
	for file in a.get_files():
		if file[:7] == 'assets/':
			started = True
			if not is_blacklist_filetype(file):
				ret.append(file)

		elif started == True:
			break
	return ret

def regex_apk_files(a, files, pat):
	results = []
	for file in files:
		data = a.get_file(file)
		found = re.findall(pat, data)
		for find in found:
			results.append([find, file])
	return results

class FPDetect():
	def __init__(self, a, d):
		self.a = a
		self.d = d
		# create blob of data to regex, kinda a hack but faster than multiple calls to re.*
		self.classes_str = str(self.d.get_classes_names())

	def _find_in_classes(self, data):
		if self.classes_str.find(data) != -1:
			return True

		# fall back to case insensitive search. 
		if re.search(".%s." % data, self.classes_str, re.IGNORECASE):
			return True
		return False

	def is_sec_fp(self, data):
		if data[:5] == "/com/":
			return True
		elif data[:9] == "Landroid/":
			return True
		elif data[:5] == "Lcom/":
			return True
		elif data[:6] == "Ljava/":
			return True
		elif data == "ABCDEFGHJKLMNPQRSTXY": # placeholder AWS_ID
			return True
		elif data == "DROPPEDSESSIONLENGTH":
			return True
		elif data == "LAUNCHESAFTERUPGRADE":
			return True
		elif data == "COMPROMISEDLIBRARIES":
			return True
		elif data == "========================================": # derp
			return True
		elif data == "3i2ndDfv2rTHiSisAbouNdArYfORhtTPEefj3q2f": # MIME boundry
			return True
		elif data == "5e8f16062ea3cd2c4a0d547876baa6f38cabf625": # FB hash
			return True
		elif data == "8a3c4b262d721acd49a4bf97d5213199c86fa2b9": # FB hash
			return True
		elif data == "a4b7452e2ed8f5f191058ca7bbfd26b0d3214bfc": # FB hash
			return True
		elif data == "bca6990fc3c15a8105800c0673517a4b579634a1": # X-CRASHLYTICS-DEVELOPER-TOKEN
			return True
		elif data == "registerOnSharedPreferenceChangeListener": # nfc why this is not found
			return True
		elif data == "setJavaScriptCanOpenWindowsAutomatically":
			return True
		elif data == "startAppWidgetConfigureActivityForResult":
			return True
		elif self._find_in_classes(data):     # is this string a method
			return True
		elif self.d.get_method(data): # is this string a class
			return True
		else:
			return False

	def is_xref_fp(self, data):
		if data[:14] == "Lmono/android/":
			return True
		elif data[:25] == "Lcom/twitter/sdk/android/":
			return True
		elif data[:12] == "Lcom/amazon/":
			return True
		elif data[:20] == "Lcom/google/android/":
			return True
		elif data[:18] == "Lorg/spongycastle/":
			return True
		else:
			return False

