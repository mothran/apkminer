import urllib
import urllib2
import cookielib

class HttpShit:
	"""
	Class to basically wrap urllib and present a sendHTTP() function
	"""

	Debug = False
	# 'publics'
	last_code = None
	
	def __init__(self):
		# I keep a instance of the HttpShit class with a cookie jar in each thread
		# so that each thread is like a mini browsers and has its own saved state.

		self.cookies = cookielib.CookieJar()

		# inorder to run through tor look at this:http://stackoverflow.com/questions/2317849/how-can-i-use-a-socks-4-5-proxy-with-urllib2/8100870#8100870
		# currently this is setup for Burp -> Tor, you can outbound proxy burp
		#self.opener = urllib2.build_opener(urllib2.ProxyHandler({'http': 'http://127.0.0.1:8080'}), urllib2.HTTPCookieProcessor(self.cookies))
		self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookies))
		
		# Spoof some headers
		self.opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:17.0) Gecko/20100101 Firefox/17.0")]		
		
	def send(self, url, args="", xml=False):
		"""
		send http requests with urllib,
		
		If there is an error in the connection it will return False
		"""
		
		# encode and send
		if not xml:
			args = urllib.urlencode(args)
		
		try:
			# Open the url with args or not.
			if len(args) > 0:
				response = self.opener.open(url, args)
			else:
				response = self.opener.open(url)
		except:
			print "connection problem"
			if self.Debug:
				traceback.print_exc(file=sys.stdout)
			return False
	
		self.last_code = response.code
		self.last_url = response.geturl() 

		# attempt to read the data out of the resposne
		try:
			data = response.read()
		except:
			print "read zero bytes or issues in .read()"
			if self.Debug:
				traceback.print_exc(file=sys.stdout)
			return False

		return data
