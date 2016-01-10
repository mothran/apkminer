import sys
from androguard.core.bytecodes import apk

a = apk.APK(sys.argv[1])

record_perm = "android.permission.RECORD_AUDIO" in a.get_permissions()

if "com.silverpush.sdk.android.SPService" in a.get_services() or "com.silverpush.sdk.android.BR_CallState" in a.get_receivers():
	print "found silverpush, can record: " + str(record_perm)
else:
	print "did not find silverpush"