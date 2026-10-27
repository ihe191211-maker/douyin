import frida,time,subprocess
PKG="com.ss.android.ugc.aweme"
pid=int(subprocess.run("adb shell pidof "+PKG,shell=True,capture_output=True,text=True).stdout.strip().split()[0])
dev=frida.get_usb_device(timeout=10); s=dev.attach(pid)
sc=s.create_script(open("dy_unpin.js",encoding="utf-8").read())
sc.set_log_handler(lambda l,t:print("[%s] %s"%(l,t),flush=True))
sc.load()
print("[*] unpin attached to pid",pid,"— 保持 600s。抖音现在接受任意证书(含 Yakit)。",flush=True)
time.sleep(1200); print("[*] done",flush=True)
