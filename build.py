import os
import subprocess
import sys



if (os.path.exists("build")):
	dl=[]
	for r,ndl,fl in os.walk("build"):
		r=r.replace("\\","/").strip("/")+"/"
		for d in ndl:
			dl.insert(0,r+d)
		for f in fl:
			os.remove(r+f)
	for k in dl:
		os.rmdir(k)
else:
	os.mkdir("build")
if ("--release" in sys.argv):
	fl=[]
	error=False
	for r,_,cfl in os.walk("src"):
		r+="/"
		for f in cfl:
			if (f[-2:]==".c"):
				fl.append(f"build/{(r+f).replace('/','$')}.o")
				if (subprocess.run(["gcc","-Wall","-Werror","-O3","-c",r+f,"-o",f"build/{(r+f).replace('/','$')}.o","-Isrc/include","-DNULL=((void*)0)","-D_GNU_SOURCE"]).returncode!=0):
					error=True
	if (error or subprocess.run(["gcc","-o","build/websocket"]+fl).returncode!=0):
		sys.exit(1)
else:
	fl=[]
	error=False
	for r,_,cfl in os.walk("src"):
		r+="/"
		for f in cfl:
			if (f[-2:]==".c"):
				fl.append(f"build/{(r+f).replace('/','$')}.o")
				if (subprocess.run(["gcc","-Wall","-Werror","-O0","-g","-c",r+f,"-o",f"build/{(r+f).replace('/','$')}.o","-Isrc/include","-DNULL=((void*)0)","-D_GNU_SOURCE"]).returncode!=0):
					error=True
	if (error or subprocess.run(["gcc","-o","build/websocket"]+fl).returncode!=0):
		sys.exit(1)
if ("--run" in sys.argv):
	subprocess.run(["build/websocket"])
