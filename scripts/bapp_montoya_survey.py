import zipfile,sys,re,collections,subprocess,tempfile,os,shutil
jar=sys.argv[1]
tmp=tempfile.mkdtemp(dir='/tmp/bappsurvey')
z=zipfile.ZipFile(jar)
names=[n for n in z.namelist() if n.endswith('.class') and not n.startswith(('burp/api/','kotlin/','org/','com/google','com/fasterxml','io/','okhttp','okio','javax/','com/nimbusds','net/minidev','com/auth0'))]
z.extractall(tmp,names)
c=collections.Counter()
cls=[n[:-6] for n in names]
for i in range(0,len(cls),300):
    out=subprocess.run(['javap','-c','-p','-cp',tmp]+[x.replace('/','.') for x in cls[i:i+300]],capture_output=True,text=True).stdout
    for m in re.finditer(r'InterfaceMethod burp/api/montoya/([\w/$]+)\.(\w+):',out): c[(m.group(1),m.group(2))]+=1
shutil.rmtree(tmp)
top=collections.Counter()
for (k,m),v in c.items(): top[k]+=v
print(os.path.basename(jar),'classes',len(cls),'distinct montoya methods',len(c))
api=sorted(m for (k,m) in c if k=='MontoyaApi'); print(' MontoyaApi:',' '.join(api))
print(' interfaces:',', '.join(f"{k.split('/')[-1]}({v})" for k,v in top.most_common(28)))
