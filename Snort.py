import Tkinter
import ttk
import tkFileDialog
import tkMessageBox
import subprocess
import threading
import time
import fileinput
import re
import ConfigParser
import webbrowser
import MySQLdb
import PIL.Image
import PIL.ImageTk
import matplotlib.pyplot
import matplotlib.cbook
import pandas

def refreshSnortIsEnad():
    snortIsEnaOut=subprocess.Popen("systemctl is-enabled snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortIsEnaOut.communicate()
    labelStatSnortIsEnaOut.config(text=stdout)

def refreshSnortIsFled():
    snortIsFledOut=subprocess.Popen("systemctl is-failed snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortIsFledOut.communicate()
    labelStatSnortIsFledOut.config(text=stdout)

def refreshBarnyardIsEnad():
    barnyardIsEnaOut=subprocess.Popen("systemctl is-enabled barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardIsEnaOut.communicate()
    labelStatBarnyardIsEnaOut.config(text=stdout)
    
def refreshBarnyardIsFled():
    barnyardIsFledOut=subprocess.Popen("systemctl is-failed barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardIsFledOut.communicate()
    labelStatBarnyardIsFledOut.config(text=stdout)

def refreshSnortStat():
    snortStatOut=subprocess.Popen("systemctl status snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortStatOut.communicate()
    labelStatSnortStatOut.config(text=stdout)

def refreshBarnyardStat():
    barnyardStatOut=subprocess.Popen("systemctl status barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardStatOut.communicate()
    labelStatBarnyardStatOut.config(text=stdout)
    
def autoRefresh():
    while True:
        time.sleep(1)
        refreshSnortIsEnad()
        refreshSnortIsFled()
        refreshBarnyardIsEnad()
        refreshBarnyardIsFled()
        refreshSnortStat()
        refreshBarnyardStat()

def snortEnaSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl enable snort.service",shell=True)
    
def snortDisaSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl disable snort.service",shell=True)

def snortStrtSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl start snort.service",shell=True)
    
def snortStSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl stop snort.service",shell=True)

def barnyardEnaSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl enable barnyard2.service",shell=True)
    
def barnyardDisaSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl disable barnyard2.service",shell=True)

def barnyardStrtSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl start barnyard2.service",shell=True)
    
def barnyardStSvc():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl stop barnyard2.service",shell=True)

def dReload():
    subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S systemctl daemon-reload",shell=True)

def dlRlset():
    pulledPorkOut=subprocess.Popen("echo "+pwd.get()+" | "+"sudo -S /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=pulledPorkOut.communicate()
    
    labelFrameOut=ttk.Labelframe(frameUd,text="Output")
    labelFrameOut.grid(column=1,row=0,rowspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    labelPulledPorkOut=ttk.Label(labelFrameOut)
    labelPulledPorkOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelPulledPorkOut.config(text=stdout)

def askAppLoc():
    openAppLoc=tkFileDialog.askopenfilename(initialdir="/usr/local/bin/",title="Select application file")
    openAppLoc.set(appLoc)

def askCfgLoc():
    openCfgLoc=tkFileDialog.askopenfilename(initialdir="/etc/snort/",title="Select configuration file")
    openCfgLoc.set(cfgLoc)

def svExecStart():
    execStart=appLoc.get()+" -c "+cfgLoc.get()+" -i "+netItf.get()+" -u "+usr.get()+" -g "+grp.get()

    if optQtOp.get()==1:
        execStart=execStart+" -q "
    config=ConfigParser.ConfigParser()
    config.optionxform=str
    config.read("/lib/systemd/system/snort.service")
    config.set("Service","ExecStart",execStart)
    with open("/lib/systemd/system/snort.service","w") as configfile:
        config.write(configfile)
    dReload()

def rRlF():
    with open("/etc/snort/rules/snort.rules","r") as rF:
        lnNo=0
        e=[]
        valLs=[]
        for line in rF:
            lnNo=lnNo+1
            line=line.lstrip()
            line=re.sub("#\s*","#",line,count=1)
            if line.startswith("alert") or line.startswith("#alert") or line.startswith("log") or line.startswith("#log") or line.startswith("pass") or line.startswith("#pass") or line.startswith("activate") or line.startswith("#activate") or line.startswith("dynamic") or line.startswith("#dynamic") or line.startswith("drop") or line.startswith("#drop") or line.startswith("reject") or line.startswith("#reject") or line.startswith("sdrop") or line.startswith("#sdrop"):
                line=re.split("\s",line,maxsplit=7)[:8]
                Actn=line[0]
                Prot=line[1]
                SrcIPAdd=line[2]
                SrcPtNo=line[3]
                DirOpr=line[4]
                DestIPAdd=line[5]
                DestPtNo=line[6]
                
                srchMsg=re.search('msg:\"([^";]*)\";',line[7])
                if srchMsg:
                    msg=srchMsg.group(1)
                else:
                    msg=''
                
                srchRefIdSys=re.search('reference:([^,]*),([^;]*);',line[7])
                if srchRefIdSys:
                    refIdSys=srchRefIdSys.group(1)
                    refId=srchRefIdSys.group(2)
                else:
                    refIdSys=''
                    refId=''

                srchGId=re.search('gid:([^;]*);',line[7])
                if srchGId:
                    gId=srchGId.group(1)
                else:
                    gId=''

                srchSId=re.search('sid:([^;]*);',line[7])
                if srchSId:
                    sId=srchSId.group(1)
                else:
                    sId=''

                srchRev=re.search('rev:([^;]*);',line[7])
                if srchRev:
                    rev=srchRev.group(1)
                else:
                    rev=''

                srchClTp=re.search('classtype:([^;]*);',line[7])
                if srchClTp:
                    clTp=srchClTp.group(1)
                else:
                    clTp=''

                srchPri=re.search('priority:([^;]*);',line[7])
                if srchPri:
                    pri=srchPri.group(1)
                else:
                    pri=''
                
                if Actn=="alert" or Actn=="log" or Actn=="pass" or Actn=="activate" or Actn=="dynamic" or Actn=="drop" or Actn=="reject" or Actn=="sdrop":
                    rlStat="Enable"
                elif Actn=="#alert" or Actn=="#log" or Actn=="#pass" or Actn=="#activate" or Actn=="#dynamic" or Actn=="#drop" or Actn=="#reject" or Actn=="#sdrop":
                    rlStat="Disable"
                else:
                    rlStat="Unknown"
                treeViewRl.insert("","end",values=(lnNo,rlStat,Actn,Prot,SrcIPAdd,SrcPtNo,DirOpr,DestIPAdd,DestPtNo,msg,refIdSys,refId,gId,sId,rev,clTp,pri))

def clrTreeVRl():
    for row in treeViewRl.get_children():
        treeViewRl.delete(row)

def addRl():
    clrTreeVRl()
    with open("/etc/snort/rules/local.rules","a+") as wF:
        nRl=["\n"]
        if actn.get() != "":
            nRl.insert(len(nRl),actn.get())
        if prot.get() != "":
            nRl.insert(len(nRl),prot.get())
        if srcIPAdd.get() != "":
            nRl.insert(len(nRl),srcIPAdd.get())
        if srcPtNo.get() != "":
            nRl.insert(len(nRl),srcPtNo.get())
        if dirOpr.get() != "":
            nRl.insert(len(nRl),dirOpr.get())
        if destIPAdd.get() != "":
            nRl.insert(len(nRl),destIPAdd.get())
        if destPtNo.get() != "":
            nRl.insert(len(nRl),destPtNo.get())
        if msg.get() != "" or refIdSys.get() != "" or gId.get() != "" or sId.get() != "" or rev.get() != "" or clTp.get() != "" or pri.get() != "":
            nRl.insert(len(nRl),"(")
        if msg.get() != "":
            fMsg="msg:\""+msg.get()+"\";"
            nRl.insert(len(nRl),fMsg)
        if refIdSys.get() != "" and refId.get() != "":
            fRefIdSys="reference:"+refIdSys.get()+","
            nRl.insert(len(nRl),fRefIdSys)
            fRefId=refId.get()+";"
            nRl.insert(len(nRl),fRefId)
        if gId.get() != "":
            fGId="gid:"+gId.get()+";"
            nRl.insert(len(nRl),fGId)
        if sId.get() != "":
            fSId="sid:"+sId.get()+";"
            nRl.insert(len(nRl),fSId)
        if rev.get() != "":
            fRev="rev:"+rev.get()+";"
            nRl.insert(len(nRl),fRev)
        if clTp.get() != "":
            fClTp="classtype:"+clTp.get()+";"
            nRl.insert(len(nRl),fClTp)
        if pri.get() != "":
            fPri="priority:"+pri.get()+";"
            nRl.insert(len(nRl),fPri)
        if msg.get() != "" or refIdSys.get() != "" or gId.get() != "" or sId.get() != "" or rev.get() != "" or clTp.get() != "" or pri.get() != "":
            nRl.insert(len(nRl),")")
        wF.writelines(" ".join(nRl))
    rRlF()

def treeviewClick(event):
    for item in treeViewRl.selection():
        item_text=treeViewRl.item(item,"values")
        print(item_text)

def shwSnortVer():
    snortVerOut=subprocess.Popen("snort -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortVerOut.communicate()
    labelFrameSnortVerOut.config(text=stderr)

def shwBarnyardVer():
    barnyardVerOut=subprocess.Popen("barnyard2 -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardVerOut.communicate()
    labelFrameBarnyardVerOut.config(text=stderr)

def shwPulledPorkVer():
    verO=subprocess.Popen("pulledpork.pl -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=verO.communicate()
    labelFramePulledPorkVerOut.config(text=stdout)
    
def saveVar():
    for line in fileinput.input("/etc/snort/snort2.conf"):
        line=re.sub(r"\s.*$",HomeNet,"ipvar HOME_NET .*$")

def opBase():
    webbrowser.open("http://127.0.0.1/base/base_main.php")

def mysql_graph():
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()
    
    sql="SELECT * FROM event"
    cursor.execute(sql)
    data=cursor.fetchall()
    df=pandas.DataFrame(list(data),columns=["sid","cid","signature","timestamp"])
    w=df.sid
    x=df.cid
    y=df.signature
    z=df.timestamp
    
    matplotlib.pyplot.title("Signature event happen time",fontsize=24)
    matplotlib.pyplot.scatter(w,x,y,z)
    matplotlib.pyplot.xlabel("SID")
    matplotlib.pyplot.ylabel("CID")
    matplotlib.pyplot.tick_params(axis="both",which="major",labelsize=14)

root=Tkinter.Tk()
root.resizable(0,0)
root.title("Snort GUI")

mysql_graph()

matplotlib.pyplot.savefig("graph.png")

pwd=Tkinter.StringVar(value="John1212")

appLoc=Tkinter.StringVar(value="/usr/local/bin/snort")

cfgLoc=Tkinter.StringVar(value="/etc/snort/snort.conf")

netItf=Tkinter.StringVar(value="ens33")

usr=Tkinter.StringVar(value="snort")

grp=Tkinter.StringVar(value="snort")

optQtOp=Tkinter.IntVar()

HomeNet=Tkinter.StringVar(value="any")

ExtNet=Tkinter.StringVar(value="any")

DNSS=Tkinter.StringVar(value="$HOME_NET")

SMTPS=Tkinter.StringVar(value="$HOME_NET")

HTTPS=Tkinter.StringVar(value="$HOME_NET")

SQLS=Tkinter.StringVar(value="$HOME_NET")

TelnetS=Tkinter.StringVar(value="$HOME_NET")

SSHS=Tkinter.StringVar(value="$HOME_NET")

FTPS=Tkinter.StringVar(value="$HOME_NET")

SIPS=Tkinter.StringVar(value="$HOME_NET")

rlStat=Tkinter.StringVar()

nRNo=Tkinter.StringVar()

actn=Tkinter.StringVar()

prot=Tkinter.StringVar()

srcIPAdd=Tkinter.StringVar()

srcPtNo=Tkinter.StringVar()

dirOpr=Tkinter.StringVar()

destIPAdd=Tkinter.StringVar()

destPtNo=Tkinter.StringVar()

msg=Tkinter.StringVar()

refIdSys=Tkinter.StringVar()

refId=Tkinter.StringVar()

gId=Tkinter.StringVar()

sId=Tkinter.StringVar()

rev=Tkinter.StringVar()

clTp=Tkinter.StringVar()

pri=Tkinter.StringVar()

noteBookMain=ttk.Notebook(root)
noteBookMain.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5)

frameHome=ttk.Frame(noteBookMain)

labelFrameSysStat=ttk.Labelframe(frameHome,text="System Status")
labelFrameSysStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelStatSnortIsEna=ttk.Label(labelFrameSysStat,text="Snort startup type:")
labelStatSnortIsEna.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatSnortIsEnaOut=ttk.Label(labelFrameSysStat)
labelStatSnortIsEnaOut.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelStatSnortIsFled=ttk.Label(labelFrameSysStat,text="Snort service status:")
labelStatSnortIsFled.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatSnortIsFledOut=ttk.Label(labelFrameSysStat)
labelStatSnortIsFledOut.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

separatorSysStat=ttk.Separator(labelFrameSysStat)
separatorSysStat.grid(column=0,row=3,columnspan=2,sticky=Tkinter.E+Tkinter.W)

labelStatBarnyardIsEna=ttk.Label(labelFrameSysStat,text="Barnyard startup type:")
labelStatBarnyardIsEna.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatBarnyardIsEnaOut=ttk.Label(labelFrameSysStat)
labelStatBarnyardIsEnaOut.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelStatBarnyardIsFled=ttk.Label(labelFrameSysStat,text="Barnyard service status:")
labelStatBarnyardIsFled.grid(column=0,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatBarnyardIsFledOut=ttk.Label(labelFrameSysStat)
labelStatBarnyardIsFledOut.grid(column=1,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

frameSnort=ttk.Frame(noteBookMain)

labelFrameSnortStat=ttk.Labelframe(frameSnort,text="Snort Status")
labelFrameSnortStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelStatSnortStatOut=ttk.Label(labelFrameSnortStat)
labelStatSnortStatOut.grid(column=0,row=0,columnspan=4,ipadx=5,ipady=5,padx=5,pady=5)

separatorSnortStat=ttk.Separator(labelFrameSnortStat)
separatorSnortStat.grid(column=0,row=1,columnspan=4,sticky=Tkinter.E+Tkinter.W)

buttonEnable=ttk.Button(labelFrameSnortStat,text="Enable",command=snortEnaSvc)
buttonEnable.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonDisable=ttk.Button(labelFrameSnortStat,text="Disable",command=snortDisaSvc)
buttonDisable.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonStart=ttk.Button(labelFrameSnortStat,text="Start",command=snortStrtSvc)
buttonStart.grid(column=2,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonStop=ttk.Button(labelFrameSnortStat,text="Stop",command=snortStSvc)
buttonStop.grid(column=3,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

labelFrameSetting=ttk.Labelframe(frameSnort,text="Setting")
labelFrameSetting.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelAppLoc=ttk.Label(labelFrameSetting,text="Application location:")
labelAppLoc.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryAppLoc=ttk.Entry(labelFrameSetting,textvariable=appLoc)
entryAppLoc.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5)

buttonAskApp=ttk.Button(labelFrameSetting,text="Browse",command=askAppLoc)
buttonAskApp.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5)

labelCfgLoc=ttk.Label(labelFrameSetting,text="Configuration location:")
labelCfgLoc.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryCfgLoc=ttk.Entry(labelFrameSetting,textvariable=cfgLoc)
entryCfgLoc.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5)

buttonAskCfg=ttk.Button(labelFrameSetting,text="Browse",command=askCfgLoc)
buttonAskCfg.grid(column=2,row=1,ipadx=5,ipady=5,padx=5,pady=5)

labelNetItf=ttk.Label(labelFrameSetting,text="Network Interface:")
labelNetItf.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryNetItf=ttk.Entry(labelFrameSetting,textvariable=netItf)
entryNetItf.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5)

labelUsr=ttk.Label(labelFrameSetting,text="User:")
labelUsr.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryUsr=ttk.Entry(labelFrameSetting,textvariable=usr)
entryUsr.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5)

labelGrp=ttk.Label(labelFrameSetting,text="Group:")
labelGrp.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryGrp=ttk.Entry(labelFrameSetting,textvariable=grp)
entryGrp.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5)

separatorSetting=ttk.Separator(labelFrameSetting)
separatorSetting.grid(column=0,row=5,columnspan=3,sticky=Tkinter.E+Tkinter.W)

checkButtonQtOp=ttk.Checkbutton(labelFrameSetting,variable=optQtOp,text="Quiet operation")
checkButtonQtOp.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

separatorSetting=ttk.Separator(labelFrameSetting)
separatorSetting.grid(column=0,row=7,columnspan=3,sticky=Tkinter.E+Tkinter.W)

buttonSv=ttk.Button(labelFrameSetting,text="Save with reload",command=svExecStart)
buttonSv.grid(column=0,row=8,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

frameBarnyard=ttk.Frame(noteBookMain)

labelFrameBarnyardStat=ttk.Labelframe(frameBarnyard,text="Barnyard Status")
labelFrameBarnyardStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelStatBarnyardStatOut=ttk.Label(labelFrameBarnyardStat)
labelStatBarnyardStatOut.grid(column=0,row=0,columnspan=4,ipadx=5,ipady=5,padx=5,pady=5)

separatorBarnyard=ttk.Separator(labelFrameBarnyardStat)
separatorBarnyard.grid(column=0,row=1,columnspan=4,sticky=Tkinter.E+Tkinter.W)

buttonBarnyardEna=ttk.Button(labelFrameBarnyardStat,text="Enable",command=barnyardEnaSvc)
buttonBarnyardEna.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonBarnyardDisa=ttk.Button(labelFrameBarnyardStat,text="Disable",command=barnyardDisaSvc)
buttonBarnyardDisa.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonBarnyardStrt=ttk.Button(labelFrameBarnyardStat,text="Start",command=barnyardStrtSvc)
buttonBarnyardStrt.grid(column=2,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonBarnyardSt=ttk.Button(labelFrameBarnyardStat,text="Stop",command=barnyardStSvc)
buttonBarnyardSt.grid(column=3,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

frameCfg=ttk.Frame(noteBookMain)

labelFrameNetVar=ttk.Labelframe(frameCfg,text="Network variable")
labelFrameNetVar.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelHomeNet=ttk.Label(labelFrameNetVar,text="Home network:")
labelHomeNet.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryHomeNet=ttk.Entry(labelFrameNetVar,textvariable=HomeNet)
entryHomeNet.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5)

labelExtNet=ttk.Label(labelFrameNetVar,text="External network:")
labelExtNet.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryExtNet=ttk.Entry(labelFrameNetVar,textvariable=ExtNet)
entryExtNet.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5)

labelDNSS=ttk.Label(labelFrameNetVar,text="DNS Servers:")
labelDNSS.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryDNSS=ttk.Entry(labelFrameNetVar,textvariable=DNSS)
entryDNSS.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5)

labelSMTPS=ttk.Label(labelFrameNetVar,text="SMTP Servers:")
labelSMTPS.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entrySMTPS=ttk.Entry(labelFrameNetVar,textvariable=SMTPS)
entrySMTPS.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5)

labelHTTPS=ttk.Label(labelFrameNetVar,text="HTTP Servers:")
labelHTTPS.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryHTTPS=ttk.Entry(labelFrameNetVar,textvariable=HTTPS)
entryHTTPS.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5)

labelSQLS=ttk.Label(labelFrameNetVar,text="SQL Servers:")
labelSQLS.grid(column=0,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entrySQLS=ttk.Entry(labelFrameNetVar,textvariable=SQLS)
entrySQLS.grid(column=1,row=5,ipadx=5,ipady=5,padx=5,pady=5)

labelTelnetS=ttk.Label(labelFrameNetVar,text="Telnet Servers:")
labelTelnetS.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryTelnetS=ttk.Entry(labelFrameNetVar,textvariable=TelnetS)
entryTelnetS.grid(column=1,row=6,ipadx=5,ipady=5,padx=5,pady=5)

labelSSHS=ttk.Label(labelFrameNetVar,text="SSH Servers:")
labelSSHS.grid(column=0,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entrySSHS=ttk.Entry(labelFrameNetVar,textvariable=SSHS)
entrySSHS.grid(column=1,row=7,ipadx=5,ipady=5,padx=5,pady=5)

labelFTPS=ttk.Label(labelFrameNetVar,text="FTP Servers:")
labelFTPS.grid(column=0,row=8,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryFTPS=ttk.Entry(labelFrameNetVar,textvariable=FTPS)
entryFTPS.grid(column=1,row=8,ipadx=5,ipady=5,padx=5,pady=5)

labelSIPS=ttk.Label(labelFrameNetVar,text="SIP Servers:")
labelSIPS.grid(column=0,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entrySIPS=ttk.Entry(labelFrameNetVar,textvariable=SIPS)
entrySIPS.grid(column=1,row=9,ipadx=5,ipady=5,padx=5,pady=5)

buttonSave=ttk.Button(labelFrameNetVar,text="Save",command=saveVar)
buttonSave.grid(column=0,row=10,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameRl=ttk.Frame(noteBookMain)

treeViewRl=ttk.Treeview(frameRl,columns=["columnLnNo","columnStat","columnActn","columnProt","columnSrcIPAdd","columnSrcPtNo","columnDirOpr","columnDestIPAdd","columnDestPtNo","columnMsg","columnRefIdSys",
"columnRefId","columnGId","columnSId","columnRev","columnClTp","columnPri"],show="headings")
treeViewRl.heading("columnLnNo",text="Line number")
treeViewRl.column("columnLnNo",width=40)
treeViewRl.heading("columnStat",text="Status")
treeViewRl.column("columnStat",width=50)
treeViewRl.heading("columnActn",text="Action")
treeViewRl.column("columnActn",width=50)
treeViewRl.heading("columnProt",text="Protocol")
treeViewRl.column("columnProt",width=40)
treeViewRl.heading("columnSrcIPAdd",text="Source IP Address")
treeViewRl.column("columnSrcIPAdd",width=110)
treeViewRl.heading("columnSrcPtNo",text="Source Port Number")
treeViewRl.column("columnSrcPtNo",width=110)
treeViewRl.heading("columnDirOpr",text="Direction Operator")
treeViewRl.column("columnDirOpr",width=10)
treeViewRl.heading("columnDestIPAdd",text="Destination IP Address")
treeViewRl.column("columnDestIPAdd",width=110)
treeViewRl.heading("columnDestPtNo",text="Destination Port Number")
treeViewRl.column("columnDestPtNo",width=110)
treeViewRl.heading("columnMsg",text="Message")
treeViewRl.column("columnMsg",width=100)
treeViewRl.heading("columnRefIdSys",text="Reference ID System")
treeViewRl.column("columnRefIdSys",width=20)
treeViewRl.heading("columnRefId",text="Reference ID")
treeViewRl.column("columnRefId",width=200)
treeViewRl.heading("columnGId",text="GID")
treeViewRl.column("columnGId",width=30)
treeViewRl.heading("columnSId",text="SID")
treeViewRl.column("columnSId",width=60)
treeViewRl.heading("columnRev",text="Revision")
treeViewRl.column("columnRev",width=10)
treeViewRl.heading("columnClTp",text="Class Type")
treeViewRl.column("columnClTp",width=100)
treeViewRl.heading("columnPri",text="Priority")
treeViewRl.column("columnPri",width=10)
treeViewRl.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)
treeViewRl.bind("<ButtonRelease-1>",treeviewClick)

scrollbarXRl=ttk.Scrollbar(frameRl,orient="horizontal",command=treeViewRl.xview)
scrollbarXRl.grid(column=0,row=1,sticky=Tkinter.N+Tkinter.E+Tkinter.W)

scrollbarYRl=ttk.Scrollbar(frameRl,command=treeViewRl.yview)
scrollbarYRl.grid(column=1,row=0,sticky=Tkinter.N+Tkinter.S+Tkinter.W)

treeViewRl.config(xscrollcommand=scrollbarXRl,yscrollcommand=scrollbarYRl)

labelFrameED=ttk.Labelframe(frameRl,text="Rule edit")
labelFrameED.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5)

labelActn=ttk.Label(labelFrameED,text="Action:")
labelActn.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxActn=ttk.Combobox(labelFrameED,textvariable=actn)
comboboxActn["values"]=("alert","log","pass","activate","dynamic","drop","reject","sdrop")
comboboxActn.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelProt=ttk.Label(labelFrameED,text="Protocol:")
labelProt.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxProt=ttk.Combobox(labelFrameED,textvariable=prot)
comboboxProt["values"]=("tcp","icmp","udp","ip")
comboboxProt.grid(column=3,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelSrcIPAdd=ttk.Label(labelFrameED,text="Source IP Address:")
labelSrcIPAdd.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxSrcIPAdd=ttk.Combobox(labelFrameED,textvariable=srcIPAdd)
comboboxSrcIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
comboboxSrcIPAdd.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelSrcPtNo=ttk.Label(labelFrameED,text="Source Port Number:")
labelSrcPtNo.grid(column=2,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxSrcPtNo=ttk.Combobox(labelFrameED,textvariable=srcPtNo)
comboboxSrcPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
comboboxSrcPtNo.grid(column=3,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelDirOpr=ttk.Label(labelFrameED,text="Direction Operator:")
labelDirOpr.grid(column=4,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxDirOpr=ttk.Combobox(labelFrameED,textvariable=dirOpr)
comboboxDirOpr["values"]=("->","<>")
comboboxDirOpr.grid(column=5,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)


labelDestIPAdd=ttk.Label(labelFrameED,text="Destination IP Address:")
labelDestIPAdd.grid(column=4,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxDestIPAdd=ttk.Combobox(labelFrameED,textvariable=destIPAdd)
comboboxDestIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
comboboxDestIPAdd.grid(column=5,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelDestPtNo=ttk.Label(labelFrameED,text="Destination Port Number:")
labelDestPtNo.grid(column=6,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxDestPtNo=ttk.Combobox(labelFrameED,textvariable=destPtNo)
comboboxDestPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
comboboxDestPtNo.grid(column=7,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

separatorED=ttk.Separator(labelFrameED)
separatorED.grid(column=0,row=2,columnspan=8,sticky=Tkinter.E+Tkinter.W)

labelMsg=ttk.Label(labelFrameED,text="Message:")
labelMsg.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryMsg=ttk.Entry(labelFrameED,textvariable=msg)
entryMsg.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelRefIdSys=ttk.Label(labelFrameED,text="Reference ID System:")
labelRefIdSys.grid(column=2,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxRefIdSys=ttk.Combobox(labelFrameED,textvariable=refIdSys)
comboboxRefIdSys["values"]=("bugtraq","cve","nessus","arachnids","mcafee","osvdb","msb","url")
comboboxRefIdSys.grid(column=3,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelRefId=ttk.Label(labelFrameED,text="Reference ID:")
labelRefId.grid(column=4,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryRefId=ttk.Entry(labelFrameED,textvariable=refId)
entryRefId.grid(column=5,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelGId=ttk.Label(labelFrameED,text="GID:")
labelGId.grid(column=6,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryGId=ttk.Entry(labelFrameED,textvariable=gId)
entryGId.grid(column=7,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelSId=ttk.Label(labelFrameED,text="SID:")
labelSId.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entrySId=ttk.Entry(labelFrameED,textvariable=sId)
entrySId.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelRev=ttk.Label(labelFrameED,text="Revision:")
labelRev.grid(column=2,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryRev=ttk.Entry(labelFrameED,textvariable=rev)
entryRev.grid(column=3,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelClTp=ttk.Label(labelFrameED,text="Class Type:")
labelClTp.grid(column=4,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxClTp=ttk.Combobox(labelFrameED,textvariable=clTp)
comboboxClTp["values"]=("attempted-admin","attempted-user","inappropriate-content","policy-violation","shellcode-detect","successful-admin","successful-user","trojan-activity","unsuccessful-user","web-application-attack","attempted-dos","attempted-recon","bad-unknown","default-login-attempt","denial-of-service","misc-attack","non-standard-protocol","rpc-portmap-decode","successful-dos","successful-recon-largescale","successful-recon-limited","suspicious-filename-detect","suspicious-login","system-call-detect","unusual-client-port-connection","web-application-activity","icmp-event","misc-activity","network-scan","not-suspicious","protocol-command-decode","string-detect","unknown","tcp-connection")
comboboxClTp.grid(column=5,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelPri=ttk.Label(labelFrameED,text="Priority:")
labelPri.grid(column=6,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryPri=ttk.Entry(labelFrameED,textvariable=pri)
entryPri.grid(column=7,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonaddRl=ttk.Button(labelFrameED,text="Add rule",command=addRl)
buttonaddRl.grid(column=0,row=5,columnspan=8,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameUd=ttk.Frame(noteBookMain)

labelFrameSnortVer=ttk.Labelframe(frameUd,text="Snort Version")
labelFrameSnortVer.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameSnortVerOut=ttk.Label(labelFrameSnortVer)
labelFrameSnortVerOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameBarnyardVer=ttk.Labelframe(frameUd,text="Barnyard Version")
labelFrameBarnyardVer.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameBarnyardVerOut=ttk.Label(labelFrameBarnyardVer)
labelFrameBarnyardVerOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFramePulledPorkVer=ttk.Labelframe(frameUd,text="PulledPork Version")
labelFramePulledPorkVer.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFramePulledPorkVerOut=ttk.Label(labelFramePulledPorkVer)
labelFramePulledPorkVerOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorPulledPork=ttk.Separator(labelFramePulledPorkVer)
separatorPulledPork.grid(column=0,row=1,sticky=Tkinter.E+Tkinter.W)

buttonUdRlset=ttk.Button(labelFramePulledPorkVer,text="Update ruleset",command=dlRlset)
buttonUdRlset.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameAlert=ttk.Frame(noteBookMain)

labelFrameBase=ttk.Labelframe(frameAlert,text="BASE")
labelFrameBase.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelBase=ttk.Label(labelFrameBase,text="BASE is the Basic Analysis and Security Engine.\nIt is based on the code from the Analysis Console for Intrusion Databases (ACID) project.\nThis application provides a web front-end to query and analyze the alerts coming from a SNORT IDS system.")
labelBase.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5)

buttonOpBase=ttk.Button(labelFrameBase,text="Open BASE",command=opBase)
buttonOpBase.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameGraph=ttk.Labelframe(frameAlert,text="Graph")
labelFrameGraph.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

img=PIL.Image.open("graph.png")
graph=PIL.ImageTk.PhotoImage(img)
graphlabel=Tkinter.Label(labelFrameGraph,image=graph)
graphlabel.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5)

noteBookMain.add(frameHome,text="Home")
noteBookMain.add(frameSnort,text="Snort")
noteBookMain.add(frameBarnyard,text="Barnyard")
noteBookMain.add(frameRl,text="Rule")
noteBookMain.add(frameCfg,text="Configuration")
noteBookMain.add(frameUd,text="Update")
noteBookMain.add(frameAlert,text="Alert")

shwSnortVer()

shwBarnyardVer()

shwPulledPorkVer()

refreshSnortStat()

rRlF()

refreshThread=threading.Thread(target=autoRefresh)
refreshThread.start()

root.mainloop()
