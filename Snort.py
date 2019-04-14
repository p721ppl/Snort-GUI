import Tkinter
import ttk
import tkFileDialog
import tkMessageBox
import subprocess
import threading
import time
import fileinput
import re
import pwd
import grp
import ConfigParser
import webbrowser
import netifaces
import MySQLdb
import PIL.Image
import PIL.ImageTk
import matplotlib.pyplot
import matplotlib.cbook
import pandas

global seledRlLnNo
seledRlLnNo=0

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
    
def refrshAllStat():
    while True:
        refreshSnortIsEnad()
        refreshSnortIsFled()
        refreshBarnyardIsEnad()
        refreshBarnyardIsFled()
        refreshSnortStat()
        refreshBarnyardStat()
        time.sleep(1)

def snortEnaSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl enable snort.service",shell=True)
    
def snortDisaSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl disable snort.service",shell=True)

def snortStrtSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl start snort.service",shell=True)
    
def snortStSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl stop snort.service",shell=True)

def barnyardEnaSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl enable barnyard2.service",shell=True)
    
def barnyardDisaSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl disable barnyard2.service",shell=True)

def barnyardStrtSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl start barnyard2.service",shell=True)
    
def barnyardStSvc():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl stop barnyard2.service",shell=True)

def dReload():
    subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S systemctl daemon-reload",shell=True)

def dlRlset():
    pulledPorkOut=subprocess.Popen("echo "+sudoPwd.get()+" | "+"sudo -S /usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=pulledPorkOut.communicate()
    separatorUd=ttk.Separator(labelFrameUd)
    separatorUd.grid(column=0,row=2,sticky=Tkinter.E+Tkinter.W)
    labelPulledPorkOut=ttk.Label(labelFrameUd)
    labelPulledPorkOut.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelPulledPorkOut.config(text=stdout)

def askAppLoc():
    openAppLoc=tkFileDialog.askopenfilename(initialdir="/usr/local/bin/",title="Select application file",filetypes = (("Snort application files","snort"),("All files","*.*")))
    appLoc.set(openAppLoc)

def askCfgLoc():
    openCfgLoc=tkFileDialog.askopenfilename(initialdir="/etc/snort/",title="Select configuration file",filetypes = (("Configuration files","*.conf"),("All files","*.*")))
    cfgLoc.set(openCfgLoc)

def usrLs():
    usrLs=[]
    for user in pwd.getpwall():
        usrLs.append(user[0])
    return usrLs

def grpLs():
    grpLs=[]
    for group in grp.getgrall():
        grpLs.append(group[0])
    return grpLs

def svExecStart():
    execStart=appLoc.get()+" -c "+cfgLoc.get()+" -i "+netItf.get()+" -u "+usr.get()+" -g "+seledgrp.get()
    if optQtOp.get()==1:
        execStart=execStart+" -q "
    config=ConfigParser.ConfigParser()
    config.optionxform=str
    config.read("/lib/systemd/system/snort.service")
    config.set("Service","ExecStart",execStart)
    with open("/lib/systemd/system/snort.service","w") as configfile:
        config.write(configfile)
    dReload()

def askRlFLoc():
    openRlFLoc=tkFileDialog.askopenfilename(initialdir="/etc/snort/rules",title="Select rule file",filetypes=(("Rule files","*.rules"),("All files","*.*")))
    seledRlF.set(openRlFLoc)

def clrTreeVRl():
    for row in treeViewRl.get_children():
        treeViewRl.delete(row)

def rRlF():
    with open(seledRlF.get(),"r") as rF:
        lnNo=0
        e=[]
        valLs=[]
        for line in rF:
            lnNo=lnNo+1
            line=line.lstrip()
            line=re.sub("#\s*","#",line,count=1)
            if re.match("\s*#*\s*alert|\s*#*\s*log|\s*#*\s*pass|\s*#*\s*activate|\s*#*\s*dynamic|\s*#*\s*drop|\s*#*\s*reject|\s*#*\s*sdrop",line) != None:
                line=re.split("\s",line,maxsplit=7)[:8]
                Actn=line[0]
                Prot=line[1]
                SrcIPAdd=line[2]
                SrcPtNo=line[3]
                DirOpr=line[4]
                DestIPAdd=line[5]
                DestPtNo=line[6]
                if len(line) > 7:
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
                else:
                    msg=''
                    refIdSys=''
                    refId=''
                    gId=''
                    sId=''
                    rev=''
                    clTp=''
                    pri=''
                if Actn=="alert" or Actn=="log" or Actn=="pass" or Actn=="activate" or Actn=="dynamic" or Actn=="drop" or Actn=="reject" or Actn=="sdrop":
                    rlStat="Enable"
                elif Actn=="#alert" or Actn=="#log" or Actn=="#pass" or Actn=="#activate" or Actn=="#dynamic" or Actn=="#drop" or Actn=="#reject" or Actn=="#sdrop":
                    rlStat="Disable"
                else:
                    rlStat="Unknown"
                treeViewRl.insert("","end",values=(lnNo,rlStat,Actn,Prot,SrcIPAdd,SrcPtNo,DirOpr,DestIPAdd,DestPtNo,msg,refIdSys,refId,gId,sId,rev,clTp,pri))

def reloadRl():
    clrTreeVRl()
    rRlF()

def enaRl():
    global seledRlLnNo
    intSeledRlLnNo=int(seledRlLnNo)-1
    with open(seledRlF.get(),"r+") as rF:
        readlines=rF.readlines()
        readlines[intSeledRlLnNo]=re.sub("#","",readlines[intSeledRlLnNo],count=1)
    with open(seledRlF.get(),"w+") as wF:
        wF.writelines(readlines)
    reloadRl()

def disaRl():
    global seledRlLnNo
    intSeledRlLnNo=int(seledRlLnNo)-1
    with open(seledRlF.get(),"r+") as rF:
        readlines=rF.readlines()
    if re.match("\s*#+\s*",readlines[intSeledRlLnNo])!=None:
        pass
    else:
        with open(seledRlF.get(),"w+") as wF:
            readlines[intSeledRlLnNo]="#"+readlines[intSeledRlLnNo]
            wF.writelines(readlines)
        reloadRl()

def addRl():
    clrTreeVRl()
    with open(seledRlF.get(),"a+") as wF:
        nRl=[]
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
        wF.writelines("\n")
        wF.writelines(" ".join(nRl))
    rRlF()

def treeviewClick(event):
    for item in treeViewRl.selection():
        global seledRlLnNo
        itemLs=treeViewRl.item(item,"values")
        seledRlLnNo=itemLs[0]
    return seledRlLnNo

def saveVar():
    pass

def shwAlert():
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()
    sql="SELECT sid, cid, signature, sig_name, sig_class_id, sig_priority, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), ip_proto, layer4_sport, layer4_dport FROM acid_event"
    cursor.execute(sql)
    data=cursor.fetchall()
    for row in data:
        treeviewAlert.insert("","end",values=row)

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

def shwSnortVer():
    snortVerOut=subprocess.Popen("snort -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortVerOut.communicate()
    labelFrameSnortInfoOut.config(text=stderr)

def shwBarnyardVer():
    barnyardVerOut=subprocess.Popen("barnyard2 -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardVerOut.communicate()
    labelFrameBarnyardInfoOut.config(text=stderr)

def shwPulledPorkVer():
    verO=subprocess.Popen("pulledpork.pl -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=verO.communicate()
    labelFramePulledPorkInfoOut.config(text=stdout)

def aRlTLvl():
    ToplevelaRl=Tkinter.Toplevel()
    ToplevelaRl.title("Rule adding - Snort IDS GUI")
    ToplevelaRl.resizable(False,False)
    ToplevelaRl.attributes("-topmost",1) 
    
    labelFrameARl=ttk.Labelframe(ToplevelaRl,text="Rule adding")
    labelFrameARl.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    
    labelActn=ttk.Label(labelFrameARl,text="Action:")
    labelActn.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxActn=ttk.Combobox(labelFrameARl,textvariable=actn)
    comboboxActn["values"]=("alert","log","pass","activate","dynamic","drop","reject","sdrop")
    comboboxActn.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelProt=ttk.Label(labelFrameARl,text="Protocol:")
    labelProt.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxProt=ttk.Combobox(labelFrameARl,textvariable=prot)
    comboboxProt["values"]=("tcp","icmp","udp","ip")
    comboboxProt.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelSrcIPAdd=ttk.Label(labelFrameARl,text="Source IP Address:")
    labelSrcIPAdd.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxSrcIPAdd=ttk.Combobox(labelFrameARl,textvariable=srcIPAdd)
    comboboxSrcIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
    comboboxSrcIPAdd.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelSrcPtNo=ttk.Label(labelFrameARl,text="Source Port Number:")
    labelSrcPtNo.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxSrcPtNo=ttk.Combobox(labelFrameARl,textvariable=srcPtNo)
    comboboxSrcPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
    comboboxSrcPtNo.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelDirOpr=ttk.Label(labelFrameARl,text="Direction Operator:")
    labelDirOpr.grid(column=0,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxDirOpr=ttk.Combobox(labelFrameARl,textvariable=dirOpr)
    comboboxDirOpr["values"]=("->","<>")
    comboboxDirOpr.grid(column=1,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelDestIPAdd=ttk.Label(labelFrameARl,text="Destination IP Address:")
    labelDestIPAdd.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxDestIPAdd=ttk.Combobox(labelFrameARl,textvariable=destIPAdd)
    comboboxDestIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
    comboboxDestIPAdd.grid(column=1,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelDestPtNo=ttk.Label(labelFrameARl,text="Destination Port Number:")
    labelDestPtNo.grid(column=0,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxDestPtNo=ttk.Combobox(labelFrameARl,textvariable=destPtNo)
    comboboxDestPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
    comboboxDestPtNo.grid(column=1,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

    separatorED=ttk.Separator(labelFrameARl)
    separatorED.grid(column=0,row=8,columnspan=2,sticky=Tkinter.E+Tkinter.W)
    
    labelMsg=ttk.Label(labelFrameARl,text="Message:")
    labelMsg.grid(column=0,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryMsg=ttk.Entry(labelFrameARl,textvariable=msg)
    entryMsg.grid(column=1,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelRefIdSys=ttk.Label(labelFrameARl,text="Reference ID System:")
    labelRefIdSys.grid(column=0,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxRefIdSys=ttk.Combobox(labelFrameARl,textvariable=refIdSys)
    comboboxRefIdSys["values"]=("bugtraq","cve","nessus","arachnids","mcafee","osvdb","msb","url")
    comboboxRefIdSys.grid(column=1,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelRefId=ttk.Label(labelFrameARl,text="Reference ID:")
    labelRefId.grid(column=0,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryRefId=ttk.Entry(labelFrameARl,textvariable=refId)
    entryRefId.grid(column=1,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelGId=ttk.Label(labelFrameARl,text="GID:")
    labelGId.grid(column=0,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryGId=ttk.Entry(labelFrameARl,textvariable=gId)
    entryGId.grid(column=1,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelSId=ttk.Label(labelFrameARl,text="SID:")
    labelSId.grid(column=0,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entrySId=ttk.Entry(labelFrameARl,textvariable=sId)
    entrySId.grid(column=1,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelRev=ttk.Label(labelFrameARl,text="Revision:")
    labelRev.grid(column=0,row=14,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryRev=ttk.Entry(labelFrameARl,textvariable=rev)
    entryRev.grid(column=1,row=14,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelClTp=ttk.Label(labelFrameARl,text="Class Type:")
    labelClTp.grid(column=0,row=15,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxClTp=ttk.Combobox(labelFrameARl,textvariable=clTp)
    comboboxClTp["values"]=("attempted-admin","attempted-user","inappropriate-content","policy-violation","shellcode-detect","successful-admin","successful-user","trojan-activity","unsuccessful-user","web-application-attack","attempted-dos","attempted-recon","bad-unknown","default-login-attempt","denial-of-service","misc-attack","non-standard-protocol","rpc-portmap-decode","successful-dos","successful-recon-largescale","successful-recon-limited","suspicious-filename-detect","suspicious-login","system-call-detect","unusual-client-port-connection","web-application-activity","icmp-event","misc-activity","network-scan","not-suspicious","protocol-command-decode","string-detect","unknown","tcp-connection")
    comboboxClTp.grid(column=1,row=15,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelPri=ttk.Label(labelFrameARl,text="Priority:")
    labelPri.grid(column=0,row=16,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

    entryPri=ttk.Entry(labelFrameARl,textvariable=pri)
    entryPri.grid(column=1,row=16,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

    separatorED=ttk.Separator(labelFrameARl)
    separatorED.grid(column=0,row=17,columnspan=2,sticky=Tkinter.E+Tkinter.W)

    buttonaddRl=ttk.Button(labelFrameARl,text="Add rule",command=addRl)
    buttonaddRl.grid(column=0,row=18,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

def edRlTLvl():
    ToplevelaRl=Tkinter.Toplevel()
    ToplevelaRl.title("Rule editing - Snort IDS GUI")
    ToplevelaRl.resizable(False,False)
    ToplevelaRl.attributes("-topmost",1) 
    
    labelFrameEdRl=ttk.Labelframe(ToplevelaRl,text="Rule editing")
    labelFrameEdRl.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    
    labelEdActn=ttk.Label(labelFrameEdRl,text="Action:")
    labelEdActn.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdActn=ttk.Combobox(labelFrameEdRl,textvariable=actn)
    comboboxEdActn["values"]=("alert","log","pass","activate","dynamic","drop","reject","sdrop")
    comboboxEdActn.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdProt=ttk.Label(labelFrameEdRl,text="Protocol:")
    labelEdProt.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdProt=ttk.Combobox(labelFrameEdRl,textvariable=prot)
    comboboxEdProt["values"]=("tcp","icmp","udp","ip")
    comboboxEdProt.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdSrcIPAdd=ttk.Label(labelFrameEdRl,text="Source IP Address:")
    labelEdSrcIPAdd.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdSrcIPAdd=ttk.Combobox(labelFrameEdRl,textvariable=srcIPAdd)
    comboboxEdSrcIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
    comboboxEdSrcIPAdd.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdSrcPtNo=ttk.Label(labelFrameEdRl,text="Source Port Number:")
    labelEdSrcPtNo.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdSrcPtNo=ttk.Combobox(labelFrameEdRl,textvariable=srcPtNo)
    comboboxEdSrcPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
    comboboxEdSrcPtNo.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdDirOpr=ttk.Label(labelFrameEdRl,text="Direction Operator:")
    labelEdDirOpr.grid(column=0,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdDirOpr=ttk.Combobox(labelFrameEdRl,textvariable=dirOpr)
    comboboxEdDirOpr["values"]=("->","<>")
    comboboxEdDirOpr.grid(column=1,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdDestIPAdd=ttk.Label(labelFrameEdRl,text="Destination IP Address:")
    labelEdDestIPAdd.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdDestIPAdd=ttk.Combobox(labelFrameEdRl,textvariable=destIPAdd)
    comboboxEdDestIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
    comboboxEdDestIPAdd.grid(column=1,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelDestPtNo=ttk.Label(labelFrameEdRl,text="Destination Port Number:")
    labelDestPtNo.grid(column=0,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdDestPtNo=ttk.Combobox(labelFrameEdRl,textvariable=destPtNo)
    comboboxEdDestPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
    comboboxEdDestPtNo.grid(column=1,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

    separatorEd=ttk.Separator(labelFrameEdRl)
    separatorEd.grid(column=0,row=8,columnspan=2,sticky=Tkinter.E+Tkinter.W)
    
    labelEdMsg=ttk.Label(labelFrameEdRl,text="Message:")
    labelEdMsg.grid(column=0,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdMsg=ttk.Entry(labelFrameEdRl,textvariable=msg)
    entryEdMsg.grid(column=1,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdRefIdSys=ttk.Label(labelFrameEdRl,text="Reference ID System:")
    labelEdRefIdSys.grid(column=0,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdRefIdSys=ttk.Combobox(labelFrameEdRl,textvariable=refIdSys)
    comboboxEdRefIdSys["values"]=("bugtraq","cve","nessus","arachnids","mcafee","osvdb","msb","url")
    comboboxEdRefIdSys.grid(column=1,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdRefId=ttk.Label(labelFrameEdRl,text="Reference ID:")
    labelEdRefId.grid(column=0,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdRefId=ttk.Entry(labelFrameEdRl,textvariable=refId)
    entryEdRefId.grid(column=1,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdGId=ttk.Label(labelFrameEdRl,text="GID:")
    labelEdGId.grid(column=0,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdGId=ttk.Entry(labelFrameEdRl,textvariable=gId)
    entryEdGId.grid(column=1,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdSId=ttk.Label(labelFrameEdRl,text="SID:")
    labelEdSId.grid(column=0,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdSId=ttk.Entry(labelFrameEdRl,textvariable=sId)
    entryEdSId.grid(column=1,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdRev=ttk.Label(labelFrameEdRl,text="Revision:")
    labelEdRev.grid(column=0,row=14,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdRev=ttk.Entry(labelFrameEdRl,textvariable=rev)
    entryEdRev.grid(column=1,row=14,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdClTp=ttk.Label(labelFrameEdRl,text="Class Type:")
    labelEdClTp.grid(column=0,row=15,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdClTp=ttk.Combobox(labelFrameEdRl,textvariable=clTp)
    comboboxEdClTp["values"]=("attempted-admin","attempted-user","inappropriate-content","policy-violation","shellcode-detect","successful-admin","successful-user","trojan-activity","unsuccessful-user","web-application-attack","attempted-dos","attempted-recon","bad-unknown","default-login-attempt","denial-of-service","misc-attack","non-standard-protocol","rpc-portmap-decode","successful-dos","successful-recon-largescale","successful-recon-limited","suspicious-filename-detect","suspicious-login","system-call-detect","unusual-client-port-connection","web-application-activity","icmp-event","misc-activity","network-scan","not-suspicious","protocol-command-decode","string-detect","unknown","tcp-connection")
    comboboxEdClTp.grid(column=1,row=15,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdPri=ttk.Label(labelFrameEdRl,text="Priority:")
    labelEdPri.grid(column=0,row=16,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

    entryEdPri=ttk.Entry(labelFrameEdRl,textvariable=pri)
    entryEdPri.grid(column=1,row=16,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

    separatorEd=ttk.Separator(labelFrameEdRl)
    separatorEd.grid(column=0,row=17,columnspan=2,sticky=Tkinter.E+Tkinter.W)

    buttonEdRl=ttk.Button(labelFrameEdRl,text="Edit rule")
    buttonEdRl.grid(column=0,row=18,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

root=Tkinter.Tk()
root.resizable(0,0)
root.title("Snort Intrusion Detection System Graphical User Interface")

mysql_graph()

matplotlib.pyplot.savefig("graph.png")

sudoPwd=Tkinter.StringVar(value="John1212")

appLoc=Tkinter.StringVar()

cfgLoc=Tkinter.StringVar()

netItf=Tkinter.StringVar()

usr=Tkinter.StringVar()

seledgrp=Tkinter.StringVar()

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

seledRlF=Tkinter.StringVar(value="/etc/snort/rules/test.rules")

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
noteBookMain.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameSnort=ttk.Frame(noteBookMain)

labelFrameSnortStat=ttk.Labelframe(frameSnort,text="Snort Status")
labelFrameSnortStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSnortStrtUTyp=ttk.Label(labelFrameSnortStat,text="Snort startup type:")
labelSnortStrtUTyp.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatSnortIsEnaOut=ttk.Label(labelFrameSnortStat)
labelStatSnortIsEnaOut.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonSecEnaSnort=ttk.Button(labelFrameSnortStat,text="Enable",command=snortEnaSvc)
buttonSecEnaSnort.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonSecDisaSnort=ttk.Button(labelFrameSnortStat,text="Disable",command=snortDisaSvc)
buttonSecDisaSnort.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

separatorFSnortStat=ttk.Separator(labelFrameSnortStat)
separatorFSnortStat.grid(column=0,row=2,columnspan=2,sticky=Tkinter.E+Tkinter.W)

labelSnortSvcStat=ttk.Label(labelFrameSnortStat,text="Snort service status:")
labelSnortSvcStat.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatSnortIsFledOut=ttk.Label(labelFrameSnortStat)
labelStatSnortIsFledOut.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonSecStrtSnort=ttk.Button(labelFrameSnortStat,text="Start",command=snortStrtSvc)
buttonSecStrtSnort.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonSecStSnort=ttk.Button(labelFrameSnortStat,text="Stop",command=snortStSvc)
buttonSecStSnort.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

separatorSecSnortStat=ttk.Separator(labelFrameSnortStat)
separatorSecSnortStat.grid(column=0,row=5,columnspan=2,sticky=Tkinter.E+Tkinter.W)

labelStatSnortStatOut=ttk.Label(labelFrameSnortStat)
labelStatSnortStatOut.grid(column=0,row=6,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5)

labelFrameSetting=ttk.Labelframe(frameSnort,text="Setting")
labelFrameSetting.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelAppLoc=ttk.Label(labelFrameSetting,text="Application location:")
labelAppLoc.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryAppLoc=ttk.Entry(labelFrameSetting,textvariable=appLoc)
entryAppLoc.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonAskApp=ttk.Button(labelFrameSetting,text="Browse",command=askAppLoc)
buttonAskApp.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5)

labelCfgLoc=ttk.Label(labelFrameSetting,text="Configuration location:")
labelCfgLoc.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryCfgLoc=ttk.Entry(labelFrameSetting,textvariable=cfgLoc)
entryCfgLoc.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonAskCfg=ttk.Button(labelFrameSetting,text="Browse",command=askCfgLoc)
buttonAskCfg.grid(column=2,row=1,ipadx=5,ipady=5,padx=5,pady=5)

labelNetItf=ttk.Label(labelFrameSetting,text="Network Interface:")
labelNetItf.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxNetItf=ttk.Combobox(labelFrameSetting,textvariable=netItf,values=netifaces.interfaces())
comboboxNetItf.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelUsr=ttk.Label(labelFrameSetting,text="User:")
labelUsr.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryUsr=ttk.Combobox(labelFrameSetting,textvariable=usr,values=usrLs())
entryUsr.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

labelGrp=ttk.Label(labelFrameSetting,text="Group:")
labelGrp.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryGrp=ttk.Combobox(labelFrameSetting,textvariable=seledgrp,values=grpLs())
entryGrp.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

separatorSetting=ttk.Separator(labelFrameSetting)
separatorSetting.grid(column=0,row=5,columnspan=3,sticky=Tkinter.E+Tkinter.W)

checkButtonQtOp=ttk.Checkbutton(labelFrameSetting,variable=optQtOp,text="Quiet operation")
checkButtonQtOp.grid(column=0,row=6,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

separatorSetting=ttk.Separator(labelFrameSetting)
separatorSetting.grid(column=0,row=7,columnspan=3,sticky=Tkinter.E+Tkinter.W)

buttonSv=ttk.Button(labelFrameSetting,text="Save with reload",command=svExecStart)
buttonSv.grid(column=0,row=8,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

frameBarnyard=ttk.Frame(noteBookMain)

labelFrameBarnyardStat=ttk.Labelframe(frameBarnyard,text="Barnyard Status")
labelFrameBarnyardStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelBarnyardSvcStat=ttk.Label(labelFrameBarnyardStat,text="Barnyard service status:")
labelBarnyardSvcStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatBarnyardIsEnaOut=ttk.Label(labelFrameBarnyardStat)
labelStatBarnyardIsEnaOut.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonEnaBarnyard=ttk.Button(labelFrameBarnyardStat,text="Enable",command=barnyardEnaSvc)
buttonEnaBarnyard.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonDisaBarnyard=ttk.Button(labelFrameBarnyardStat,text="Disable",command=barnyardDisaSvc)
buttonDisaBarnyard.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

separatorBarnyard=ttk.Separator(labelFrameBarnyardStat)
separatorBarnyard.grid(column=0,row=2,columnspan=3,sticky=Tkinter.E+Tkinter.W)

labelBarnyardSvcStat=ttk.Label(labelFrameBarnyardStat,text="Barnyard service status:")
labelBarnyardSvcStat.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatBarnyardIsFledOut=ttk.Label(labelFrameBarnyardStat)
labelStatBarnyardIsFledOut.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonStrtBarnyard=ttk.Button(labelFrameBarnyardStat,text="Start",command=barnyardStrtSvc)
buttonStrtBarnyard.grid(column=0,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonStBarnyard=ttk.Button(labelFrameBarnyardStat,text="Stop",command=barnyardStSvc)
buttonStBarnyard.grid(column=1,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

separatorSecBarnyardStat=ttk.Separator(labelFrameBarnyardStat)
separatorSecBarnyardStat.grid(column=0,row=6,columnspan=2,sticky=Tkinter.E+Tkinter.W)

labelStatBarnyardStatOut=ttk.Label(labelFrameBarnyardStat)
labelStatBarnyardStatOut.grid(column=0,row=7,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5)

frameCfg=ttk.Frame(noteBookMain)
frameCfg.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

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

labelFrameRlFSelion=ttk.Labelframe(frameRl,text="Rule file selection")
labelFrameRlFSelion.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelRlF=ttk.Label(labelFrameRlFSelion,text="Rule file:")
labelRlF.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxRlF=ttk.Combobox(labelFrameRlFSelion,textvariable=seledRlF)
comboboxRlF["values"]=("/etc/snort/rules/snort.rules")
comboboxRlF.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonAskRlF=ttk.Button(labelFrameRlFSelion,text="Browse",command=askRlFLoc)
buttonAskRlF.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5)

buttonReloadRlF=ttk.Button(labelFrameRlFSelion,text="Reload file",command=reloadRl)
buttonReloadRlF.grid(column=0,row=1,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameSeledFsRl=ttk.Labelframe(frameRl,text="Selected file's rule")
labelFrameSeledFsRl.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

treeViewRl=ttk.Treeview(labelFrameSeledFsRl,columns=["columnLnNo","columnStat","columnActn","columnProt","columnSrcIPAdd","columnSrcPtNo","columnDirOpr","columnDestIPAdd","columnDestPtNo","columnMsg","columnRefIdSys",
"columnRefId","columnGId","columnSId","columnRev","columnClTp","columnPri"],selectmode="browse",show="headings")
treeViewRl.heading("columnLnNo",text="Line")
treeViewRl.column("columnLnNo",width=50)
treeViewRl.heading("columnStat",text="Status")
treeViewRl.column("columnStat",width=70)
treeViewRl.heading("columnActn",text="Action")
treeViewRl.column("columnActn",width=50)
treeViewRl.heading("columnProt",text="Prot")
treeViewRl.column("columnProt",width=40)
treeViewRl.heading("columnSrcIPAdd",text="Source Address")
treeViewRl.column("columnSrcIPAdd",width=110)
treeViewRl.heading("columnSrcPtNo",text="Source Port")
treeViewRl.column("columnSrcPtNo",width=130)
treeViewRl.heading("columnDirOpr",text="DO")
treeViewRl.column("columnDirOpr",width=30)
treeViewRl.heading("columnDestIPAdd",text="Dest Address")
treeViewRl.column("columnDestIPAdd",width=110)
treeViewRl.heading("columnDestPtNo",text="Dest Port")
treeViewRl.column("columnDestPtNo",width=120)
treeViewRl.heading("columnMsg",text="Message")
treeViewRl.column("columnMsg",width=170)
treeViewRl.heading("columnRefIdSys",text="RefSys")
treeViewRl.column("columnRefIdSys",width=60)
treeViewRl.heading("columnRefId",text="Reference ID")
treeViewRl.column("columnRefId",width=170)
treeViewRl.heading("columnGId",text="GID")
treeViewRl.column("columnGId",width=30)
treeViewRl.heading("columnSId",text="SID")
treeViewRl.column("columnSId",width=70)
treeViewRl.heading("columnRev",text="Rev")
treeViewRl.column("columnRev",width=40)
treeViewRl.heading("columnClTp",text="Class Type")
treeViewRl.column("columnClTp",width=170)
treeViewRl.heading("columnPri",text="Pri")
treeViewRl.column("columnPri",width=30)
treeViewRl.grid(column=0,row=0,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
treeViewRl.bind("<ButtonRelease-1>",treeviewClick)

scrollbarXRl=ttk.Scrollbar(labelFrameSeledFsRl,orient="horizontal",command=treeViewRl.xview)
scrollbarXRl.grid(column=0,row=1,sticky=Tkinter.E+Tkinter.W)

scrollbarYRl=ttk.Scrollbar(labelFrameSeledFsRl,command=treeViewRl.yview)
scrollbarYRl.grid(column=1,row=0,sticky=Tkinter.N+Tkinter.S)

treeViewRl.config(xscrollcommand=scrollbarXRl.set,yscrollcommand=scrollbarYRl.set)

labelFrameRlActn=ttk.Labelframe(frameRl,text="Rule action")
labelFrameRlActn.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonARl=ttk.Button(labelFrameRlActn,text="Add rule",command=aRlTLvl)
buttonARl.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonEdRl=ttk.Button(labelFrameRlActn,text="Edit rule",command=edRlTLvl)
buttonEdRl.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorRlActn=ttk.Separator(labelFrameRlActn,orient="vertical")
separatorRlActn.grid(column=2,row=0,sticky=Tkinter.N+Tkinter.S)

buttonEnaRl=ttk.Button(labelFrameRlActn,text="Enable rule",command=enaRl)
buttonEnaRl.grid(column=3,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonDisaRl=ttk.Button(labelFrameRlActn,text="Disable rule",command=disaRl)
buttonDisaRl.grid(column=4,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameUd=ttk.Frame(noteBookMain)

labelFrameUd=ttk.Labelframe(frameUd,text="Update")
labelFrameUd.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelUdRlset=ttk.Label(labelFrameUd,text="Click [Update ruleset] to check for and automatically apply any new posted updates for selected rules packages.")
labelUdRlset.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5)

buttonUdRlset=ttk.Button(labelFrameUd,text="Update ruleset",command=dlRlset)
buttonUdRlset.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameAlert=ttk.Frame(noteBookMain)

treeviewAlert=ttk.Treeview(frameAlert,columns=["sid","cid","signature","sig_name","sig_class_id","sig_priority","timestamp","ip_src","ip_dst","ip_proto","layer4_sport","layer4_dport"],selectmode="browse",show="headings")
treeviewAlert.heading("sid",text="SID")
treeviewAlert.column("sid",width=30)
treeviewAlert.heading("cid",text="CID")
treeviewAlert.column("cid",width=30)
treeviewAlert.heading("signature",text="Sig")
treeviewAlert.column("signature",width=30)
treeviewAlert.heading("sig_name",text="Signature Name")
treeviewAlert.column("sig_name",width=700)
treeviewAlert.heading("sig_class_id",text="SigClID")
treeviewAlert.column("sig_class_id",width=70)
treeviewAlert.heading("sig_priority",text="SigPri")
treeviewAlert.column("sig_priority",width=60)
treeviewAlert.heading("timestamp",text="Timestamp")
treeviewAlert.column("timestamp",width=120)
treeviewAlert.heading("ip_src",text="Source Address")
treeviewAlert.column("ip_src",width=120)
treeviewAlert.heading("ip_dst",text="Dest Address")
treeviewAlert.column("ip_dst",width=120)
treeviewAlert.heading("ip_proto",text="Prot")
treeviewAlert.column("ip_proto",width=40)
treeviewAlert.heading("layer4_sport",text="SrcPt")
treeviewAlert.column("layer4_sport",width=50)
treeviewAlert.heading("layer4_dport",text="DestPt")
treeviewAlert.column("layer4_dport",width=50)
treeviewAlert.grid(column=0,row=0,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

scrollbarXAlert=ttk.Scrollbar(frameAlert,orient="horizontal",command=treeviewAlert.xview)
scrollbarXAlert.grid(column=0,row=1,sticky=Tkinter.E+Tkinter.W)

scrollbarYAlert=ttk.Scrollbar(frameAlert,command=treeviewAlert.yview)
scrollbarYAlert.grid(column=1,row=0,sticky=Tkinter.N+Tkinter.S)

treeviewAlert.configure(xscrollcommand=scrollbarXAlert.set,yscrollcommand=scrollbarYAlert.set)

frameGraph=ttk.Frame(noteBookMain)

labelFrameBase=ttk.Labelframe(frameGraph,text="Basic Analysis and Security Engine")
labelFrameBase.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelBase=ttk.Label(labelFrameBase,text="BASE is the Basic Analysis and Security Engine.\nIt is based on the code from the Analysis Console for Intrusion Databases (ACID) project.\nThis application provides a web front-end to query and analyze the alerts coming from a SNORT IDS system.")
labelBase.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5)

buttonOpBase=ttk.Button(labelFrameBase,text="Open BASE",command=opBase)
buttonOpBase.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameGraph=ttk.Labelframe(frameGraph,text="Graph Alert Data")
labelFrameGraph.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

img=PIL.Image.open("graph.png")
graph=PIL.ImageTk.PhotoImage(img)
graphlabel=Tkinter.Label(labelFrameGraph,image=graph)
graphlabel.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5)

frameAbt=ttk.Frame(noteBookMain)

labelFrameSnortInfo=ttk.Labelframe(frameAbt,text="Snort Information")
labelFrameSnortInfo.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameSnortInfoOut=ttk.Label(labelFrameSnortInfo)
labelFrameSnortInfoOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameBarnyardInfo=ttk.Labelframe(frameAbt,text="Barnyard Information")
labelFrameBarnyardInfo.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameBarnyardInfoOut=ttk.Label(labelFrameBarnyardInfo)
labelFrameBarnyardInfoOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFramePulledPorkInfo=ttk.Labelframe(frameAbt,text="PulledPork Information")
labelFramePulledPorkInfo.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFramePulledPorkInfoOut=ttk.Label(labelFramePulledPorkInfo)
labelFramePulledPorkInfoOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

noteBookMain.add(frameSnort,text="Snort")
noteBookMain.add(frameBarnyard,text="Barnyard")
noteBookMain.add(frameRl,text="Rule")
noteBookMain.add(frameCfg,text="Configuration")
noteBookMain.add(frameAlert,text="Alert")
noteBookMain.add(frameGraph,text="Graph")
noteBookMain.add(frameUd,text="Update")
noteBookMain.add(frameAbt,text="About")

shwAlert()
shwSnortVer()
shwBarnyardVer()
shwPulledPorkVer()
refreshSnortStat()
rRlF()

refreshThread=threading.Thread(target=refrshAllStat)
refreshThread.start()

root.mainloop()
