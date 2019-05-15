import ConfigParser
import datetime
import fileinput
import grp
import matplotlib.pyplot
import matplotlib.cbook
import MySQLdb
import netifaces
import os
import pandas
import PIL.Image
import PIL.ImageTk
import pwd
import re
import ScrolledText
import subprocess
import threading
import time
import Tkinter
import tkFileDialog
import tkMessageBox
import ttk
import webbrowser

global seledRlLnNo
seledRlLnNo=0

def refreshSnortIsEnad():
    snortIsEnaOut=subprocess.Popen("sudo systemctl is-enabled snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortIsEnaOut.communicate()
    if stdout == "":
        labelStatSnortIsEnaOut.config(text="Unknown")
    else:
        labelStatSnortIsEnaOut.config(text=re.sub("\n","",stdout))
       
def refreshSnortIsFled():
    snortIsFledOut=subprocess.Popen("sudo systemctl is-failed snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortIsFledOut.communicate()
    if stdout == "":
        labelStatSnortIsFledOut.config(text="Unknown")
    else:
        labelStatSnortIsFledOut.config(text=re.sub("\n","",stdout))

def refreshBarnyardIsEnad():
    barnyardIsEnaOut=subprocess.Popen("sudo systemctl is-enabled barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardIsEnaOut.communicate()
    if stdout == "":
        labelStatBarnyardIsEnaOut.config(text="Unknown")
    else:
        labelStatBarnyardIsEnaOut.config(text=re.sub("\n","",stdout))
    
def refreshBarnyardIsFled():
    barnyardIsFledOut=subprocess.Popen("sudo systemctl is-failed barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardIsFledOut.communicate()
    if stdout == "":
        labelStatBarnyardIsFledOut.config(text="Unknown")
    else:
        labelStatBarnyardIsFledOut.config(text=re.sub("\n","",stdout))


def refreshBarnyardStat():
    barnyardStatOut=subprocess.Popen("sudo systemctl status barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardStatOut.communicate()
    if stdout == "":
        labelStatBarnyardStatOut.config(text="Unknown")
    else:
        labelStatBarnyardStatOut.config(text=stdout)
    
def refrshAllStat():
    try:
        while True:
            refreshSnortIsEnad()
            refreshSnortIsFled()
            refreshBarnyardIsEnad()
            refreshBarnyardIsFled()
            time.sleep(1)
    except:
        pass

def snortEnaSvc():
    snortEnaSvcO=subprocess.Popen("sudo systemctl enable snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortEnaSvcO.communicate()
    if snortEnaSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Snort service was successfully enabled.")
    if snortEnaSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
    
def snortDisaSvc():
    snortDisaSvcO=subprocess.Popen("sudo systemctl disable snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortDisaSvcO.communicate()
    if snortDisaSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Snort service was successfully disabled.")
    if snortDisaSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def snortStrtSvc():
    snortStrtSvcO=subprocess.Popen("sudo systemctl start snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortStrtSvcO.communicate()
    if snortStrtSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Snort service started successfully.")
    if snortStrtSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def snortStSvc():
    snortStSvcO=subprocess.Popen("sudo systemctl stop snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=snortStSvcO.communicate()
    if snortStSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Snort service stopped successfully.")
    if snortStSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def barnyardEnaSvc():
    barnyardEnaSvcO=subprocess.Popen("sudo systemctl enable barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardEnaSvcO.communicate()
    if barnyardEnaSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Barnyard service was successfully enabled.")
    if barnyardEnaSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def barnyardDisaSvc():
    barnyardDisaSvcO=subprocess.Popen("sudo systemctl disable barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardDisaSvcO.communicate()
    if barnyardDisaSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Barnyard service was successfully disabled.")
    if barnyardDisaSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def barnyardStrtSvc():
    barnyardStrtSvcO=subprocess.Popen("sudo systemctl start barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardStrtSvcO.communicate()
    if barnyardStrtSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Barnyard service started successfully.")
    if barnyardStrtSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def barnyardStSvc():
    barnyardStSvcO=subprocess.Popen("sudo systemctl stop barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=barnyardStSvcO.communicate()
    if barnyardStSvcO.returncode == 0:
        tkMessageBox.showinfo("Information","The Barnyard service stopped successfully.")
    if barnyardStSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def reStrtSnortSvc():
    reStrtSnortSvcO=subprocess.Popen("sudo systemctl restart snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=reStrtSnortSvcO.communicate()
    if reStrtSnortSvcO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def reloadSysDMrgCfg():
    reloadSysDMrgCfgO=subprocess.Popen("sudo systemctl daemon-reload",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=reloadSysDMrgCfgO.communicate()
    if reloadSysDMrgCfgO.returncode != 0:
        tkMessageBox.showerror("Error",stderr)
        
def restatAllSvc():
    reloadSysDMrgCfg()
    reStrtSnortSvc()
    
def snortSvcStatDetTLvl():
    ToplevelSnortSvcStatDet=Tkinter.Toplevel()
    ToplevelSnortSvcStatDet.title("Snort service status detail - Snort IDS GUI")
    ToplevelSnortSvcStatDet.grid_columnconfigure(0,weight=1)
    ToplevelSnortSvcStatDet.grid_rowconfigure(0,weight=1)

    labelFrameSnortSvcStatDet=ttk.Labelframe(ToplevelSnortSvcStatDet,text="Service status detail")
    labelFrameSnortSvcStatDet.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelFrameSnortSvcStatDet.grid_columnconfigure(0,weight=1)
    labelFrameSnortSvcStatDet.grid_rowconfigure(0,weight=1)

    labelSnortSvcStatDetO=ttk.Label(labelFrameSnortSvcStatDet)
    labelSnortSvcStatDetO.grid(column=0,row=0,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5)

    ckSnortSvcStatDet=subprocess.Popen("sudo systemctl status snort.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=ckSnortSvcStatDet.communicate()
    if stdout == "":
        labelSnortSvcStatDetO.config(text="Unknown")
    else:
        labelSnortSvcStatDetO.config(text=stdout)

def barnyardSvcStatDetTLvl():
    ToplevelBarnyardSvcStatDet=Tkinter.Toplevel()
    ToplevelBarnyardSvcStatDet.title("Barnyard service status detail - Snort IDS GUI")
    ToplevelBarnyardSvcStatDet.grid_columnconfigure(0,weight=1)
    ToplevelBarnyardSvcStatDet.grid_rowconfigure(0,weight=1)

    labelFrameBarnyardSvcStatDet=ttk.Labelframe(ToplevelBarnyardSvcStatDet,text="Service status detail")
    labelFrameBarnyardSvcStatDet.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelFrameBarnyardSvcStatDet.grid_columnconfigure(0,weight=1)
    labelFrameBarnyardSvcStatDet.grid_rowconfigure(0,weight=1)

    labelBarnyardSvcStatDetO=ttk.Label(labelFrameBarnyardSvcStatDet)
    labelBarnyardSvcStatDetO.grid(column=0,row=0,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5)

    ckBarnyardSvcStatDet=subprocess.Popen("sudo systemctl status barnyard2.service",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr=ckBarnyardSvcStatDet.communicate()
    if stdout == "":
        labelBarnyardSvcStatDetO.config(text="Unknown")
    else:
        labelBarnyardSvcStatDetO.config(text=stdout)

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

def loadSvcCfg():
    config=ConfigParser.ConfigParser()
    config.optionxform=str
    config.read("/lib/systemd/system/snort.service")
    try:
        execStart=config.get("Service","ExecStart")
        matchAppLoc=re.match('([^\s*]*)\s*',execStart)
        if matchAppLoc:
            appLoc.set(matchAppLoc.group(1))
        srchCfgLoc=re.search('-c\s*([^\s*]*)\s*',execStart)
        if srchCfgLoc:
            cfgLoc.set(srchCfgLoc.group(1))
        srchNetItf=re.search('-i\s*([^\s*]*)\s*',execStart)
        if srchNetItf:
            netItf.set(srchNetItf.group(1))
        srchExecUsr=re.search('-u\s*([^\s*]*)\s*',execStart)
        if srchExecUsr:
            execUsr.set(srchExecUsr.group(1))
        srchExecGrp=re.search('-g\s*([^\s*]*)\s*',execStart)
        if srchExecGrp:
            execGrp.set(srchExecGrp.group(1))
        srchOptQtOp=re.search('-q',execStart)
        if srchOptQtOp:
            optQtOp.set(1)
    except:
        tkMessageBox.showerror("Error","The option or section was not found in the configuration file.\nMake sure the profile is created and configured correctly.")
    
def svSvcCfg():
    execStart=appLoc.get()+" -c "+cfgLoc.get()+" -i "+netItf.get()+" -u "+execUsr.get()+" -g "+execGrp.get()
    if optQtOp.get()==1:
        execStart=execStart+" -q "
    config=ConfigParser.ConfigParser()
    config.optionxform=str
    config.read("/lib/systemd/system/snort.service")
    config.set("Service","ExecStart",execStart)
    with open("/lib/systemd/system/snort.service","w") as configfile:
        config.write(configfile)
    tkMessageBox.showinfo("Information","The systemd manager needs to reload the configuration to finish changes.")

def askRlFLoc():
    openRlFLoc=tkFileDialog.askopenfilename(initialdir="/etc/snort/rules",title="Select rule file",filetypes=(("Rule files","*.rules"),("All files","*.*")))
    seledRlF.set(openRlFLoc)

def clrTreeVRl():
    for row in treeViewRl.get_children():
        treeViewRl.delete(row)

def rRlF():
    try:
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
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid rule file.")

def reloadRl():
    clrTreeVRl()
    rRlF()

def enaRl():
    global seledRlLnNo
    intSeledRlLnNo=int(seledRlLnNo)-1
    try:
        with open(seledRlF.get(),"r+") as rF:
            readlines=rF.readlines()
            readlines[intSeledRlLnNo]=re.sub("#","",readlines[intSeledRlLnNo],count=1)
        with open(seledRlF.get(),"w+") as wF:
            wF.writelines(readlines)
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid rule file.")
    else:
        tkMessageBox.showinfo("Information","The rule was successfully enabled.\nThe Snort service needs to restart to finish changes.")
    reloadRl()

def disaRl():
    global seledRlLnNo
    intSeledRlLnNo=int(seledRlLnNo)-1
    try:
        with open(seledRlF.get(),"r+") as rF:
            readlines=rF.readlines()
        if re.match("\s*#+\s*",readlines[intSeledRlLnNo])!=None:
            pass
        else:
            with open(seledRlF.get(),"w+") as wF:
                readlines[intSeledRlLnNo]="#"+readlines[intSeledRlLnNo]
                wF.writelines(readlines)
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid rule file.")
    else:
        tkMessageBox.showinfo("Information","The rule was successfully disabled.\nThe Snort service needs to restart to finish changes.")
    reloadRl()

def addRl():
    clrTreeVRl()
    try:
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
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid rule file.")
    else:
        tkMessageBox.showinfo("Information","The rule was successfully added to the rule file.\nThe Snort service needs to restart to finish changes.")
    rRlF()

def aRlTLvl():
    ToplevelaRl=Tkinter.Toplevel()
    ToplevelaRl.title("Rule adding - Snort IDS GUI")
    ToplevelaRl.grid_columnconfigure(0,weight=1)
    ToplevelaRl.grid_rowconfigure(0,weight=1)

    labelFrameARl=ttk.Labelframe(ToplevelaRl,text="Rule adding")
    labelFrameARl.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelFrameARl.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelFrameARl.grid_columnconfigure(0,weight=1)
    labelFrameARl.grid_columnconfigure(1,weight=1)
    labelFrameARl.grid_rowconfigure(0,weight=1)
    labelFrameARl.grid_rowconfigure(1,weight=1)
    labelFrameARl.grid_rowconfigure(2,weight=1)
    labelFrameARl.grid_rowconfigure(3,weight=1)
    labelFrameARl.grid_rowconfigure(4,weight=1)
    labelFrameARl.grid_rowconfigure(5,weight=1)
    labelFrameARl.grid_rowconfigure(6,weight=1)
    labelFrameARl.grid_rowconfigure(7,weight=1)
    labelFrameARl.grid_rowconfigure(8,weight=1)
    labelFrameARl.grid_rowconfigure(9,weight=1)
    labelFrameARl.grid_rowconfigure(10,weight=1)
    labelFrameARl.grid_rowconfigure(11,weight=1)
    labelFrameARl.grid_rowconfigure(12,weight=1)
    labelFrameARl.grid_rowconfigure(13,weight=1)
    labelFrameARl.grid_rowconfigure(14,weight=1)
    labelFrameARl.grid_rowconfigure(15,weight=1)
    labelFrameARl.grid_rowconfigure(16,weight=1)
    labelFrameARl.grid_rowconfigure(17,weight=1)
    labelFrameARl.grid_rowconfigure(18,weight=1)

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

def edRl():
    global seledRlLnNo
    intSeledRlLnNo=int(seledRlLnNo)-1
    try:
        with open(seledRlF.get(),"r+") as rF:
            readlines=rF.readlines()
            nRl=["\n"]
            if seledActn.get() != "":
                nRl.insert(len(nRl),seledActn.get())
            if seledProt.get() != "":
                nRl.insert(len(nRl),seledProt.get())
            if seledSrcIPAdd.get() != "":
                nRl.insert(len(nRl),seledSrcIPAdd.get())
            if seledSrcPtNo.get() != "":
                nRl.insert(len(nRl),seledSrcPtNo.get())
            if seledDirOpr.get() != "":
                nRl.insert(len(nRl),seledDirOpr.get())
            if seledDestIPAdd.get() != "":
                nRl.insert(len(nRl),seledDestIPAdd.get())
            if seledDestPtNo.get() != "":
                nRl.insert(len(nRl),seledDestPtNo.get())
            if seledMsg.get() != "" or seledRefIdSys.get() != "" or seledGId.get() != "" or seledGId.get() != "" or seledRev.get() != "" or seledClTp.get() != "" or seledPri.get() != "":
                nRl.insert(len(nRl),"(")
            if seledMsg.get() != "":
                fSeledMsg="msg:\""+seledMsg.get()+"\";"
                nRl.insert(len(nRl),fSeledMsg)
            if seledRefIdSys.get() != "" and seledRefId.get() != "":
                fSeledRefIdSys="reference:"+seledRefIdSys.get()+","
                nRl.insert(len(nRl),fSeledRefIdSys)
                fSeledRefId=seledRefId.get()+";"
                nRl.insert(len(nRl),fSeledRefId)
            if seledGId.get() != "":
                fSeledGId="gid:"+seledGId.get()+";"
                nRl.insert(len(nRl),fSeledGId)
            if seledSId.get() != "":
                fSeledSId="sid:"+seledSId.get()+";"
                nRl.insert(len(nRl),fSeledSId)
            if seledRev.get() != "":
                fSeledRev="rev:"+seledRev.get()+";"
                nRl.insert(len(nRl),fSeledRev)
            if seledClTp.get() != "":
                fSeledClTp="classtype:"+seledClTp.get()+";"
                nRl.insert(len(nRl),fSeledClTp)
            if seledPri.get() != "":
                fSeledPri="priority:"+seledPri.get()+";"
                nRl.insert(len(nRl),fSeledPri)
            if seledMsg.get() != "" or seledRefIdSys.get() != "" or seledGId.get() != "" or seledSId.get() != "" or seledRev.get() != "" or seledClTp.get() != "" or seledPri.get() != "":
                nRl.insert(len(nRl),")")
            nRl.insert(len(nRl),"\n")
            readlines[intSeledRlLnNo]=" ".join(nRl)
        with open(seledRlF.get(),"w+") as wF:
            wF.writelines(readlines)
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid rule file.")
    else:
        tkMessageBox.showinfo("Information","The rule was successfully edited into the rules file.\nThe Snort service needs to restart to finish changes.")
    reloadRl()

def treeviewClick(event):
    for item in treeViewRl.selection():
        global seledRlLnNo
        itemLs=treeViewRl.item(item,"values")
        seledRlLnNo=itemLs[0]
        seledActn.set(itemLs[2])
        seledProt.set(itemLs[3])
        seledSrcIPAdd.set(itemLs[4])
        seledSrcPtNo.set(itemLs[5])
        seledDirOpr.set(itemLs[6])
        seledDestIPAdd.set(itemLs[7])
        seledDestPtNo.set(itemLs[8])
        seledMsg.set(itemLs[9])
        seledRefIdSys.set(itemLs[10])
        seledRefId.set(itemLs[11])
        seledGId.set(itemLs[12])
        seledSId.set(itemLs[13])
        seledRev.set(itemLs[14])
        seledClTp.set(itemLs[15])
        seledPri.set(itemLs[16])
    return seledRlLnNo

def netVarHelpTLvl():
    toplevelNetVarHelp=Tkinter.Toplevel()
    toplevelNetVarHelp.title("Help - Snort IDS GUI")

    labelFrameIPNPtLs=ttk.Labelframe(toplevelNetVarHelp,text="IP and Port lists")
    labelFrameIPNPtLs.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    textIPNPtLs=ScrolledText.ScrolledText(labelFrameIPNPtLs)
    textIPNPtLs.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    try:
        with open("/usr/local/share/doc/snort/README.variables","r")as logF:
            textIPNPtLs.insert(Tkinter.INSERT,logF.read())
    except:
        tkMessageBox.showerror("Error","Unable to open the description file.")

    buttonNetVarHelpTLvl=ttk.Button(labelFrameIPNPtLs,text="Close",command=toplevelNetVarHelp.destroy)
    buttonNetVarHelpTLvl.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

def askCfgFLoc():
    openCfgFLoc=tkFileDialog.askopenfilename(initialdir="/etc/snort/",title="Select configuration file",filetypes=(("Configuration files","*.conf"),("All files","*.*")))
    seledCfgF.set(openCfgFLoc)

def loadCfg():
    try:
        with open(seledCfgF.get(),"r") as rF:
            for line in rF.readlines():
                if re.match("ipvar HOME_NET .*",line):
                    homeNetAdd.set(re.sub("\n","",re.sub("ipvar HOME_NET ","",line)))
                if re.match("ipvar EXTERNAL_NET .*",line):
                    extNetAdd.set(re.sub("\n","",re.sub("ipvar EXTERNAL_NET ","",line)))
                if re.match("ipvar DNS_SERVERS .*",line):
                    dnsSIpAdd.set(re.sub("\n","",re.sub("ipvar DNS_SERVERS ","",line)))
                if re.match("ipvar SMTP_SERVERS .*",line):
                    smtpSAdd.set(re.sub("\n","",re.sub("ipvar SMTP_SERVERS ","",line)))
                if re.match("ipvar HTTP_SERVERS .*",line):
                    httpSAdd.set(re.sub("\n","",re.sub("ipvar HTTP_SERVERS ","",line)))
                if re.match("ipvar SQL_SERVERS .*",line):
                    sqlSAdd.set(re.sub("\n","",re.sub("ipvar SQL_SERVERS ","",line)))
                if re.match("ipvar TELNET_SERVERS .*",line):
                    telnetSAdd.set(re.sub("\n","",re.sub("ipvar TELNET_SERVERS ","",line)))
                if re.match("ipvar SSH_SERVERS .*",line):
                    sshSAdd.set(re.sub("\n","",re.sub("ipvar SSH_SERVERS ","",line)))
                if re.match("ipvar FTP_SERVERS .*",line):
                    ftpSAdd.set(re.sub("\n","",re.sub("ipvar FTP_SERVERS ","",line)))
                if re.match("ipvar SIP_SERVERS .*",line):
                    sipSAdd.set(re.sub("\n","",re.sub("ipvar SIP_SERVERS ","",line)))
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid configuration file.")
                
def svNetVar():
    try:
        with open(seledCfgF.get(),"r+") as rF:
            readlines=rF.readlines()
            lnNo=0
            for line in readlines:
                if re.match("ipvar HOME_NET .*",line):
                    newHomeNetAdd="ipvar HOME_NET "+homeNetAdd.get()
                    readlines[lnNo]=re.sub("ipvar HOME_NET .*",newHomeNetAdd,line)
                elif re.match("ipvar EXTERNAL_NET .*",line):
                    newExtNetAdd="ipvar EXTERNAL_NET "+extNetAdd.get()
                    readlines[lnNo]=re.sub("ipvar EXTERNAL_NET .*",newExtNetAdd,line)
                elif re.match("ipvar DNS_SERVERS .*",line):
                    newDnsSIpAdd="ipvar DNS_SERVERS "+dnsSIpAdd.get()
                    readlines[lnNo]=re.sub("ipvar DNS_SERVERS .*",newDnsSIpAdd,line)
                elif re.match("ipvar SMTP_SERVERS .*",line):
                    newSmtpSAdd="ipvar SMTP_SERVERS "+smtpSAdd.get()
                    readlines[lnNo]=re.sub("ipvar SMTP_SERVERS .*",newSmtpSAdd,line)
                elif re.match("ipvar HTTP_SERVERS .*",line):
                    newHttpSAdd="ipvar HTTP_SERVERS "+httpSAdd.get()
                    readlines[lnNo]=re.sub("ipvar HTTP_SERVERS .*",newHttpSAdd,line)
                elif re.match("ipvar SQL_SERVERS .*",line):
                    newSqlSAdd="ipvar SQL_SERVERS "+sqlSAdd.get()
                    readlines[lnNo]=re.sub("ipvar SQL_SERVERS .*",newSqlSAdd,line)
                elif re.match("ipvar TELNET_SERVERS .*",line):
                    newTelnetSAdd="ipvar TELNET_SERVERS "+telnetSAdd.get()
                    readlines[lnNo]=re.sub("ipvar TELNET_SERVERS .*",newTelnetSAdd,line)
                elif re.match("ipvar SSH_SERVERS .*",line):
                    newSshSAdd="ipvar SSH_SERVERS "+sshSAdd.get()
                    readlines[lnNo]=re.sub("ipvar SSH_SERVERS .*",newSshSAdd,line)
                elif re.match("ipvar FTP_SERVERS .*",line):
                    newFtpSAdd="ipvar FTP_SERVERS "+ftpSAdd.get()
                    readlines[lnNo]=re.sub("ipvar FTP_SERVERS .*",newFtpSAdd,line)
                elif re.match("ipvar SIP_SERVERS .*",line):
                    newSipSAdd="ipvar SIP_SERVERS "+sipSAdd.get()
                    readlines[lnNo]=re.sub("ipvar SIP_SERVERS .*",newSipSAdd,line)
                lnNo=lnNo+1
        with open(seledCfgF.get(),"w+") as wF:
            wF.writelines(readlines)
    except IOError:
        tkMessageBox.showerror("Error","No such file. Please enter or select a valid configuration file.")
    else:
        tkMessageBox.showinfo("Information","The new variable is successfully saved in the configuration file.\nThe Snort service needs to restart to finish changes.")
    
def acidtable():
    connection=MySQLdb.connect(host="localhost",user="root",passwd="MySqlROOTpassword",db="snort")
    cursor=connection.cursor()
    cursor.execute("create or replace view acid1_event(sid,cid,signature,sig_name,timestamp,ip_src,ip_dst,ip_proto) As select iphdr.sid,iphdr.cid,event.signature,signature.sig_name,event.timestamp,iphdr.ip_src,iphdr.ip_dst,iphdr.ip_proto from iphdr,event,signature where iphdr.sid=event.sid and iphdr.cid=event.cid and event.signature=signature.sig_id")

def shwAlert():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()
    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), (CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event ORDER BY cid DESC"
    cursor.execute(sql)
    data=cursor.fetchall()
    for row in data:
        treeviewAlert.insert("","end",values=row)

def lsAlerttcp():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst),(CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE ip_proto = 6 ORDER BY cid DESC" 
    cursor.execute(sql)
    data=cursor.fetchall()

    for row in data:
        treeviewAlert.insert("","end",values = row)

def lsAlerticmp():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), (CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE ip_proto = 1 ORDER BY cid DESC"
    cursor.execute(sql)
    data=cursor.fetchall()

    for row in data:
        treeviewAlert.insert("","end",values = row)

def lsAlertudp():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), (CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE ip_proto = 17 ORDER BY cid DESC"
    cursor.execute(sql)
    data=cursor.fetchall()

    for row in data:
        treeviewAlert.insert("","end",values = row)

def lsAlert7hours():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), (CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE timestamp >= Date_SUB(NOW(), INTERVAL 7 HOUR) ORDER BY cid DESC"
    cursor.execute(sql)
    data=cursor.fetchall()

    
    for row in data:
        treeviewAlert.insert("","end",values = row)

def lsAlert30days():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), (CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY) ORDER BY cid DESC"
    cursor.execute(sql)
    data=cursor.fetchall()

    
    for row in data:
        treeviewAlert.insert("","end",values = row)

def lsAlert1year():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sql="SELECT sid, cid, signature, sig_name, timestamp, inet_ntoa(ip_src), inet_ntoa(ip_dst), (CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 YEAR) ORDER BY cid DESC"
    cursor.execute(sql)
    data=cursor.fetchall()

    
    for row in data:
        treeviewAlert.insert("","end",values = row)

def lsAlertFilter():
    treeviewAlert.delete(*treeviewAlert.get_children())
    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
    cursor=connection.cursor()

    sidque = ""
    sigque = ""
    signameque = ""
    srcque = ""
    dstque = ""
    dateque = ""
    proque = ""

    try:
        if lssid.get() != ""  :
            value = int(lssid.get())
            sidque = str("AND sid LIKE '"+lssid.get()+"'")
            print sidque
    except ValueError:
        tkMessageBox.showerror("Error","Not Integer")
    
    try:
        if lssignature.get() !="":
            value = int(lssingature.get())
            sigque = str("AND signature LIKE '"+lssignature.get()+"'")
    except ValueError:
        tkMessageBox.showerror("Error","Not Integer")
        
    if lssigname.get() !="":
        signameque = str("AND sig_name LIKE '%"+lssigname.get()+"%'")
        
    if lsipsrc.get() !="":
        srcque = str("AND ip_src LIKE inet_aton('"+lsipsrc.get()+"')")
        print srcque
    if lsipdst.get() !="":
        dstque = str("AND ip_dst LIKE inet_aton('"+lsipdst.get()+"')")
        
    try:
        if lssdatey.get() !=0 and lssdatem.get() !=0 and lssdated.get() !=0 and lsedatey.get() !=0 and lsedatem.get() !=0 and lsedated.get() !=0 :
            start = datetime.datetime(lssdatey.get(),lssdatem.get(),lssdated.get()).strftime('%Y-%m-%d %H:%M:%S')
            end = datetime.datetime(lsedatey.get(),lsedatem.get(),lsedated.get()).strftime('%Y-%m-%d %H:%M:%S')
            dateque = str ("AND timestamp between '"+start+"' AND '"+end+"'")
    except ValueError:
        tkMessageBox.showerror("Error","Not Integer")
        
    if lsipproto.get() !="":
        proque = str("AND ip_proto LIKE (CASE '%"+lsipproto.get()+"%' WHEN '%ICMP%' THEN '1' WHEN '%TCP%' THEN '6'  WHEN '%UDP%' THEN '17' ELSE '%"+lsipproto.get()+"%' END)" )

    sql =("SELECT sid,cid,signature,sig_name,timestamp,inet_ntoa(ip_src), inet_ntoa(ip_dst),(CASE ip_proto WHEN '1' THEN 'ICMP' WHEN '6' THEN 'TCP' WHEN '17' THEN 'UDP' ELSE acid1_event.ip_proto END) as ip_proto FROM acid1_event WHERE cid >=1 %s %s %s %s %s %s %s ORDER BY cid DESC")%(sidque,sigque,signameque,srcque,dstque,dateque,proque)
    cursor.execute(sql)
    data=cursor.fetchall()
    print sql
    for row in data:
        treeviewAlert.insert("","end",values = row)

#def mysql_graph():
#    connection=MySQLdb.connect(host="localhost",user="snort",passwd="MySqlSNORTpassword",db="snort")
#    cursor=connection.cursor()
#    sql="SELECT * FROM event"
#    cursor.execute(sql)
#    data=cursor.fetchall()
#    df=pandas.DataFrame(list(data),columns=["sid","cid","signature","timestamp"])
#    w=df.sid
#    x=df.cid
#    y=df.signature
#    z=df.timestamp
#    matplotlib.pyplot.title("Signature event happen time",fontsize=24)
#    matplotlib.pyplot.scatter(w,x,y,z)
#    matplotlib.pyplot.xlabel("SID")
#    matplotlib.pyplot.ylabel("CID")
#    matplotlib.pyplot.tick_params(axis="both",which="major",labelsize=14)

def edRlTLvl():
    ToplevelEdRl=Tkinter.Toplevel()
    ToplevelEdRl.title("Rule edit - Snort IDS GUI")
    ToplevelEdRl.grid_columnconfigure(0,weight=1)
    ToplevelEdRl.grid_rowconfigure(0,weight=1)
    
    labelFrameEdRl=ttk.Labelframe(ToplevelEdRl,text="Rule editing")
    labelFrameEdRl.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelFrameEdRl.grid_columnconfigure(0,weight=1)
    labelFrameEdRl.grid_columnconfigure(1,weight=1)
    labelFrameEdRl.grid_rowconfigure(0,weight=1)
    labelFrameEdRl.grid_rowconfigure(1,weight=1)
    labelFrameEdRl.grid_rowconfigure(2,weight=1)
    labelFrameEdRl.grid_rowconfigure(3,weight=1)
    labelFrameEdRl.grid_rowconfigure(4,weight=1)
    labelFrameEdRl.grid_rowconfigure(5,weight=1)
    labelFrameEdRl.grid_rowconfigure(6,weight=1)
    labelFrameEdRl.grid_rowconfigure(7,weight=1)
    labelFrameEdRl.grid_rowconfigure(8,weight=1)
    labelFrameEdRl.grid_rowconfigure(9,weight=1)
    labelFrameEdRl.grid_rowconfigure(10,weight=1)
    labelFrameEdRl.grid_rowconfigure(11,weight=1)
    labelFrameEdRl.grid_rowconfigure(12,weight=1)
    labelFrameEdRl.grid_rowconfigure(13,weight=1)
    labelFrameEdRl.grid_rowconfigure(14,weight=1)
    labelFrameEdRl.grid_rowconfigure(15,weight=1)
    labelFrameEdRl.grid_rowconfigure(16,weight=1)
    labelFrameEdRl.grid_rowconfigure(17,weight=1)
    labelFrameEdRl.grid_rowconfigure(18,weight=1)
    
    labelEdActn=ttk.Label(labelFrameEdRl,text="Action:")
    labelEdActn.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdActn=ttk.Combobox(labelFrameEdRl,textvariable=seledActn)
    comboboxEdActn["values"]=("alert","log","pass","activate","dynamic","drop","reject","sdrop")
    comboboxEdActn.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdProt=ttk.Label(labelFrameEdRl,text="Protocol:")
    labelEdProt.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdProt=ttk.Combobox(labelFrameEdRl,textvariable=seledProt)
    comboboxEdProt["values"]=("tcp","icmp","udp","ip")
    comboboxEdProt.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdSrcIPAdd=ttk.Label(labelFrameEdRl,text="Source IP Address:")
    labelEdSrcIPAdd.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdSrcIPAdd=ttk.Combobox(labelFrameEdRl,textvariable=seledSrcIPAdd)
    comboboxEdSrcIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
    comboboxEdSrcIPAdd.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdSrcPtNo=ttk.Label(labelFrameEdRl,text="Source Port Number:")
    labelEdSrcPtNo.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdSrcPtNo=ttk.Combobox(labelFrameEdRl,textvariable=seledSrcPtNo)
    comboboxEdSrcPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
    comboboxEdSrcPtNo.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdDirOpr=ttk.Label(labelFrameEdRl,text="Direction Operator:")
    labelEdDirOpr.grid(column=0,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdDirOpr=ttk.Combobox(labelFrameEdRl,textvariable=seledDirOpr)
    comboboxEdDirOpr["values"]=("->","<>")
    comboboxEdDirOpr.grid(column=1,row=5,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdDestIPAdd=ttk.Label(labelFrameEdRl,text="Destination IP Address:")
    labelEdDestIPAdd.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdDestIPAdd=ttk.Combobox(labelFrameEdRl,textvariable=seledDestIPAdd)
    comboboxEdDestIPAdd["values"]=("any","$HOME_NET","$EXTERNAL_NET","$DNS_SERVERS","$SMTP_SERVERS","$HTTP_SERVERS","$SQL_SERVERS","$TELNET_SERVERS","$SSH_SERVERS","$FTP_SERVERS","$SIP_SERVERS")
    comboboxEdDestIPAdd.grid(column=1,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdDestPtNo=ttk.Label(labelFrameEdRl,text="Destination Port Number:")
    labelEdDestPtNo.grid(column=0,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdDestPtNo=ttk.Combobox(labelFrameEdRl,textvariable=seledDestPtNo)
    comboboxEdDestPtNo["values"]=("any","$HTTP_PORTS","$SHELLCODE_PORTS","$ORACLE_PORTS","$SSH_PORTS","$FTP_PORTS","$SIP_PORTS","$FILE_DATA_PORTS","$GTP_PORTS")
    comboboxEdDestPtNo.grid(column=1,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

    separatorEd=ttk.Separator(labelFrameEdRl)
    separatorEd.grid(column=0,row=8,columnspan=2,sticky=Tkinter.E+Tkinter.W)
    
    labelEdMsg=ttk.Label(labelFrameEdRl,text="Message:")
    labelEdMsg.grid(column=0,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdMsg=ttk.Entry(labelFrameEdRl,textvariable=seledMsg)
    entryEdMsg.grid(column=1,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdRefIdSys=ttk.Label(labelFrameEdRl,text="Reference ID System:")
    labelEdRefIdSys.grid(column=0,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdRefIdSys=ttk.Combobox(labelFrameEdRl,textvariable=seledRefIdSys)
    comboboxEdRefIdSys["values"]=("bugtraq","cve","nessus","arachnids","mcafee","osvdb","msb","url")
    comboboxEdRefIdSys.grid(column=1,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdRefId=ttk.Label(labelFrameEdRl,text="Reference ID:")
    labelEdRefId.grid(column=0,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdRefId=ttk.Entry(labelFrameEdRl,textvariable=seledRefId)
    entryEdRefId.grid(column=1,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdGId=ttk.Label(labelFrameEdRl,text="GID:")
    labelEdGId.grid(column=0,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdGId=ttk.Entry(labelFrameEdRl,textvariable=seledGId)
    entryEdGId.grid(column=1,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdSId=ttk.Label(labelFrameEdRl,text="SID:")
    labelEdSId.grid(column=0,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdSId=ttk.Entry(labelFrameEdRl,textvariable=seledSId)
    entryEdSId.grid(column=1,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdRev=ttk.Label(labelFrameEdRl,text="Revision:")
    labelEdRev.grid(column=0,row=14,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    entryEdRev=ttk.Entry(labelFrameEdRl,textvariable=seledRev)
    entryEdRev.grid(column=1,row=14,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdClTp=ttk.Label(labelFrameEdRl,text="Class Type:")
    labelEdClTp.grid(column=0,row=15,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)
    
    comboboxEdClTp=ttk.Combobox(labelFrameEdRl,textvariable=seledClTp)
    comboboxEdClTp["values"]=("attempted-admin","attempted-user","inappropriate-content","policy-violation","shellcode-detect","successful-admin","successful-user","trojan-activity","unsuccessful-user","web-application-attack","attempted-dos","attempted-recon","bad-unknown","default-login-attempt","denial-of-service","misc-attack","non-standard-protocol","rpc-portmap-decode","successful-dos","successful-recon-largescale","successful-recon-limited","suspicious-filename-detect","suspicious-login","system-call-detect","unusual-client-port-connection","web-application-activity","icmp-event","misc-activity","network-scan","not-suspicious","protocol-command-decode","string-detect","unknown","tcp-connection")
    comboboxEdClTp.grid(column=1,row=15,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)
    
    labelEdPri=ttk.Label(labelFrameEdRl,text="Priority:")
    labelEdPri.grid(column=0,row=16,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

    entryEdPri=ttk.Entry(labelFrameEdRl,textvariable=seledPri)
    entryEdPri.grid(column=1,row=16,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

    separatorEd=ttk.Separator(labelFrameEdRl)
    separatorEd.grid(column=0,row=17,columnspan=2,sticky=Tkinter.E+Tkinter.W)

    buttonEdRl=ttk.Button(labelFrameEdRl,text="Edit rule",command=edRl)
    buttonEdRl.grid(column=0,row=18,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

def loadPulledPorkcfg():
    try:
        with open("/etc/snort/pulledpork.conf","r") as rF:
            for line in rF.readlines():
                if re.match("\s*rule_url=https:\/\/www.snort.org\/reg-rules\/\|snortrules-snapshot.tar.gz\|.*",line):
                    snortVRTRl.set(1)
                if re.match("\s*#*\s*rule_url=https:\/\/www.snort.org\/reg-rules\/\|snortrules-snapshot.tar.gz\|.*",line):
                    snortOinkMaC.set(re.sub("\n","",re.sub("\s*#*\s*rule_url=https:\/\/www.snort.org\/reg-rules\/\|snortrules-snapshot.tar.gz\|","",line)))
                if re.match("\s*rule_url=https:\/\/snort.org\/downloads\/community\/\|community-rules.tar.gz\|Community",line):
                    snortCmtyRl.set(1)
                if re.match("\s*rule_url=https:\/\/rules.emergingthreats.net\/\|emerging.rules.tar.gz\|open-nogpl",line):
                    eTOpRl.set(1)
                if re.match("\s*rule_url=https:\/\/rules.emergingthreatspro.com\/\|etpro.rules.tar.gz\|.*",line):
                    eTProRl.set(1)
                if re.match("\s*#*\s*rule_url=https:\/\/rules.emergingthreatspro.com\/\|etpro.rules.tar.gz\|.*",line):
                    eTProOinkMaC.set(re.sub("\n","",re.sub("\s*#*\s*rule_url=https:\/\/rules.emergingthreatspro.com\/\|etpro.rules.tar.gz\|","",line)))

    except IOError:
        tkMessageBox.showerror("Error","No such Pulled Pork configuration file.")
        
def pasSnortOinkMaC():
    snortOinkMaC.set(root.clipboard_get())

def pasETProOinkMaC():
    eTProOinkMaC.set(root.clipboard_get())

def svPulledPorkcfg():
    try:
        with open("/etc/snort/pulledpork.conf","r+") as rF:
            readlines=rF.readlines()
            lnNo=0
            for line in readlines:
                if re.match("\s*#*\s*rule_url=https:\/\/www.snort.org\/reg-rules\/\|snortrules-snapshot.tar.gz\|.*",line):
                    if snortVRTRl.get()==1:
                        nSnortVRTRl="rule_url=https://www.snort.org/reg-rules/|snortrules-snapshot.tar.gz|"+snortOinkMaC.get()
                    else:
                        nSnortVRTRl="#rule_url=https://www.snort.org/reg-rules/|snortrules-snapshot.tar.gz|"+snortOinkMaC.get()
                    readlines[lnNo]=re.sub("\s*#*\s*rule_url=https:\/\/www.snort.org\/reg-rules\/\|snortrules-snapshot.tar.gz\|.*",nSnortVRTRl,line)
                elif re.match("\s*#*\s*rule_url=https:\/\/snort.org\/downloads\/community\/\|community-rules.tar.gz\|Community",line):
                    if snortCmtyRl.get()==1:
                        nSnortCmtyRl="rule_url=https://snort.org/downloads/community/|community-rules.tar.gz|Community"
                    else:
                        nSnortCmtyRl="#rule_url=https://snort.org/downloads/community/|community-rules.tar.gz|Community"
                    readlines[lnNo]=re.sub("\s*#*\s*rule_url=https:\/\/snort.org\/downloads\/community\/\|community-rules.tar.gz\|Community",nSnortCmtyRl,line)
                elif re.match("\s*#*\s*rule_url=https:\/\/rules.emergingthreats.net\/\|emerging.rules.tar.gz\|open-nogpl",line):
                    if eTOpRl.get()==1:
                        nETOpRl="rule_url=https://rules.emergingthreats.net/|emerging.rules.tar.gz|open-nogpl"
                    else:
                        nETOpRl="#rule_url=https://rules.emergingthreats.net/|emerging.rules.tar.gz|open-nogpl"
                    readlines[lnNo]=re.sub("\s*#*\s*rule_url=https:\/\/rules.emergingthreats.net\/\|emerging.rules.tar.gz\|open-nogpl",nETOpRl,line)
                elif re.match("\s*#*\s*rule_url=https:\/\/rules.emergingthreatspro.com\/\|etpro.rules.tar.gz\|.*",line):
                    if eTProRl.get()==1:
                        nETProRl="rule_url=https://rules.emergingthreatspro.com/|etpro.rules.tar.gz|"+eTProOinkMaC.get()
                    else:
                        nETProRl="#rule_url=https://rules.emergingthreatspro.com/|etpro.rules.tar.gz|"+eTProOinkMaC.get()
                    readlines[lnNo]=re.sub("\s*#*\s*rule_url=https:\/\/rules.emergingthreatspro.com\/\|etpro.rules.tar.gz\|.*",nETProRl,line)
                lnNo=lnNo+1
        with open("/etc/snort/pulledpork.conf","w+") as wF:
            wF.writelines(readlines)
    except IOError:
        tkMessageBox.showerror("Error","No such Pulled Pork configuration file.")
    else:
        tkMessageBox.showinfo("Information","The new setting is successfully saved in the configuration file.")
    loadPulledPorkcfg()

def rLastRlsetUdTm():
    with open("/var/log/sid_changes.log","r") as logF:
        logFLnLs=logF.readlines()
        try:
            labelUdRlSetTm.config(text=re.sub("\n","",re.sub("=-","",re.sub("-=End Changes Logged for ","",logFLnLs[len(logFLnLs)-1]))))
        except:
            labelUdRlSetTm.config(text="Unknown")

def udRlTLvl():
    ToplevelUdRl=Tkinter.Toplevel()
    ToplevelUdRl.title("Rule updating - Snort IDS GUI")
    ToplevelUdRl.grid_columnconfigure(0,weight=1)
    ToplevelUdRl.grid_rowconfigure(0,weight=1)

    labelFrameUdRlSetTLvl=ttk.Labelframe(ToplevelUdRl,text="Rule update")
    labelFrameUdRlSetTLvl.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    labelFrameUdRlSetTLvl.grid_columnconfigure(0,weight=1)
    labelFrameUdRlSetTLvl.grid_rowconfigure(0,weight=1)
    labelFrameUdRlSetTLvl.grid_rowconfigure(1,weight=1)
    labelFrameUdRlSetTLvl.grid_rowconfigure(2,weight=1)
    labelFrameUdRlSetTLvl.grid_rowconfigure(3,weight=1)

    labelUdStat=ttk.Label(labelFrameUdRlSetTLvl,text="Checking latest rule updates...")
    labelUdStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    progressbarUdRl=ttk.Progressbar(labelFrameUdRlSetTLvl)
    progressbarUdRl.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    progressbarUdRl.start()
    
    pulledPorkUdRl=subprocess.Popen("sudo  pulledpork.pl -c /etc/snort/pulledpork.conf -l",shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    stdout,stderr=pulledPorkUdRl.communicate()

    separatorUdRl=ttk.Separator(labelFrameUdRlSetTLvl)
    separatorUdRl.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
    
    labelPulledPorkO=ttk.Label(labelFrameUdRlSetTLvl,text=stdout,font=("Ubuntu Mono",))
    labelPulledPorkO.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    labelUdStat.config(text="The rule update has been done.")

    progressbarUdRl.stop()
    progressbarUdRl.config(value=100)
    
    rLastRlsetUdTm()

def udRl():
    udRlThread=threading.Thread(target=udRlTLvl)
    udRlThread.start()

def vLogTLvl():
    toplevelVLog=Tkinter.Toplevel()
    toplevelVLog.title("View log - Snort IDS GUI")

    labelFrameRlSetLog=ttk.Labelframe(toplevelVLog,text="Rule set log")
    labelFrameRlSetLog.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    textRlSetLog=ScrolledText.ScrolledText(labelFrameRlSetLog)
    textRlSetLog.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

    try:
        with open("/var/log/sid_changes.log", 'r') as logF:
            textRlSetLog.insert(Tkinter.INSERT,logF.read())
    except:
        tkMessageBox.showerror("Error","Unable to open the rule update log.")

    buttonClsVLogTLvl=ttk.Button(labelFrameRlSetLog,text="Close",command=toplevelVLog.destroy)
    buttonClsVLogTLvl.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

def clsVLogTLvl():
    toplevelVLog.destroy()

def clrLog():
    try:
        open("/var/log/sid_changes.log","w").close()
    except:
        tkMessageBox.showerror("Error","Unable to clean up log content.")
    else:
        tkMessageBox.showinfo("Information","Successfully cleaned up the log content.")

def shwSnortVer():
    snortVerOut=subprocess.Popen("snort -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    stdout,stderr=snortVerOut.communicate()
    labelFrameSnortInfoOut.config(text=stdout)

def oSnortOWeb():
    webbrowser.open("https://www.snort.org/")

def shwBarnyardVer():
    barnyardVerOut=subprocess.Popen("barnyard2 -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    stdout,stderr=barnyardVerOut.communicate()
    labelFrameBarnyardInfoOut.config(text=stdout)

def oBarnyardOWeb():
    webbrowser.open("https://www.securixlive.com/")

def oBarnyardGHWeb():
    webbrowser.open("https://github.com/firnsy/barnyard2/")

def oBarnyardOEMail():
    webbrowser.open("mailto:firnsy@securixlive.com")

def shwPulledPorkVer():
    verO=subprocess.Popen("pulledpork.pl -V",shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    stdout,stderr=verO.communicate()
    labelPulledPorkInfoOut.config(text=stdout)

def oPulledPorkGHWeb():
    webbrowser.open("https://github.com/shirkdog/pulledpork/")

root=Tkinter.Tk()
root.title("Snort Intrusion Detection System Graphical User Interface")
root.grid_columnconfigure(0,weight=1)
root.grid_rowconfigure(0,weight=1)
root.grid_rowconfigure(1,weight=99)

style=ttk.Style()
style.configure("restartSnort.TButton",font=("",),foreground="orange",background="gray1")
style.map("restartSnort.TButton",foreground=[('pressed','orange'),('active','orange')],background=[('pressed','gray20'),('active','gray10')])


appLoc=Tkinter.StringVar()
cfgLoc=Tkinter.StringVar()
netItf=Tkinter.StringVar()
execUsr=Tkinter.StringVar()
execGrp=Tkinter.StringVar()
optQtOp=Tkinter.IntVar()

seledRlF=Tkinter.StringVar(value="/etc/snort/rules/snort.rules")
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

seledActn=Tkinter.StringVar()
seledProt=Tkinter.StringVar()
seledSrcIPAdd=Tkinter.StringVar()
seledSrcPtNo=Tkinter.StringVar()
seledDirOpr=Tkinter.StringVar()
seledDestIPAdd=Tkinter.StringVar()
seledDestPtNo=Tkinter.StringVar()
seledMsg=Tkinter.StringVar()
seledRefIdSys=Tkinter.StringVar()
seledRefId=Tkinter.StringVar()
seledGId=Tkinter.StringVar()
seledSId=Tkinter.StringVar()
seledRev=Tkinter.StringVar()
seledClTp=Tkinter.StringVar()
seledPri=Tkinter.StringVar()

seledCfgF=Tkinter.StringVar(value="/etc/snort/snort.conf")
homeNetAdd=Tkinter.StringVar()
extNetAdd=Tkinter.StringVar()
dnsSIpAdd=Tkinter.StringVar()
smtpSAdd=Tkinter.StringVar()
httpSAdd=Tkinter.StringVar()
sqlSAdd=Tkinter.StringVar()
telnetSAdd=Tkinter.StringVar()
sshSAdd=Tkinter.StringVar()
ftpSAdd=Tkinter.StringVar()
sipSAdd=Tkinter.StringVar()

lssid=Tkinter.StringVar()
lssignature=Tkinter.StringVar()
lssigname=Tkinter.StringVar()
lsipsrc=Tkinter.StringVar()
lsipdst=Tkinter.StringVar()
lssdatey=Tkinter.IntVar()
lssdatey.set(2019)
lssdatem=Tkinter.IntVar()
lssdatem.set(1)
lssdated=Tkinter.IntVar()
lssdated.set(1)
lsedatey=Tkinter.IntVar()
lsedatey.set(2019)
lsedatem=Tkinter.IntVar()
lsedatem.set(1)
lsedated=Tkinter.IntVar()
lsedated.set(1)
lsipproto=Tkinter.StringVar()

snortVRTRl=Tkinter.IntVar()
snortOinkMaC=Tkinter.StringVar()
snortCmtyRl=Tkinter.IntVar()
eTOpRl=Tkinter.IntVar()
eTProRl=Tkinter.IntVar()
eTProOinkMaC=Tkinter.StringVar()

noteBookMain=ttk.Notebook(root)
noteBookMain.grid(column=0,row=1,columnspan=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
noteBookMain.grid_columnconfigure(0,weight=1)
noteBookMain.grid_rowconfigure(0,weight=1)

try:
    snortImg=PIL.ImageTk.PhotoImage(PIL.Image.open("snort.png"))
    labelSnortImg=ttk.Label(root,image=snortImg,anchor=Tkinter.CENTER,background="black")
    labelSnortImg.grid(column=0,row=0,ipadx=10,ipady=10,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
except:
    labelSnort=ttk.Label(root,text="Snort",font=("UKIJ Tughra",30),anchor=Tkinter.CENTER,foreground="orange",background="black")
    labelSnort.grid(column=0,row=0,ipadx=10,ipady=10,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonReload=ttk.Button(root,text="Restart Snort",command=restatAllSvc,style="restartSnort.TButton")
buttonReload.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

frameHome=ttk.Frame(noteBookMain)
frameHome.grid(column=0,row=0,padx=5,pady=5,ipadx=5,ipady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
frameHome.grid_columnconfigure(0,weight=1)
frameHome.grid_columnconfigure(1,weight=1)
frameHome.grid_rowconfigure(0,weight=1)
frameHome.grid_rowconfigure(1,weight=1)

labelFrameSnortStat=ttk.Labelframe(frameHome,text="Snort service Status")
labelFrameSnortStat.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameSnortStat.grid_columnconfigure(0,weight=1)
labelFrameSnortStat.grid_columnconfigure(1,weight=1)
labelFrameSnortStat.grid_rowconfigure(0,weight=1)
labelFrameSnortStat.grid_rowconfigure(1,weight=1)
labelFrameSnortStat.grid_rowconfigure(2,weight=1)
labelFrameSnortStat.grid_rowconfigure(3,weight=1)
labelFrameSnortStat.grid_rowconfigure(4,weight=1)
labelFrameSnortStat.grid_rowconfigure(5,weight=1)
labelFrameSnortStat.grid_rowconfigure(6,weight=1)

labelSnortStrtUTyp=ttk.Label(labelFrameSnortStat,text="Snort service startup type:")
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

buttonSnortDet=ttk.Button(labelFrameSnortStat,text="Show detail",command=snortSvcStatDetTLvl)
buttonSnortDet.grid(column=0,row=6,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

labelFrameBarnyardStat=ttk.Labelframe(frameHome,text="Barnyard service status")
labelFrameBarnyardStat.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameBarnyardStat.grid_columnconfigure(0,weight=1)
labelFrameBarnyardStat.grid_columnconfigure(1,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(0,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(1,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(2,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(3,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(4,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(5,weight=1)
labelFrameBarnyardStat.grid_rowconfigure(6,weight=1)

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
labelBarnyardSvcStat.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

labelStatBarnyardIsFledOut=ttk.Label(labelFrameBarnyardStat)
labelStatBarnyardIsFledOut.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

buttonStrtBarnyard=ttk.Button(labelFrameBarnyardStat,text="Start",command=barnyardStrtSvc)
buttonStrtBarnyard.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

buttonStBarnyard=ttk.Button(labelFrameBarnyardStat,text="Stop",command=barnyardStSvc)
buttonStBarnyard.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

separatorSecBarnyardStat=ttk.Separator(labelFrameBarnyardStat)
separatorSecBarnyardStat.grid(column=0,row=5,columnspan=2,sticky=Tkinter.E+Tkinter.W)

buttonSnortDet=ttk.Button(labelFrameBarnyardStat,text="Show detail",command=barnyardSvcStatDetTLvl)
buttonSnortDet.grid(column=0,row=6,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

labelFrameSetting=ttk.Labelframe(frameHome,text="Snort service configuration")
labelFrameSetting.grid(column=0,row=1,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameSetting.grid_columnconfigure(0,weight=1)
labelFrameSetting.grid_columnconfigure(1,weight=98)
labelFrameSetting.grid_columnconfigure(2,weight=1)
labelFrameSetting.grid_rowconfigure(0,weight=1)
labelFrameSetting.grid_rowconfigure(1,weight=1)
labelFrameSetting.grid_rowconfigure(2,weight=1)
labelFrameSetting.grid_rowconfigure(3,weight=1)
labelFrameSetting.grid_rowconfigure(4,weight=1)
labelFrameSetting.grid_rowconfigure(5,weight=1)
labelFrameSetting.grid_rowconfigure(6,weight=1)
labelFrameSetting.grid_rowconfigure(7,weight=1)
labelFrameSetting.grid_rowconfigure(8,weight=1)

labelAppLoc=ttk.Label(labelFrameSetting,text="Snort application:")
labelAppLoc.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryAppLoc=ttk.Entry(labelFrameSetting,textvariable=appLoc)
entryAppLoc.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonAskApp=ttk.Button(labelFrameSetting,text="Browse",command=askAppLoc)
buttonAskApp.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelCfgLoc=ttk.Label(labelFrameSetting,text="Snort configuration:")
labelCfgLoc.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryCfgLoc=ttk.Entry(labelFrameSetting,textvariable=cfgLoc)
entryCfgLoc.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonAskCfg=ttk.Button(labelFrameSetting,text="Browse",command=askCfgLoc)
buttonAskCfg.grid(column=2,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelNetItf=ttk.Label(labelFrameSetting,text="Monitoring interface:")
labelNetItf.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxNetItf=ttk.Combobox(labelFrameSetting,textvariable=netItf,values=netifaces.interfaces())
comboboxNetItf.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelUsr=ttk.Label(labelFrameSetting,text="Executive user:")
labelUsr.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryUsr=ttk.Combobox(labelFrameSetting,textvariable=execUsr,values=usrLs())
entryUsr.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelGrp=ttk.Label(labelFrameSetting,text="Executive group:")
labelGrp.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

entryGrp=ttk.Combobox(labelFrameSetting,textvariable=execGrp,values=grpLs())
entryGrp.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorSetting=ttk.Separator(labelFrameSetting)
separatorSetting.grid(column=0,row=5,columnspan=3,sticky=Tkinter.E+Tkinter.W)

labelQtOpOpt=ttk.Label(labelFrameSetting,text="Quiet operation option:")
labelQtOpOpt.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

checkButtonQtOp=ttk.Checkbutton(labelFrameSetting,variable=optQtOp,text="Do not log banner and initialization information to syslog")
checkButtonQtOp.grid(column=1,row=6,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.W)

separatorSetting=ttk.Separator(labelFrameSetting)
separatorSetting.grid(column=0,row=7,columnspan=3,sticky=Tkinter.E+Tkinter.W)

buttonSv=ttk.Button(labelFrameSetting,text="Save configuration",command=svSvcCfg)
buttonSv.grid(column=0,row=8,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E+Tkinter.W)

frameCfg=ttk.Frame(noteBookMain)
frameCfg.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
frameCfg.grid_columnconfigure(0,weight=1)
frameCfg.grid_rowconfigure(0,weight=1)
frameCfg.grid_rowconfigure(1,weight=99)

labelFrameCfgFSelion=ttk.Labelframe(frameCfg,text="Configuration file selection")
labelFrameCfgFSelion.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameCfgFSelion.grid_columnconfigure(0,weight=1)
labelFrameCfgFSelion.grid_columnconfigure(1,weight=98)
labelFrameCfgFSelion.grid_columnconfigure(2,weight=1)
labelFrameCfgFSelion.grid_rowconfigure(0,weight=1)
labelFrameCfgFSelion.grid_rowconfigure(1,weight=1)

labelCfgF=ttk.Label(labelFrameCfgFSelion,text="Configuration file:")
labelCfgF.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxCfgF=ttk.Combobox(labelFrameCfgFSelion,textvariable=seledCfgF)
comboboxCfgF["values"]=("/etc/snort/snort.rules")
comboboxCfgF.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonAskCfgF=ttk.Button(labelFrameCfgFSelion,text="Browse",command=askCfgFLoc)
buttonAskCfgF.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonReloadCfgF=ttk.Button(labelFrameCfgFSelion,text="Load configure",command=loadCfg)
buttonReloadCfgF.grid(column=0,row=1,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameNetVar=ttk.Labelframe(frameCfg,text="Network and server IP variable definitions")
labelFrameNetVar.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameNetVar.grid_columnconfigure(0,weight=1)
labelFrameNetVar.grid_columnconfigure(1,weight=98)
labelFrameNetVar.grid_columnconfigure(2,weight=1)
labelFrameNetVar.grid_rowconfigure(0,weight=1)
labelFrameNetVar.grid_rowconfigure(1,weight=1)
labelFrameNetVar.grid_rowconfigure(2,weight=1)
labelFrameNetVar.grid_rowconfigure(3,weight=1)
labelFrameNetVar.grid_rowconfigure(4,weight=1)
labelFrameNetVar.grid_rowconfigure(5,weight=1)
labelFrameNetVar.grid_rowconfigure(6,weight=1)
labelFrameNetVar.grid_rowconfigure(7,weight=1)
labelFrameNetVar.grid_rowconfigure(8,weight=1)
labelFrameNetVar.grid_rowconfigure(9,weight=1)
labelFrameNetVar.grid_rowconfigure(10,weight=1)
labelFrameNetVar.grid_rowconfigure(11,weight=1)
labelFrameNetVar.grid_rowconfigure(12,weight=1)
labelFrameNetVar.grid_rowconfigure(13,weight=1)
labelFrameNetVar.grid_rowconfigure(14,weight=1)
labelFrameNetVar.grid_rowconfigure(15,weight=1)

labelIPPptH=ttk.Label(labelFrameNetVar,text="IP variable example:")
labelIPPptH.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

labelIPPptE=ttk.Label(labelFrameNetVar,text="192.168.1.0/24")
labelIPPptE.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelIPPptH=ttk.Label(labelFrameNetVar,text="IP list example:")
labelIPPptH.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

labelIPPptE=ttk.Label(labelFrameNetVar,text="[192.168.1.1,192.168.2.0/24,![192.168.2.1,192.168.2.2]]")
labelIPPptE.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonVLog=ttk.Button(labelFrameNetVar,text="Help",command=netVarHelpTLvl)
buttonVLog.grid(column=2,row=0,rowspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorNetVarPpt=ttk.Separator(labelFrameNetVar)
separatorNetVarPpt.grid(column=0,row=2,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelHomeNet=ttk.Label(labelFrameNetVar,text="Home network address(es):")
labelHomeNet.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxHomeNet=ttk.Combobox(labelFrameNetVar,textvariable=homeNetAdd,values=["any","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","10.0.0.0/24","192.168.1.0/24"])
comboBoxHomeNet.grid(column=1,row=3,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelExtNet=ttk.Label(labelFrameNetVar,text="External network address(es):")
labelExtNet.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxExtNet=ttk.Combobox(labelFrameNetVar,textvariable=extNetAdd,values=["any","!$HOME_NET"])
comboBoxExtNet.grid(column=1,row=4,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorNetVarNet=ttk.Separator(labelFrameNetVar)
separatorNetVarNet.grid(column=0,row=5,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelDNSS=ttk.Label(labelFrameNetVar,text="DNS server address(es):")
labelDNSS.grid(column=0,row=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxDNSS=ttk.Combobox(labelFrameNetVar,textvariable=dnsSIpAdd,values=["$HOME_NET"])
comboBoxDNSS.grid(column=1,row=6,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSMTPS=ttk.Label(labelFrameNetVar,text="SMTP server address(es):")
labelSMTPS.grid(column=0,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxSMTPS=ttk.Combobox(labelFrameNetVar,textvariable=smtpSAdd,values=["$HOME_NET"])
comboBoxSMTPS.grid(column=1,row=7,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelHTTPS=ttk.Label(labelFrameNetVar,text="HTTP server address(es):")
labelHTTPS.grid(column=0,row=8,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxHTTPS=ttk.Combobox(labelFrameNetVar,textvariable=httpSAdd,values=["$HOME_NET"])
comboBoxHTTPS.grid(column=1,row=8,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSQLS=ttk.Label(labelFrameNetVar,text="SQL server address(es):")
labelSQLS.grid(column=0,row=9,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxSQLS=ttk.Combobox(labelFrameNetVar,textvariable=sqlSAdd,values=["$HOME_NET"])
comboBoxSQLS.grid(column=1,row=9,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelTelnetS=ttk.Label(labelFrameNetVar,text="Telnet server address(es):")
labelTelnetS.grid(column=0,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxTelnetS=ttk.Combobox(labelFrameNetVar,textvariable=telnetSAdd,values=["$HOME_NET"])
comboBoxTelnetS.grid(column=1,row=10,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSSHS=ttk.Label(labelFrameNetVar,text="SSH server address(es):")
labelSSHS.grid(column=0,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxSSHS=ttk.Combobox(labelFrameNetVar,textvariable=sshSAdd,values=["$HOME_NET"])
comboBoxSSHS.grid(column=1,row=11,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFTPS=ttk.Label(labelFrameNetVar,text="FTP server address(es):")
labelFTPS.grid(column=0,row=12,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxFTPS=ttk.Combobox(labelFrameNetVar,textvariable=ftpSAdd,values=["$HOME_NET"])
comboBoxFTPS.grid(column=1,row=12,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSIPS=ttk.Label(labelFrameNetVar,text="SIP server address(es):")
labelSIPS.grid(column=0,row=13,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboBoxSIPS=ttk.Combobox(labelFrameNetVar,textvariable=sipSAdd,values=["$HOME_NET"])
comboBoxSIPS.grid(column=1,row=13,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorNetVarS=ttk.Separator(labelFrameNetVar)
separatorNetVarS.grid(column=0,row=14,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonSvNetVar=ttk.Button(labelFrameNetVar,text="Save configuration",command=svNetVar)
buttonSvNetVar.grid(column=0,row=15,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameRl=ttk.Frame(noteBookMain)
frameRl.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
frameRl.grid_columnconfigure(0,weight=1)
frameRl.grid_rowconfigure(0,weight=1)
frameRl.grid_rowconfigure(1,weight=98)
frameRl.grid_rowconfigure(2,weight=1)

labelFrameRlFSelion=ttk.Labelframe(frameRl,text="Rule file selection")
labelFrameRlFSelion.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameRlFSelion.grid_columnconfigure(0,weight=1)
labelFrameRlFSelion.grid_columnconfigure(1,weight=100)
labelFrameRlFSelion.grid_columnconfigure(2,weight=1)
labelFrameRlFSelion.grid_rowconfigure(0,weight=1)
labelFrameRlFSelion.grid_rowconfigure(1,weight=1)

labelRlF=ttk.Label(labelFrameRlFSelion,text="Rule file:")
labelRlF.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.E)

comboboxRlF=ttk.Combobox(labelFrameRlFSelion,textvariable=seledRlF)
comboboxRlF["values"]=("/etc/snort/rules/snort.rules")
comboboxRlF.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonAskRlF=ttk.Button(labelFrameRlFSelion,text="Browse",command=askRlFLoc)
buttonAskRlF.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonReloadRlF=ttk.Button(labelFrameRlFSelion,text="Load rules",command=reloadRl)
buttonReloadRlF.grid(column=0,row=1,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameSeledFsRl=ttk.Labelframe(frameRl,text="Selected file's rule")
labelFrameSeledFsRl.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameSeledFsRl.grid_columnconfigure(0,weight=1)
labelFrameSeledFsRl.grid_rowconfigure(0,weight=1)

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
labelFrameRlActn.grid_columnconfigure(0,weight=1)
labelFrameRlActn.grid_columnconfigure(1,weight=1)
labelFrameRlActn.grid_columnconfigure(2,weight=1)
labelFrameRlActn.grid_columnconfigure(3,weight=1)
labelFrameRlActn.grid_columnconfigure(4,weight=1)
labelFrameRlActn.grid_rowconfigure(0,weight=1)

buttonARl=ttk.Button(labelFrameRlActn,text="Add rule",command=aRlTLvl)
buttonARl.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonEdRl=ttk.Button(labelFrameRlActn,text="Edit rule",command=edRlTLvl)
buttonEdRl.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorRlActn=ttk.Separator(labelFrameRlActn,orient=Tkinter.VERTICAL)
separatorRlActn.grid(column=2,row=0,sticky=Tkinter.N+Tkinter.S)

buttonEnaRl=ttk.Button(labelFrameRlActn,text="Enable rule",command=enaRl)
buttonEnaRl.grid(column=3,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonDisaRl=ttk.Button(labelFrameRlActn,text="Disable rule",command=disaRl)
buttonDisaRl.grid(column=4,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameAlert=ttk.Frame(noteBookMain)
frameAlert.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
frameAlert.grid_columnconfigure(0,weight=1)
frameAlert.grid_rowconfigure(0,weight=98)
frameAlert.grid_rowconfigure(1,weight=1)
frameAlert.grid_rowconfigure(2,weight=1)

labelFrameAlertLogE=ttk.Labelframe(frameAlert,text="Alert log entries")
labelFrameAlertLogE.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameAlertLogE.grid_columnconfigure(0,weight=1)
labelFrameAlertLogE.grid_rowconfigure(0,weight=1)

treeviewAlert=ttk.Treeview(labelFrameAlertLogE,columns=["sid","cid","signature","sig_name","timestamp","ip_src","ip_dst","ip_proto"],selectmode="browse",show="headings")
treeviewAlert.heading("sid",text="SID")
treeviewAlert.column("sid",width=30)
treeviewAlert.heading("cid",text="CID")
treeviewAlert.column("cid",width=50)
treeviewAlert.heading("signature",text="Signature")
treeviewAlert.column("signature",width=30)
treeviewAlert.heading("sig_name",text="Signature Name")
treeviewAlert.column("sig_name",width=200)
treeviewAlert.heading("timestamp",text="Timestamp")
treeviewAlert.column("timestamp",width=190)
treeviewAlert.heading("ip_src",text="Source Address")
treeviewAlert.column("ip_src",width=150)
treeviewAlert.heading("ip_dst",text="Destination Address")
treeviewAlert.column("ip_dst",width=150)
treeviewAlert.heading("ip_proto",text="Protocol")
treeviewAlert.column("ip_proto",width=40)
treeviewAlert.grid(column=0,row=0,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

scrollbarXAlert=ttk.Scrollbar(labelFrameAlertLogE,orient="horizontal",command=treeviewAlert.xview)
scrollbarXAlert.grid(column=0,row=1,sticky=Tkinter.E+Tkinter.W)

scrollbarYAlert=ttk.Scrollbar(labelFrameAlertLogE,command=treeviewAlert.yview)
scrollbarYAlert.grid(column=1,row=0,sticky=Tkinter.N+Tkinter.S)

treeviewAlert.config(xscrollcommand=scrollbarXAlert.set,yscrollcommand=scrollbarYAlert.set)

labelFrameAlertLogVSetting=ttk.Labelframe(frameAlert,text="Alert log view basic filter")
labelFrameAlertLogVSetting.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameAlertLogVSetting.grid_columnconfigure(0,weight=1)
labelFrameAlertLogVSetting.grid_columnconfigure(1,weight=1)
labelFrameAlertLogVSetting.grid_columnconfigure(2,weight=1)
labelFrameAlertLogVSetting.grid_columnconfigure(3,weight=1)
labelFrameAlertLogVSetting.grid_rowconfigure(0,weight=1)
labelFrameAlertLogVSetting.grid_rowconfigure(1,weight=1)
labelFrameAlertLogVSetting.grid_rowconfigure(2,weight=1)

buttonlsAlertall=ttk.Button(labelFrameAlertLogVSetting,text="All protocol",command=shwAlert)
buttonlsAlertall.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlerttcp=ttk.Button(labelFrameAlertLogVSetting,text="TCP only",command=lsAlerttcp)
buttonlsAlerttcp.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlertudp=ttk.Button(labelFrameAlertLogVSetting,text="UDP only",command=lsAlertudp)
buttonlsAlertudp.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlerticmp=ttk.Button(labelFrameAlertLogVSetting,text="ICMP only",command=lsAlerticmp)
buttonlsAlerticmp.grid(column=3,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorAlert=ttk.Separator(labelFrameAlertLogVSetting)
separatorAlert.grid(column=0,row=1,columnspan=4,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlert1month=ttk.Button(labelFrameAlertLogVSetting,text="Past 1 year",command=lsAlert1year)
buttonlsAlert1month.grid(column=0,row=2,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlert1month=ttk.Button(labelFrameAlertLogVSetting,text="Past 30 days",command=lsAlert30days)
buttonlsAlert1month.grid(column=2,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlert7hours=ttk.Button(labelFrameAlertLogVSetting,text="Past 7 hours",command=lsAlert7hours)
buttonlsAlert7hours.grid(column=3,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)


labelFrameFilter=ttk.Labelframe(frameAlert,text="Alert log view advanced filter")
labelFrameFilter.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameFilter.grid_columnconfigure(0,weight=1)
labelFrameFilter.grid_columnconfigure(1,weight=1)
labelFrameFilter.grid_columnconfigure(2,weight=1)
labelFrameFilter.grid_columnconfigure(3,weight=1)
labelFrameFilter.grid_columnconfigure(4,weight=1)
labelFrameFilter.grid_columnconfigure(5,weight=1)
labelFrameFilter.grid_rowconfigure(0,weight=1)
labelFrameFilter.grid_rowconfigure(1,weight=1)
labelFrameFilter.grid_rowconfigure(2,weight=1)
labelFrameFilter.grid_rowconfigure(3,weight=1)
labelFrameFilter.grid_rowconfigure(4,weight=1)
labelFrameFilter.grid_rowconfigure(5,weight=1)

labellssid=ttk.Label(labelFrameFilter,text="SID:")
labellssid.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylssid=ttk.Entry(labelFrameFilter,textvariable=lssid)
entrylssid.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellssignature=ttk.Label(labelFrameFilter,text="Signature:")
labellssignature.grid(column=2,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylssignature=ttk.Entry(labelFrameFilter,textvariable=lssignature)
entrylssignature.grid(column=3,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellssig_name=ttk.Label(labelFrameFilter,text="Signature name:")
labellssig_name.grid(column=4,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylssig_name=ttk.Entry(labelFrameFilter,textvariable=lssigname)
entrylssig_name.grid(column=5,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellsip_src=ttk.Label(labelFrameFilter,text="Source IP address:")
labellsip_src.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylsip_src=ttk.Entry(labelFrameFilter,textvariable=lsipsrc)
entrylsip_src.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellsip_dst=ttk.Label(labelFrameFilter,text="Destination IP address:")
labellsip_dst.grid(column=2,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylsip_dst=ttk.Entry(labelFrameFilter,textvariable=lsipdst)
entrylsip_dst.grid(column=3,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellsip_proto=ttk.Label(labelFrameFilter,text="Protocol:")
labellsip_proto.grid(column=4,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylsip_proto=ttk.Combobox(labelFrameFilter,textvariable=lsipproto,values=["TCP","UDP","ICMP"])
entrylsip_proto.grid(column=5,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellssdate=ttk.Label(labelFrameFilter,text="Date From:")
labellssdate.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylssdatey=Tkinter.Spinbox(labelFrameFilter,from_=1970,to=3000,textvariable=lssdatey)
entrylssdatey.grid(column=1,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

entrylssdatem=Tkinter.Spinbox(labelFrameFilter,from_=1,to=12,textvariable=lssdatem)
entrylssdatem.grid(column=2,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

entrylssdated=Tkinter.Spinbox(labelFrameFilter,from_=1,to=31,textvariable=lssdated)
entrylssdated.grid(column=3,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labellsedate=ttk.Label(labelFrameFilter,text="Date To:")
labellsedate.grid(column=0,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrylsedatey=Tkinter.Spinbox(labelFrameFilter,from_=1970,to=3000,textvariable=lsedatey)
entrylsedatey.grid(column=1,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

entrylsedatem=Tkinter.Spinbox(labelFrameFilter,from_=1,to=12,textvariable=lsedatem)
entrylsedatem.grid(column=2,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

entrylsedated=Tkinter.Spinbox(labelFrameFilter,from_=1,to=31,textvariable=lsedated)
entrylsedated.grid(column=3,row=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonlsAlertFilter=ttk.Button(labelFrameFilter,text="Filter",command=lsAlertFilter)
buttonlsAlertFilter.grid(column=0,row=4,columnspan=6,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

#frameGraph=ttk.Frame(noteBookMain)

#labelFrameGraph=ttk.Labelframe(frameGraph,text="Graph alert data")
#labelFrameGraph.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

#mysql_graph()
#matplotlib.pyplot.savefig("graph.png")
#img=PIL.Image.open("graph.png")
#graph=PIL.ImageTk.PhotoImage(img)
#graphlabel=Tkinter.Label(labelFrameGraph,image=graph)
#graphlabel.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameUd=ttk.Frame(noteBookMain)
frameUd.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
frameUd.grid_columnconfigure(0,weight=1)
frameUd.grid_rowconfigure(0,weight=1)
frameUd.grid_rowconfigure(1,weight=1)
frameUd.grid_rowconfigure(2,weight=1)

labelFrameRlSetUDSetting=ttk.Labelframe(frameUd,text="Rule set Update setting")
labelFrameRlSetUDSetting.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameRlSetUDSetting.grid_columnconfigure(0,weight=1)
labelFrameRlSetUDSetting.grid_columnconfigure(1,weight=98)
labelFrameRlSetUDSetting.grid_columnconfigure(2,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(0,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(1,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(2,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(3,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(4,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(5,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(6,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(7,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(8,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(9,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(10,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(11,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(12,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(13,weight=1)
labelFrameRlSetUDSetting.grid_rowconfigure(14,weight=1)

labelSnortVRT=ttk.Label(labelFrameRlSetUDSetting,text="Snort Vulnerability Research Team rules:")
labelSnortVRT.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

checkButtonEnaSnortVRT=ttk.Checkbutton(labelFrameRlSetUDSetting,variable=snortVRTRl,text="Enable download of Snort VRT free registered user or paid subscriber rules")
checkButtonEnaSnortVRT.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSnortOinkMaC=ttk.Label(labelFrameRlSetUDSetting,text="Snort oinkmaster code:")
labelSnortOinkMaC.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entrySnortOinkMaC=ttk.Entry(labelFrameRlSetUDSetting,textvariable=snortOinkMaC)
entrySnortOinkMaC.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonPasSnortOinkMaC=ttk.Button(labelFrameRlSetUDSetting,text="Paste",command=pasSnortOinkMaC)
buttonPasSnortOinkMaC.grid(column=2,row=1,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSnortOinkMaCPpt=ttk.Label(labelFrameRlSetUDSetting,text="Obtain a snort.org oinkmaster code and paste it here.")
labelSnortOinkMaCPpt.grid(column=1,row=2,ipadx=5,padx=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorSnortVRT=ttk.Separator(labelFrameRlSetUDSetting)
separatorSnortVRT.grid(column=0,row=3,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSnortGPL=ttk.Label(labelFrameRlSetUDSetting,text="Snort GPLv2 Community rules:")
labelSnortGPL.grid(column=0,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

checkButtonSnortGPL=ttk.Checkbutton(labelFrameRlSetUDSetting,variable=snortCmtyRl,text="Enable download of Snort GPLv2 community rules")
checkButtonSnortGPL.grid(column=1,row=4,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelSnortGPLPpt=ttk.Label(labelFrameRlSetUDSetting,text="The Snort Community ruleset is a GPLv2 VRT certified ruleset that is distributed free of charge without any VRT license restrictions.\nThis ruleset is updated daily and is a subset of the subscriber ruleset.")
labelSnortGPLPpt.grid(column=1,row=5,ipadx=5,padx=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorSnortGPL=ttk.Separator(labelFrameRlSetUDSetting)
separatorSnortGPL.grid(column=0,row=6,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelETOp=ttk.Label(labelFrameRlSetUDSetting,text="Emerging Threats Open rules:")
labelETOp.grid(column=0,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

checkButtonETOp=ttk.Checkbutton(labelFrameRlSetUDSetting,variable=eTOpRl,text="Enable download of Emerging Threats Open rules")
checkButtonETOp.grid(column=1,row=7,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelETOpPpt=ttk.Label(labelFrameRlSetUDSetting,text="ETOpen is an open source set of Snort rules whose coverage is more limited than ETPro.")
labelETOpPpt.grid(column=1,row=8,ipadx=9,padx=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorETOp=ttk.Separator(labelFrameRlSetUDSetting)
separatorETOp.grid(column=0,row=9,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelETOp=ttk.Label(labelFrameRlSetUDSetting,text="Emerging Threats Pro rules:")
labelETOp.grid(column=0,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

checkButtonETPro=ttk.Checkbutton(labelFrameRlSetUDSetting,variable=eTProRl,text="Enable download of Emerging Threats Pro rules")
checkButtonETPro.grid(column=1,row=10,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelETProOinkMaC=ttk.Label(labelFrameRlSetUDSetting,text="Emerging Threats oinkmaster code:")
labelETProOinkMaC.grid(column=0,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

entryETProOinkMaC=ttk.Entry(labelFrameRlSetUDSetting,textvariable=eTProOinkMaC)
entryETProOinkMaC.grid(column=1,row=11,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonPasETOinkMaC=ttk.Button(labelFrameRlSetUDSetting,text="Paste",command=pasETProOinkMaC)
buttonPasETOinkMaC.grid(column=2,row=11,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelETProPpt=ttk.Label(labelFrameRlSetUDSetting,text="ETPro for Snort offers daily updates and extensive coverage of current malware threats.")
labelETProPpt.grid(column=1,row=12,ipadx=9,padx=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

separatorETPro=ttk.Separator(labelFrameRlSetUDSetting)
separatorETPro.grid(column=0,row=13,columnspan=3,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonSvRlUdSetting=ttk.Button(labelFrameRlSetUDSetting,text="Save setting",command=svPulledPorkcfg)
buttonSvRlUdSetting.grid(column=0,row=14,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameUdRlSet=ttk.Labelframe(frameUd,text="Rule set update")
labelFrameUdRlSet.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameUdRlSet.grid_columnconfigure(0,weight=1)
labelFrameUdRlSet.grid_columnconfigure(1,weight=1)
labelFrameUdRlSet.grid_rowconfigure(0,weight=1)
labelFrameUdRlSet.grid_rowconfigure(1,weight=1)
labelFrameUdRlSet.grid_rowconfigure(2,weight=1)

labelUdRlSet=ttk.Label(labelFrameUdRlSet,text="Last update time:")
labelUdRlSet.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S)

labelUdRlSetTm=ttk.Label(labelFrameUdRlSet,text="Unknown")
labelUdRlSetTm.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.S+Tkinter.W)

buttonUdRl=ttk.Button(labelFrameUdRlSet,text="Update rules",command=udRl)
buttonUdRl.grid(column=0,row=1,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelUdRlset=ttk.Label(labelFrameUdRlSet,text="Click [Update rules] to check for and automatically apply any new posted updates for selected rules packages.",anchor=Tkinter.CENTER)
labelUdRlset.grid(column=0,row=2,columnspan=2,ipadx=5,padx=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameManageRlSetUdLog=ttk.Labelframe(frameUd,text="Manage rule update log")
labelFrameManageRlSetUdLog.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameManageRlSetUdLog.grid_columnconfigure(0,weight=1)
labelFrameManageRlSetUdLog.grid_columnconfigure(1,weight=1)
labelFrameManageRlSetUdLog.grid_rowconfigure(0,weight=1)
labelFrameManageRlSetUdLog.grid_rowconfigure(1,weight=1)

buttonVLog=ttk.Button(labelFrameManageRlSetUdLog,text="View log",command=vLogTLvl)
buttonVLog.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonClrLog=ttk.Button(labelFrameManageRlSetUdLog,text="Clear log",command=clrLog)
buttonClrLog.grid(column=1,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelClrLog=ttk.Label(labelFrameManageRlSetUdLog,text="Log files can be cleaned manually.",anchor=Tkinter.CENTER)
labelClrLog.grid(column=0,row=1,columnspan=2,ipadx=5,padx=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

frameAbt=ttk.Frame(noteBookMain)
frameAbt.grid_columnconfigure(0,weight=1)
frameAbt.grid_rowconfigure(0,weight=1)
frameAbt.grid_rowconfigure(1,weight=1)
frameAbt.grid_rowconfigure(2,weight=1)

labelFrameSnortInfo=ttk.Labelframe(frameAbt,text="Snort Information")
labelFrameSnortInfo.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameSnortInfo.grid_columnconfigure(0,weight=1)
labelFrameSnortInfo.grid_rowconfigure(0,weight=1)
labelFrameSnortInfo.grid_rowconfigure(1,weight=1)

labelFrameSnortInfoOut=ttk.Label(labelFrameSnortInfo,anchor=Tkinter.CENTER,font=("Ubuntu Mono",))
labelFrameSnortInfoOut.grid(column=0,row=0,columnspan=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonOSnortOWeb=ttk.Button(labelFrameSnortInfo,text="Official website",command=oSnortOWeb)
buttonOSnortOWeb.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFrameBarnyardInfo=ttk.Labelframe(frameAbt,text="Barnyard Information")
labelFrameBarnyardInfo.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFrameBarnyardInfo.grid_columnconfigure(0,weight=1)
labelFrameBarnyardInfo.grid_columnconfigure(1,weight=1)
labelFrameBarnyardInfo.grid_columnconfigure(2,weight=1)
labelFrameBarnyardInfo.grid_rowconfigure(0,weight=1)
labelFrameBarnyardInfo.grid_rowconfigure(1,weight=1)

labelFrameBarnyardInfoOut=ttk.Label(labelFrameBarnyardInfo,anchor=Tkinter.CENTER,font=("Ubuntu Mono",))
labelFrameBarnyardInfoOut.grid(column=0,row=0,columnspan=3,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonOBarnyardOWeb=ttk.Button(labelFrameBarnyardInfo,text="Official website",command=oBarnyardOWeb)
buttonOBarnyardOWeb.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonOBarnyardGHWeb=ttk.Button(labelFrameBarnyardInfo,text="GitHub website",command=oBarnyardGHWeb)
buttonOBarnyardGHWeb.grid(column=1,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonOBarnyardOEMail=ttk.Button(labelFrameBarnyardInfo,text="Official e-mail",command=oBarnyardOEMail)
buttonOBarnyardOEMail.grid(column=2,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

labelFramePulledPorkInfo=ttk.Labelframe(frameAbt,text="Pulled Pork Information")
labelFramePulledPorkInfo.grid(column=0,row=2,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)
labelFramePulledPorkInfo.grid_columnconfigure(0,weight=1)
labelFramePulledPorkInfo.grid_rowconfigure(0,weight=1)
labelFramePulledPorkInfo.grid_rowconfigure(1,weight=1)

labelPulledPorkInfoOut=ttk.Label(labelFramePulledPorkInfo,anchor=Tkinter.CENTER,font=("Ubuntu Mono",))
labelPulledPorkInfoOut.grid(column=0,row=0,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

buttonOPulledPorkGHWeb=ttk.Button(labelFramePulledPorkInfo,text="GitHub website",command=oPulledPorkGHWeb)
buttonOPulledPorkGHWeb.grid(column=0,row=1,ipadx=5,ipady=5,padx=5,pady=5,sticky=Tkinter.N+Tkinter.E+Tkinter.S+Tkinter.W)

noteBookMain.add(frameHome,text="Home")
noteBookMain.add(frameCfg,text="Configuration")
noteBookMain.add(frameRl,text="Rule")
noteBookMain.add(frameAlert,text="Alert")
#noteBookMain.add(frameGraph,text="Graph")
noteBookMain.add(frameUd,text="Update")
noteBookMain.add(frameAbt,text="About")

loadSvcCfg()
acidtable()
shwAlert()
rRlF()
loadCfg()
loadPulledPorkcfg()
rLastRlsetUdTm()
shwSnortVer()
shwBarnyardVer()
shwPulledPorkVer()

refreshThread=threading.Thread(target=refrshAllStat)
refreshThread.start()

root.mainloop()
