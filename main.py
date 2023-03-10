import socket, sys, threading, ctypes, time, os
from tkinter import *
from getmac import get_mac_address
from time import ctime
from scapy.all import ARP, Ether, srp

#importing library for GUI
from tkinter import font
from PIL import ImageTk, Image
import time

w=Tk()

# ==== Scan Vars ====
ip_s = 1
ip_f = 1024
log = []
ports = []
target = 'localhost'

# ==== Check Wifi's SSID and IP address ====
def getCurrentWifiInfo():
    global wifi_ssid, wifi_ip_address , mycomputer_hostname


    ssid_search = os.popen("netsh wlan show interfaces").read()
    search_result = ssid_search.split("\n")
    SSID = list()
    for i in search_result:
        if "disconnected" in i:
            wifi_ssid = "You are not connected to any internet connection"
        elif "connected" in i:
            for j in search_result:
                if "BSSID" in j:
                    pass
                elif "SSID" in j:
                    SSID.append(j[j.index(":")+2:])
                    wifi_ssid = SSID[0]

    mycomputer_hostname = socket.gethostname()
    wifi_ip_address = socket.gethostbyname(mycomputer_hostname)
    if wifi_ip_address == "127.0.0.1":
	    wifi_ip_address = "-"

# ==== Scan Live Host ====
def ScanLiveHost():

    livehost_list.delete(0,END)

    target_ip=wifi_ip_address+"/24"
    arp = ARP(pdst=target_ip)
    ether =Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    livehost_result = srp(packet,timeout=3,verbose=0)[0]

    livehost_list.insert(0, "Live Host's IP(s) :")

    if wifi_ip_address != "-" :
        for sent, received in livehost_result:
            livehost_list.insert(1,received.psrc)
            H4.configure(text="The Live Host Scanning Result for "+wifi_ssid+" Connection : ")
    else:
        livehost_list.insert(2,"No live host found.")
        H4.configure(text="The Live Host Scanning Result Without Connection : ")

        
# ====LiveHostRefresh====
def LHRefresh():
    getCurrentWifiInfo()
    H2.configure(text="Current Connected Internet     : "+wifi_ssid)
    H3.configure(text="My IP Address in the Internet  : "+wifi_ip_address)
    refresh_complete = Label(LH, text="Refresh Complete", font=("Cascadia Code", 12))
    refresh_complete.place(x=16, y=210)
    #refresh_complete.after(1000,refresh_complete.configure(text="Refresh Complete."))
    #refresh_complete.after(1000,refresh_complete.configure(text="Refresh Complete.."))
    #refresh_complete.after(3000,refresh_complete.configure(text="Refresh Complete..."))
    refresh_complete.after(1000,refresh_complete.destroy)

# ====Next Module to bring the IP to further action====
def LHNext():
    select_ip = livehost_list.get(livehost_list.curselection())
    SP.pack(fill='both',expand=1)
    LH.pack_forget()
    L22.delete(0,END)
    L22.insert(0, select_ip)

def back():
    LH.pack(fill='both',expand=1)
    SP.pack_forget()

def getMacAddress(ip_address):
    mac_address = get_mac_address(ip=ip_address)
    if mac_address == None:
        mac_address = "MAC Address not found"
    return mac_address

# Open Port Vulnerabilities Suggestion
def vulSuggestion(port):
    if port == 21:
        return 'Dridex'
    elif port == 22:
        return 'Brute-force attack'
    elif port == 23:
        return 'Sniffing, Spoofing, Brute-force attack'
    elif port == 25:
        return 'Mail spamming, Spoofing'
    elif port == 53:
        return 'DDoS attack'
    elif port == 80:
        return 'SQL injection, Cross-site scripting'
    else:
        return 'Not found'

def service(port):
    if port == 21:
        return  'FTP'
    elif port == 22:
        return  'SSH'
    elif port == 23:
        return 'Telnet'
    elif port == 25:
        return 'SMTP'
    elif port == 43:
        return 'WhoIs'
    elif port == 53:
        return 'DNS'
    elif port == 80:
        return 'HTTP'
    elif port == 109:
        return 'POP2'
    elif port == 110:
        return 'POP3'
    elif port == 135:
        return 'LOC-SRV'
    elif port == 139:
        return 'NetBIOS Datagram Service'
    elif port == 161:
        return 'SNMP'
    elif port == 443:
        return 'HTTPS'
    elif port == 445:
        return 'Microsoft-DS'
    elif port == 458:
        return 'Apple QuickTime'
    elif port == 902:
        return 'IdeaForm-Chat'
    elif port == 912:
        return 'APEX'
    else:
        return 'Unknown'

# ==== Scanning Functions ====
def scanPort(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        c = s.connect_ex((target, port))
        if c == 0:
            ports.append(port)
            vul = vulSuggestion(port)
            ser = service(port)
            m = '%d               [open]        %s                  %s' % (port, ser, vul)
            log.append(m)
            listbox.insert("end", str(m))
        updateResult()
        s.close()
    except OSError:
        print('> Too many open sockets. Port ' + str(port))
    except:
        c.close()
        s.close()
        sys.exit()
    sys.exit()


def updateResult():
    rtext = " [ " + str(len(ports)) + " / " + str(ip_f) + " ] ~ " + str(target)
    L27.configure(text=rtext)


def startScan():
    global ports, log, target, ip_f, startTime
    clearScan()
    log = []
    ports = []
    # Get ports ranges from GUI
    ip_s = int(L24.get())
    ip_f = int(L25.get())
    # port number validation
    # while ip_s < 1 or ip_f > 65535:
        # L24.configure(text="1")
        # L25.configure(text="1024")
        # ctypes.windll.user32.MessageBoxW(0, "Please enter a valid port", "ZeePort", 1)
        # Start writing the log file
    log.append('ZeePort')
    log.append('=' * 14 + '\n')
    log.append(' Target:\t\t' + str(L22.get()))
    startTime = time.time()
    mac = getMacAddress(str(target))
    try:
        target = socket.gethostbyname(str(L22.get()))
        log.append(' IP Address:\t' + str(target))
        log.append(' MAC Address:\t' + str(mac))
        log.append('\n')
        #Header in listbox
        listbox.insert("end", 'PORT           STATE         SERVICE             VULNERABILITY')
        # Lets start scanning ports!
        while ip_s <= ip_f:
            try:
                scan = threading.Thread(target=scanPort, args=(target, ip_s))
                scan.setDaemon(True)
                scan.start()
            except:
                time.sleep(0.01)
            ip_s += 1
    except:
        m = '> Target ' + str(L22.get()) + ' not found.'
        log.append(m)
        listbox.insert(0, str(m))
    endTime = time.time() - startTime
    #display time taken
    L28.configure(text='ZeePort: done scanned in ' + str(round(endTime, 2)) + ' seconds ')
    L29.configure(text='MAC Address: ' + str(mac))


def saveScan():
    global log, target, ports, ip_f
    if not ports:
        # Pop out a window to alert user that no result
        ctypes.windll.user32.MessageBoxW(0, "Empty result", "ZeePort", 1)
    else:
        log[5] = " Result:\t\t[ " + str(len(ports)) + " / " + str(ip_f) + " ]\n\nPORT\t\t\t\tSTATUS\t\tSERVICE\t\tVULNERABILITY"
        # log[7] = 'PORT\t\t\t\tSTATUS\t\tSERVICE\t\tVULNERABILITY'
        with open('ZeePort (' + str(target) + ').txt', mode='wt', encoding='utf-8') as myfile:
            myfile.write('\n'.join(log))
            myfile.write('\n\nScanned at ' + str(ctime(startTime)))
        # Pop out a window to alert user that result has been downloaded
        ctypes.windll.user32.MessageBoxW(0, "Result for " + str(target) + " has been downloaded.", "ZeePort", 1)


def clearScan():
    listbox.delete(0, 'end')


# ==== GUI Splash Screen ====
width_of_window = 427
height_of_window = 250
screen_width = w.winfo_screenwidth()
screen_height = w.winfo_screenheight()
x_coordinate = (screen_width/2)-(width_of_window/2)
y_coordinate = (screen_height/2)-(height_of_window/2)
w.geometry("%dx%d+%d+%d" %(width_of_window,height_of_window,x_coordinate,y_coordinate))
#w.configure(bg='#ED1B76')
w.overrideredirect(1) #for hiding titlebar

Frame(w, width=427, height=250, bg='#203749').place(x=0,y=0)
label1=Label(w, text='ZEEPORT', fg='white', bg='#203749')
label1.configure(font=("Algerian", 24, "bold"))
label1.place(x=137,y=100)

label2=Label(w, text='Loading...', fg='white', bg='#203749')
label2.configure(font=("Cascadia Code", 11))
label2.place(x=10,y=215)

#making animation

image_a=ImageTk.PhotoImage(Image.open('c2.png'))
image_b=ImageTk.PhotoImage(Image.open('c1.png'))

image_c=ImageTk.PhotoImage(Image.open('Logo.png'))
label3=Label(w, image=image_c, border=0, relief=SUNKEN).place(x=182, y=25)


for i in range(3): #3loops
    l1=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=177, y=155)
    l2=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=197, y=155)
    l3=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=217, y=155)
    l4=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=237, y=155)
    w.update_idletasks()
    time.sleep(0.5)

    l1=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=177, y=155)
    l2=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=197, y=155)
    l3=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=217, y=155)
    l4=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=237, y=155)
    w.update_idletasks()
    time.sleep(0.5)

    l1=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=177, y=155)
    l2=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=197, y=155)
    l3=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=217, y=155)
    l4=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=237, y=155)
    w.update_idletasks()
    time.sleep(0.5)

    l1=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=177, y=155)
    l2=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=197, y=155)
    l3=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=217, y=155)
    l4=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=237, y=155)
    w.update_idletasks()
    time.sleep(0.5)

w.destroy()
w.mainloop()


# ==== Colors ====
m1c = '#FFF4EA'         #text
bgc = '#607D8B'         #background
fgc = '#455A64'         #button clicked

# ==== LH ====
win = Tk()
win.title('ZeePort')
# set window icon
win.iconbitmap('Logo.ico')
win.geometry("750x700+20+20")
win.tk_setPalette(background=bgc, foreground=m1c, activeBackground=fgc, activeForeground=bgc, highlightColor=m1c,
                  highlightBackground=m1c)

LH = Frame(win)
getCurrentWifiInfo()
LH.pack(fill='both',expand=1)
H1 = Label(LH, text="ZeePort", font=("Algerian", 20))
H1.place(x=16, y=10)
H11 = Label(LH, text="Device's Host Name             : "+mycomputer_hostname, font=("Cascadia Code", 12))
H11.place(x=16, y=80)
H2 = Label(LH, text="Current Connected Internet     : "+wifi_ssid, font=("Cascadia Code", 12))
H2.place(x=16, y=110)
H3 = Label(LH, text="My IP Address in the Internet  : "+wifi_ip_address, font=("Cascadia Code", 12))
H3.place(x=16, y=140)


HB1 = Button(LH, text="Scan For Live Host", command=ScanLiveHost)
HB1.place(x=550, y=170, width=170)
HB2 = Button(LH, text="Refresh", command=LHRefresh)
HB2.place(x=550, y=210, width=170)
HB3 = Button(LH, text="Next", command=LHNext)
HB3.place(x=550, y=600, width=170)


ip_var=StringVar()

frame = Frame(LH)
frame.place(x=16, y=275, width=700, height=270)
livehost_list = Listbox(frame, listvariable=ip_var, width=700, height=16,font=12,selectmode=SINGLE)
livehost_list.place(x=0, y=0)
livehost_list.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
livehost_list.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=livehost_list.yview)

H4 = Label(LH, text="", font=("Cascadia Code", 12))
H4.place(x=16, y=240)

#win.mainloop()

# ==== GUI ====
SP = Frame(win)


# ==== Labels ====
L11 = Label(SP, text="ZeePort", font=("Algerian", 20))
L11.place(x=16, y=10)

L21 = Label(SP, text="Target: ", font=("Cascadia Code", 12))
L21.place(x=16, y=90)

L22 = Entry(SP, text="localhost", font=("Cascadia Code", 12))
L22.place(x=180, y=95)

L23 = Label(SP, text="Ports: ", font=("Cascadia Code", 12))
L23.place(x=16, y=158)

L24 = Entry(SP, text="1", font=("Cascadia Code", 12))
L24.place(x=180, y=163, width=95)
L24.insert(0, "1")

L25 = Entry(SP, text="1024", font=("Cascadia Code", 12))
L25.place(x=290, y=163, width=95)
L25.insert(0, "1024")

L26 = Label(SP, text="Results: ", font=("Cascadia Code", 12))
L26.place(x=16, y=220)
L27 = Label(SP, text="[ ... ]", font=("Cascadia Code", 12))
L27.place(x=180, y=222)

L28 = Label(SP, text="", font=("Cascadia Code", 12))
L28.place(x=16, y=465)

L29 =Label(SP, text="", font=("Cascadia Code", 12))
L29.place(x=16, y=490)

# ==== Ports list ====
frame = Frame(SP)
frame.place(x=16, y=275, width=550, height=180)
listbox = Listbox(frame, width=450, height=11)
listbox.place(x=0, y=0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

# ==== Buttons / Scans ====
B11 = Button(SP, text="Start Scan", command=startScan)
B11.place(x=16, y=540, width=170)
B21 = Button(SP, text="Save Result", command=saveScan)
B21.place(x=210, y=540, width=170)
BB = Button(SP, text="Back", command=back)
BB.place(x=16, y=600, width=170)
# ==== Start GUI ====
win.mainloop()