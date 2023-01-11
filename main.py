import socket, sys, threading, ctypes, time
from tkinter import *
from getmac import get_mac_address
from time import ctime

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
# Using piece of code from old splash screen
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
label1=Label(w, text='ZEEPORT', fg='white', bg='#203749') #decorate it
label1.configure(font=("Algerian", 24, "bold"))   #You need to install this font in your PC or try another one
label1.place(x=140,y=90)

label2=Label(w, text='Loading...', fg='white', bg='#203749') #decorate it
label2.configure(font=("Slyfaen", 12))
label2.place(x=10,y=215)

#making animation

image_a=ImageTk.PhotoImage(Image.open('c2.png'))
image_b=ImageTk.PhotoImage(Image.open('c1.png'))


for i in range(3): #3loops
    l1=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=180, y=145)
    l2=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=200, y=145)
    l3=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=220, y=145)
    l4=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=240, y=145)
    w.update_idletasks()
    time.sleep(0.5)

    l1=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=180, y=145)
    l2=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=200, y=145)
    l3=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=220, y=145)
    l4=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=240, y=145)
    w.update_idletasks()
    time.sleep(0.5)

    l1=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=180, y=145)
    l2=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=200, y=145)
    l3=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=220, y=145)
    l4=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=240, y=145)
    w.update_idletasks()
    time.sleep(0.5)

    l1=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=180, y=145)
    l2=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=200, y=145)
    l3=Label(w, image=image_b, border=0, relief=SUNKEN).place(x=220, y=145)
    l4=Label(w, image=image_a, border=0, relief=SUNKEN).place(x=240, y=145)
    w.update_idletasks()
    time.sleep(0.5)



w.destroy()
#new_win()
w.mainloop()


# ==== GUI ====
gui = Tk()
# set window title
gui.title('ZeePort')
# set window icon
gui.iconbitmap('Logo.ico')
# gui.geometry("500x700+40+40")
width_of_window = 500
height_of_window = 700
screen_width = gui.winfo_screenwidth()
screen_height = gui.winfo_screenheight()
x_coordinate = (screen_width/2)-(width_of_window/2)
y_coordinate = (screen_height/2)-(height_of_window/2)
gui.geometry("%dx%d+%d+%d" %(width_of_window,height_of_window,x_coordinate,y_coordinate))

# ==== Colors ====
m1c = '#FFF4EA'         #text
bgc = '#607D8B'         #background
fgc = '#455A64'         #button clicked

gui.tk_setPalette(background=bgc, foreground=m1c, activeBackground=fgc, activeForeground=bgc, highlightColor=m1c,
                  highlightBackground=m1c)

# ==== Labels ====
L11 = Label(gui, text="ZeePort", font=("Algerian", 20)) #'underline'
L11.place(x=16, y=10)

L21 = Label(gui, text="Target: ", font=("Cascadia Code", 12))
L21.place(x=16, y=90)

L22 = Entry(gui, text="localhost", font=("Times New Roman", 12))
L22.place(x=180, y=95)
L22.insert(0, "localhost")

L23 = Label(gui, text="Ports: ", font=("Cascadia Code", 12))
L23.place(x=16, y=158)

L24 = Entry(gui, text="1", font=("Times New Roman", 12))
L24.place(x=180, y=163, width=95)
L24.insert(0, "1")

L25 = Entry(gui, text="1024", font=("Times New Roman", 12))
L25.place(x=290, y=163, width=95)
L25.insert(0, "1024")

L26 = Label(gui, text="Results: ", font=("Cascadia Code", 12))
L26.place(x=16, y=220)
L27 = Label(gui, text="[ ... ]", font=("Times New Roman", 12))
L27.place(x=180, y=222)

L28 = Label(gui, text="", font=("Times New Roman", 12))
L28.place(x=16, y=465)

L29 =Label(gui, text="", font=("Times New Roman", 12))
L29.place(x=16, y=490)

# ==== Ports list ====
frame = Frame(gui)
frame.place(x=16, y=275, width=450, height=180)
listbox = Listbox(frame, width=450, height=11)
listbox.place(x=0, y=0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

# ==== Buttons / Scans ====
B11 = Button(gui, text="Start Scan", command=startScan)
B11.place(x=16, y=540, width=170)
B21 = Button(gui, text="Save Result", command=saveScan)
B21.place(x=210, y=540, width=170)

# ==== Start GUI ====
gui.mainloop()