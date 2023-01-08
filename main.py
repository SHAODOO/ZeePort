import socket, sys, threading, time, ctypes, time, subprocess
from tkinter import *
from getmac import get_mac_address

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
        vul = "ftp vul"
    elif port == 53:
        vul = 'dns vul'
    else:
        vul = "unknown"
    #continue
    return vul

def service(port):
    if port == 21:
        service = 'ftp'
    elif port == 23:
        service = 'telnet'
    elif port == 53:
        service = 'dns'
    else:
        service = 'unknown'
    #continue
    return service

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
            m = '%d               [open]        %s      %s' % (port, ser, vul)
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
    global ports, log, target, ip_f
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
    log.append(' Target:\t\t' + str(target))
    startTime = time.time()
    mac = getMacAddress(str(target))
    try:
        target = socket.gethostbyname(str(L22.get()))
        log.append(' IP Address:\t' + str(target))
        log.append(' Ports: \t\t[ ' + str(ip_s) + ' / ' + str(ip_f) + ' ]')
        log.append(' MAC Address:\t' + str(mac))
        log.append('\n')
        #Header in listbox
        listbox.insert("end", 'PORT           STATE         SERVICE         VULNERABILITY')
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
        log[6] = " Result:\t\t[ " + str(len(ports)) + " / " + str(ip_f) + " ]\n"
        log[7] = 'PORT\t\t\t\tSTATUS\t\tSERVICE\t\tVULNERABILITY'
        with open('ZeePort (' + str(target) + ').txt', mode='wt', encoding='utf-8') as myfile:
            myfile.write('\n'.join(log))
        # Pop out a window to alert user that result has been downloaded
        ctypes.windll.user32.MessageBoxW(0, "Result for " + str(target) + " has been downloaded.", "ZeePort", 1)


def clearScan():
    listbox.delete(0, 'end')


# ==== GUI ====
gui = Tk()
# set window title
gui.title('ZeePort')
# set window icon
gui.iconbitmap('Logo.ico')
gui.geometry("400x600+20+20")

# ==== Colors ====
m1c = '#F49F1C'         #text
bgc = '#030E4F'         #background
fgc = '#F49F1C'         #button clicked

gui.tk_setPalette(background=bgc, foreground=m1c, activeBackground=fgc, activeForeground=bgc, highlightColor=m1c,
                  highlightBackground=m1c)

# ==== Labels ====
L11 = Label(gui, text="ZeePort", font=("Helvetica", 16, 'underline'))
L11.place(x=16, y=10)

L21 = Label(gui, text="Target: ")
L21.place(x=16, y=90)

L22 = Entry(gui, text="localhost")
L22.place(x=180, y=90)
L22.insert(0, "localhost")

L23 = Label(gui, text="Ports: ")
L23.place(x=16, y=158)

L24 = Entry(gui, text="1")
L24.place(x=180, y=158, width=95)
L24.insert(0, "1")

L25 = Entry(gui, text="1024")
L25.place(x=290, y=158, width=95)
L25.insert(0, "1024")

L26 = Label(gui, text="Results: ")
L26.place(x=16, y=220)
L27 = Label(gui, text="[ ... ]")
L27.place(x=180, y=220)

L28 = Label(gui, text="")
L28.place(x=16, y=465)

L29 =Label(gui, text="")
L29.place(x=16, y=490)

# ==== Ports list ====
frame = Frame(gui)
frame.place(x=16, y=275, width=370, height=180)
listbox = Listbox(frame, width=59, height=11)
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