MITMer
======


**This tool can do the following:**

- MITM attack on a specific host or all LAN hosts.

- Show HTTP and DNS activity of attacked hosts.

- Drop DNS queries asking about a website and redirects them to your PC.

- Convert that website into a fake page and host it on your PC.


**Dependencies:**

- python2

- scapy

- python2-nfqueue


**Examples:**

- Attack all hosts and show their HTTP traffic, create fake page for www.somewebsite.com:

        sudo ./mitmer.py -http -dnames www.somewebsite.com

- Attack 192.168.1.111 and show its DNS traffic, create fake pages for website1.com & website2.com:

        sudo ./mitmer.py -dns -dnames "website1.com website2.com"

- To show help:

        ./mitmer -h
