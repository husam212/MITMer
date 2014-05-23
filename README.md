MITMer
======

**This tool can do the following:**

- MITM attack on a specific host/IP or all of them.

- Show HTTP and DNS activity of attacked hosts.

- Fake DNS queries asking about some website and redirects them to your PC.

- Covert that website into a fake page and host it on your PC.

- Reveal entered credentials into that fake website.


**Dependencies:**

- python2

- scapy

- python2-nfqueeu


**Examples:**

- Attack all hosts and show their HTTP traffic, create fake pages for www.somewebsite.com:

        sudo ./mitmer.py -http -dnames www.somewebsite.com

- Attack 192.168.1.111 and its DNS traffic, create fake pages for website1.com & website2.com:

        sudo ./mitmer.py -dns -dnames "website1.com website2.com"

- To show help:

        ./mitmer -h
