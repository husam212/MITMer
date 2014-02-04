MITMer
=======

MITMer is a man-in-the-middle and phishing attack tool that steals the victim's credentials of some web services like Facebook.


**Dependencies:**

* python2
* scapy
* python2-nfqueue


**How to:**

* Run it as root.

        sudo python2 mitmer.py

* Select a network interface.

* After scanning the network for available hosts, choose one as a victim or enter an IP address manually.

* Select one of the attack profiles or custom.

* If custom is selected, type the domain(s) you want in the "Query request" field, and type the domain (or IP address) of the server that the victim should be redirected to in the "Query reply" field.

* Start the attack and wait.
