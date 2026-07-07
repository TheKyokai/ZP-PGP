import tkinter as tk
from datetime import datetime
from tkinter import ttk, filedialog, simpledialog, messagebox
from tkinter.scrolledtext import ScrolledText

from Crypto.PublicKey import RSA

from PGP import PGP


class App:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PGP App")
        self.root.geometry("1200x700")

        self.pgp = PGP()

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Tabs
        self.send_tab = ttk.Frame(self.notebook)
        self.receive_tab = ttk.Frame(self.notebook)
        self.public_ring_tab = ttk.Frame(self.notebook)
        self.private_ring_tab = ttk.Frame(self.notebook)


        self.notebook.add(self.send_tab, text="Slanje")
        self.notebook.add(self.receive_tab, text="Prijem")
        self.notebook.add(self.public_ring_tab, text="Javni Prsten")
        self.notebook.add(self.private_ring_tab, text="Privatni Prsten")

        self.configure_send_tab()
        self.configure_receive_tab()
        self.configure_public_ring_tab()
        self.configure_private_ring_tab()

        self.selected_key_pair = None
        self.selected_public_key = None

        self.public_key_import_dialog_result = None
        self.key_pair_import_dialog_result = None

        self.file = None
        self.content = None
        self.verified_check = None
        self.save_button = None

    def choose_file(self):
        filename = filedialog.askopenfilename(title="Izaberi fajl")

        if filename:
            self.file_label.config(text=filename)
            self.file = filename
        else:
            self.file = None

    def choose_save_destination(self):
        filename = filedialog.asksaveasfilename(
            parent=self.root,
            title="Izaberite destinaciju za slanje",
            defaultextension=".pgp",
            filetypes=[
                ("MSG files", "*.msg"),
                ("All files", "*.*")
            ]
        )
        if not filename:
            return None

        return filename

    def save_original_message(self):
        filename = self.choose_save_destination()
        if filename is None:
            self.report_error("Nije odabran fajl za cuvanje poruke")
        with open(filename, "w") as file:
            print("CONTENT" , self.content)
            file.write(self.content)
            self.report_success("Poruka je uspesno sacuvana")
        return

    def decrypt(self):
        if self.save_button is not None:
            self.save_button.destroy()

        if self.file is None:
            self.report_error("Nije odabran fajl")
            return

        try:
            decrypted_message, verified, timestamp, signer_username, signer_email = self.pgp.receive_message(self.file, self)
            self.content = decrypted_message
            date = datetime.fromtimestamp(int(timestamp))
            formatted = date.strftime("%d.%m.%Y. %H:%M:%S")

            if verified is None:
                bg_color = "#ffffff"
                verification_message = f"Poruka nije potpisana"
            elif verified:
                bg_color = "#C3FCBB"
                verification_message = f"Verifikovan potpis korisnika:\n {signer_username} ({signer_email})"
            else:
                bg_color = "#FA918F"
                verification_message = f"Nevažeći potpis korisnika:\n {signer_username} ({signer_email})"

            self.content = formatted + "\n" + self.content

            self.message_text.config(state="normal")
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert(tk.INSERT, self.content)
            self.message_text.config(state="disabled")

            if self.verified_check is None:
                self.verified_check = ScrolledText(self.decrypt_option_panel, state="disabled", bg=bg_color, height = 1, width = 10)
            else:
                self.verified_check.config(bg=bg_color)
            self.verified_check.config(state="normal")
            self.verified_check.delete("1.0", tk.END)
            self.verified_check.insert("1.0", verification_message)
            self.verified_check.config(state="disabled")

            self.verified_check.pack(fill="both")
        except Exception as e:
            self.report_error(e)


        self.save_button = ttk.Button(
            self.decrypt_option_panel,
            text="Sacuvaj originalnu poruku",
            command=self.save_original_message,
            width=30)
        self.save_button.pack(anchor = "center", pady = 5)

    def configure_receive_tab(self):
        #RECIEVE TAB

        receive_container = ttk.Frame(self.receive_tab)
        receive_container.pack(fill="both", expand=True)

        # Configure 1:2 split
        receive_container.columnconfigure(0, weight=1)
        receive_container.columnconfigure(1, weight=1)
        receive_container.rowconfigure(0, weight=1)
        receive_container.rowconfigure(1, weight=0)

        # Control panel
        self.decrypt_option_panel = ttk.Frame(receive_container)
        self.decrypt_option_panel.grid(row=0, column=0, sticky="nsew")

        # Message area
        self.message_panel = ttk.Frame(receive_container)
        self.message_panel.grid(row=0, column=1, sticky="nsew")

        receive_button = ttk.Button(
            self.decrypt_option_panel,
            text="Izaberi fajl",
            command=self.choose_file,
            width=20
            )
        receive_button.pack(anchor = "center", pady = 5)

        self.file_label = ttk.Label(self.decrypt_option_panel, text="Nijedan fajl nije izabran",
                                    width=60, anchor="center")
        self.file_label.pack(anchor = "center")

        read_button = ttk.Button(self.decrypt_option_panel,
                   text="Procitaj",
                   command = self.decrypt,
                   width=20)
        read_button.pack(anchor = "center", pady = 5)

        self.message_text = tk.Text(self.message_panel, wrap = "word")
        self.message_text.pack(fill="both", expand=True)
        self.message_text.insert(tk.INSERT, "")
        self.message_text.config(state="disabled")

    def configure_send_tab(self):
        # Send tab layout container
        send_container = ttk.Frame(self.send_tab)
        send_container.pack(fill="both", expand=True)

        # Configure 1:2 split
        send_container.columnconfigure(0, weight=1)
        send_container.columnconfigure(1, weight=2)
        send_container.rowconfigure(0, weight=1)
        send_container.rowconfigure(1, weight=0)

        # Control panel
        left_panel = ttk.Frame(send_container)
        left_panel.grid(row=0, column=0, sticky="nsew")

        # Text area
        right_panel = ttk.Frame(send_container)
        right_panel.grid(row=0, column=1, sticky="nsew")

        # Bottom panel
        bottom_panel = ttk.Frame(send_container)
        bottom_panel.grid(row=1, column=0, columnspan=2, sticky="sew", pady=5)

        self.send_encrypt_bool = tk.BooleanVar(value=False)
        self.send_sign_bool = tk.BooleanVar(value=False)
        self.send_zip_bool = tk.BooleanVar(value=False)
        self.send_radix64_bool = tk.BooleanVar(value=False)

        # Control panel contents
        encrypt_checkbox = ttk.Checkbutton(left_panel, text="Enkripcija", variable=self.send_encrypt_bool)
        encrypt_checkbox.pack(anchor="w", pady=5)

        self.send_enc_algorithm = tk.StringVar(value="AES128")
        self.send_aes_radio = ttk.Radiobutton(
            left_panel,
            text='AES128',
            variable=self.send_enc_algorithm,
            value='AES128'
        )
        self.send_3des_radio = ttk.Radiobutton(
            left_panel,
            text='CAST5',
            variable=self.send_enc_algorithm,
            value='CAST5'
        )
        self.send_aes_radio.configure(state='disabled')
        self.send_aes_radio.pack(anchor="w", pady=5)
        self.send_3des_radio.configure(state='disabled')
        self.send_3des_radio.pack(anchor="w", pady=5)

        encrypt_key_label = ttk.Label(left_panel, text="Javni ključ za enkripciju")
        encrypt_key_label.pack(anchor="w", pady=(5, 0))

        self.encrypt_public_key_options = ttk.Combobox(left_panel, values=[""])
        self.encrypt_public_key_options.current(0)
        self.encrypt_public_key_options.configure(state="disabled")
        self.encrypt_public_key_options.pack(anchor="w", pady=(2, 10))
        self.send_encrypt_bool.trace_add("write", self.update_encrypt_key)


        sign_checkbox = ttk.Checkbutton(left_panel, text="Potpisivanje", variable=self.send_sign_bool)
        sign_checkbox.pack(anchor="w", pady=5)

        sign_key_label = ttk.Label(left_panel, text="Privatni ključ za potpisivanje")
        sign_key_label.pack(anchor="w", pady=(5, 0))

        self.sign_private_key_options = ttk.Combobox(left_panel, values=[""])
        self.sign_private_key_options.current(0)
        self.sign_private_key_options.configure(state="disabled")
        self.sign_private_key_options.pack(anchor="w", pady=(2, 10))
        self.send_sign_bool.trace_add("write", self.update_sign_key)

        self.update_key_options()

        zip_checkbox = ttk.Checkbutton(left_panel, text="Kompresija", variable=self.send_zip_bool)
        zip_checkbox.pack(anchor="w", pady=5)

        radix64_checkbox = ttk.Checkbutton(left_panel, text="Radix64 konverzija", variable=self.send_radix64_bool)
        radix64_checkbox.pack(anchor="w", pady=5)


        # Text area
        self.send_text_area = tk.Text(right_panel, wrap="word")
        self.send_text_area.pack(fill="both", expand=True)

        # Bottom panel contents
        send_button = ttk.Button(bottom_panel, text="Pošaljite", command=self.send_message)
        send_button.pack(side="right", padx=10)

    def update_key_options(self):
        private_keys = []
        public_keys = []

        for row in self.pgp.private_key_ring:
            private_keys.append(row["Username"] + "---" + row["KeyID"])

        for row in self.pgp.public_key_ring:
            public_keys.append(row["Username"] + "---" + row["KeyID"])

        self.sign_private_key_options.configure(values=private_keys if len(private_keys) > 0 else [""])
        self.sign_private_key_options.current(0)
        self.encrypt_public_key_options.configure(values=public_keys if len(public_keys) > 0 else [""])
        self.encrypt_public_key_options.current(0)

    def send_message(self):
        content = self.send_text_area.get("1.0", "end").strip()

        try:
            if self.send_encrypt_bool.get() and not self.encrypt_public_key_options.get():
                raise Exception("Nije izabran ključ za enkripciju")

            if self.send_sign_bool.get() and not self.sign_private_key_options.get():
                raise Exception("Nije izabran ključ za potpisivanje")

            password = None
            if self.send_sign_bool.get():
                password = self.prompt_password()

                if password is None:
                    return # Not error - User opted out of sending

            filename = self.choose_send_destination()
            if filename is None:
                return # Not error - User opted out of sending

            sign_key = self.sign_private_key_options.get() if self.send_sign_bool.get() else None
            if sign_key is not None:
                sign_key = sign_key.strip().split("---")
                sign_key = sign_key[len(sign_key) - 1]

            enc_key = self.encrypt_public_key_options.get() if self.send_encrypt_bool.get() else None
            if enc_key is not None:
                enc_key = enc_key.strip().split("---")
                enc_key = enc_key[len(enc_key) - 1]

            options = {
                "sign": self.send_sign_bool.get(),
                "sign_key": sign_key,
                "sign_key_password": password,
                "zip": self.send_zip_bool.get(),
                "encrypt": self.send_encrypt_bool.get(),
                "enc_public_key": enc_key,
                "enc_algorithm": self.send_enc_algorithm.get() if self.send_encrypt_bool.get() else None,
                "radix64": self.send_radix64_bool.get(),
            }


            send_status = self.pgp.send_message(content, options, filename)

            if send_status:
                self.report_success("Poruka je uspešno poslata (fajl sačuvan).")

        except Exception as e:
            self.report_error(e)

    def prompt_password(self, prompt_text="Unesite lozinku za privatni ključ:"):
        password = simpledialog.askstring(
            "Lozinka",
            prompt_text,
            parent=self.root,
            show="*"
        )
        return password

    def choose_send_destination(self):
        filename = filedialog.asksaveasfilename(
            parent=self.root,
            title="Izaberite destinaciju za slanje",
            defaultextension=".pgp",
            filetypes=[
                ("PGP files", "*.pgp"),
                ("All files", "*.*")
            ]
        )
        if not filename:
            return None

        return filename

    def choose_export_destination(self):
        filename = filedialog.asksaveasfilename(
            parent=self.root,
            title="Izaberite destinaciju za eksport",
            defaultextension=".pem",
            filetypes=[
                ("PEM files", "*.pem"),
                ("All files", "*.*")
            ]
        )
        if not filename:
            return None

        return filename

    def update_encrypt_key(self, dummy1, dummy2, dummy3):
        if self.send_encrypt_bool.get():
            state = "normal"
        else:
            state = "disabled"

        self.encrypt_public_key_options.configure(state="readonly" if state == "normal" else "disabled")

        self.send_aes_radio.configure(state=state)
        self.send_3des_radio.configure(state=state)

    def update_sign_key(self, dummy1, dummy2, dummy3):
        if self.send_sign_bool.get():
            self.sign_private_key_options.configure(state="readonly")
        else:
            self.sign_private_key_options.configure(state="disabled")

    def delete_public_key(self):

        row = self.pgp.find_public_row(self.selected_public_key)
        self.pgp.public_key_ring.remove(row)
        self.show_public_keys(self.public_ring_container)
        self.selected_public_key = None
        self.report_success("Uspesno je izbrisan javni kljuc")

    def delete_private_key(self):
        password = self.prompt_password()
        private_key, row = self.pgp.decrypt_private_key(password, self.selected_key_pair)
        self.pgp.private_key_ring.remove(row)
        self.show_private_keys()
        self.selected_key_pair = None
        self.report_success("Uspesno je izbrisan privatni kljuc")

    def delete_public_key_popup(self):
        popup = tk.Toplevel(self.root)
        popup.geometry("400x300")

        if self.selected_key_pair is None and self.selected_public_key is None:
            self.report_error("Nije odabran nijedan kljuc")
            return

        def delete_confirmed():
            self.delete_public_key()
            popup.destroy()

        def delete_canceled():
            self.selected_key_pair = None
            popup.destroy()

        popup.title("Brisanje kljuca")
        ttk.Label(popup, text=self.selected_key_pair).pack()
        ttk.Label(popup, text="Da li ste sigurni da zelite da izbrisete kljuc?").pack()
        ttk.Button(
            popup, padding = 10, text = "DA", command = delete_confirmed).pack(side = tk.LEFT)
        ttk.Button(
            popup, padding=10, text="NE", command=delete_canceled).pack(side = tk.RIGHT)

    def delete_private_key_popup(self):
        popup = tk.Toplevel(self.root)
        popup.geometry("400x300")

        if self.selected_key_pair is None and self.selected_public_key is None:
            self.report_error("Nije odabran nijedan kljuc")
            return

        def delete_confirmed():
            self.delete_private_key()
            popup.destroy()

        def delete_canceled():
            self.selected_key_pair = None
            popup.destroy()

        popup.title("Brisanje kljuca")
        ttk.Label(popup, text=self.selected_key_pair).pack()
        ttk.Label(popup, text="Da li ste sigurni da zelite da izbrisete kljuc?").pack()
        ttk.Button(
            popup, padding = 10, text = "DA", command = delete_confirmed).pack(side = tk.LEFT)
        ttk.Button(
            popup, padding=10, text="NE", command=delete_canceled).pack(side = tk.RIGHT)

    def show_private_key(self, values):
        try:
            password = self.prompt_password()
            popup = tk.Toplevel(self.root)
            private_key, row = self.pgp.decrypt_private_key(password, values[2])
            print(private_key)
            print(private_key.d)
            print(private_key.n)
            popup.title("Privatni kljuc")
            popup.geometry("710x300")


            #formatting d and n
            hex_d = hex(private_key.d)
            body = hex_d[2:]
            formatted_d = "0x" + "\n".join(
                body[i:i + 64]
                for i in range(0, len(body), 64)
            )
            hex_n = hex(private_key.n)
            body = hex_n[2:]
            formatted_n = "0x" + "\n".join(
                body[i:i + 64]
                for i in range(0, len(body), 64)
            )
            hex_e = hex(private_key.e)
            body = hex_e[2:]
            formatted_e = "0x" + "\n".join(
                body[i:i + 64]
                for i in range(0, len(body), 64)
            )

            ttk.Label(popup, text="ID kljuca: ").grid(column=0, row=1)
            ttk.Label(popup, text=values[2]).grid(column=1, row=1, sticky="w")
            ttk.Label(popup, text="d").grid(column=0, row=2)
            d_text = tk.Text(popup, height=3,  wrap = "char")
            d_text.grid(column=1, row=2, sticky = "w", pady = 10)
            d_text.insert(tk.INSERT, formatted_d)
            d_text.config(state="disabled")
            ttk.Label(popup, text="n").grid(column=0, row=4)
            n_text = tk.Text(popup, height=3, wrap="char")
            n_text.grid(column=1, row=4, sticky="w", pady = 10)
            n_text.insert(tk.INSERT, formatted_n)
            n_text.config(state="disabled")
            ttk.Label(popup, text="e").grid(column=0, row=6)
            e_text = tk.Text(popup, height=3, wrap="char")
            e_text.grid(column=1, row=6, sticky="w", pady=10)
            e_text.insert(tk.INSERT, formatted_e)
            e_text.config(state="disabled")

        except Exception as e:
            if str(e) == "Incorrect password - noticed due to unpadding issue":
                self.report_error("Pogresna lozinka za dekriptovanje kljuca")
            else:
                print(str(e))
        return

    def show_private_keys(self):
        table = ttk.Treeview(
            self.private_key_bottom_panel,
            columns=("name", "email", "keyid","show"),
            show="headings"
        )

        table.heading("name", text="Ime")
        table.heading("email", text="Email")
        table.heading("keyid", text="Key ID")
        table.heading("show", text="")

        table.grid(row=0, column=0,sticky="nsew")

        self.selected_key_pair = None

        for row in self.pgp.private_key_ring:
            table.insert("", tk.END, values = (row["Username"], row["UserEmail"], row["KeyID"], "PRIKAZI"))
        def private_table_click_detected(event):
            item = table.identify_row(event.y)
            column = table.identify_column(event.x)

            if not item:
                return

            # TODO Update je ovde
            self.selected_key_pair = table.item(item)["values"][2]

            if column == "#4":
                print("PRIKAZIVANJE:", table.item(item)["values"])
                self.show_private_key(table.item(item)["values"])

        table.bind("<Button-1>", private_table_click_detected)

    def show_public_keys(self, public_ring_container):

        table = ttk.Treeview(
            public_ring_container,
            columns=("name", "email", "keyid", "length", "n", "e"),
            show="headings"
        )

        table.heading("name", text="Ime")
        table.heading("email", text="Email")
        table.heading("keyid", text="Key ID")
        table.heading("length", text="Duzina kljuca")
        table.heading("n", text="n")
        table.heading("e", text="e")

        table.column("e", anchor = tk.CENTER)

        table.grid(row=1, column=0, sticky="nsew", columnspan=3)

        self.selected_public_key = None

        for row in self.pgp.public_key_ring:
            key= RSA.importKey(row["PublicKey"])
            table.insert("", tk.END, values=(row["Username"], row["UserEmail"], row["KeyID"], row["Length"], hex(key.n), hex(key.e)))

        def public_table_click_detected(event):
            item = table.identify_row(event.y)

            if not item:
                return

            self.selected_public_key = table.item(item)["values"][2]
            print(self.selected_public_key)

        table.bind("<Button-1>", public_table_click_detected)

    def configure_public_ring_tab(self):

        self.public_ring_container = ttk.Frame(self.public_ring_tab)
        public_ring_container = self.public_ring_container
        public_ring_container.pack(fill="both", expand=True)

        public_ring_container.rowconfigure(0, weight=1)
        public_ring_container.rowconfigure(1, weight=4)
        public_ring_container.columnconfigure(0, weight=1)
        public_ring_container.columnconfigure(1, weight=1)
        public_ring_container.columnconfigure(2, weight=1)

        import_keys_button = ttk.Button(
            public_ring_container,
            padding=10,
            text="Uvezite ključ",
            command=self.import_public_key
        )
        import_keys_button.grid(row=0, column=0)

        export_keys_button = ttk.Button(
            public_ring_container,
            padding=10,
            text="Izvezite ključ",
            command=self.export_public_key
        )
        export_keys_button.grid(row=0, column=1)

        delete_key_button = ttk.Button(
            public_ring_container,
            padding=10,
            text="Izbrisite kljuc",
            command=self.delete_public_key_popup
        )
        delete_key_button.grid(row=0, column=2)

        self.show_public_keys(public_ring_container)

    def configure_private_ring_tab(self):
        pr_container = ttk.Frame(self.private_ring_tab)
        pr_container.pack(fill="both", expand=True)

        pr_container.rowconfigure(0, weight=1)
        pr_container.rowconfigure(1, weight=5)
        pr_container.columnconfigure(0, weight=1)

        # Control panel
        top_panel = ttk.Frame(pr_container)
        top_panel.grid(row=0, column=0, sticky="nsew")
        top_panel.columnconfigure(0, weight=4)
        top_panel.columnconfigure(1, weight=1)

        # Bottom panel
        self.private_key_bottom_panel = ttk.Frame(pr_container)
        self.private_key_bottom_panel.grid(row=1, column=0, sticky="nsew")
        self.private_key_bottom_panel.rowconfigure(0, weight=1)
        self.private_key_bottom_panel.columnconfigure(0, weight=1)

        # Control panel content
        top_left_panel = ttk.Frame(top_panel)
        top_left_panel.grid(row=0, column=0, sticky="nsew")

        top_right_panel = ttk.Frame(top_panel)
        top_right_panel.grid(row=0, column=1, sticky="nsew", padx = 50)

        # Name and email
        top_left_panel.columnconfigure(0, weight=1)

        ttk.Label(top_left_panel, text="Ime:").grid(row=0, column=0, sticky="w", pady=(5, 0))
        self.name_entry = ttk.Entry(top_left_panel)
        self.name_entry.grid(row=1, column=0, sticky="ew", padx=5)

        ttk.Label(top_left_panel, text="Email:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.email_entry = ttk.Entry(top_left_panel)
        self.email_entry.grid(row=3, column=0, sticky="ew", padx=5)

        # Key size
        self.key_size_var = tk.IntVar(value=2048)

        ttk.Label(top_right_panel, text="Veličina ključa:").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            top_right_panel,
            text="1024",
            variable=self.key_size_var,
            value=1024
        ).grid(row=1, column=0, sticky="w")

        ttk.Radiobutton(
            top_right_panel,
            text="2048",
            variable=self.key_size_var,
            value=2048
        ).grid(row=2, column=0, sticky="w")


        # Generate button
        generate_key_button = ttk.Button(
            top_right_panel,
            text="Generišite ključ",
            command=self.generate_key,
            padding = 5
        )
        generate_key_button.grid(row=3, column=0, sticky="w")

        # Export and import buttons
        import_key_pair_button = ttk.Button(
            top_right_panel,
            text="Uvezite par ključeva",
            command=self.import_key_pair,
            padding = 5,
            width = 50
        )
        import_key_pair_button.grid(row=1, column=2, sticky="e", padx = 80)

        export_key_pair_button = ttk.Button(
            top_right_panel,
            text="Izvezite par ključeva",
            command=self.export_key_pair,
            padding = 5,
            width = 50
        )
        export_key_pair_button.grid(row=2, column=2, sticky="e", padx = 80)

        #delete key pair button

        delete_key_pair_button = ttk.Button(
            top_right_panel,
            text="Izbrisite odabrani kljuc",
            command=self.delete_private_key_popup,
            padding = 5,
            width = 50
        )
        delete_key_pair_button.grid(row=3, column=2, sticky="e", padx = 80)

        self.show_private_keys()

        # Bottom panel contents

    def generate_key(self):
        if not self.name_entry.get() or not self.email_entry.get():
            return

        password = self.prompt_password()
        if password is None:
            return

        name = self.name_entry.get()
        email = self.email_entry.get()
        length = self.key_size_var.get()

        self.pgp.generate_key_pair(name, email, password, length)

        self.update_key_options()
        self.show_private_keys()
        self.selected_key_pair = None

    # Helper functions
    def report_error(self, error_msg):
        messagebox.showerror("Greška", error_msg)

    def report_success(self, msg):
        messagebox.showinfo("Uspeh", msg)

    # Import helper functions
    def choose_PEM_key(self):
        filename = filedialog.askopenfilename(
            parent=self.root,
            title="Izaberite ključ za uvoz",
            defaultextension=".pem",
            filetypes=[
                ("PEM files", "*.pem"),
                ("All files", "*.*")
            ]
        )
        if not filename:
            return None

        return filename

    def public_key_dialog_window(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Uvoz javnog ključa")
        dialog.resizable(False, False)

        self.public_key_import_dialog_result = None

        ttk.Label(dialog, text="Ime:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        username_entry = ttk.Entry(dialog)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(dialog, text="Email:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        email_entry = ttk.Entry(dialog)
        email_entry.grid(row=1, column=1, padx=10, pady=5)

        def submit():
            self.public_key_import_dialog_result = {
                "username": username_entry.get(),
                "email": email_entry.get()
            }
            dialog.destroy()

        ttk.Button(dialog, text="Ok", command=submit).grid(
            row=2, column=0, columnspan=2, pady=10
        )

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        return self.public_key_import_dialog_result

    def key_pair_dialog_window(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Uvoz para ključeva")
        dialog.resizable(False, False)

        self.key_pair_import_dialog_result = None

        ttk.Label(dialog, text="Ime:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        username_entry = ttk.Entry(dialog)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(dialog, text="Email:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        email_entry = ttk.Entry(dialog)
        email_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        password_entry = ttk.Entry(dialog)
        password_entry.grid(row=2, column=1, padx=10, pady=5)

        def submit():
            self.key_pair_import_dialog_result = {
                "username": username_entry.get(),
                "email": email_entry.get(),
                "password": password_entry.get()
            }
            dialog.destroy()

        ttk.Button(dialog, text="Ok", command=submit).grid(
            row=3, column=0, columnspan=2, pady=10
        )

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        return self.key_pair_import_dialog_result

    def import_public_key(self):
        filename = self.choose_PEM_key()
        if filename is None:
            return

        info = self.public_key_dialog_window()
        if info is None:
            return

        username = info['username']
        email = info['email']

        self.selected_public_key = None
        try:
            self.pgp.import_public_key_PEM(filename, username, email)
            self.report_success("Javni ključ je uspešno uvezen")
            self.show_public_keys(self.public_ring_container)
        except Exception as e:
            self.report_error(e)


    def import_key_pair(self):
        filename = self.choose_PEM_key()
        if filename is None:
            return

        info = self.key_pair_dialog_window()
        if info is None:
            return

        username = info['username']
        email = info['email']
        password = info['password']

        self.selected_public_key = None
        try:
            self.pgp.import_private_key_PEM(filename, username, email, password)
            self.report_success("Par ključeva je uspešno uvezen")
            self.show_private_keys()
        except Exception as e:
            self.report_error(e)

    def export_public_key(self):
        try:
            if self.selected_public_key is None:
                raise Exception("Nije izabran ključ za izvoz")

            filename = self.choose_export_destination()
            if filename is None:
                return

            self.pgp.export_public_key_PEM(self.selected_public_key, filename)
            self.report_success("Javni ključ je uspešno izvezen")
            self.selected_public_key = None
        except Exception as e:
            self.report_error(e)

    def export_key_pair(self):
        try:
            if self.selected_key_pair is None:
                raise Exception("Nije izabran ključ za izvoz")

            filename = self.choose_export_destination()
            if filename is None:
                return

            password = self.prompt_password()
            if password is None:
                return

            self.pgp.export_private_key_PEM(self.selected_key_pair, filename, password)
            self.report_success("Par ključeva je uspešno izvezen")
            self.selected_key_pair = None
        except Exception as e:
            self.report_error(e)

    def start(self):
        self.root.mainloop()
        self.pgp.save_key_rings()


# TODO Connect the back for key import (username, email for both - +password for pair)
if __name__ == "__main__":
    app = App()
    app.start()
