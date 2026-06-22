import tkinter as tk
from tkinter import ttk, filedialog, simpledialog

from PGP import PGP


class App:

    #TODO Spusti ovo ispod konstruktora
    def choose_file(self):
        filename = filedialog.askopenfilename(title="Izaberi fajl")

        if filename:
            self.file_label.config(text=filename)
            self.file = filename
        else:
            self.file = None

    def save(self):
        pass

    def decrypt(self):

        if self.file is None:
            popup = tk.Toplevel(self.root)
            popup.title("GRESKA")
            popup.geometry("300x200")
            ttk.Label(popup, text="Mora se odabrati fajl za citanje!").pack(pady=50)
            ttk.Button(popup, text="OK", command=popup.destroy).pack()
            return

        #TODO ovde ne treba samo da se dohvati ime nego da se pozove funkcija za citanje
        decrypted_message = self.file_label.cget("text")
        verified = True

        if verified:
            bg_color = "#C3FCBB"
        else:
            bg_color = "#FA918F"

        self.message_text.config(state="normal")
        self.message_text = tk.Text(self.receive_tab, width=100, height=5, bg=bg_color)
        self.message_text.grid(row=4, column=1)
        self.message_text.insert(tk.INSERT, decrypted_message)
        self.message_text.config(state="disabled")


        if verified:
            ttk.Button(self.receive_tab, text="Izaberi destinaciju", command=self.choose_file, width=20).grid(row=10, column=0, pady=10)
            self.file_destination_label = ttk.Label(self.receive_tab, text="Nijedan fajl nije izabran")
            self.file_destination_label.grid(row=10, column=1)
            ttk.Button(self.receive_tab, text="Sacuvaj", command=self.save, width=20).grid(row=11, column=0, pady=10)

    def configure_receive_tab(self):
        #RECIEVE TAB

        self.file = None
        self.file_destination_label = None

        ttk.Button(self.receive_tab, text="Izaberi fajl", command=self.choose_file, width=20).grid(row=1, column=0, pady=10)
        self.file_label = ttk.Label(self.receive_tab, text="Nijedan fajl nije izabran")
        self.file_label.grid(row=1, column=1)
        ttk.Button(self.receive_tab, text="Procitaj", command = self.decrypt, width=20).grid(row=2, column=0, pady=10)

        self.message_text = tk.Text(self.receive_tab, width=100, height=5)
        self.message_text.grid(row=4, column=1)
        self.message_text.insert(tk.INSERT, "")
        self.message_text.config(state="disabled")

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

        # Placeholder
        ttk.Label(self.public_ring_tab, text="Javni Prsten").pack(pady=20)

        self.configure_private_ring_tab()


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
        send_button = ttk.Button(bottom_panel, text="Pošalji", command=self.send_message)
        send_button.pack(side="right", padx=10)

    def update_key_options(self):
        private_keys = []
        public_keys = []

        for row in self.pgp.private_key_ring:
            private_keys.append(row["KeyID"])

        for row in self.pgp.public_key_ring:
            public_keys.append(row["KeyID"])

        self.sign_private_key_options.configure(values=private_keys if len(private_keys) > 0 else [""])
        self.sign_private_key_options.current(0)
        self.encrypt_public_key_options.configure(values=public_keys if len(public_keys) > 0 else [""])
        self.encrypt_public_key_options.current(0)

    def send_message(self):
        content = self.send_text_area.get("1.0", "end").strip()

        if self.send_encrypt_bool.get() and not self.encrypt_public_key_options.get():
            return # No key selected

        if self.send_sign_bool.get() and not self.sign_private_key_options.get():
            return # No key selected

        password = None
        if self.send_sign_bool.get():
            password = self.prompt_password()

            if password is None:
                return

        filename = self.choose_send_destination()
        if filename is None:
            return

        options = {
            "sign": self.send_sign_bool.get(),
            "sign_key": int(self.sign_private_key_options.get()) if self.send_sign_bool.get() else None,
            "sign_key_password": password,
            "zip": self.send_zip_bool.get(),
            "encrypt": self.send_encrypt_bool.get(),
            "enc_public_key": int(self.encrypt_public_key_options.get()) if self.send_encrypt_bool.get() else None,
            "enc_algorithm": self.send_enc_algorithm.get() if self.send_encrypt_bool.get() else None,
            "radix64": self.send_radix64_bool.get(),
        }

        self.pgp.send_message(content, options, filename)

    def prompt_password(self):
        password = simpledialog.askstring(
            "Lozinka",
            "Unesite lozinku za privatni ključ:",
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

    def update_encrypt_key(self, *args):
        if self.send_encrypt_bool.get():
            state = "normal"
        else:
            state = "disabled"

        self.encrypt_public_key_options.configure(state="readonly" if state == "normal" else "disabled")

        self.send_aes_radio.configure(state=state)
        self.send_3des_radio.configure(state=state)

    def update_sign_key(self, *args):
        if self.send_sign_bool.get():
            self.sign_private_key_options.configure(state="readonly")
        else:
            self.sign_private_key_options.configure(state="disabled")



    def configure_private_ring_tab(self):
        pr_container = ttk.Frame(self.private_ring_tab)
        pr_container.pack(fill="both", expand=True)

        pr_container.columnconfigure(0, weight=1)
        pr_container.rowconfigure(0, weight=1)
        pr_container.rowconfigure(1, weight=2)

        # Control panel
        top_panel = ttk.Frame(pr_container)
        top_panel.grid(row=0, column=0, sticky="nsew")
        top_panel.columnconfigure(0, weight=1)
        top_panel.columnconfigure(1, weight=1)
        top_panel.columnconfigure(2, weight=1)
        top_panel.rowconfigure(0, weight=1)

        # Bottom panel
        bottom_panel = ttk.Frame(pr_container)
        bottom_panel.grid(row=1, column=0, sticky="nsew")

        # Control panel content
        top_left_panel = ttk.Frame(top_panel)
        top_left_panel.grid(row=0, column=0, sticky="nsew")

        top_mid_panel = ttk.Frame(top_panel)
        top_mid_panel.grid(row=0, column=1, sticky="nsew")

        top_right_panel = ttk.Frame(top_panel)
        top_right_panel.grid(row=0, column=2, sticky="nsew")


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

        ttk.Label(top_mid_panel, text="Veličina ključa:").grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(
            top_mid_panel,
            text="1024",
            variable=self.key_size_var,
            value=1024
        ).grid(row=1, column=0, sticky="w")

        ttk.Radiobutton(
            top_mid_panel,
            text="2048",
            variable=self.key_size_var,
            value=2048
        ).grid(row=2, column=0, sticky="w")


        # Generate button
        generate_key_button = ttk.Button(
            top_right_panel,
            text="Generišite ključ",
            command=self.generate_key
        )
        generate_key_button.pack()


        # Bottom panel contents
        send_text_area = tk.Text(bottom_panel, wrap="word")
        send_text_area.pack(fill="both", expand=True)


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


    def start(self):
        self.root.mainloop()
        self.pgp.save_key_rings()


if __name__ == "__main__":
    app = App()
    app.start()
