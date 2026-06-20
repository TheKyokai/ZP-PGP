import tkinter as tk
from tkinter import ttk, filedialog


class App:

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

    def recieve_tab_conifgure(self):
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

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Tabs
        self.send_tab = ttk.Frame(self.notebook)
        self.receive_tab = ttk.Frame(self.notebook)
        self.recieve_tab_conifgure()
        self.public_ring_tab = ttk.Frame(self.notebook)
        self.private_ring_tab = ttk.Frame(self.notebook)


        self.notebook.add(self.send_tab, text="Slanje")
        self.notebook.add(self.receive_tab, text="Prijem")
        self.notebook.add(self.public_ring_tab, text="Javni Prsten")
        self.notebook.add(self.private_ring_tab, text="Privatni Prsten")

        self.configure_send_tab()

        # Placeholder

        ttk.Label(self.public_ring_tab, text="Javni Prsten").pack(pady=20)
        ttk.Label(self.private_ring_tab, text="Privatni Prsten").pack(pady=20)


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
            text='3DES',
            variable=self.send_enc_algorithm,
            value='3DES'
        )
        self.send_aes_radio.configure(state='disabled')
        self.send_aes_radio.pack(anchor="w", pady=5)
        self.send_3des_radio.configure(state='disabled')
        self.send_3des_radio.pack(anchor="w", pady=5)


        self.encrypt_public_key_options = ttk.Combobox(left_panel, values=["Key 1", "Key 2"])
        self.encrypt_public_key_options.current(0)
        self.encrypt_public_key_options.configure(state="disabled")
        self.encrypt_public_key_options.pack(anchor="w", pady=(2, 10))
        self.send_encrypt_bool.trace_add("write", self.update_encrypt_key)


        sign_checkbox = ttk.Checkbutton(left_panel, text="Potpisivanje", variable=self.send_sign_bool)
        sign_checkbox.pack(anchor="w", pady=5)

        self.sign_private_key_options = ttk.Combobox(left_panel, values=["PKey 1", "PKey 2", "PKey 3"])
        self.sign_private_key_options.current(0)
        self.sign_private_key_options.configure(state="disabled")
        self.sign_private_key_options.pack(anchor="w", pady=(2, 10))
        self.send_sign_bool.trace_add("write", self.update_sign_key)

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

    def send_message(self):
        content = self.send_text_area.get("1.0", "end").strip()
        options = {
            "sign": self.send_sign_bool.get(),
            "sign_key": self.sign_private_key_options.get() if self.send_sign_bool.get() else None,
            "zip": self.send_zip_bool.get(),
            "encrypt": self.send_encrypt_bool.get(),
            "enc_public_key": self.encrypt_public_key_options.get() if self.send_encrypt_bool.get() else None,
            "enc_elgorithm": self.send_enc_algorithm.get() if self.send_encrypt_bool.get() else None,
            "radix64": self.send_radix64_bool.get(),
        }

        print("\n===   PGP OPTIONS    ===")
        for key, value in options.items():
            print(f"{key}: {value}")
        print("===   SEND CONTENT   ===")
        print(content)
        print("=== SEND CONTENT END ===")


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


    def start(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = App()
    app.start()
