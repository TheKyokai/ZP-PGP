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

        # Placeholder

        ttk.Label(self.public_ring_tab, text="Javni Prsten").pack(pady=20)
        ttk.Label(self.private_ring_tab, text="Privatni Prsten").pack(pady=20)


    def start(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = App()
    app.start()
