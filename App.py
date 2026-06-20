import tkinter as tk
from tkinter import ttk


class App:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PGP App")
        self.root.geometry("1200x700")

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

        # Placeholder

        ttk.Label(self.send_tab, text="Slanje").pack(pady=20)
        ttk.Label(self.receive_tab, text="Prijem").pack(pady=20)
        ttk.Label(self.public_ring_tab, text="Javni Prsten").pack(pady=20)
        ttk.Label(self.private_ring_tab, text="Privatni Prsten").pack(pady=20)


    def start(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = App()
    app.start()
