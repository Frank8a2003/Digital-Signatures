import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import sqlite3
import hashlib
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import gnupg
from pypdf import PdfReader
import requests
import csv
from datetime import datetime, timedelta

# Conectar a la base de datos SQLite
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Crear la tabla de usuarios si no existe
c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                keyid TEXT,
                last_login TIMESTAMP
            )''')

# Crear la tabla de iniciativas si no existe
c.execute('''CREATE TABLE IF NOT EXISTS initiatives (
                initiative_id INTEGER PRIMARY KEY,
                url TEXT,
                hashant TEXT,
                hashnew TEXT,
                sign TEXT,
                first_mod TIMESTAMP,
                last_mod TIMESTAMP,
                user TEXT
            )''')

# Insertar usuarios en la base de datos (solo la primera vez)
users_data = [
    ("user1", "password1", "D58E9ED3FFBB71FEF96C59161AE642D5C8246CF0", None),
    ("user2", "password2", "ED4846DFBA86F067FF46A3FE187800EE48592EC6", None),
    ("user3", "password3", "C8AF2EAE8DC610159881C6DA43CB22FA983B0FC1", None),
    ("user4", "password4", "FB9EBE5D3B15F6D54E9506863751D1C9890CA901", None),
    ("admin", "admin1234", "144EBC2933341539EC9B930BE79F8446610BA8E6", None)
]

# Insertar usuarios si no existen ya en la base de datos
for user in users_data:
    c.execute("INSERT OR IGNORE INTO users (username, password, keyid, last_login) VALUES (?, ?, ?, ?)", user)

conn.commit()

def signed_doc(url,gpg_key_id):
    hasher = hashlib.sha256()
    response = requests.get(url, stream=True)
    if response.status_code != 200:
        print("The file could not be downloaded.")

    for letter in response.iter_content():
        if letter:
            hasher.update(letter)
    
    return hasher.hexdigest(), clean_key(sign_document(hasher.hexdigest(),gpg,gpg_key_id))

def sign_document(pdf_content, gpg, gpg_key_id):
    signed_data = gpg.sign(pdf_content, keyid=gpg_key_id)
    if signed_data:
        return str(signed_data)
    

def clean_key(signed_data):
    s = ""
    bandera = False
    for i in range(28, len(signed_data)):
        if signed_data[i-29:i] == "-----BEGIN PGP SIGNATURE-----":
            bandera = True
            continue
        if bandera:
            s += signed_data[i]
    return s[:-29]

# Inicializar GPG
gpg = gnupg.GPG(gnupghome='C:\\Users\\frank\\AppData\\Roaming\\gnupg', gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Firma de Documentos PDF")
        self.root.geometry('600x400')
        self.root.configure(bg='#282C34')
        
        self.logged_in_user = None
        
        self.style = ttk.Style()
        self.style.configure('TLabel', background='#282C34', foreground='#61AFEF', font=('Arial', 12, 'bold'))
        self.style.configure('TEntry', font=('Arial', 12))
        self.style.configure('TButton', font=('Arial', 12, 'bold'), background='#61AFEF', foreground='#282C34', padding=6)
        
        self.style.map('TButton',
            foreground=[('active', '#FFFFFF'), ('!active', '#282C34')],
            background=[('active', '#61AFEF'), ('!active', '#61AFEF')]
        )
        
        self.label_user = ttk.Label(root, text="Nombre de usuario:")
        self.label_user.pack(pady=(20, 5))
        
        self.entry_user = ttk.Entry(root)
        self.entry_user.pack(pady=5, padx=20)
        
        self.label_password = ttk.Label(root, text="Contraseña:")
        self.label_password.pack(pady=5)
        
        self.entry_password = ttk.Entry(root, show='*')
        self.entry_password.pack(pady=5, padx=20)
        
        self.button_login = ttk.Button(root, text="Iniciar Sesión", command=self.login)
        self.button_login.pack(pady=(20, 10))

    def login(self):
        
        username = self.entry_user.get()
        password = self.entry_password.get()
        
        c.execute("SELECT password, keyid, last_login FROM users WHERE username=?", (username,))
        user = c.fetchone()
        
        if username=="admin" and password=="admin1234":
            self.nameUsuario="admin"
            self.show_Admin()
            
        elif user and user[0] == password:
            self.nameUsuario=username
            gpg_key_id = user[1]
            last_login = user[2]
            
            if last_login:
                last_login_date = datetime.strptime(last_login, '%Y-%m-%d %H:%M:%S')
                if datetime.now() - last_login_date > timedelta(hours=1):
                    messagebox.showerror("Error", "El acceso está bloqueado debido a inactividad de más de un mes.")
                    return
            
            c.execute("UPDATE users SET last_login=? WHERE username=?", (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
            conn.commit()
            
            self.logged_in_user = username
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Nombre de usuario o contraseña incorrectos.")
    
    def show_Admin(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.button_generate_report = ttk.Button(self.root, text="Generar reporte y actualizar", command=self.generate_report)
        self.button_generate_report.pack(pady=10)
    
    def generate_report(self):
        messagebox.showinfo("Boton correcto", "Se ha generado el reporte correctamente")
        c.execute('SELECT * FROM initiatives')
        rows = c.fetchall()
        username=self.nameUsuario
        with open('initiatives_report.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['initiative_id', 'status'])  # Escribir el encabezado
            for row in rows:
                initiative_id, url, hashant, hashnew, sign, first_mod, last_mod, user  = row
                if hashnew == hashant:
                    writer.writerow([f'La iniciativa {initiative_id} no ha sido modificada desde la ultima revision, fue creada el dia {first_mod} y la ultima revision fue el: {last_mod},  hecha por: {user}' ])
                else:
                   writer.writerow([f'La iniciativa {initiative_id} fue modificada desde la ultima revision, fue creada el dia {first_mod} y la ultima revision fue el: {last_mod},  hecha por: {user}' ])
                    
                c.execute("UPDATE initiatives SET hashant=?,last_mod=?,user=? WHERE initiative_id=?", (hashnew,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),username, initiative_id))

        conn.close()
        
    def show_main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.label_main = ttk.Label(self.root, text=f"Bienvenido, {self.logged_in_user}")
        self.label_main.pack(pady=(20, 5))
        
        self.button_add_initiative = ttk.Button(self.root, text="Agregar Iniciativa", command=self.add_initiative)
        self.button_add_initiative.pack(pady=10)
        
        self.button_sign_document = ttk.Button(self.root, text="Firmar Documento", command=self.sign_initiative_document)
        self.button_sign_document.pack(pady=10)

    def add_initiative(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.label_initiative_id = ttk.Label(self.root, text="ID de la Iniciativa:")
        self.label_initiative_id.pack(pady=(20, 5))
        
        self.entry_initiative_id = ttk.Entry(self.root)
        self.entry_initiative_id.pack(pady=5, padx=20)
        
        self.label_url = ttk.Label(self.root, text="URL de la Iniciativa:")
        self.label_url.pack(pady=5)
        
        self.entry_url = ttk.Entry(self.root)
        self.entry_url.pack(pady=5, padx=20)
        
        self.button_save_initiative = ttk.Button(self.root, text="Guardar y firmar Iniciativa", command=self.save_initiative)
        self.button_save_initiative.pack(pady=(20, 10))
        
        self.button_back = ttk.Button(self.root, text="Volver", command=self.show_main_menu)
        self.button_back.pack(pady=(10, 10))

    def save_initiative(self):
        initiative_id = self.entry_initiative_id.get()
        url = self.entry_url.get()
        username=self.nameUsuario
        c.execute("SELECT password, keyid, last_login FROM users WHERE username=?", (username,))
        user = c.fetchone()
        gpg_key_id=user[1]
        if initiative_id and url:
            local_filename = f'iniciativa_{initiative_id}.pdf'
            hashD, signed_content = signed_doc(url, gpg_key_id)
            # Guardar los detalles de la firma en un archivo CSV
            with open('signatures.csv', 'a', newline='') as csvfile:
                fieldnames = ['username', 'timestamp','initiative','signed_content']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                writer.writerow({'username': username, 'timestamp': timestamp, 'initiative':initiative_id, 'signed_content': signed_content})
                
            c.execute("INSERT INTO initiatives (initiative_id, url, hashant, hashnew, sign, first_mod, last_mod, user) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (initiative_id, url, hashD, hashD, signed_content,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),datetime.now().strftime('%Y-%m-%d %H:%M:%S'),username))
            conn.commit()
            messagebox.showinfo("Éxito", "Iniciativa guardada correctamente.")
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Ningún campo puede estar vacío.")

    def sign_initiative_document(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.label_initiative_id = ttk.Label(self.root, text="ID de la Iniciativa:")
        self.label_initiative_id.pack(pady=(20, 5))
        
        self.entry_initiative_id = ttk.Entry(self.root)
        self.entry_initiative_id.pack(pady=5, padx=20)
        
        self.button_sign = ttk.Button(self.root, text="Firmar Documento", command=self.sign_document)
        self.button_sign.pack(pady=(20, 10))
        
        self.button_back = ttk.Button(self.root, text="Volver", command=self.show_main_menu)
        self.button_back.pack(pady=(10, 10))

    def sign_document(self):
        initiative_id = self.entry_initiative_id.get()
        c.execute("SELECT url,hashnew FROM initiatives WHERE initiative_id=?", (initiative_id,))
        initiative = c.fetchone()
        username=self.nameUsuario
        c.execute("SELECT password, keyid, last_login FROM users WHERE username=?", (username,))
        user = c.fetchone()
        gpg_key_id=user[1]
        if initiative:
            url = initiative[0]
            hashD, signed_content = signed_doc(url, gpg_key_id)
            
                # Guardar los detalles de la firma en un archivo CSV
            with open('signatures.csv', 'a', newline='') as csvfile:
                fieldnames = ['username', 'timestamp', 'signed_content']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                writer.writerow({'username': username, 'timestamp': timestamp, 'signed_content': signed_content})
            
            if initiative[1]==hashD:
                messagebox.showinfo("Exito","La iniciativa no se ha modificado desde el ultimo chequeo")
            else:
                messagebox.showinfo("Cuidado","¡Revisar la iniciativa! Se ha modificado")
                    
            c.execute("UPDATE initiatives SET hashnew=?, sign=?, last_mod=?, user=? WHERE initiative_id=?", (hashD,signed_content, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),username, initiative_id))
            conn.commit()
        else:
            messagebox.showerror("Error", "No exite esta iniciativa")
            
root = tk.Tk()
app = App(root)
root.mainloop()
conn.close()
