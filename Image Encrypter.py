def encrypt(byte):
        loc=filedialog.askopenfilename(filetypes=(("Image files",("*.jpg","*.png","*.jpeg")),))
        with open (loc,'rb') as f:
                img=base64.b64encode(f.read())
        key = get_random_bytes(byte)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(img)
        with open(os.path.dirname(os.path.abspath(loc))+"\Encrypted Image.bin", "wb") as f:
                f.write(cipher.nonce)
                f.write(tag)
                f.write(key)
                f.write(ciphertext)
        successful()
def decrypt():
        loc=filedialog.askopenfilename(filetypes=(("Bin files","*.bin"),))
        for byte in [16,24,32]:
                try:  
                        with open(loc, "rb") as f:
                                nonce=f.read(16)
                                tag=f.read(16)
                                key=f.read(byte)
                                ciphertext=f.read(-1)
                                cipher = AES.new(key, AES.MODE_EAX, nonce)
                                img=base64.b64decode(cipher.decrypt_and_verify(ciphertext, tag))
                        with open(os.path.dirname(os.path.abspath(loc))+"\Decrypted Image.jpg", "wb") as f:
                                f.write(img)
                        successful()
                        break
                except:
                        if(byte==32):
                                error()
                        else:
                                pass
def successful():
        suc=CTk()
        suc.focus_force()
        suc.geometry('500x250')
        suc.title('Successful')
        lab_1=CTkLabel(suc,text='Successful',fg_color=None,text_color="white",text_font=('bold',40)).place(relx=0.5,y=50,anchor='center')
        but_1=CTkButton(suc,text='Exit',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=quit).place(relx=0.5,y=150,anchor='center')
        suc.mainloop()
def error():
        err=CTk()
        err.focus_force()
        err.geometry('500x250')
        err.title('Unsuccessful')
        lab_1=CTkLabel(err,text='Error',fg_color=None,text_color="white",text_font=('bold',40)).place(relx=0.5,y=50,anchor='center')
        lab_2=CTkLabel(err,text='Encrypted file\nhas been tampered',fg_color=None,text_color="red",text_font=('bold',20)).place(relx=0.5,y=125,anchor='center')
        but_1=CTkButton(err,text='Home',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=lambda:[err.destroy(),main()]).place(relx=0.25,y=200,anchor='center')
        but_2=CTkButton(err,text='Exit',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=quit).place(relx=0.75,y=200,anchor='center')
        err.mainloop()
def main():
    main=CTk()
    main.geometry('500x500')
    main.title('Image Encrypter')
    lab_1=CTkLabel(main,text='Image Encryption',fg_color=None,text_color="white",text_font=('bold',40)).place(relx=0.5,y=50,anchor='center')
    but_1=CTkButton(main,text='Encrypt\n(128 bit)',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=lambda:[main.destroy(),encrypt(16)]).place(relx=0.25,y=200,anchor='center')
    but_2=CTkButton(main,text='Encrypt\n(192 bit)',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=lambda:[main.destroy(),encrypt(24)]).place(relx=0.75,y=200,anchor='center')
    but_3=CTkButton(main,text='Encrypt\n(256 bit)',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=lambda:[main.destroy(),encrypt(32)]).place(relx=0.25,y=350,anchor='center')
    but_4=CTkButton(main,text='Decrypt',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=lambda:[main.destroy(),decrypt()]).place(relx=0.75,y=350,anchor='center')
    but_5=CTkButton(main,text='Exit',fg_color='black',text_color="white",text_font=('bold',20),corner_radius=8,hover_color="#545352",command=quit).place(relx=0.5,y=425,anchor='center')
    main.mainloop()
from tkinter import*
from customtkinter import *
set_appearance_mode("dark")

from tkinter import filedialog
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os,sys
main()
