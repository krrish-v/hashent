#_________________________________________________________________
# Copyright 2022 krrish, All rights reserved.
# You are not allowed to use this code to represent yoursself in the front of outsiders as you do from stackoverflow or form github,
# Coperate with us. THANK YOU
# Written by a Indian Developer - username on GitHub: @krrish-v
#__________________________________________________________________

import os
import sys
from tkinter import messagebox
import tkinter
import base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from tinyec import registry
import hashlib
import binascii
import secrets
from hmac import compare_digest

def necessary():
    #check that the folder is present or not 
    try:
        try:
            with open('.hashent[not_to_delete]/certificate/certificate.pem') as f_:
                f_.close()
        except PermissionError:
            try:
                messagebox.showerror('permission error', 'Start it with magic word "sudo" or give administrative access')
                sys.exit()
            except:
                sys.exit()
    
    # if it not present or aything missing, so it's will create the setup(basically for the first time usage)
    except FileNotFoundError:
        try:
            #create a folder and if present move to next and create keys
            os.mkdir('.hashent[not_to_delete]')
            path = os.path.join('.hashent[not_to_delete]', 'certificate')
            os.mkdir(path)
        except:
            None
        
        # create a keys for encrypting of data encryption keys
        #create random string
        random_string = str()
        for _ in range(256):
            random_integer = secrets.randbelow(9)
            random_string += str(random_integer)
        
        print(random_string)
        private = hashlib.sha3_256(int.to_bytes(int(random_string), 256, 'big')).hexdigest()
        # insert the keys in a file
        try:
            f2 = open('.hashent[not_to_delete]/certificate/certificate.pem', 'w')
            f2.write(private)
            f2.close()
        except:
            None

        # create a settings file/folder, if not present
        try:
            os.mkdir('.hashent[not_to_delete]/settings')
        except:
            None
        
        f3 = open('.hashent[not_to_delete]/settings/setting', 'w')
        sett = "__________##_Basic_Settings[don't_touch_this_text_file]______________\nECC\n1\n384"
        f3.write(sett)
        f3.close()

        #create a private keys folder
        try:
            os.mkdir('private_keys')
        except:
            None

        #make a cert files not readable and writeables for nonroot users
        #os.chmod('.hashent[not_to_delete]/certificate/certificate.pem', stat.S_IWRITE)

        #again read the file to confirm
        try:
            with open('.hashent[not_to_delete]/certificate/certificate.pem') as f_:
                f_.close()
        except PermissionError:
            try:
                messagebox.showerror('permission error', 'Start it with magic word "sudo" or give administrative access')
                sys.exit()
            except:
                sys.exit()

import tkinter.ttk as ttk
from ttkthemes import ThemedStyle
from tkinter import *

#get password for salting
sal = []
h = []
def get_salt():
    has= ttk.tkinter.Tk()
    ttk.Style().configure("Treeview", background="black", foreground="white")
    has.title('inosec(salt)')
    style = ThemedStyle(has)
    style.set_theme("black")
    has.geometry("300x180")
    h.append(0)

    def close_win():
        messagebox.showwarning('Keep in mind', 'make sure you dont forget if you are entring first time')
        if len(password.get()) >= 12:
            sal.append(password.get().encode())
            has.destroy()
        else:
            try:
                messagebox.showerror('error', 'Salt length should be 12 or more characters to stregthn security')
            except:
                None

    ttk.Label(has, text="Enter your unique salt carefully", font=('Helvetica',15)).pack(pady=20)

    password = ttk.Entry(has ,width=35)
    password.pack()

    ttk.Button(has, text="Next", command=close_win).pack(pady=20)
    has.configure(bg='black')
    has.mainloop()

# start the main script
def session():
    from tkinter import filedialog as fd
    import webbrowser
    
    # create a whole setup
    necessary()
    try:
        # it checks that the license is been seen or not
        fg = open('.hashent[not_to_delete]/settings/check_license')
        fg.close()
    except FileNotFoundError:
        # and if not it display a license as GUI
        listen()
        f_ = open('.hashent[not_to_delete]/settings/check_license', 'w')
        f_.close()

    while len(sal) <= 0:
        get_salt()
        if len(h) >= 0 and len(sal) == 0:
            sys.exit()
            break

    page = ttk.tkinter.Tk()
    ttk.Style().configure("Treeview", background="black", foreground="white")
    page.title('Hashent ## -v 120.5')
    style = ThemedStyle(page)
    style.set_theme("arc")
    #print(style.theme_names())
    
    #functions

    #it will display a html web page taht contains a its usage type
    def help():
        cmd.insert(END, '[+] Opening help page')
        try:
            webbrowser.open('https://it-inosec.blogspot.com/2021/08/open-source-programs.html')
        except:
            cmd.insert(END, '[-] Cannot able to open your webrowser visit https://github.com/krrish-dev/')

    # padding of data
    # this peice of source code is been pulled out from one of the one source library
    def add_padding(message: bytes, target_length: int) -> bytes:\
        #target length is key.bit_length() == 256, 384, 512...
        max_msglength = target_length - 11
        msglength = len(message)

        if msglength > max_msglength:
            raise OverflowError('%i bytes needed for message, but there is only'
                                ' space for %i' % (msglength, max_msglength))

        # Get random padding
        padding = b''
        padding_length = target_length - msglength - 3

        # We remove 0-bytes, so we'll end up with less padding than we've asked for,
        # so keep adding data until we're at the correct length.
        while len(padding) < padding_length:
            needed_bytes = padding_length - len(padding)

            # Always read at least 8 bytes more than we need, and trim off the rest
            # after removing the 0-bytes. This increases the chance of getting
            # enough bytes, especially when needed_bytes is small
            new_padding = os.urandom(needed_bytes + 5)
            new_padding = new_padding.replace(b'\x00', b'')
            padding = padding + new_padding[:needed_bytes]

        assert len(padding) == padding_length

        return b''.join([b'\x00\x02',
                         padding,
                         b'\x00',
                         message])
    
    #remove pading from decrypted message
    # this peice of source code is been pulled out from one of the one source library
    def remove_padding(msg: bytes):
        cleartext_marker_bad = not compare_digest(msg[:2], b'\x00\x02')
        sep_idx = msg.find(b'\x00', 2)
        sep_idx_bad = sep_idx < 10
        anything_bad = cleartext_marker_bad | sep_idx_bad

        if anything_bad:
            raise DecryptionError('Decryption failed')
        return msg[sep_idx + 1:]

    # it will read the cert file and encrypt the generated key
    def enc_key(keys: tuple):
        try:
            f1 = open('.hashent[not_to_delete]/certificate/certificate.pem', 'r')
            enc_ky = f1.read()
            f1.close()
        except:
            cmd.insert(END, '[-] Cant found the certificate file in a folder')
        # encryption og keys with AES_GCM
        try:
            _salt = sal[0]
            salt_hash = hashlib.sha3_256(_salt).hexdigest()
            dec_key = PBKDF2(enc_ky, salt_hash)

            kys = []
            # create a nonce and save it
            nonc = str()
            for i in range(16):
                num = secrets.randbelow(9)
                nonc+=str(num)
            
            iv = int.to_bytes(int(nonc), 16, 'big')
        except:
            None
        try:
            f2 = open('.hashent[not_to_delete]/certificate/cert_nonce.pem', 'wb')
            f2.write(iv)
            f2.close()
            #os.chmod('..hashent[not_to_delete]/certificate/cert_nonce.pem', stat.S_IWRITE)
        except:
            cmd.insert(END, '[-] Found difficulties in writting a file"nonce.pem"')

        try:
            for i in  range(0, len(keys)):
                nbit = len(keys[i]) + 12
                j = add_padding(keys[i], nbit)
                crip = AES.new(dec_key, AES.MODE_GCM, nonce=iv)
                enc_ = crip.encrypt_and_digest(j)
                enc_data, authtag = enc_
                whole_enc_key = enc_data + b', ' + authtag
                kys.append(whole_enc_key)
        except:
            cmd.insert(END, '[-] Error occurs in encryption the generated keys')
        
        return tuple(kys)

    # it will generate the encryption key based on the user selection
    def genk():
        ret = None
        try:
            #check that the key file is present or not nad of not, it generates
            f1 = open('.hashent[not_to_delete]/public__key.pem', 'rb')
            key = f1.read()
            f1.close()
            ret = True
            ifor = messagebox.askokcancel('Make sure', 'You had already generated the key file, generation new one may loss priviously encrypted files')
            if ifor == True:
                ret = False
        except:
            ret = False
        if ret == False:
            if varLi.get() == 'ECC': # taking data form the slected user option
                try:
                    setsave()
                    cmd.insert(END, '[+] Generating Keys...')
                    byyt = varList.get() # this is a number of bytes (-- bit kyes) to be generated
                    
                    bit_size = {
                        160: 'brainpoolP160r1',
                        192: 'brainpoolP192r1',
                        224: 'brainpoolP224r1',
                        256: 'brainpoolP256r1',
                        320: 'brainpoolP320r1',
                        384: 'brainpoolP384r1',
                        512: 'brainpoolP512r1'
                    }
                    
                    # ECC key generation
                    curve = registry.get_curve(bit_size[byyt])
                    pub_key = secrets.randbelow(curve.field.n)
                    pubKey = pub_key * curve.g
                    priv_key = pubKey.x + pubKey.y % 2

                    #create nonce random nmuber
                    nonc = str()
                    for i in range(16):
                        num = secrets.randbelow(9)
                        nonc+=str(num)
                    iv = int.to_bytes(int(nonc), 16, 'big')
                    
                    # encryption of keys
                    hash_ = enc_key((int.to_bytes(pub_key, 256, 'big'), int.to_bytes(priv_key, 256, 'big'), iv))

                    # writing a encrypted private key
                    try:
                        cmd.insert(END, '[+] Writing all generated keys in a seperate file file')
                        f4 = open('private_keys/private_key.pem', 'wb')
                        f4.write(hash_[1])
                        f4.close()
                        f5 = open('.hashent[not_to_delete]/public__key.pem', 'wb')
                        f5.write(hash_[0])
                        f5.close()
                        # write nonce file
                        f6 = open('private_keys/nonce.pem', 'wb')
                        f6.write(hash_[2])
                        f6.close()
                        cmd.insert(END, '[+] Keys Generated')
                    except:
                        cmd.insert(END, '[-] Found error in writing a key in files')
                except:
                    cmd.insert(END, '[-] Found error in generating keys')
        else:
            cmd.insert(END, '[-] Keys are already generated')

    # collenction of selected files
    def get_file():
        for i in filen.curselection():
            return filen.get(i)

    # decryption of ecrypted keys with cert file
    def dec_key():
        try:
            f1 = open('.hashent[not_to_delete]/certificate/certificate.pem', 'rb')
            enc_ky = f1.read()
            f1.close()

            _salt = sal[0] #get salt as a password
            salt_hash = hashlib.sha3_256(_salt).hexdigest()
            dec_key = PBKDF2(enc_ky, salt_hash)
            # reading a nonce from file
            f3 = open('.hashent[not_to_delete]/certificate/cert_nonce.pem', 'rb')
            nonc = f3.read()
            f3.close()
        except:
            cmd.insert(END, '[-] Some files for certificate are missing')

        try:
            f4 = open('private_keys/private_key.pem', 'rb')
            priv = f4.read()
            f4.close()
        except:
            cmd.insert(END, '[-] Cannot find privte key file, if moved it replace again')
        try:
            f5 = open('.hashent[not_to_delete]/public__key.pem', 'rb')
            pub = f5.read()
            f5.close()
        except:
            cmd.insert(END, '[-] Cannot find public key file')
            cmd.insert(END, '~Generate new one, make sure before generating new key. You cant decrypt previously encrypted files')
        try:
            f6 = open('private_keys/nonce.pem', 'rb')
            nonc_enc = f6.read()
            f6.close()
        except:
            cmd.insert(END, '[-] nonce.pem file is not been found, if had moved the folder/file make sure to provide directory path')
        
        dec_ky = []
        try:
            enc_key = (pub, priv, nonc_enc)
            for i in range(0, len(enc_key)):
                dcrip = AES.new(dec_key, AES.MODE_GCM, nonce=nonc)
                # seperating encrypted data and authtag
                enc_data = tuple(map(bytes, enc_key[i].split(b', ')))

                decry = dcrip.decrypt_and_verify(enc_data[0], enc_data[1])
                decr = remove_padding(decry)
                dec_ky.append(decr)
        except:
            cmd.insert(END, '[-] Cant decrypt the encrypted keys may be cause of wrong salt, check above error to veirfy problem')

        return tuple(dec_ky)
    
    #encryption algoritm for file
    def aes_enc(msg: bytes, key: tuple):
        try:
            # load a key
            hash_key = hashlib.sha3_256(key[0])
            hash_key.update(key[1])
            enc_key = hash_key.digest()

            crip = AES.new(enc_key, AES.MODE_GCM, nonce=key[2])

            nbit_ = len(msg) + 12
            mssg = add_padding(msg, nbit_)
            enc_data, authtag = crip.encrypt_and_digest(mssg)
            cripertext = enc_data + b' -:::- ' + authtag
        except:
            cmd.insert(END, '[-] Encryption failed due some unknow error')    
        return cripertext

    # ecnryption of file data form the give key
    def encf():
        sir = None
        try:
            # display the messge box for user convinence
            messagebox.showwarning('Make it clear', 'Closing the program during the process cause problems')
            sir = messagebox.askquestion('sure it', 'It may take time, want to proceed')
        except:
            None
        
        try:
            if sir == 'yes':
                # if it is 'yes' then proceed
                key = dec_key()
                pubic, private = key[0], key[1]
                cmd.insert(END, '[+] Started the encryption process fo all the files')
                fil = filen_value.get() # get the file name/path

                for i in fil:
                    typ = None
                    # files is been imported in a list where extra '\n' got added so, its to been removed
                    fille = i.replace('\n', '')
                    typ = None
                    try:
                        try:
                            # open the file and read the data
                            f = open(fille, 'r')
                            f.read(1)
                            f.close()
                            typ = False
                        except: # if files are in the form og bytes
                            f = open(fille, 'rb')
                            f.read(1)
                            f.close()
                            typ = True
                    # if file not founf return error
                    except FileNotFoundError:
                        cmd.insert(END, '[-] Selected file not found moving to next')
                    
                    #importing key function
                    keys = dec_key()
                    auth_data = (keys[0], keys[1], keys[2])
                    if typ == True:
                        # encryption of bytes file
                        try:
                            cmd.insert(END, '[+] Encrypting the file')
                            fi = open(fille, 'rb')
                            data = fi.read()
                            fi.close()

                            criptext = aes_enc(data, auth_data)

                            fin = open(fille, 'wb')
                            fin.write(criptext)
                            fin.close()
                            cmd.insert(END, '[+] Successfully encrypted the file')
                        except:
                            cmd.insert(END, '[-] Cant encrypt the selected file')
                    
                    # encryption of nonbytes file
                    elif typ == False:
                        try:
                            cmd.insert(END, '[+] Encrypting the file')
                            f1 = open(fille, 'r')
                            data_ = f1.read()
                            f1.close()
                            # checking if data may be in the form of int
                            if type(data_) != type(str()):
                                data_ = str(data_).encode()
                            else:
                                data_ = data_.encode()

                            criptext = aes_enc(data_, auth_data)

                            f2 = open(fille, 'wb')
                            f2.write(criptext)
                            f2.close()
                            cmd.insert(END, '[+] Successfully encrypted the file')
                        except:
                            cmd.insert(END, '[-] Unable encrypt your file')
                    elif typ == None:
                        pass
                    else:
                        cmd.insert(END, '[-] File format is not valid for encryption')
                cmd.insert(END, '[+] Process finished')
        except:
            cmd.insert(END, '[-] There is a some error while processing try again!!')
        try:
            messagebox.showinfo('', 'All done')
        except:
            None

    #decryption algorithm for file
    def aes_dec(msg: bytes, key: tuple):
        try:
            hash_key = hashlib.sha3_256(key[0])
            hash_key.update(key[1])
            enc_key = hash_key.digest()
            dcrip = AES.new(enc_key, AES.MODE_GCM, nonce=key[2])
            enc_data, authtag = tuple(map(bytes, msg.split(b' -:::- ')))
            dec_data_ = dcrip.decrypt_and_verify(enc_data, authtag)

            dec_data = remove_padding(dec_data_)
        except:
            cmd.insert(END, '[-] Decrytpion failed due to some unkonwn error')

        return dec_data

    #decryption of file, it is also used in xyz function
    def decf():
        sir = None
        try:
            messagebox.showwarning('Warning', 'Closing the program during the process cause problems')
            sir = messagebox.askquestion('sure it', 'It may take time, want to proceed')
        except:
            None
        try:
            if sir == 'yes':
                # get file name from GUI
                cmd.insert(END, '[+] Decryption process start for all the files')
                fil = filen_value.get()
                fli = []
                tex = []
                
                keys = dec_key()
                auth_data = (keys[0], keys[1], keys[2])
                
                for i in fil:
                    try:
                        f1 = open(i, 'rb')
                        data = f1.read()
                        f1.close()
                        fdec = aes_dec(data, auth_data) #decryption

                        tex.append(fdec) #appending decrypted the filedata in list
                        fli.append(i) #appending the fiename
                        cmd.insert(END, '[+] Decrypted')
                    except:
                        cmd.insert(END, '[-] Found problem in decrypting one of the file moving to next')
                cmd.insert(END, '[+] Succesfully decrepted the all files')
                return (fli, tex)
        except:
            cmd.insert(END, '[-] Extremely sorry to inform you that decryption is failed...')
    
    def dec_sav():
        try:
            file_text = decf()
        except:
            None
        try:
            nam = len(file_text)
            filem = file_text[0] # file name
            content = file_text[1] # text content
        except:
            nam = 0
        if nam != 0:
            for f in range(0, len(filem)):
                try:
                    cont = content[f].decode()
                    mode = 'w'
                except:
                    cont = content[f]
                    mode = 'wb'
                try:
                    f9 = open(filem[f], mode)
                    f9.write(cont)
                    f9.close()
                    cmd.insert(END, '[+] Saved the decrypted content in file')
                except:
                    cmd.insert(END, '[-] Unable to save the decrypted content in a file')
        try:
            messagebox.showinfo('', 'All done')       
        except:
            None

    def inser():
        cmd.insert(END, '[-] File format is not valid and cant open in text editor')

    def xyz():
        try:
            file_text = decf()
            try:
                filem = file_text[0]
                content = file_text[1]
                nam = len(filem)
            except:
                nam = 0
            if nam != 0:
                try:
                    from tkinter import messagebox as msg
                    win = ttk.tkinter.Tk()
                    ttk.Style().configure("Treeview", background="black", foreground="white")
                    win.title('## Editor')
                    style = ThemedStyle(win)
                    style.set_theme("black")

                    #function
                    def text_sav_enc():
                        # loading keys
                        keys = dec_key()
                        auth_data = (keys[0], keys[1], keys[2])
                        cmd.insert(END, '[+] Encrypting all the opened files')

                        for i in range(0, len(text_lis)):
                            final_text = text_lis[i].get('1.0', 'end-1c')
                            fill = list_fil[i]
                            if priv_text[i] != final_text:
                                fenc = bytes()
                                # decryption
                                reenc =  aes_enc(final_text.encode(), auth_data)

                                f2 = open(fill, 'wb')
                                f2.write(reenc)
                                f2.close()
                                cmd.insert(END, '[+] Sucessfully written all the files')

                    def bac():
                        win.destroy()

                    butt = ttk.Button(win, text='Save all', command=text_sav_enc)
                    butt.pack(side='right')
                    butt1 = ttk.Button(win, text='Cancel', command=bac)
                    butt1.pack(side='top')
                    notebook= ttk.Notebook(win)
                    notebook.pack(fill=BOTH)
                    
                    list_fil = [] # name of text only
                    text_lis = []
                    priv_text = []
                    # check if there any file is not
                    check_istxt = []

                    for k in range(0, len(filem)):
                        text_lis.append(k)
                        try:
                            xont = content[k].decode()
                            confirm = True
                            check_istxt.append(k)
                        except:
                            confirm = False
                        
                        if confirm == True:
                            #Create Tabs
                            fname = filem[k]
                            list_fil.append(fname)
                            f_name = tuple(map(str, fname.split('/')))
                            for h in f_name:
                                l = h
                            tab = ttk.Frame(notebook)
                            notebook.add(tab, text= l)
                            text_lis[k] = Text(tab, height=60, font=('Helvetica 12'), bg ='white', fg='black')
                            text_lis[k].insert('insert', xont)
                            priv_text.append(text_lis[k].get('1.0', 'end-1c'))
                            text_lis[k].pack(fill=BOTH, side='top')
                        else:
                            inser()
                    
                    #creations
                    if len(check_istxt) == 0:
                        win.destroy()
                    else:
                        pass
                    win.geometry("700x700")
                    win.config(bg='black')
                    win.mainloop()
                except:
                    cmd.insert(END, '[-] Unable to open the Hashent text editor')
        except:
            cmd.insert(END, '[-] Cant processed, try again!')

    def call2():
        try:
            name= fd.askopenfilename()
            filen.insert(END, name)
        except:
            cmd.insert(END, '[-] File is not been selected, try again!!')

    def quit():
        sys.exit()
        
    
    def sett():
        try:
            f1 = open('.hashent[not_to_delete]/settings/setting', 'r')
            sett = f1.read()
            f1.close()
            rep = sett.replace('\n', ' ')
            lis = rep.split()
        except:
            None
        return lis

    def setsave():
        try:
            data = open('.hashent[not_to_delete]/settings/setting', 'r').readlines()
            algo= varLi.get()
            turn = varLis.get()
            byt = varList.get()
            if algo != data[1]:
                data[1] = algo + '\n'
                f1 = open('.hashent[not_to_delete]/settings/setting', 'w')
                f1.writelines(data)
                f1.close()
                cmd.insert(END, '[+] Algorithm loaded:: ' + sett()[1])
            if turn != data[2]:
                data[2] = str(turn) + '\n'
                f1 = open('.hashent[not_to_delete]/settings/setting', 'w')
                f1.writelines(data)
                f1.close()
                cmd.insert(END, '[+] Preset number of turns:: ' + sett()[2])
            if byt != data[3]:
                data[3] = str(byt) + '\n'
                f1 = open('.hashent[not_to_delete]/settings/setting', 'w')
                f1.writelines(data)
                f1.close()
                cmd.insert(END, '[+] Preset bits:: ' + sett()[3])
            cmd.insert(END, '[+] Settings are been saved')
        except:
            cmd.insert(END, '[+] Settings cant be changed')

    def item_ddl():
        filen.delete(ANCHOR)
        cmd.insert(END, '[+] Removed from the selected list')

    #creations
    notebook_ = ttk.Notebook(page)
    notebook_.pack(side='top', fill=tkinter.X)

    ttk.Button(notebook_, text='Quit', command=quit).pack(side='right')
    ttk.Button(notebook_, text='Help', command=help).pack(side='left')

    scroll1 = ttk.Scrollbar(page, orient='vertical')
    scroll2 = ttk.Scrollbar(page, orient='vertical')

    filen_value = tkinter.Variable()
    filen = tkinter.Listbox(page, listvariable=filen_value, height=14, width=40, bg="black", fg='white', yscrollcommand=scroll1.set)
    cmd = tkinter.Listbox(page, height=13, width=85, bg="black", fg="white", yscrollcommand=scroll2.set)

    scroll1.config(command=filen.yview)
    scroll2.config(command=cmd.yview)
    text4 = ttk.Label(page, text=" Powered by I N O S E C")
    text2 = ttk.Label(page, text='--------------------------------------------------------- L o g s ---------------------------------------------------------------------')
    errmsg = 'Error!'

    button2 = ttk.Button(page, text='Choose Files', command=call2)
    button3 = ttk.Button(page, text='Encrypt', command=encf)
    button4 = ttk.Button(page, text='Decrypt', command=dec_sav)
    button5 = ttk.Button(page, text ="Generate key", command = genk)
    button11 = ttk.Button(page, text='Open in editor', command=xyz)
    button12 = ttk.Button(page, text='Remove', command=item_ddl)
    
    varList = IntVar(page)
    button8 = ttk.OptionMenu(page, varList, sett()[3], 160, 192, 224, 256, 320, 384, 512)
    varLis = IntVar(page)
    button9 = ttk.OptionMenu(page, varLis, sett()[2], 1)
    varLi = StringVar(page)
    button10 = ttk.OptionMenu(page, varLi, sett()[1], 'ECC')
    
    #logs for previous settings
    cmd.insert(END, '[+] Algorithm loaded:: ' + sett()[1])
    cmd.insert(END, '[+] Preset number of turns:: ' + sett()[2])
    cmd.insert(END, '[+] Preset bits:: ' + sett()[3])

    #place fixing
    button12.place(x=230, y=60)
    button11.place(x=480, y=250)
    button10.place(x=554, y=80)
    button9.place(x=440, y=80)
    button8.place(x=489, y=80)
    button5.place(x=480, y=120)
    button4.place(x=560, y=200)
    button3.place(x=430, y=200)
    button2.place(x=20, y=60)
    text4.pack(side='bottom', fill=tkinter.X)
    text2.place(x=1, y=410)
    filen.place(x=18, y=102)
    scroll1.pack(ipady=114, pady=72)
    cmd.place(x= 1, y=430)
    scroll2.pack(side='right', fill='y')
    page.geometry("700x688")
    page.configure(bg='black')
    page.mainloop()

def listen():
    main1 = ttk.tkinter.Tk()
    ttk.Style().configure("Treeview", background="black", foreground="white")
    main1.title('Terms and Conditions')
    style = ThemedStyle(main1)
    style.set_theme("black")

    def tece():
        if ch_ag.get()==1:
            main1.destroy()
        else:
            messagebox.showerror('confirm it', 'Please agree all the terms and conditions')
    
    notebook= ttk.Notebook(main1)
    notebook.pack(side='top' ,fill=tkinter.X)
    rlu = '''---------Terms_and_Conditions_for_User-------------

    Usage- It's a free software and is designed to 
    provide the security to the user's personal data, 
    they can use it without any restrictions.

    Limits- Users are not allowed for selling, 
    distributing, adaption of this software without 
    owner's permission.

    Ownership- It is been powered by the INOSEC.

    Warning- If someone tries perform anything that is  
    not allowed for this software that will be against 
    this aggrement and will also be against its 
    provider.

    Note- As this software is been provided without and
    registration, so everything is under the hand of 
    user and the provider is not responsible for any
    kind of issues that will be there while its usage.

    ------------END_OF_USER_AGGREMENT------------------'''
    text_lis = Label(notebook, text=rlu, font=('Helvetica 12'), bg ='black', fg='white')
    text_lis.pack( side='left', fill=tkinter.X)

    ch_ag = IntVar()
    okk = ttk.Checkbutton(main1, text='I agree all the terms and conditions', variable=ch_ag, offvalue = 0)

    butt = ttk.Button(main1, text='Next', command=tece)

    okk.pack(side='left')
    butt.pack(side='right')
    main1.geometry('405x480')
    main1.config(bg='black')
    main1.mainloop()

session()
