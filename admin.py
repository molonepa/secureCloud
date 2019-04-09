from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import os
import shutil

def encrypt(f,files):
    for fi in files:
        plaintext = fi.GetContentString()
        token = f.encrypt(plaintext.encode())
        fi.SetContentString(token.decode())
        fi.Upload()

def decrypt(f,files):
    for fi in files:
        token = fi.GetContentString()
        plaintext = f.decrypt(token.encode())
        fi.SetContentString(plaintext.decode())
        fi.Upload()

def options(i):
    return {
            'enc': 1,
            'dec': 2,
            'lf': 3,
            'addu': 4,
            'rmvu': 5,
            'lu': 6,
            'q': 7
            }.get(i, 8)


def main():
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)
    print("** ADMIN MODE **")

    # search for symmetric key in ./keys/key.txt
    try:
        f = open('keys/key.txt', 'r')
        key = f.read()
        print("~Found existing symmetric key: '" + key + "'")
    # if none found generate new key and store in./keys/key.txt
    except:
        key = Fernet.generate_key()
        f = open('keys/key.txt', 'w')
        f.write(key)
        print("~New symmetric key generated: '" + key + "'")

    f = Fernet(key)
    files = drive.ListFile({'q':"'1qwdkeX0WApKsX0JAOZctEnjkjj3MhcfK' in parents and trashed=false"}).GetList()

    end = False
    while not end:
        i = raw_input("> *OPTIONS*\
                \n> 'enc': encrypt files\
                \n> 'dec': decrypt files\
                \n> 'lf': list files\
                \n> 'addu': add user\
                \n> 'rmvu': remove user\
                \n> 'lu': list users\
                \n> 'q': quit\n")

        opt = options(str(i))

        if opt is 1:
            encrypt(f, files)

        elif opt is 2:
            decrypt(f,files)

        elif opt is 3:
            print("~All files in drive: ")
            for fi in files:
                print("~" + fi['title'])

        elif opt is 4:
            username = raw_input("~Enter a username to add: ")
            if os.path.exists("group/" + str(username)):
                print("~User already exists.")
            else:
                print("~Adding user " + str(username))
                os.mkdir("group/" + str(username))
                print("~Generating RSA private key for " + str(username))
                privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                privateSerializedKey = privateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
                file = open("group/" + str(username) + "/privateKey.txt", "w")
                file.write(privateSerializedKey)
                file.close()
                print("~Added user " + str(username))

        elif opt is 5:
            username = raw_input("~Enter the username to remove: ")
            if os.path.exists("group/" + str(username)):
                print("~Removing user " + str(username))
                shutil.rmtree("group/" + str(username))
                print("~Generating new symmetric key and encrypting files.")
                decrypt(f, files)
                key = Fernet.generate_key()
                file = open('keys/key.txt', 'w')
                file.write(key)
                file.close()
                f = Fernet(key)
                print("~New symmetric key: " + key)
                encrypt(f, fileList)
            else:
                print("~User " + str(username) + " does not exist. Enter 'lu' to list existing users.")

        elif opt is 6:
            users = os.listdir('group/')
            print("~All users in drive: ")
            for user in users:
                print("~" + user)

        elif opt is 7:
            print("~Exiting...")
            end = True

        elif opt is 8:
            print("~Invalid command.")

if __name__ == "__main__":
    main()
