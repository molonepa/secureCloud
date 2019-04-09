from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from cryptography.fernet import Fernet
import os

def encrypt(f,files):
    for fi in files:
        unencoded = fi.GetContentString()
        encoded = f.encrypt(unencoded.encode())
        fi.SetContentString(encoded.decode())
        fi.Upload()

def decrypt(f,files):
    for fi in files:
        encoded = fi.GetContentString()
        unencoded = f.decrypt(encoded.encode())
        fi.SetContentString(unencoded.decode())
        fi.Upload()


def getKey(username):
    with open("group/" + str(username) + "/privateKey.txt", "rb") as fileWithPrivateKey:
        privateKey = fileWithPrivateKey.read()

    privateKey = load_pem_private_key(privateKey, None, default_backend())

    publicKey = privateKey.public_key()
    key = open("keys/key.txt", "r")
    key = key.read()

    encrypted = publicKey.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("~Getting encrypted symmetric key.")

    symmetricKey = privateKey.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("~Decrypting symmetric key.")
    return symmetricKey

def options(i):
    return {
            'lf': 1,
            'op': 2,
            'up': 3,
            'q': 4
            }.get(i, 5)

def main():
    print("** USER MODE **")
    username = raw_input("~Username: ")
    if os.path.exists("group/" + str(username)):
        print("~Welcome " + str(username))
        gauth = GoogleAuth()
    	gauth.LocalWebserverAuth()
    	drive = GoogleDrive(gauth)

        key = getKey(username)
        f = Fernet(key)
        files = drive.ListFile({'q':"'1qwdkeX0WApKsX0JAOZctEnjkjj3MhcfK' in parents and trashed=false"}).GetList()

        end = False
        while not end:
            i = raw_input("> *OPTIONS*\
                \n> 'lf': list files\
                \n> 'op': open file\
                \n> 'up': upload file\
                \n> 'q': quit\n")
            opt = options(str(i))
            
            if opt is 1:
                files = drive.ListFile({'q':"'1qwdkeX0WApKsX0JAOZctEnjkjj3MhcfK' in parents and trashed=false"}).GetList()
                print("~All Files in Secure Drive: ")
                for file in files:
                    print("~" + file['title'])

            elif opt is 2:
                found = 0
                nameOfFile = raw_input("~Enter name of file you wish to open: ")
                for file in files:
                    if file["title"] == nameOfFile:
                        found = 1
                        token = file.GetContentString()
                        print("~Decrypting file:")
                        plaintext = f.decrypt(token.encode())

                        print("~File Contains: ")
                        print(plaintext.decode())
                if found is 0:
                        print("~File: " + nameOfFile + " not in drive.. enter 'lf' to list existing files.")

            elif opt is 3:
                filePath = raw_input("~Enter the path to the file to upload: ")
                if os.path.exists(filePath):
                    with open(filePath,"r") as file:
                        parents = ["1qwdkeX0WApKsX0JAOZctEnjkjj3MhcfK"]
                        driveFile = drive.CreateFile({ "parents": [{"kind": "drive#fileLink", "id": '1qwdkeX0WApKsX0JAOZctEnjkjj3MhcfK'}] , 'title':os.path.basename(file.name)})
                        readFile = file.read()
                        encoded = f.encrypt(readFile.encode())
                        driveFile.SetContentString(encoded.decode())
                        driveFile.Upload()

            elif opt is 4:
                print("~Exiting...")
                end = True

            elif opt is 5:
                print("~Invalid command.")

        else:
            print("~Invalid username.")

if __name__ == "__main__":
        main()
