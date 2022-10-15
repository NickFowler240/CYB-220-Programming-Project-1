#This is gonna be a password encryptor at some point, not sure how that's gonna work tbh
#Maybe just use it as a thing to copy and paste from, but not entirely sure how the gui is gonna look
#Can you even use text boxes in easygui? Many questions...

#Uses either RSA or AES, but not sure how to impliment the key feature.
#I'd like to make it password protected, but the private key is definitely more secure.
#But it's not really user friendly to prompt for a file input every time they want to access their sensitive passwords.
#Maybe just try something else? Not entirely sure what though. Maybe it messes with wireshark and grabs nearby specific traffic, then marks frequency of traffic?
#That doesn't seem helpful. I'd like it to be useful for other people as well as myself.

#Alright read some, tkinter is a lot better
#GUI is goin in the final, forget it. Final = Add users and Add GUI

import getpass
import csv
import secrets
import hashlib
import pyAesCrypt
import os

def AddPass(password, user, site):
    """It adds a password, wow!"""
    try:
        ReadSheet("site")
    except FileNotFoundError:
        with open(CSV, 'a') as file:
            writer = csv.writer(file, delimiter=',', quotechar='"')
            writer.writerow(["site", "username", "password"])
    with open(CSV, 'a') as file:
        writer = csv.writer(file, delimiter=',', quotechar='"')
        writer.writerow([site, user, password])

def DecodePassword():
    """Decodes CSV file"""
    pyAesCrypt.decryptFile("psda.csv.aes", CSV, master)
    os.delete("psda.csv")

def EncodePassword():
    """ENCODING!!! I FIGURED IT OUT!!!"""
    pyAesCrypt.encryptFile(CSV, "psda.csv.aes", master)
    os.delete(CSV)

#def HashPassword(password, length):
#    """This one hashes a password, neat!"""
#    salt = secrets.token_hex(64)
#    hash = hashlib.sha512((salt + password).encode('utf-8')).hexdigest()
#    hash = hash[:length]
#    return salt, hash

def ReadSheet(site):
    """Read CSV sheet for site name"""
    with open(CSV) as data:
        read = csv.reader(data, delimiter=',')
        line = 0
        for i in read:
            if (line != 0):
                try:
                    if (i[0] == site):
                        return i
                except IndexError:
                    pass
            line += 1

def ListSheet():
    """Lists out CSV site names"""
    with open(CSV) as file:
        reader = csv.reader(file, delimiter=',')
        sites = list()
        line_count = 0
        for row in reader:
            if (line_count != 0):
                try:
                    sites.append(row[0])
                except IndexError:
                    pass
            line_count += 1
    return sites

def RemovePass(site):
    """It removes a password, wow!"""
    changes = list()
    with open(CSV) as file:
        reader = csv.reader(file, delimiter=',')
        for row in reader:
            try:
                if (row[0] != site):
                    changes.append(row)
            except IndexError:
                pass

    with open(CSV, 'w') as file:
        writer = csv.writer(file, delimiter=',', quotechar='"')
        writer.writerows(changes)

def CreateMaster(password):
    """Create master password"""
    master = open(Masterfile, 'w')
    salt = secrets.token_hex(64)
    hash = hashlib.sha512((salt + password).encode('utf-8')).hexdigest()
    master.write(f"{salt}\n")
    master.write(f"{hash}\n")
    master.close()

def CompareHash(password):
    """Compares master password hashes"""
    master = open(Masterfile)
    lines = master.read().splitlines()
    salt = lines[0]
    hash = hashlib.sha512((salt + password).encode('utf-8')).hexdigest()
    if (hash == lines[1]):
        return True
    else:
        return False

def hub():
    print("\nPlease select an item below:")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("1. Add new password")
    print("2. Retrieve password")
    print("3. Delete password")
    print("4. Show stored sites")
    print("5. Change master password")
    print("6. Exit")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    selection = int(input("Enter selection (1-6): "))
    return selection

#can't be run in IDLE, only in cmd

i = 0
previous = "old.txt"
Masterfile = "maps.txt"
CSV = "psda.csv"
attempts = 0
open(previous, 'w')

while(True):
    try:
        master = getpass.getpass("Enter master password: ")
        if (not CompareHash(master)):
            if (attempts > 2):
                print("Too many attempts.")
                raise SystemExit(0)
            else:
                print("Invalid login.")
                attempts += 1
                continue
        else:
            try:
                pyAesCrypt.decryptFile("psda.csv.aes", CSV, master)
                os.remove("psda.csv.aes")
            except ValueError:
                pass
            break
    except FileNotFoundError:
        print("No master file found. Creating a new file...")
        while i == 0:
            master = getpass.getpass("Enter new password: ")
            confirm = getpass.getpass("Confirm password: ")
            if (master != confirm):
                print("Passwords do not match. Please try again.")
            else:
                CreateMaster(master)
                break
while (i == 0):
    with open(previous) as file:
        old = file.read()
    if old != "y":
        print("\nWelcome, newcomer!")
    else:
        print("\nWelcome back!")
    try:
        choice = hub()
        if (choice > 6 or choice < 1):
            print("\nPlease input a valid menu option.")
    except ValueError:
        print("\nPlease input a valid menu option.")
        continue
    i = 1
#oh here we go
    if (choice == 1):
        while (i == 1):
            print("\nType 'exit' to exit.")
            site = input("Enter site name: ")
            if (site == "site"):
                print("\nplease choose a different name...")
                continue
            elif (site == exit):
                i = 0
            try:
                if (ReadSheet(site) != None):
                    print("Site already exists.")
                    continue
            except FileNotFoundError:
                pass
            username = input(f"Enter username for {site.title()}: ")
            password = input(f"Enter password for {username}@{site.title()}: ")
            print("\nIs this information correct?")
            print(f"Site: {site}")
            print(f"Username: {username}")
            print(f"Password: {password}")
            i = 2
            while i == 2:
                check = input("(Yes/No) ")
                if check.lower() == "no":
                    i = 1
                elif check.lower() == "yes":
                    print(f"\nAdding new entry to database...")
                    AddPass(password, username, site)
                    print(f"New Entry added for site: {site.title()}")
                    i = 3
                    while i == 3:
                        cont = input("\nAdd another password? (y/n) ")
                        if cont.lower() == "y":
                            i = 1
                        elif cont.lower() == "n":
                            exit = input("\nReturn to main menu? (y/n) ")
                            if exit == 'y':
                                i = 0
                            elif exit == 'n':
                                print("\nBye!")
                                pyAesCrypt.encryptFile(CSV, "psda.csv.aes", master)
                                os.remove(CSV)
                                with open(previous, 'w') as file:
                                    file.write('y')
                                raise SystemExit(0)

                            else:
                                print("Invalid selection.")
                        else:
                            print("Invalid selection.")
                elif check.lower() != "yes" or check.lower() != "no":
                    print("Invalid option.")
                    continue

    if (choice == 2):
        while i == 1:
            print("\nType 'exit' to exit.")
            site = input("Enter site name to retrieve: ")
            if (site.lower() == "site"):
                print("Invalid name.")
            elif (site.lower() == "exit"):
                i = 0
            try:
                if (ReadSheet(site) == None):
                    print("Site not found.")
                    continue
                else:
                    row = ReadSheet(site)
                    print("\n")
                    print(f"Site: {row[0]}")
                    print(f"Username: {row[1]}")
                    print(f"Password: {row[2]}")
                    i = 2
                    while i == 2:
                        cont = input("\nRetrieve another password? (y/n) ")
                        if cont.lower() == "y":
                            i = 1
                        elif cont.lower() == "n":
                            exit = input("\nReturn to main menu? (y/n) ")
                            if exit == 'y':
                                i = 0
                            elif exit == 'n':
                                print("\nBye!")
                                pyAesCrypt.encryptFile(CSV, "psda.csv.aes", master)
                                os.delete(CSV)
                                with open(previous, 'w') as file:
                                    file.write('y')
                                raise SystemExit(0)

                            else:
                                print("Invalid selection.")
                        else:
                            print("Invalid selection.")
            except FileNotFoundError:
                print("Password file not found.")
                i = 0

    if (choice == 3):
        while i == 1:
            print("\nType 'exit' to exit.")
            site = input("Enter site to delete: ")
            if (site.lower() == "site"):
                print("Invalid name.")
            elif (site.lower() == "exit"):
                i = 0
            elif (ReadSheet(site) == None):
                print("No site found.")
            else:
                name = ReadSheet(site)
                choice = input(f"Are you sure you want to delete password for {name[1]}@{site.title()}? (yes/no) ")
                if choice.lower() == 'yes':
                    RemovePass(site)
                    print(f"Info for {name[1]}@{site.title()} has been deleted.")
                    i = 2
                    while i == 2:
                        cont = input("\nDelete another password? (y/n) ")
                        if cont.lower() == "y":
                            i = 1
                        elif cont.lower() == "n":
                            exit = input("\nReturn to main menu? (y/n) ")
                            if exit == 'y':
                                i = 0
                            elif exit == 'n':
                                print("\nBye!")
                                pyAesCrypt.encryptFile(CSV, "psda.csv.aes", master)
                                os.delete(CSV)
                                with open(previous, 'w') as file:
                                    file.write('y')
                                raise SystemExit(0)
                            else:
                                print("Invalid selection.")
                        else:
                            print("Invalid selection.")
                elif choice.lower() == 'no':
                    print("Returning to menu...")
                    i = 0
                else:
                    print("Invalid selection.")

    if (choice == 4):
        try:
            if (ListSheet()):
                counter = 1
                print("\n\nSites stored:")
                print("----------------")
                for site in ListSheet():
                    print(f"{counter}: {site}")
                    counter += 1
                    print("\n")
            else:
                print("\nNo sites avaliable.")
            i = 0
        except FileNotFoundError:
            print("No password file found. Have you added any passwords yet?")
            i = 0

    if (choice == 5):
        while i == 1:
            print("Type 'exit' to exit.")
            insert = getpass.getpass("Enter current password: ")
            if (not CompareHash(insert)):
                print("Incorrect password. Please try again.")
            elif insert.lower() == 'exit':
                i = 0
            else:
                master = getpass.getpass("Enter new password: ")
                confirm = getpass.getpass("Confirm password: ")
                if (master != confirm):
                    print("Passwords do not match. Please try again.")
                else:
                    CreateMaster(master)
                    print("\n-------------------------------------")
                    print("Master password successfully changed!")
                    print("-------------------------------------")
                    i = 0

    if (choice == 6):
        print("\nBye!")
        try:
            pyAesCrypt.encryptFile(CSV, "psda.csv.aes", master)
            os.remove(CSV)
        except ValueError:
            print("\nUNABLE TO ENCRYPT CSV PASSWORD FILE.")
            print("DISREGARD IF NO PASSWORD DATA EXISTS.")
        with open(previous, 'w') as file:
            file.write('y')
        raise SystemExit(0)