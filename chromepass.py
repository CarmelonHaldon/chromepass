#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import sqlite3
import csv
import json
import argparse
# TODO CarmelonHaldon: Para capturar el error...
import pywintypes
# TODO CarmelonHaldon: https://github.com/AlessandroZ/LaZagne/blob/master/Windows/lazagne/softwares/browsers/chromium_based.py
import base64

try:
    import win32crypt
except:
    pass

from Crypto.Cipher import AES

# TODO CarmelonHaldon: https://github.com/hassaanaliw/chromepass

def args_parser():

    parser = argparse.ArgumentParser(description="Retrieve Google Chrome Passwords")
#    parser.add_argument("-o", "--output", choices=['csv', 'json'], help="Output passwords to [ CSV | JSON ] format.")
    parser.add_argument("-f", "--format", choices=['csv', 'json'], help="Output passwords to [ CSV | JSON ] format.")
    parser.add_argument("-d", "--dump", help="Dump passwords to stdout. ", action="store_true")
	# TODO CarmelonHaldon: ...
    parser.add_argument("-p", "--path", help="path.")
    parser.add_argument("-o", "--output", help="output.")

    args = parser.parse_args()

    if args.dump:
        for data in main(args.path):
            print(data)
        return

    if args.format == 'csv':
        output_csv(main(args.path), args.output)
        return

    if args.format == 'json':
        output_json(main(args.path), args.output)
        return

    else:
        parser.print_help()



def _decrypt_v80(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass
    except Exception as e:
#        pass
        print(e)



def main(path):
    info_list = []
#    path = getpath()

#    try:



    # TODO CarmelonHaldon: https://stackoverflow.com/questions/60329372/i-have-this-error-pywintypes-error-87-cryptprotectdata-param%C3%A8tre-incorrec
#    master_key = None

#    with open('C:\\__home\\xxx\\user\\chrome\\Local State') as f:
    with open(path + "Local State") as f:
        try:
            master_key = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]  # removing DPAPI
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        except Exception:
            master_key = None



    connection = sqlite3.connect(path + "Default\\Login Data")

    with connection:
        cursor = connection.cursor()
        v = cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        value = v.fetchall()

    if (os.name == "posix") and (sys.platform == "darwin"):
        print("Mac OSX not supported.")
        sys.exit(0)

    for origin_url, username, password in value:
        # TODO CarmelonHaldon: Captura los errores por línea...
        try:
            if os.name == 'nt':
#                password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                password = _decrypt_v80(password, master_key)

            if password:
                info_list.append({
                    'origin_url': origin_url,
                    'username': username,
                    'password': str(password)
                })

        # TODO CarmelonHaldon: "Module 'pywintypes' has no 'error' member"??
        # TODO CarmelonHaldon: https://stackoverflow.com/questions/20553551/how-do-i-get-pylint-to-recognize-numpy-members
        except pywintypes.error as e:
            info_list.append({
                'origin_url': origin_url,
                'username': username,
                'password': str(e)
            })

#    except sqlite3.OperationalError as e:
#        e = str(e)
#        if (e == 'database is locked'):
#            print('[!] Make sure Google Chrome is not running in the background')
#        elif (e == 'no such table: logins'):
#            print('[!] Something wrong with the database name')
#        elif (e == 'unable to open database file'):
#            print('[!] Something wrong with the database path')
#        else:
#            print(e)
#        sys.exit(0)

    return info_list



# def getpath():

#     if os.name == "nt":
#         # This is the Windows Path
# # TODO CarmelonHaldon: Yo no tengo el Default...
# #        PathName = os.getenv('localappdata') + \
# #            '\\Google\\Chrome\\User Data\\Default\\'
#         PathName = 'C:\\__home\\xxx\\user\\chrome\\Default\\'
#     elif os.name == "posix":
#         PathName = os.getenv('HOME')
# # TODO CarmelonHaldon: Faltaba el :
#         if sys.platform == "darwin":
#             # This is the OS X Path
#             PathName += '/Library/Application Support/Google/Chrome/Default/'
#         else:
#             # This is the Linux Path
#             PathName += '/.config/google-chrome/Default/'
#     if not os.path.isdir(PathName):
#         print('[!] Chrome Doesn\'t exists')
#         sys.exit(0)

#     return PathName



def output_csv(info, output):
    try:
#        with open('chrome-passwords.txt', 'wb') as csv_file:
        with open(output, 'wb') as csv_file:
            csv_file.write('origin_url,username,password \n'.encode('utf-8'))
            for data in info:
                csv_file.write(('%s, %s, %s \n' % (data['origin_url'], data['username'], data['password'])).encode('utf-8'))
        print("Data written to chromepass-passwords.csv")
    except EnvironmentError:
        print('EnvironmentError: cannot write data')


def output_json(info, output):
	try:
#		with open('chromepass-passwords.json', 'w') as json_file:
		with open(output, 'w') as json_file:
			json.dump({'password_items':info},json_file)
		print("Data written to chromepass-passwords.json")
	except EnvironmentError:
		print('EnvironmentError: cannot write data')



if __name__ == '__main__':
    args_parser()
