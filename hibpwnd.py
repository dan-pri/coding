import requests
import hashlib
import json
import argparse


def check_pwnd(password):
    """
        This function checks whether a password has been leaked.
        It expect a string (password) as input and return True if
        password is leaked or False if password is not leaked.

        A SHA1 hash is made from the string and the first 5 
        characters are passed as a prefix to the hibpwnd API via
        get request.

        If the password has been leaked, the hibpwnd API returns 
        a list of possible hashes and the function checks if the
        given password is in list.

    """

    #create hash object, set the encoded password
    sha1_hash = hashlib.sha1()
    sha1_hash.update(password.encode())

    #generate hash, change in uppercase and get first 5 chars as prefix
    password_hash = sha1_hash.hexdigest().upper()
    hash_prefix = password_hash[:5]

    #create link for check hibpwnd and make request
    link = "https://api.pwnedpasswords.com/range/{}".format(hash_prefix)
    pwnd_request = requests.get(link)

    #check response status code; 
    #200 = pwnd -> return true, 
    #404 = not found -> return false
    if pwnd_request.status_code == 200:

        #split the response content in single lines
        response_pwnd = pwnd_request.content.decode()
        response_pwnd = response_pwnd.splitlines()

        response_list = []

        #split the response hash between the ":" and append it with the 
        # hashprefix in a response list
        for i in response_pwnd:
            full_hash = hash_prefix + i.split(":")[0]
            response_list.append(full_hash)

        #check if given hash is in response list -> return true
        if password_hash in response_list:
            return True
        else:
            return False

    elif pwnd_request.status_code == 404:
        return False            


if __name__ == "__main__":
    """
    	if the module was not imported as an external one, an input 
        is required to enter a password
    """
    
    #create an argparse instance and specify command-line options
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--password", help="Password prüfen")

    #get data from options
    args = parser.parse_args()

    #if the option is set handover the content 
    if args.password:
        password = args.password
    else:
        #if option is not set
        #get input and check pw
        password = input("Please type password to check:")


    #check password
    if check_pwnd(password) == True:
        print("pwnd!")
    else:
        print("Password ok")