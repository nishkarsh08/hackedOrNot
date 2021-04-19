# PASSWORD CHECKER / HOW MANY TIMES ITS BEEN HACKED

import requests
import hashlib
import sys


def request_api_data(query_char):  # Receives first5_char of Hash Value
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)  # requests.get(url) return status: 400, 200
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res  # A requests class OBJECT. Returns status. We can apply methods on this object.
    


def get_password_leaks_count(hashes, hash_to_check):  
    
    hashes = (line.split(':') for line in hashes.text.splitlines())  # hashes is a generator
    
    for h, count in hashes:
        # print(h)
        # print(count)
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):  # receives text password
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  
    first5_char, tail = sha1password[:5], sha1password[5:]  
    # remaining is tail
    response = request_api_data(first5_char)  # Sends to API - first5_char
    return get_password_leaks_count(response, tail)


def main(args):  
    for password in args:  
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))  

