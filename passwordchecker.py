import requests
import hashlib
import sys


def request_api(query_char):
    # use SHA1 hash for the password security
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    # print(response)
    if response.status_code != 200:
        raise RuntimeError(f'Error: {response.status_code}, please check your API again')
    return response


def pwd_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    print(hashes, hash_to_check)
    for hashh, count in hashes:
        if hashh == hash_to_check:
            return count
    return 0


# check password if it exists in api response
def pwned_api_verify(pwd):
    # covert password to the hex
    sha1pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    first5Char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_api(first5Char)
    return pwd_leak_count(response, tail)


def main(args):
    for pwd in args:
        count = pwned_api_verify(pwd)
        if count:
            print(f'{pwd} was found {count} times...you should change your password')
        else:
            print(f'{pwd} was NOT found. Good!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


