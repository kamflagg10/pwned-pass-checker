import requests
import hashlib
import sys


# API Request
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, try again')
    return res


# Number of times the password was found.
def get_pass_occurrence(response, hashed_pass):
    hashes_list = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes_list:
        if h == hashed_pass:
            return count
    return 0




def pwned_api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1pass[:5], sha1pass[5:]
    api_res = request_api_data(first5)
    return get_pass_occurrence(api_res, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. Change your password!')
        else:
            print(f'{password} is safe to use.')


if __name__ == "__main__":
    main(sys.argv[1:])
