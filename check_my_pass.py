import argparse
import requests
import hashlib
import sys
import getpass
import os.path



def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    resp = requests.get(url)
    if resp.status_code != 200:
        raise RuntimeError(f'Error fetching: {resp.status_code}, check api and try again')
    return resp

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    passwords_to_check = []

    # Case 1 - When no arguments are passed, prompt, then mask what's entered
    if not args.passwords:
        # Prompt the user securely
        users_input = getpass.getpass('Enter password to check: ')
        if users_input:
            passwords_to_check.append(users_input)

    # Case 2 - One argument passed, and it matches a file on disk
    elif len(args.passwords) == 1 and os.path.isfile(args.passwords[0]):
        file_path = args.passwords[0]
        print(f"[*] Reading passwords from file: {file_path}")
        with open(file_path, 'r', encoding="utf-8") as f:
            # .strip() removes trailing newlines and carriage returns
            passwords_to_check = [line.strip() for line in f if line.strip()]

    # Case 3 Standard command line arguments
    else:
        passwords_to_check = args

    with open('audit_results.txt', 'w', encoding="utf-8") as output_file:
        for password in passwords_to_check:
            count = pwned_api_check(password)
            if count:
                result = f'{password} was found {count} times...you should change your password'
            else:
                result = f'{password} was NOT found.'

            print(result)
            output_file.write(result + '\n')
        return 'done!'




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Check if passwords have been breached")

    parser.add_argument("passwords", nargs='*', help="List of passwords to check")

    args = parser.parse_args()

    sys.exit(main(args))






