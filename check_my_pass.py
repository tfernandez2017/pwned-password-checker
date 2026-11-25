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

    # File flag passed (-f / file)
    if args.file:
        file_path = args.file
        if not os.path.isfile(file_path):
            print(f" [!] Error: File '{file_path}' not found.")
            return 1
        print(f"[*] Reading passwords from file: {file_path}")
        with open(file_path, 'r', encoding="utf-8") as f:
            passwords_to_check = [line.strip() for line in f if line.strip()]

    # Case 2 - Standard command line arguments passed directly
    elif args.passwords:
        passwords_to_check = args.passwords

    # Case 3 No file or passwords passed, prompt and mask what's entered
    else:
        users_input = getpass.getpass(prompt='Enter password to check: ')
        if users_input:
            passwords_to_check.append(users_input)

    with open(args.output, 'w', encoding="utf-8") as output_file:
        for password in passwords_to_check:
            count = pwned_api_check(password)
            if count:
                result = f'{password} was found {count} times...you should change your password'
            else:
                result = f'{password} was NOT found.'

            print(result)
            output_file.write(result + '\n')
        return 0




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Check if passwords have been breached")

    parser.add_argument("passwords", nargs='*', help="List of passwords to check")
    parser.add_argument('-V', '--version', action='version', version='%(prog)s 1.0.0', help='version number')
    parser.add_argument('--verbose', '-v', action='store_true', help='verbose output')
    parser.add_argument('-f', '--file', )
    parser.add_argument('-o', '--output', default='audit_results.txt')


    args = parser.parse_args()

    sys.exit(main(args))






