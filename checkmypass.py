import sys
import requests
import hashlib


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching data: {response.status_code}.")

    return response


def get_passwords_leak_count(hashes, hash_to_check):
    foo = (line.split(":") for line in hashes.text.splitlines())
    for h, count in foo:
        if hash_to_check == h:
            return count

    return 0


def pwned_api_check(password):
    # check if password exists in API response
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    head_5, tail = sha1pass[:5], sha1pass[5:]
    response = request_api_data(head_5)
    return get_passwords_leak_count(response, tail)


def main(args):
    for passwd in args:
        count = pwned_api_check(passwd)
        suffix = "time" if count == 1 else "times"
        if count:
            print(f"password \"{passwd}\" has been pwnd {count} {suffix}")
        else:
            print(f"password \"{passwd}\" has NOT been pwnd, carry on!")

    return 'Done!'


if __name__ == "__main__":
    main(sys.argv[1:])
