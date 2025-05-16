import hashlib
import requests

def check_password(password):
    # Step 1: Hash the password using SHA1
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    # Step 2: Use k-anonymity — only send prefix to API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError("API request failed")

    # Step 3: Search the returned suffixes
    hashes = res.text.splitlines()
    for line in hashes:
        leaked_suffix, count = line.split(':')
        if leaked_suffix == suffix:
            return f"Password FOUND in breach {count} times!"
    
    return "Password not found in any known breach."

# Example usage
if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    result = check_password(pwd)
    print(result)
