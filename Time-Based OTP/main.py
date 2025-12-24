import hmac
import hashlib
import time
def generate_totp(secret_key, current_timestamp):
    """
         input:
         secret_key: str
         current_timestamp: int

         output:
         str: The 6-digit string (e.g., "012345")

         Logic:
         1. Calculate time_counter = current_timestamp // 30.
         2. Convert time_counter to string and encode to bytes.
         3. Compute HMAC-SHA256 using secret_key (encoded).
         Use .hexdigest() to get the hex string.
         4. Take the LAST 8 characters of the hex digest.
         5. Convert that hex slice to an integer (base 16).
         6. Return str(integer % 1000000).zfill(6)
    """
    time_counter = current_timestamp // 30
    msg = str(time_counter).encode()

    digest = hmac.new(key=secret_key.encode(), msg=msg, digestmod=hashlib.sha256).hexdigest()
    last8hex = digest[-8:]
    value = int(last8hex, 16)

    # print("key_bytes:", secret_key.encode('utf-8'))
    # print("TimeCounter:", time_counter)
    # print("HMACHex:", last8hex)
    # print("IntValue:", value)
    return str(value % 1000000).zfill(6)

def verify_totp(secret_key, user_token, current_timestamp):
     """
         input:
         secret_key: str
         user_token: str
         current_timestamp: int

         output:
         boolean: True if matches, False otherwise.

         Logic:
         1. Generate the expected token using 'generate_totp' with the provided
        timestamp.
         2. Compare expected token vs user_token.
         3. Return True if identical.
     """
     expected_token = generate_totp(secret_key,current_timestamp)
     return expected_token == user_token

if __name__ == "__main__":
    # Testcase 1: Expected: 924761
    SECRET_KEY = "STUDENT_ID_SECRET"
    Timestamp = 1700000000

    # key_bytes = SECRET_KEY.encode('utf-8')
    # TimeCounter = 56666666
    # HMACHex = 87b71d59
    # IntValue = 2276924761

    res = generate_totp(SECRET_KEY, Timestamp)
    print("Testcase 1:")
    print("TOTP:", res)

    # Testcase 2:
    print("Testcase 2:")

    current_time = int(time.time())
    key = "TESTING KEY"
    token = generate_totp(key,current_time)

    if verify_totp(key,token,current_time):
        print("PASS")
    else: print("FAIL")

    # time.sleep(5)
    # print("After 5 sec:")
    time.sleep(31)
    print("After 31 sec:")

    new_time = int(time.time())
    if verify_totp(key,token,new_time):
        print("PASS")
    else: print("FAIL")
