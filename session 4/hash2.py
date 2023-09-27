import hashlib
import itertools
from time import perf_counter_ns


def hash_password(password):
    password = password.encode('utf-8')
    
    sha256 = hashlib.sha256()
    
    sha256.update(password)
    
    hashed_password = sha256.hexdigest()
    
    return hashed_password



if __name__ == "__main__":
    
    password_hash = input("input the password hash: ")
    
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    combinations = []
    for i in range(1,5):
        combinations.extend([''.join(combination) for combination in itertools.product(characters, repeat=i)])

    start_time = perf_counter_ns()

    for hash in combinations:
        if password_hash == hash_password(hash):
            print("Password is:",hash)
            break

    end_time = perf_counter_ns()

    print("Duration(ms)=", (end_time-start_time)/10**6)