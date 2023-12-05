from hashlib import sha256


#ECDSA functions ---------------------------------------------------------------------------------

#Create a digital signature for the string message using a given curve with a distinguished
#point P which generates a prime order subgroup of size n.
def sign(message, r, n, nonce, d):
    #Extract the private and public keys, and compute z by hashing the message.
    z = hash_and_truncate(message, n)
    s = 0
    while r == 0 or s == 0:
        r = r % n
        s = (pow(nonce, -1, n) * (z + r*d)) % n
    #print('ECDSA sig of \"' + message+ '\" : (Q, r, s) = (' + str(Q) + ', ' + str(r) + ', ' + str(s) + ')')
    return (r, s)

#Hash and truncate the message to be signed
def hash_and_truncate(message, n):
    h = int(sha256(str(message).encode('utf-8')).hexdigest(), 16)
    b = bin(h)[2:len(bin(n))]
    return int(b, 2)



n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
r = int(input("Enter r query parameter: "))
print(r)

msg1 = input("Enter name of file 1: ").strip()
h1 = hash_and_truncate(msg1, n)
s1 = int(input("Enter s query parameter for file 1: "))


msg2 = input("Enter name of file 2: ").strip()
h2 = hash_and_truncate(msg2, n)
s2 = int(input("Enter s query parameter for file 2: "))


nonce = (((h1-h2)%n) * pow((s1-s2)%n, -1, n)) % n
print(f"nonce: {nonce}")
secret_key = ((s1*nonce - h1)*pow(r, -1, n)) % n
print(f"secret key: {secret_key}")

msg3 = "flag.txt"
flag_sig = sign(msg3, r, n, nonce, secret_key)[1]
print(f"s query parameter to access 'flag.txt': {flag_sig}")