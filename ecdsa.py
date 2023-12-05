
# Thanks to Brendan Cordy and Dr. Tsoutsos for this in-house implementation of ECDSA 

from hashlib import sha256


#ECDSA functions ---------------------------------------------------------------------------------

#Create a digital signature for the string message using a given curve with a distinguished
#point P which generates a prime order subgroup of size n.
def sign(message, curve, base_point, order, nonce, sec_key, pub_key):
    #Extract the private and public keys, and compute z by hashing the message.
    z = hash_and_truncate(message, order)
    r, s = 0, 0
    while r == 0 or s == 0:
        R = curve.mult(base_point, nonce)
        r = R.x % order
        s = (mult_inv(nonce, order) * (z + r*sec_key)) % order
    #print('ECDSA sig of \"' + message+ '\" : (Q, r, s) = (' + str(Q) + ', ' + str(r) + ', ' + str(s) + ')')
    return (pub_key, r, s)


#Verify that the signature of a message is valid
def verify(message, curve, base_point, n, pub_key, r, s):
    #Confirm that Q is on the curve.
    if pub_key.is_infinite() or not curve.contains(pub_key):
        return False
    #Confirm that Q has order that divides n.
    if not curve.mult(pub_key,n).is_infinite():
        return False
    #Confirm that r and s are at least in the acceptable range.
    if r > n or s > n:
        return False
    #Compute z in the same manner used in the signing procedure,
    #and verify the message is authentic.
    z = hash_and_truncate(message, n)
    w = mult_inv(s, n) % n
    u_1, u_2 = z * w % n, r * w % n
    C_1, C_2 = curve.mult(base_point, u_1), curve.mult(pub_key, u_2)
    C = curve.add(C_1, C_2)
    return r % n == C.x % n


#Hash and truncate the message to be signed
def hash_and_truncate(message, n):
    h = int(sha256(str(message).encode('utf-8')).hexdigest(), 16)
    b = bin(h)[2:len(bin(n))]
    return int(b, 2)


#Compute the multiplicative inverse mod n of a with 0 < a < n.
def mult_inv(a, n):
    return pow(a, -1, n)


# THE REST OF THIS IS JUST ELLIPTIC CURVE LOGIC (not important)

class Point(object):
    #Construct a point with two given coordindates.
    def __init__(self, x, y):
        self.x, self.y = x, y
        self.inf = False

    #Construct the point at infinity.
    @classmethod
    def atInfinity(cls):
        P = cls(0, 0)
        P.inf = True
        return P

    def __str__(self):
        if self.inf:
            return 'Inf'
        else:
            return '(' + str(self.x) + ',' + str(self.y) + ')'

    def __eq__(self,other):
        if self.inf:
            return other.inf
        elif other.inf:
            return self.inf
        else:
            return self.x == other.x and self.y == other.y

    def is_infinite(self):
        return self.inf

#Elliptic Curves over any Field ------------------------------------------------------------------

class Curve(object):
    #Set attributes of a general Weierstrass cubic y^2 = x^3 + ax^2 + bx + c over any field.
    def __init__(self, a, b, c, char, exp):
        self.a, self.b, self.c = a, b, c
        self.char, self.exp = char, exp
        #print(self)

    #Compute the order of a point on the curve.
    def order(self, P):
        Q = P
        orderP = 1
        #Add P to Q repeatedly until obtaining the identity (point at infinity).
        while not Q.is_infinite():
            Q = self.add(P,Q)
            orderP += 1
        return orderP

    #Double a point on the curve.
    def double(self, P):
        return self.add(P,P)

    #Add P to itself k times.
    def mult(self, P, k):
        if P.is_infinite():
            return P
        elif k == 0:
            return Point.atInfinity()
        elif k < 0:
            return self.mult(self.invert(P), -k)
        else:
            #Convert k to a bitstring and use peasant multiplication to compute the product quickly.
            b = bin(k)[2:]
            return self.repeat_additions(P, b, 1)

    #Add efficiently by repeatedly doubling the given point, and adding the result to a running
    #total when, after the ith doubling, the ith digit in the bitstring b is a one.
    def repeat_additions(self, P, b, n):
        if b == '0':
            return Point.atInfinity()
        elif b == '1':
            return P
        elif b[-1] == '0':
            return self.repeat_additions(self.double(P), b[:-1], n+1)
        elif b[-1] == '1':
            return self.add(P, self.repeat_additions(self.double(P), b[:-1], n+1))

    


#Elliptic Curves over Prime Order Fields ---------------------------------------------------------

class CurveOverFp(Curve):
    #Construct a Weierstrass cubic y^2 = x^3 + ax^2 + bx + c over Fp.
    def __init__(self, a, b, c, p):
        Curve.__init__(self, a, b, c, p, 1)

    #The secp256k1 curve.
    @classmethod
    def secp256k1(cls):
        return cls(0, 0, 7, 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1)

    def contains(self, P):
        if P.is_infinite():
            return True
        else:
            return (P.y*P.y) % self.char == (P.x*P.x*P.x + self.a*P.x*P.x + self.b*P.x + self.c) % self.char

    def invert(self, P):
        if P.is_infinite():
            return P
        else:
            return Point(P.x, -P.y % self.char)

    def add(self, P_1, P_2):
        #Adding points over Fp and can be done in exactly the same way as adding over Q,
        #but with of the all arithmetic now happening in Fp.
        y_diff = (P_2.y - P_1.y) % self.char
        x_diff = (P_2.x - P_1.x) % self.char
        if P_1.is_infinite():
            return P_2
        elif P_2.is_infinite():
            return P_1
        elif x_diff == 0 and y_diff != 0:
            return Point.atInfinity()
        elif x_diff == 0 and y_diff == 0:
            if P_1.y == 0:
                return Point.atInfinity()
            else:
                ld = ((3*P_1.x*P_1.x + 2*self.a*P_1.x + self.b) * mult_inv(2*P_1.y, self.char)) % self.char
        else:
            ld = (y_diff * mult_inv(x_diff, self.char)) % self.char
        nu = (P_1.y - ld*P_1.x) % self.char
        x = (ld*ld - self.a - P_1.x - P_2.x) % self.char
        y = (-ld*x - nu) % self.char
        return Point(x,y)
