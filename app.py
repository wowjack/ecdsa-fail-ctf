from flask import Flask, request, render_template
from secrets import token_hex
from os import getcwd, listdir
from os.path import isfile
from ecdsa import *
app = Flask(__name__, template_folder=".")

# Initialize cryptographic stuff
curve = CurveOverFp.secp256k1()
base_point = Point(55066263022277343669578718895168534326250603453777594175500187360389116729240,
                  32670510020758816978083085130507043184471273380659243275938904335757337482424)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
with open("./sec_key.txt") as f:
   sec_key = int(f.readline(), base=10)
pub_key = curve.mult(base_point, sec_key)
# Generate a random nonce to sign allowed file names
nonce = int(token_hex(32), base=16)


# Create the list of files that should not be accessed
blocked_files = ["sec_key.txt", "flag.txt", "solution.py"]
# Get all files in the cwd and omit the files that are blocked
allowed_files = [f for f in listdir(getcwd()) if f not in blocked_files and isfile(f)]
# Sign the names of all the files that are allowed to be accessed
signatures = [sign(filename, curve, base_point, order, nonce, sec_key, pub_key) for filename in allowed_files]
# Pair up the filenames and their associated signatures
names_and_sigs = [{"name": name, "r": sig[1], "s": sig[2]} for name, sig in zip(allowed_files, signatures)]


@app.route('/', methods=["GET"])
def main_page():
   return render_template("mainpage.html", files=names_and_sigs)


@app.route("/file", methods=["GET"])
def show_file():
   params = request.args.to_dict()
   filename = params.get('name', '')
   try:
      r = int(params.get('r', 0), base=10)
      s = int(params.get('s', 0), base=10)
   except:
      r, s = 0, 0
   

   # Make sure the file actually exists and the signature is correct
   if not isfile(filename):
      return render_template("filepage.html", name=filename, contents=f"{filename} does not exist!")
   try:
      if not verify(filename, curve, base_point, order, pub_key, r, s):
         return render_template("filepage.html", name=filename, contents=f"Invalid signature! You're not allowed to access {filename}")
   except:
      return render_template("filepage.html", name=filename, contents=f"Invalid signature! You're not allowed to access {filename}")
   

   with open(filename) as f:
      file_contents = f.read()

   return render_template("filepage.html", name=filename, contents=file_contents)


if __name__ == "__main__":
   app.run(host='0.0.0.0', port=5000, debug=True)