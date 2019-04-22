from flask import Flask,request,abort
import gnupg
import time
app = Flask(__name__)
gpg = gnupg.GPG(gnupghome="/tmp/gpg")

couponCodes = {
    "water": "WATER_2019",
    "beer" : "鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻�" # REDACTED
}

@app.route("/generateEncryptedVoucher", methods=['POST'])
def generateEncryptedVoucher():

    content = request.json
    (recipientName,drink) = (content['recipientName'],content['drink'])

    encryptedVoucher = str(gpg.encrypt(
        "%s||%s" % (recipientName,couponCodes[drink]),
        recipients  = None,
        symmetric   = True,
        passphrase  = couponCodes[drink]
    )).replace("PGP MESSAGE","DRINK VOUCHER")
    return encryptedVoucher

@app.route("/redeemEncryptedVoucher", methods=['POST'])
def redeemEncryptedVoucher():

    content = request.json
    (encryptedVoucher,passphrase) = (content['encryptedVoucher'],content['passphrase'])
    
    # Reluctantly go to the fridge...
    time.sleep(15)

    decryptedVoucher = str(gpg.decrypt(
        encryptedVoucher.replace("DRINK VOUCHER","PGP MESSAGE"),
        passphrase = passphrase
    ))
    (recipientName,couponCode) = decryptedVoucher.split("||")

    if couponCode == couponCodes["water"]:
        return "Here is some fresh water for %s\n" % recipientName
    elif couponCode == couponCodes["beer"]:
        return "Congrats %s! The flag is INS{%s}\n" % (recipientName, couponCode)
    else:
        abort(500)

if __name__ == "__main__":
    app.run(host='0.0.0.0')