from flask import Flask, render_template, redirect, url_for, request,session
import rsa
import base64
app = Flask(__name__)
app.secret_key="SecretKey"



def generates_keys():
    (pubKey, privKey) = rsa.newkeys(1024)
    return pubKey, privKey

(server_public,server_private)=generates_keys()
(daniel_public,daniel_private)=generates_keys()

def encrypt(PlainText, key):
    return rsa.encrypt(PlainText.encode('ascii'), key)


def decrypt(CipherText,key):
    try:
        return rsa.decrypt(CipherText, key).decode('ascii')
    except:
        return False

def sign_sha1(msg, key):
   return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False




@app.route("/")
def EncryptionLab():
    return render_template("EncryptionLab.html")

@app.route("/NextPage")
def NextPage():
    return render_template("welcome.html")

@app.route("/generate_keys")
def generate_keys():
    (pub, pri) = generates_keys()
    session["pub"]=pub.save_pkcs1("PEM")
    session["pri"]=pri.save_pkcs1("PEM")
    return redirect(url_for("generated_keys"))



@app.route("/generated_keys")
def generated_keys():
    if "pub" in session and "pri" in session:
        pub=session["pub"]
        pri=session["pri"]
        return render_template("GeneratedKeys.html",message= str(pub),msg= str(pri))
    else:
        return redirect(url_for("generate_keys"))


@app.route("/exchanging_keys")
def exchanging_keys():
    pub= session["pub"]
    pri= session["pri"]
    return render_template("KeysSharing.html",msg1=pub,msg2=pri)

@app.route("/exchanged_keys",methods=["POST","GET"])
def exchanged_keys():
    if request.method == "POST":
        if request.form.get("keytype") == "public":
            return render_template("EncryptionPage.html")
        else:
            return render_template("PrivacyIssue.html")

@app.route("/message_encryption")
def message_encryption():
        return render_template("EncryptionPage.html")



@app.route("/encrypted_message",methods=["POST","GET"])
def encrypted_message():
    if request.method == "POST":
        if request.form.get("keytype") == "public":
            return render_template("BobFalseReading.html")
        if request.form.get("keytype") == "private":
            msg=request.form.get("me")
            return render_template("ThirdPartyUser.html",message=msg)
        else:
            return redirect(url_for("message_decryption"))





@app.route("/message_decryption")
def message_decryption():
    msg="Congratulations, you have decrypted the message correctly"
    pub = rsa.PublicKey.load_pkcs1(session["pub"], "PEM")
    enc=encrypt(msg,pub)
    return render_template("DecryptionPage.html",message=enc)



@app.route("/decrypted_message",methods=["POST","GET"])
def decrypted_message():
    pub = rsa.PublicKey.load_pkcs1(session["pub"], "PEM")
    msg="Congratulations, you have decrypted the message correctly"
   # pri = rsa.PrivateKey.load_pkcs1(session["pri"], "PEM")
    if request.method == "POST":
        if request.form.get("keytype") == "public":
            enc1=encrypt(msg,pub)
            first_part,second_part=enc1[:80],enc1[80:]
            enc2=encrypt(base64.b64encode(first_part,None).decode(),pub)
            enc3=encrypt(base64.b64encode(second_part,None).decode(),pub)
            enc4=enc2+enc3
            return render_template("DoubleEncrypted.html",message=enc4)
        if request.form.get("keytype") == "BobPublic":
            en1=encrypt(msg,pub)
            first__part,second__part=en1[:80],en1[80:]
            en2=encrypt(base64.b64encode(first__part,None).decode(),server_public)
            en3=encrypt(base64.b64encode(second__part,None).decode(),server_public)
            en4=en2+en3
            return render_template("BobDoubleEncrypted.html",message=en4)
        else:
            return render_template("BobWrote.html",message=msg)

@app.route("/after_signing",methods=["POST","GET"])
def after_signing():
    if request.method == "POST":
        if request.form.get("m1") == "dan" and request.form.get("m2") == "bob":
            return render_template("Successful.html")
        else:
            return render_template("WrongSubmission.html")


@app.route("/signing")
def signing():
    msg1="Hello my name is Daniel"
    msg2="I'm Bob, do you remember me?"
    msg1_enc=encrypt(msg1,daniel_private)
    msg2_enc=encrypt(msg2,server_private)
    return render_template("Signing.html",message1=msg1_enc,message2=msg2_enc)


@app.route("/message1")
def message1():
    return render_template("CheckMessage1.html")


@app.route("/message2")
def message2():
    return render_template("CheckMessage2.html")

@app.route("/check_message1",methods=["POST","GET"])
def check_message1():
    if request.method == "POST":
        if request.form.get("whichkey") == "dan":
            msg="Hello my name is Daniel"
            return render_template("CheckSuccessful.html",message=msg)
        else:
            return render_template("WrongChoice1.html")

@app.route("/check_message2",methods=["POST","GET"])
def check_message2():
    if request.method == "POST":
        if request.form.get("whichkey") == "bob":
            msg="I'm Bob, do you remember me?"
            return render_template("CheckSuccessful.html",message=msg)
        else:
            return render_template("WrongChoice2.html")


@app.route("/hashing")
def hashing():
    return render_template("Hashing.html")

if __name__ == "__main__":
     app.run(debug=True)