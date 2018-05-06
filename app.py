# -*- coding: utf-8 -*-
from Savoir.Savoir import Savoir
from flask import Flask,jsonify,request
from flask_cors import CORS, cross_origin
import subprocess
import getpass
import re
import time
from Crypto.PublicKey import RSA
import os
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from datetime import datetime
from threading import Timer
import json
from datetime import datetime
import urllib.request

si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
si.wShowWindow = subprocess.SW_HIDE # default

local_username = getpass.getuser()
chainname = 'newchain'
rpchost = '127.0.0.1'
rpcuser = ''
rpcpasswd = ''
rpcport = ''

try:
    conf_file = open(
        "C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\multichain.conf", "r")
    conf_lines = conf_file.readlines()
    rpcuser = re.findall(r"[\w']+", str(str(conf_lines[0])))[1]
    rpcpasswd = re.findall(r"[\w']+", str(str(conf_lines[1])))[1]

    conf_file.close()
    params_file = open("C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\params.dat",
                       "r")
    # params_lines = params_file.readlines()

    for params_line in params_file:
        if "default-rpc-port" in (str(params_line)):
            rpcport = re.findall(r"[\w']+", str(params_line))[3]

    params_file.close()

except FileNotFoundError:
    print("File Not Found")

try:
    conf_file = open(
        "C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\permissions.dat","r")
    conf_file.close()

except FileNotFoundError:
    print("Multichain not found")
    result = subprocess.Popen("multichaind newchain@192.248.15.152:4267", startupinfo=si, stdout=subprocess.PIPE)
    lines = result.stdout.readlines()
    tokens = str(lines[4]).split(' ')
    node = tokens[3]
    params = urllib.parse.urlencode({'node': node})
    result = urllib.request.urlopen("http://blockwork.projects.mrt.ac.lk/grant_connect.php?" + params).read()
    print(result)
    print("successfully initiated blockchain")

api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)

app = Flask(__name__)
CORS(app)


x=datetime.today()
d = x.day
if(x.day > 30):
    d = 1

y=x.replace(day=d+1, hour=0, minute=0, second=0, microsecond=0)
delta_t=y-x

secs=delta_t.seconds+1

def autoupdatecontracts():
    print("auto executing contracts")
    contracts_stream = "contracts"
    rules_stream = "ContractRules"
    con_status_stream = "ContractStatus"

    count = 100
    contracts = json.loads(json.dumps(api.liststreamitems(contracts_stream, False, count)))
    for c in contracts:
        contract = json.loads(Hex2String(c['data']))

        # load contract rule
        client_email = contract['client_email']
        r = json.loads(json.dumps(api.liststreamkeyitems(rules_stream, client_email)))
        if r:
            rule = json.loads(Hex2String(r[len(r) - 1]["data"]))

        # load contract status
        contract_txid = c['txid']
        cs = json.loads(json.dumps(api.liststreamkeyitems(con_status_stream, contract_txid)))

        if len(cs) != 0:
            contract_status = json.loads(Hex2String(cs[len(cs) - 1]['data']))

            # load active contracts
            if contract_status['status'] == "Active":

                # check if contract has milestones
                if (len(contract['milestoneValues']) > 0):

                    current_milestone = contract_status['current_milestone']
                    milestoneValue = contract['milestoneValues'][current_milestone - 1]
                    contract_deadline = datetime.date(datetime.strptime(milestoneValues['deadline'], "%Y-%m-%d"))

                else:
                    contract_deadline = datetime.date(datetime.strptime(contract['deadline'], "%Y-%m-%d"))

                today = datetime.date(datetime.now())

                if contract_deadline < today:
                    delay = today.day - contract_deadline.day
                    print(delay)

                    project_worth_mark = int(rule['project_worth_mark'])
                    contract_amount = int(contract['amount'])

                    # Freelancer fail to meet a deadline
                    if contract['type'] == "Freelancer":

                        reduce_percentage = rule['freelancer_pay_reduce_percentage']

                        if project_worth_mark < contract_amount:
                            if delay < rule['freelancer_contract_cancel_days_high']:
                                if (milestoneValue):
                                    # calculate reduced amount
                                    milestone_amout = int(milestoneValue['value']) - contract_amount * int(
                                        milestoneValue['value']) * (reduce_percentage) / 10000

                                    # update reduced amount
                                    contract['milestoneValues'][current_milestone - 1]['value'] = milestone_amout
                                    data_hex = String2Hex(json.dumps(contract))
                                    # api.publish(contracts_stream,str(contract['projectName']),data_hex)

                            elif delay == rule['freelancer_contract_cancel_days_high']:

                                # cancel contract
                                contract_status['status'] = "Cancelled"
                                data_hex = String2Hex(json.dumps(contract_status))
                                # api.publish(con_status_stream, str(contract_txid), data_hex)

                                try:
                                    if contract['contract_link'] != None:
                                        linked_contract_txid = str(contract['contract_link'])
                                        cancel_linked_contract(linked_contract_txid, con_status_stream)
                                except KeyError:
                                    print("Key error")

                        else:
                            if delay < rule['freelancer_contract_cancel_days_low']:
                                if (milestoneValue):
                                    # calculate reduced amount
                                    milestone_amout = int(milestoneValue['value']) - contract_amount * int(
                                        milestoneValue['value']) * (reduce_percentage) / 10000

                                    # update reduced amount
                                    contract['milestoneValues'][current_milestone - 1]['value'] = milestone_amout
                                    data_hex = String2Hex(json.dumps(contract))
                                    # api.publish(contracts_stream, str(contract['projectName']), data_hex)

                            elif delay == rule['freelancer_contract_cancel_days_low']:

                                # cancel contract
                                contract_status['status'] = "Cancelled"
                                data_hex = String2Hex(json.dumps(contract_status))
                                # api.publish(con_status_stream, str(contract_txid), data_hex)

                                try:
                                    if contract['contract_link'] != None:
                                        linked_contract_txid = str(contract['contract_link'])
                                        cancel_linked_contract(linked_contract_txid, con_status_stream)
                                except KeyError:
                                    print("Key error")

                    # QA fail to meet a deadline
                    if contract['type'] == "QA":

                        reduce_percentage = rule['qa_pay_reduce_percentage']

                        if project_worth_mark < contract_amount:
                            if delay < rule['qa_contract_cancel_days_high']:
                                if (milestoneValue):
                                    # calculate reduced amount
                                    milestone_amout = int(milestoneValue['value']) - contract_amount * int(
                                        milestoneValue['value']) * (reduce_percentage) / 10000

                                    # update reduced amount
                                    contract['milestoneValues'][current_milestone - 1]['value'] = milestone_amout
                                    data_hex = String2Hex(json.dumps(contract))
                                    # api.publish(contracts_stream, str(contract['projectName']), data_hex)

                            elif delay == rule['freelancer_contract_cancel_days_high']:
                                # cancel contract
                                contract_status['status'] = "Cancelled"
                                data_hex = String2Hex(json.dumps(contract_status))
                                # api.publish(con_status_stream, str(contract_txid), data_hex)

                        else:
                            if delay < rule['qa_contract_cancel_days_low']:
                                if (milestoneValue):
                                    # calculate reduced amount
                                    milestone_amout = int(milestoneValue['value']) - contract_amount * int(
                                        milestoneValue['value']) * (reduce_percentage) / 10000

                                    # update reduced amount
                                    contract['milestoneValues'][current_milestone - 1]['value'] = milestone_amout
                                    data_hex = String2Hex(json.dumps(contract))
                                    # api.publish(contracts_stream, str(contract['projectName']), data_hex)

                            elif delay == rule['qa_contract_cancel_days_high']:
                                # cancel contract
                                contract_status['status'] = "Cancelled"
                                data_hex = String2Hex(json.dumps(contract_status))
                                # api.publish(con_status_stream, str(contract_txid), data_hex)

    print("end of auto executing contracts")


t = Timer(secs, autoupdatecontracts)
t.start()

@app.route('/')
def index():
    return "Working"

def cancel_linked_contract(linked_contract_txid,con_status_stream):
    # laod linked contract
    lcs = json.loads(
        json.dumps(api.liststreamkeyitems(con_status_stream, linked_contract_txid)))
    linked_contract_status = json.loads(Hex2String(lcs[len(lcs) - 1]['data']))

    # cancel linked contract
    linked_contract_status['status'] = "Cancelled"
    data_hex = String2Hex(json.dumps(linked_contract_status))
    # api.publish(con_status_stream, linked_contract_txid, data_hex)

def Hex2String(hex_str):
    chunks =len(hex_str)
    chunk_size = 4
    hs = [ hex_str[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
    result_back = "";
    for h in hs:
        result_back += chr(int(h, 16))
    return result_back

def String2Hex(s):
    result = "";
    for i in list(s):
        h = hex(ord(i))
        result += ("000" + str(h)[2:])[-4:]
    return result

# General utilities
@app.route('/keygenerate', methods=['GET'])
def keygenerate():
    address = request.args.get('address')
    if not address:
        return "Please add address"
    addresses = api.getaddresses()

    if not (address in addresses):
        return "You dont have permission to generate keys the address: "+address
    pubkeys = api.liststreamkeyitems("pubkeys",address)
    print (pubkeys)
    if pubkeys:
        return "Address already exists"
    private = RSA.generate(1024)
    public = private.publickey()
    prikey = private.exportKey()
    pubkey = public.exportKey()
    print(pubkey, prikey)
    path = "C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\stream-privkeys"
    print("mkdir " + path)
    if not os.path.exists(path):
        os.makedirs(path)
    f = open(path +'\\' + address + '.pem','ab')
    f.write(prikey)
    f.close()
    f = open(path +'\\' + address + '.pem','rb')
    stream = "pubkeys"
    key = address
    data_hex = public.exportKey("DER") 
    decode = bytes.fromhex(data_hex.hex())
    p_key = RSA.importKey(decode).exportKey()
    api.publish(stream,key, data_hex.hex())
    return jsonify({"key":pubkey.decode('utf-8'),"address":address})

@app.route('/encrypt', methods=['GET'])
def encrypt():
    address = request.args.get('address')
    data = request.args.get('data')
    stream = "pubkeys"
    result = api.liststreamkeyitems(stream,address)
    decode = bytes.fromhex(result[0]['data'])
    p_key = RSA.importKey(decode).exportKey()
    encrypted = RSA.importKey(p_key).encrypt(data.encode('utf-8'), 32)
    return jsonify({"data":encrypted[0].hex()})


@app.route('/decrypt', methods=['GET'])
def decrypt():
    address = request.args.get('address')
    encrypted =  request.args.get('encrypted')
    decode = bytes.fromhex(encrypted)
    path = "C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\stream-privkeys"
    f = open(path +'\\' + address + '.pem','rb')
    key = RSA.importKey(f.read())
    print(key.exportKey())
    prikey = key.exportKey()
    #Decrypt with private key
    decrypted = RSA.importKey(prikey).decrypt(decode)
    return jsonify({'data':decrypted.decode('utf-8')})


@app.route('/sign', methods=['GET'])
def sign():
    address = request.args.get('address')
    data = request.args.get('data')
    # Hash the data
    digest = SHA256.new()
    digest.update(str(data).encode('utf-8'))
    print("digetst : ",digest)
    # Load private key
    path = "C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\stream-privkeys"
    f = open(path +'\\' + address + '.pem','rb')
    key = RSA.importKey(f.read())
    print("pri key : ", key)
    # Sign message
    signer = PKCS1_v1_5.new(key)
    sig = signer.sign(digest)
    return jsonify({'sign':sig.hex()})

@app.route('/verify', methods=['GET'])
def verify():
    stream = "pubkeys"
    address = request.args.get('address')
    signature = request.args.get('signature')
    data = request.args.get('data')
    # Hash the data
    digest = SHA256.new()
    digest.update(str(data).encode('utf-8'))
    print("digetst : ",digest)
    # Load public key
    result = api.liststreamkeyitems(stream,address)
    decode = bytes.fromhex(result[0]['data'])
    p_key = RSA.importKey(decode)
    print("Public key : ", p_key)
    # Load public key and verify message
    verifier = PKCS1_v1_5.new(p_key)
    decode_sig = bytes.fromhex(signature)
    verified = verifier.verify(digest, decode_sig)
    assert verified, 'Signature verification failed'
    print('Successfully verified message')
    return jsonify({'verified':verified})


@app.route('/start')
def start():
    r=subprocess.Popen("multichaind " + chainname + " -deamon", startupinfo=si)
    r.stdout
    time.sleep(10)
    return "started"

@app.route('/checkchain')
def checkchain():
    try:
        conf_file = open(
            "C:\\Users\\" + local_username + "\\AppData\\Roaming\\MultiChain\\" + chainname + "\\permissions.dat", "r")
        conf_file.close()
        return "yes"
    except FileNotFoundError:
        return "no"

# @app.route('/stop')
# def stop():
#     subprocess.Popen("multichain-cli " + chainname + " stop", startupinfo=si)
#     return "Multichain stopped"

@app.route('/node', methods=['GET'])
def getnodeinfo():
    result = subprocess.Popen("multichaind newchain@192.248.15.152:4267", startupinfo=si, stdout=subprocess.PIPE)
    lines = result.stdout.readlines()
    tokens = str(lines[4]).split(' ')
    return tokens[3]

@app.route('/getinfo', methods=['GET'])
def getinfo():
    return jsonify(api.getinfo())

@app.route('/getpeerinfo', methods=['GET'])
def getpeerinfo():
    return jsonify(api.getpeerinfo())

@app.route('/stop', methods=['GET'])
def stop():
    return jsonify(api.stop())

@app.route('/getblockchainparams', methods=['GET'])
def getblockchainparams():
    return jsonify(api.getblockchainparams())

@app.route('/getruntimeparams', methods=['GET'])
def getruntimeparams():
    return jsonify(api.getruntimeparams())

@app.route('/setruntimeparam', methods=['GET'])
def setruntimeparam():
    param = request.args.get('param')
    value = request.args.get('value')
    return jsonify(api.setruntimeparam(param,value))

# Managing wallet addresses

@app.route('/getaddresses', methods=['GET'])
def getaddresses():
    return jsonify(api.getaddresses(True))

@app.route('/getnewaddress', methods=['GET'])
def getnewaddress():
    return jsonify(api.getnewaddress())

@app.route('/listaddresses', methods=['GET'])
def listaddresses():
    return jsonify(api.listaddresses())

# Working with non-wallet addresses

@app.route('/validateaddress', methods=['GET'])
def validateaddress():
    address = request.args.get('address')
    return jsonify(api.validateaddress(address))

# Permissions management

@app.route('/grant', methods=['GET'])
def grant():
    addresses = request.args.get('addresses')
    permissions = request.args.get('permissions')
    return jsonify(api.grant(addresses,permissions))

@app.route('/grantfrom', methods=['GET'])
def grantfrom():
    from_address = request.args.get('from_address')
    to_addresses = request.args.get('to_addresses')
    permissions = request.args.get('permissions')
    return jsonify(api.grantfrom(from_address,to_addresses,permissions))

@app.route('/listpermissions', methods=['GET'])
def listpermissions():
    addresses = request.args.get('addresses')
    permissions = request.args.get('permissions')
    if (permissions and addresses):
        return jsonify(api.listpermissions(permissions,addresses))
    elif (addresses):
        return jsonify(api.listpermissions("*",addresses))
    elif (permissions):
        return jsonify(api.listpermissions(permissions))
    else:
        return jsonify(api.listpermissions())

@app.route('/revoke', methods=['GET'])
def revoke():
    addresses = request.args.get('addresses')
    permissions = request.args.get('permissions')
    return jsonify(api.revoke(addresses,permissions))

@app.route('/revokefrom', methods=['GET'])
def revokefrom():
    from_address = request.args.get('from_address')
    to_addresses = request.args.get('to_addresses')
    permissions = request.args.get('permissions')
    return jsonify(api.revokefrom(from_address,to_addresses,permissions))

# Asset management

@app.route('/issue', methods=['GET'])
def issue():
    address = request.args.get('address')
    name = request.args.get('name')
    qty = request.args.get('qty')
    units = request.args.get('units')
    custom_fields = request.args.get('custom_fields')
    return jsonify(api.issue(address,name,qty,units,custom_fields))

@app.route('/issuefrom', methods=['GET'])
def issuefrom():
    from_address = request.args.get('from-address')
    to_address = request.args.get('to-address')
    name = request.args.get('name')
    qty = request.args.get('qty')
    units = request.args.get('units')
    custom_fields = request.args.get('custom_fields')
    return jsonify(api.issuefrom(from_address,to_address,name,qty,units,custom_fields))

@app.route('/issuemore', methods=['GET'])
def issuemore():
    address = request.args.get('address')
    asset = request.args.get('asset')
    qty = request.args.get('qty')
    custom_fields = request.args.get('custom_fields')
    return jsonify(api.issuemore(address,asset,qty,custom_fields))

@app.route('/issuemorefrom', methods=['GET'])
def issuemorefrom():
    from_address = request.args.get('from_address')
    to_address = request.args.get('to_address')
    asset = request.args.get('asset')
    qty = request.args.get('qty')
    custom_fields = request.args.get('custom_fields')
    return jsonify(api.issuemorefrom(from_address,to_address,asset,qty,custom_fields))

@app.route('/listassets', methods=['GET'])
def listassets():
    return jsonify(api.listassets(True))

# Querying wallet balances and transactions

@app.route('/getaddressbalances', methods=['GET'])
def getaddressbalances():
    address = request.args.get('address')
    includeLocked = eval(request.args.get('includeLocked'))
    return jsonify(api.getaddressbalances(address,0,includeLocked))

@app.route('/getaddresstransaction', methods=['GET'])
def getaddresstransaction():
    address = request.args.get('address')
    txid = request.args.get('txid')
    return jsonify(api.getaddresstransaction(address,txid))

@app.route('/getmultibalances', methods=['GET'])
def getmultibalances():
    return jsonify(api.getmultibalances())

@app.route('/gettotalbalances', methods=['GET'])
def gettotalbalances():
    return jsonify(api.gettotalbalances())

@app.route('/getwallettransaction', methods=['GET'])
def getwallettransaction():
    txid = request.args.get('txid')
    return jsonify(api.getwallettransaction(txid))

@app.route('/listaddresstransactions', methods=['GET'])
def listaddresstransactions():
    address = request.args.get('address')
    count = 100
    return jsonify(api.listaddresstransactions(address,count))

@app.route('/listwallettransactions', methods=['GET'])
def listwallettransactions():
    return jsonify(api.listwallettransactions())

# Sending one-way payments

@app.route('/send', methods=['GET'])
def send():
    address = request.args.get('address')
    amount = request.args.get('amount')
    return jsonify(api.send(address,amount))

@app.route('/sendasset', methods=['GET'])
def sendasset():
    address = request.args.get('address')
    asset = request.args.get('asset')
    qty = int(request.args.get('qty'))
    return jsonify(api.sendasset(address,asset,qty))

@app.route('/sendassetfrom', methods=['GET'])
def sendassetfrom():
    from_address = request.args.get('from_address')
    to_address = request.args.get('to_address')
    asset = request.args.get('asset')
    qty = int(request.args.get('qty'))
    return jsonify(api.sendassetfrom(from_address,to_address,asset,qty))

@app.route('/sendfrom', methods=['GET'])
def sendfrom():
    from_address = request.args.get('from_address')
    to_address = request.args.get('to_address')
    amount = request.args.get('amount')
    return jsonify(api.sendfrom(from_address,to_address,amount))

@app.route('/sendwithdata', methods=['GET'])
def sendwithdata():
    address = request.args.get('address')
    amount = request.args.get('amount')
    data = request.args.get('data')     #hex-object
    return jsonify(api.sendwithdata(address,amount,data))

@app.route('/sendwithdatafrom', methods=['GET'])
def sendwithdatafrom():
    from_address = request.args.get('from_address')
    to_address = request.args.get('to_address')
    amount = request.args.get('amount')
    data = request.args.get('data')     #hex-object
    return jsonify(api.sendwithdatafrom(from_address,to_address,amount,data))

# Atomic exchange transactions

@app.route('/preparelockunspent', methods=['GET'])
def preparelockunspent():
    assets = request.args.get('assets') #{"asset":qty, ...}
    return jsonify(api.preparelockunspent(assets))

@app.route('/preparelockunspentfrom', methods=['GET'])
def preparelockunspentfrom():
    address = request.args.get('address')
    asset = request.args.get('asset') #{"asset":qty, ...}
    qty = int(request.args.get('qty'))
    assets = {asset:qty}
    return jsonify(api.preparelockunspentfrom(address,assets))

@app.route('/lockunspent', methods=['GET'])
def lockunspent():
    unlock = True;
    return jsonify(api.lockunspent(unlock))

@app.route('/appendrawexchange', methods=['GET'])

@app.route('/appendrawexchange', methods=['GET'])
def appendrawexchange():
    tx_hex = request.args.get('tx_hex')
    txid = request.args.get('txid')
    vout = request.args.get('vout')
    assets = request.args.get('assets')  # {"asset":qty, ...}
    return jsonify(api.appendrawexchange(tx_hex,txid,vout,assets))

@app.route('/createrawexchange', methods=['GET'])
def createrawexchange():
    txid = request.args.get('txid')
    vout = request.args.get('vout')
    assets = request.args.get('assets')  # {"asset":qty, ...}
    return jsonify(api.createrawexchange(txid,vout,assets))

@app.route('/completerawexchange', methods=['GET'])
def completerawexchange():
    tx_hex = request.args.get('tx_hex')
    txid = request.args.get('txid')
    vout = request.args.get('vout')
    assets = request.args.get('assets')  # {"asset":qty, ...}
    data = request.args.get('data')      # hex object
    return jsonify(api.completerawexchange(tx_hex,txid,vout,assets,data))

@app.route('/decoderawexchange', methods=['GET'])
def decoderawexchange():
    tx_hex = request.args.get('tx_hex')
    return jsonify(api.decoderawexchange())

@app.route('/disablerawtransaction', methods=['GET'])
def disablerawtransaction():
    tx_hex = request.args.get('tx_hex')
    return jsonify(api.disablerawtransaction(tx_hex))

# Stream management

@app.route('/create', methods=['GET'])
def create():
    name = request.args.get('name')
    open = request.args.get('open')
    # custom_fields = request.args.get('custom_fields')
    return jsonify(api.create("stream",name,False))

@app.route('/createfrom', methods=['GET'])
def createfrom():
    from_address = request.args.get('from_address')
    name = request.args.get('name')
    open = request.args.get('open')
    custom_fields = request.args.get('custom_fields')
    return jsonify(api.createfrom(from_address,"stream",name,False))

@app.route('/liststreams', methods=['GET'])
def liststreams():
    return jsonify(api.liststreams())

# Publishing stream items

@app.route('/publish', methods=['GET'])
def publish():
    stream = request.args.get('stream')
    key = request.args.get('key')
    data_hex = request.args.get('data_hex')
    return jsonify(api.publish(stream,key,data_hex))

@app.route('/publishfrom', methods=['GET'])
def publishfrom():
    from_address = request.args.get('from_address')
    stream = request.args.get('stream')
    key = request.args.get('key')
    data_hex = request.args.get('data_hex')
    return jsonify(api.publishfrom(from_address,stream,key,data_hex))

# Managing stream and asset subscriptions

@app.route('/subscribe', methods=['GET'])
def subscribe():
    streams = request.args.get('streams')       #or assets
    return jsonify(api.subscribe(streams))

@app.route('/unsubscribe', methods=['GET'])
def unsubscribe():
    streams = request.args.get('stream')
    return jsonify(api.unsubscribe(streams))

# Querying subscribed assets

@app.route('/getassettransaction', methods=['GET'])
def getassettransaction():
    txid = request.args.get('txid')
    asset = request.args.get('asset')
    return jsonify(api.getassettransaction(asset,txid))

@app.route('/listassettransactions', methods=['GET'])
def listassettransactions():
    asset = request.args.get('asset')
    return jsonify(api.listassettransactions(asset))

# Querying subscribed streams

@app.route('/getstreamitem', methods=['GET'])
def getstreamitem():
    txid = request.args.get('txid')
    stream = request.args.get('stream')
    return jsonify(api.getstreamitem(stream,txid))

@app.route('/gettxoutdata', methods=['GET'])
def gettxoutdata():
    txid = request.args.get('txid')
    vout = request.args.get('vout')
    return jsonify(api.gettxoutdata(txid,0))

@app.route('/liststreamkeyitems', methods=['GET'])
def liststreamkeyitems():
    key = request.args.get('key')
    stream = request.args.get('stream')
    count = 100
    return jsonify(api.liststreamkeyitems(stream,key,False,count))

@app.route('/liststreamkeys', methods=['GET'])
def liststreamkeys():
    stream = request.args.get('stream')
    return jsonify(api.liststreamkeys(stream))

@app.route('/liststreamitems', methods=['GET'])
def liststreamitems():
    stream = request.args.get('stream')
    count = 100
    return jsonify(api.liststreamitems(stream,False,count))

@app.route('/liststreampublisheritems', methods=['GET'])
def liststreampublisheritems():
    stream = request.args.get('stream')
    address = request.args.get('address')
    return jsonify(api.liststreampublisheritems(stream,address))

@app.route('/liststreampublishers', methods=['GET'])
def liststreampublishers():
    stream = request.args.get('stream')
    return jsonify(api.liststreampublishers(stream))

if __name__ == '__main__':
    app.run(debug=True)