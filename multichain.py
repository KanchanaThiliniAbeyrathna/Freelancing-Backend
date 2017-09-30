import os

rpcuser = 'multichainrpc'
rpcpasswd = 'BjAgaHcha9o59AW1Py9FVQ8DH5JefCBUwFPD3iu3hyoz'
rpchost = '127.0.0.1'
rpcport = '6448'
chainname = 'chain1'

if __name__ == '__main__':
    # os.chdir(os.getcwd()+'\multichain')
    # os.system('cd')
    os.system("multichaind "+chainname+" -deamon")