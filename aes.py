
from operator import sub
from bitvector_demo import AES_modulus
from numpy.lib.function_base import append

from BitVector import * 
import numpy as np
import time 

# Settings :::::::::::::::::::::::::::::::::

anyFile = False

debug = True

chunk_size = 16


# FUNCTION :::::::::::::::::::::::::::::::::

def print_ascii(m) :

    for i in range(4) :
        for j in range(4) :
            print(m[j][i].get_bitvector_in_ascii(),end="")
    print()
    

def print_list(m) :
    for i in m:
        print(i[2:],end=" ")
    print()

def xor(a,b):

    ret = []
    for i,j in zip(a,b) :
        ret.append ( hex( int(i,16) ^ int(j,16) ) )

    return ret 

def print_matrix(m) :

    for i in range(4) :
        for j in range(4) :
            print(m[j][i].get_bitvector_in_hex(),end=" ")
    print()

def multiply(X, Y):
    ret = []
    AES_modulus = BitVector(bitstring='100011011')
    for i in range(4):
        t = []
        for j in range(4):
            bv3 = BitVector(hexstring="00")
            for k in range(4):
                bv1 = X[i][k]
                bv2 = Y[k][j]
                bv3 =  bv3.__xor__(bv1.gf_multiply_modular(bv2, AES_modulus, 8) )
            t.append(bv3)
        ret.append(t)
    
    return ret

# DECLARATION :::::::::::::::::::::::::::::::::::::::::

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]




# Input Output ::::::::::::::::::::::::::::::::::::::::::::::::::::



if debug:
    key = "Thats my Kung Fu"
else:
    key = input("Enter the ASCII key string: ")

if (len(key)<16) :
    key = "{:0<16}".format(key)
    
elif (len(key)>16) :
    key = key[0:16]
    
if not anyFile:

    if debug : plain_text = "Two One Nine Two"
    else: plain_text = input("Enter text to encrypt: ")

    if len(plain_text)%chunk_size != 0 :

        to_add = (int(len(plain_text)/chunk_size)+1)*chunk_size
        plain_text = plain_text.ljust( to_add , " " )


    chunks = [plain_text[i:i+chunk_size] for i in range(0, len(plain_text), chunk_size)]

# I/O For file ::::::::::::::::::::::::::::::::::::::::::::::::::

if anyFile:

    input_file = open("one.txt",'rb')
    output_file = open("encrypted_file_hex.txt",'wb')
    new_file = open("new_file.txt",'wb')

    chunks = []

    while True :
        data = input_file.read(16)
        if data :
            chk = len(data)%chunk_size
            if chk:
                data += bytes(chunk_size-chk)
            chunks.append(data)
        else : break

    input_file.close()


start  = time.time()
# KEY GENERATION FOR 10 ROUND ::::::::::::::::::::::::::::::::::

w = []
hex_key = []
for k in key:
    hex_key.append( hex( ord(k) ) )


w = [hex_key[0:4],hex_key[4:8],hex_key[8:12],hex_key[12:16]]
round_const = [1,0,0,0]


for i in range(10) :
    
    np_w3 = np.array( w[4*i+3] ) 
    np_w3 = np.roll(np_w3,-1)

    sub_w3 = map( lambda x : hex(Sbox[int(x,16)]) , np_w3 )
    

    gw3 = []

    ii = 0
    for s in sub_w3:
        gw3.append( hex( int(s,16) ^ round_const[ii] ) )
        ii = ii+1

    w.append( xor(w[4*i],gw3) )
    w.append( xor( w[4*i+1],w[4*i+4] ) )
    w.append( xor( w[4*i+2],w[4*i+5] ) )
    w.append( xor( w[4*i+3],w[4*i+6] ) )

    AES_modulus = BitVector(bitstring='100011011')
    round_const[0] =  BitVector(intVal=round_const[0]).gf_multiply_modular(BitVector(hexstring = "02"),AES_modulus,8).intValue()

end = time.time()
ks_time = end - start


start = time.time()
# Encryption :::::::::::::::::::::::::::::::::::::::::::::::::::::

Encrypted_MSG = []
Plain_Text_hex = []

#print("chunk size : ",len(chunks))

for c in chunks:

    #converting into Hex
    if not anyFile :
 
        plain_text_hex = []
        for s in c:
            plain_text_hex.append( hex( ord(s) ))
        
        Plain_Text_hex.append(plain_text_hex)

    else :

        plain_text_hex = []
        for s in c:
            plain_text_hex.append( hex(s) )
    
   

    #print(plain_text_hex)
    
    #preparing matrix
    PlaneTextMatrix = []

    for round_count in range(11) :

        RoundMatrix = []

        for i in range(4) :
            t = []
            p = []
            for j in range(4) :
                t.append( BitVector( hexstring = plain_text_hex[4*j+i][2:]) )
                p.append( BitVector( hexstring = w[4*round_count+j][i][2:]) )

            if(round_count==0) : PlaneTextMatrix.append(t)
            RoundMatrix.append(p)


        # print()
        # print("ROUND :",round_count )

        if round_count != 0 :

            # substitute byte
            for l in range(4) :
                for r in range(4) :
                    s = Sbox[PlaneTextMatrix[l][r].intValue()]
                    s = BitVector(intVal=s, size=8)
                    PlaneTextMatrix[l][r] = s


            # print("Substitution bytes: ")
            # print_matrix(PlaneTextMatrix)






            for l in range(4) :
                for r in range(l) :
                        PlaneTextMatrix[l].append(PlaneTextMatrix[l].pop(0))

            # print("Shift Row: ")
            # print_matrix(PlaneTextMatrix)


            

            if round_count != 10 :
                PlaneTextMatrix = multiply(Mixer,PlaneTextMatrix)
                # print("Mix Column")
                # print_matrix(PlaneTextMatrix)


        for l in range(4) :
            for r in range(4) :
                PlaneTextMatrix[l][r] = PlaneTextMatrix[l][r].__xor__(RoundMatrix[l][r])



    Encrypted_MSG.append(PlaneTextMatrix)

  
end = time.time()
en_time = end - start
# Encryption DONE ::::::::::::::::::::::::::::::::::::::::::::::

# Report ::::

if not anyFile:
    print("\n\nKey: ")
    print(key)
    print_list(hex_key)

    print("\nInput Text: ")
    print(plain_text)
    for i in Plain_Text_hex:
        print_list(i)

    print("\nCipher Text: ")

    for e in Encrypted_MSG:
        print_matrix(e)
    print()

    print("\nCipher Text in ASCII")
    for e in Encrypted_MSG:
        print_ascii(e)
    print()
else :
    print("\nFile encryption DONE!\n")

    for e in Encrypted_MSG :
        for i in range(4):
            for j in range(4):
                e[j][i].write_to_file(output_file)

    
    output_file.close()
# Decryption :::::::::::::::::: STARTS HERE ::::::::::::::::::::::::


InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

Decrypted_MSG = []

start = time.time()


for E in Encrypted_MSG:



    for round_count in reversed(range(11)) :

       
        # getting round matrix
        RoundMatrix = []

        for i in range(4) :
            p = []
            for j in range(4) :
                p.append( BitVector( hexstring = w[4*round_count+j][i][2:]) )
            RoundMatrix.append(p)

        # Add Round Key 
        for l in range(4) :
            for r in range(4) :
                E[l][r] = E[l][r].__xor__(RoundMatrix[l][r])

        if round_count!= 0 :

            # Reverse Mixing Column :)

            if round_count != 10:
                E = multiply(InvMixer,E)


            # Inverse Shift Rows i.e. right shift
            for l in range(4) :
                for r in range(l) :
                        E[l].insert(0,E[l].pop())

            # Inverse Substitution Bytes
            for l in range(4) :
                for r in range(4) :
                    s = InvSbox[E[l][r].intValue()]
                    s = BitVector(intVal=s, size=8)
                    E[l][r] = s

    
    Decrypted_MSG.append(E)
        
end = time.time()
de_time = end - start
# Decryption DONE :::::::::::::::::::::::::::::

# Report :::::::::

if not anyFile:

    print("\n\nDeciphered Text:")
    for d in Decrypted_MSG:
        print_matrix(d)
    print()

    print("\nDecipher Text in ASCII")
    for d in Decrypted_MSG:
        print_ascii(d)
    print()
else :

    for d in Decrypted_MSG:
        for i in range(4):
            for j in range(4):
                d[j][i].write_to_file(new_file)
    new_file.close()

    print("\nFile decryption DONE!\n")

print("\nExecution Time: ")
print("Key Scheduling: ",ks_time)
print("Encryption Time: ",en_time)
print("Decryption Time: ",de_time)