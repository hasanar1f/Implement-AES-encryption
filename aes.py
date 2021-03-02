
debug = True

if debug:
    key = "Thats my Kung Fu"
else:
    key = input("Enter the ASCII key string: ")

if (len(key)<16) :
    key = "{:0<16}".format(key)
    print(key)
elif (len(key)>16) :
    key = key[0:16]
    print(key)


# generating key for all round

w = []
hex_key = []
for k in key:
    hex_key.append( hex( ord(k) ) )

if debug:
    print("Hex code")
    print(hex_key)

w.append( hex_key[0:4] )
w.append( hex_key[4:8] )
w.append( hex_key[8:12] )
w.append( hex_key[12:16] )

if debug:
    print(w)



