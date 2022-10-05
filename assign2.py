# import necessary libraries
from ast import Constant
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random
import os
from Crypto.Util.Padding import unpad

# header size constant
HEADER_SIZE = 54

def ECB():
    with open("mustang.bmp", "rb") as image:
        fileheader = image.read(54)
        filedata = image.read()
        # b = bytearray(f)
        
    #STEP 1.) AFTER PRESERVING HEADER, PAD THE FILE DATA   
    padded_file = pad(filedata)

    #STEP 2.) ENCRYPT filedata
    # encrypted_output = cipher.encrypt(padded_file)
    encrypted_output = encrypt_EBC(padded_file)
    

    #STEP 3.) FIRST WRITE THE HEADER TO THE NEW FILE
    with open("encrypted_ECB.bmp","wb") as encrypted_file:
        encrypted_file.write(fileheader)
        encrypted_file.write(encrypted_output)
        
def encrypt_EBC(padded_file):

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    index1 = 0
    index2 = 16

    counter = len(padded_file) / 16

    output = bytes()

    while(counter >= 0):
        block = padded_file[index1:index2]
        # print(block)
        index1 = index1 + 16
        index2 = index2 + 16
        counter = counter - 1
        # output = cipher.encrypt(output) + block CBC + WE NEED IV
        output = output + cipher.encrypt(block)
    # output = cipher.encrypt(padded_file)
    # print(output)
    return output

# XOR two bytes 
def XOR(block1, block2):

    # XOR bits in the bytes
    return bytes(a ^ b for a, b in zip(block1, block2))

def CBC():
    with open("mustang.bmp", "rb") as image:
        fileheader = image.read(54)
        filedata = image.read()
        # b = bytearray(f)
        
    #STEP 1.) AFTER PRESERVING HEADER, PAD THE FILE DATA
    # call the pad function and pad the file  
    padded_file = pad(filedata)

    #STEP 2.) ENCRYPT filedata
    # pass padded file to CBC encryption function
    encrypted_output =  encrypt_CBC(padded_file)

    #STEP 3.) FIRST WRITE THE HEADER TO THE NEW FILE
    with open("encrypted_CBC.bmp","wb") as encrypted_file:
        encrypted_file.write(fileheader)
        encrypted_file.write(encrypted_output)

def encrypt_CBC(padded_file):

    # generate random key
    key = get_random_bytes(16)

    # generate cipher
    cipher = AES.new(key, AES.MODE_CBC)

    # initialize indices
    index1 = 0
    index2 = 16

    # calculate counter for number of bytes to encrypt
    counter = len(padded_file) / 16

    # output is in bytes
    ciphertext = bytes()

    # ENCRYPT THE FIRST BLOCK WITH IV
    block = padded_file[index1:index2]

    # encrypt first block with iv
    first_block = cipher.encrypt(block)

    # create ciphertext with first block
    ciphertext = ciphertext + first_block

    # increment indices by 16 
    index1 = index1 + 16
    index2 = index2 + 16

    # decrement counter
    counter = counter - 1

    # ENCRYPT REMAINING BLOCKS WITHOUT IV
    while(counter > 0):

        # next block to be encrypted
        plaintext = padded_file[index1:index2]

        # increment indices 
        index1 = index1 + 16
        index2 = index2 + 16

        # decrement counter
        counter = counter - 1

        # XOR cipher text and plain text
        xorOutput = XOR(ciphertext, plaintext)

        # encrypt the xored output
        ciphertext = ciphertext + cipher.encrypt(xorOutput, None)

    return ciphertext

def pad(filedata):
    # each array slot is 8 bits
    # so 16 array slots is 128 bits
    # len(b) % 16 = how many slots to pad
    # print(type(filedata))
    bytesToPad = ( 16 - (os.path.getsize('mustang.bmp') - HEADER_SIZE) % 16 )

    #print(os.path.getsize('mustang.bmp'))

    # initialize counter
    counter = 0
    bytes = []
    
    while counter < bytesToPad:
        bytes.append(bytesToPad)
        counter = counter + 1

    byte_array = bytearray(bytes)
    padded_data = filedata + byte_array
    # print(len(padded_data))
    return padded_data

def submit2(key, iv):

    # user input string
    user_input = input('Enter a string: ')

    # prepended string
    prepend_string = "userid=456;userdata="

    # appended string
    append_string = ";session-id=31337"

    # URL encode any ; or = in user provided string
    # URL encode ; and =
    semicolon = "%3B"
    equal = "%3D"

    # replace semicolons in user input
    semi_user_input = user_input.replace(";", semicolon)

    # replace equals in user input
    equal_user_input = semi_user_input.replace("=", equal)

    #print(equal_user_input)

    # final user input
    finalUserInput = prepend_string + equal_user_input + append_string

    #print(finalUserInput)

    finalUserInput = bytes(finalUserInput, 'utf-8')

     # find the number of bytes to pad 
    bytesToPad = (16 - (len(finalUserInput) % 16))

    # intialize counter to 0
    counter = 0 

    # initialize byte array
    Bytes = []

    # pad bytes of
    while(counter < bytesToPad):
        
        # add the number of bytes to pad to the byteArray
        # pad it with the number of bytes to pad 
        Bytes.append(bytesToPad)
        
        # increment counter
        counter = counter + 1

    # convert Bytes to byte array
    byteArray = bytearray(Bytes)

    # create the padded string
    paddedString = finalUserInput + byteArray

    # create cipher generate pass key and iv
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # encrypt input to create cipher text
    cipher_text = cipher.encrypt(paddedString)

    # return padded string
    return paddedString, cipher_text

def padNewInput(newInput):
    
     # find the number of bytes to pad 
    bytesToPad = (16 - (len(newInput) % 16))

    # intialize counter to 0
    counter = 0 

    # initialize byte array
    Bytes = []

    # pad bytes of
    while(counter < bytesToPad):
        
        # add the number of bytes to pad to the byteArray
        # pad it with the number of bytes to pad 
        Bytes.append(bytesToPad)
        
        # increment counter
        counter = counter + 1

    # convert Bytes to byte array
    byteArray = bytearray(Bytes)

    # create the padded string
    paddedString = newInput + byteArray

    # return padded string
    return paddedString

def verify2(userInput, key, iv):

    # transfrom userInput from byte class to string
    stringUserInput = str(userInput)

    # create a new input to find -admin-true- easier
    newInput = stringUserInput.replace("%3Badmin%3Dtrue%3B", "-admin-true-")

    # convert new input to byte array
    byteNewInput = bytes(newInput, 'utf-8')

    # pad new byte input
    byteNewInput = padNewInput(byteNewInput)

    # create cipher generate pass key and iv
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # encrypt input to create cipher text
    cipher_text = cipher.encrypt(byteNewInput)

    # convert cipher text into a byte array
    ciphertextArray = bytearray(cipher_text)

    # XOR LOGIC

    # look at -admin-true-
    # - first char is -
    # - look a block ahead which has char r

    # xor correlated dash value
    firstXor = ciphertextArray[16] ^ ord('-')

    # xor the previous block and value with the wanted char
    insert = firstXor ^ ord(';')

    # insert the desired value into the cipher text array
    ciphertextArray[16] = insert

    # -------------------

    # xor correlated dash value
    firstXor = ciphertextArray[27] ^ ord('-')

    # xor the previous block and value with the wanted char
    insert = firstXor ^ ord(';')

    # insert the desired value into the cipher text array
    ciphertextArray[27] = insert

    # -------------------

    # xor correlated dash value
    firstXor = ciphertextArray[22] ^ ord('-')

    # xor the previous block and value with the wanted char
    insert = firstXor ^ ord('=')

    # insert the desired value into the cipher text array
    ciphertextArray[22] = insert

    # pass encrypted text to decrypt function
    decrypted_text = decrypt(key, iv, ciphertextArray)

    # convert decrypted text to string
    dtext = str(decrypted_text)

     # string to be found
    stringtobeFound = ";admin=true;"

    #print(dtext)
    
    # look if string is in decrypted text
    if stringtobeFound in dtext:
        
        print("String: ;admin=true; found.")

        # string found
        return True
    else:
        
        print("String: ;admin=true; not found.")

        # string not found
        return False

def decrypt(key, iv, etext):

    # create cipher generate pass key and iv
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # return the unpadded decrypted text
    return unpad(cipher.decrypt(etext), 16)


    
# -- Main Function -- 
def main():
    
    # Task 1
    # ECB()
    # CBC()

     # generate constant key 
    Constant.key = get_random_bytes(16)

    # generate constant iv
    Constant.iv = os.urandom(16)

    # TASK 2
    userInput, ciphertext = submit2(Constant.key, Constant.iv)

    print("Submit Function returned: ", ciphertext) 

    #print("Padded String: ", userInput)

    # Task 3
    # verify(ciphertext, Constant.key, Constant.iv)
    found = verify2(userInput, Constant.key, Constant.iv)

    if(found):
        print("The function verify returned true.")
    else:
        print("The function verify returned false.")

main()