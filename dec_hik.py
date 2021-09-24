from Crypto.Cipher import AES
import struct
from sys import exit, argv
from ctypes import c_uint

KEY_XOR = "\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE"
LIST_KEY_AES =  {"0x850000" : "\xE5\xBF\x66\x8F\x7D\x8C\xDB\x8D\x38\x1F\xAB\x79\x77\xBB\x72\x76\x5D\x2D\x2F\xF2\xC9\xB4\xF7\x1A\xDE\xC1\xF5\x74\x3E\x42\xD0\x8E", 
                "0x850001" : "\x91\x8D\xA7\xB3\x26\x69\x0E\x52\x71\x94\x2D\x6C\xCD\x1C\xD6\x82\x1D\xD9\x25\x51\x5E\x98\x8D\xD4\x0D\x98\x75\xF1\xDA\xD0\xB1\x3D",
                "0x850100" : "\x51\xE8\x46\xD7\x0B\x8E\x23\xDA\xCE\x16\x09\x46\x3A\xF2\xB2\xF1\x4A\x21\x57\x40\x9F\x49\x31\xBD\x50\xE4\x40\xFF\x76\xA6\x0A\x4D",
                "0x850101" : "\x81\xEC\xAE\xB2\x0C\x6F\x8D\xE0\xFD\xE3\xD4\xAF\xB4\xAC\xE9\x0A\x9C\xB0\xE5\x9D\x19\xD3\xB7\xB7\x00\x34\xA4\x24\x3C\xF3\x97\x54"}

SIGNATURE = [0, 0x77073096, 0xEE0E612C, 0x990951BA, 0x76DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3, 0xEDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x9B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x1DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x6B6B51F, 0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0xF00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x86D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x3B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x4DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0xD6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0xA00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x26D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x5005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0xCB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0xBDBDF21, 0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D]

def hexdump(txt):
    data = txt
    size = len(data)
    iline = 0
    offset = 0
    while iline < size / 16:
        print(hex(offset)),
        offset = offset + 16
        stri = "\t"
        for i in range(iline * 16, iline * 16 + 4):
            stri += "%02x " % ord(data[i])
        
        stri += " "
        
        for i in range(iline * 16 + 4, iline * 16 + 8):
            stri += "%02x " % ord(data[i])
        
        stri += "  " 

        for i in range(iline * 16 + 8, iline * 16 + 12):
            stri += "%02x " % ord(data[i])
        
        stri += " "
        
        for i in range(iline * 16 + 12, iline * 16 + 16):
            stri += "%02x " % ord(data[i])

        stri += " | "    
        for i in range(iline * 16, iline * 16 + 16):
            if ord(data[i]) < 32 or ord(data[i]) > 126:
                stri += '.'
            else:
                stri += data[i]
        print(stri)

        iline = iline + 1

def firm_dec_hikv0(cipher_text, key_xor, length):
    plain_text = ""
    for i in range(0, length):
        cipher_byte     =   cipher_text[i]
        key_xor_byte    =   key_xor[ (c_uint(i >> 4).value + i) & 0xF]
        plain_text      =   plain_text + chr(ord(cipher_byte) ^ ord(key_xor_byte))

    return plain_text

def firm_dec_aes(cipher_text, key):
    aes_ecb = AES.new(key, AES.MODE_ECB)
    msg = aes_ecb.decrypt(cipher_text)
    return msg

def cal_check_sum_with_signature(data, length):
    v_0xFFFFFFFF = 0xFFFFFFFF
    start = 0
    while start < length:
        v_0xFFFFFFFF = c_uint(v_0xFFFFFFFF >> 8).value ^ SIGNATURE[(v_0xFFFFFFFF ^ ord(data[start])) & 0xFF ]
        start = start + 1

    return v_0xFFFFFFFF

def firm_key_aes(select_key, lenx):
    KEY = LIST_KEY_AES[select_key]
    KEY_GEN = []

    for i in range(0, lenx):
        key_char = KEY[i]
        v5 = ((i * i) & 0xFF) + ((ord(key_char) * ord(key_char)) & 0xFF ) + ((ord(key_char) % lenx) & 0xFF) + ((ord(key_char) * lenx * i) & 0xFF)
        KEY_GEN.append( chr((v5 & 0xFF) ^ ord(key_char)) )

    return "".join(KEY_GEN)

def write2File(filename, content): 
    fpw = open(filename, "wb")
    for i in content:
        fpw.write(i)
    fpw.close()

def decrypt2File(filename, head2_body):
    posi = head2_body.find(filename) + 8*4 
    offset = struct.unpack("<I", head2_body[posi: posi+4])[0] + h1_size
    length = struct.unpack("<I", head2_body[posi+4: posi+8])[0]
    checksum = struct.unpack("<I", head2_body[posi+0xc: posi+0x10])[0]

    print("Offset: {0}, length: {1}, checksum: {2}".format(hex(offset), hex(length), hex(checksum)))
    fp.seek(offset, 0)

    ciphertext = fp.read(length)
    #hexdump(cipher_text[:0x50])
    plaintext = firm_dec_aes(ciphertext[0: len(ciphertext) - (len(ciphertext) % 16)], KEY_GEN_FILE)
    #hexdump(plain_text[:0x50])
    write2File(filename, plaintext)

if __name__ == "__main__":
    print(argv)
    if(len(argv) != 2):
        print("Usage: python2 dec_hik.py pathfile")
        exit()

    fp = open(argv[1], "rb")

    KEY_GEN_H2 = firm_key_aes("0x850000", 32)
    KEY_GEN_FILE = firm_key_aes("0x850001", 32)

    # GET SIZE HEADER 1
    ctext = fp.read(0x10)
    ctext = firm_dec_hikv0(ctext, KEY_XOR, len(ctext))
    h1_size = struct.unpack("<I", ctext[0x08: 0xc])[0]

    # DECODE HEADER 1
    fp.seek(0, 0)
    ciphertext = fp.read(h1_size)
    plaintext = firm_dec_hikv0(ciphertext, KEY_XOR, len(ciphertext))

    # GET SIZE HEADER 2
    ciphertext =   fp.read(0x10)
    plaintext  =   plaintext +  firm_dec_hikv0(ciphertext, KEY_XOR, len(ciphertext))
    h2_size = struct.unpack("<I", plaintext[0x74: 0x78])[0]

    # DECRYPT BODY HEADER 2
    ciphertext = fp.read(h2_size - 0x10)
    plaintext = plaintext + firm_dec_aes(ciphertext, KEY_GEN_H2)
    plain_dump  = plaintext + "\x00" * ( 16 - len(plaintext) % 16)

    # CHECK SUM
    checksum = cal_check_sum_with_signature(plaintext[0x78:], 0x700 - 0xc)
    hexdump(plain_dump)
    print ("checksum: ", hex(checksum))
    if(checksum != struct.unpack("<I", plaintext[0x70: 0x74])[0]):
        print("Decrypt Failed!")
        exit(1)
    else:
        print("Decrypt H2 Succcess")
    
    # GET FILE _cfgUpgClass
    decrypt2File("_cfgUpgClass", plaintext)

    # GET FILE LiteOS.bin
    decrypt2File("LiteOS.bin", plaintext)

    # GET FILE db.jffs2
    decrypt2File("ipc_db.jffs2", plaintext)
    

    
