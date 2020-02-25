#!/usr/bin/env python
import hashlib
import pefile
import sys
import struct
from collections import OrderedDict
import json

def main():
    results = OrderedDict()
    pe = pefile.PE(sys.argv[1])

    rich_data = pe.get_data(0x80)
    data = list(struct.unpack('<%sI' % str(len(rich_data)/4), rich_data))
    checksum = data[1]
    try:
        rich_end = data.index(0x68636952)
    except ValueError:
        print "PE does not have Rich Header"
        sys.exit()

    #Compute Rich Hash
    Rich_Hasher = hashlib.md5() 
    for i in range(rich_end): 
        Rich_Hasher.update(struct.pack('<I', (data[i] ^ checksum)))
    richHash = Rich_Hasher.hexdigest()

    #Compute RichPV Hash
    RichPV_Hasher = hashlib.md5()
    for i in range(rich_end):
        if i > 3:
            if i % 2: continue
            else: 
                RichPV_Hasher.update(struct.pack('<I', (data[i] ^ checksum)))
    richPV = RichPV_Hasher.hexdigest()

    #Parse elements of Rich header
    richArray = []
    for richElement in range(0, len(pe.RICH_HEADER.values), 2):
        productID = pe.RICH_HEADER.values[richElement] >> 16
        productVersion = pe.RICH_HEADER.values[richElement] & 0xffff
        productCount = pe.RICH_HEADER.values[richElement + 1]
        richArray.append({
            "Product_ID": productID,
            "Product_Version": productVersion,
            "Product_Count": productCount})
    
    results['Rich Header'] = richArray
    results['Rich Hashes'] = {'Rich Hash': richHash, 'Rich PV': richPV}
    print json.dumps(results)

if __name__ == "__main__":
    main()

