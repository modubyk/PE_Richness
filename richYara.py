#!/usr/bin/env python
import hashlib
import pefile
import sys
import struct
import yara_tools

def Rich_Yara(sample_md5,rich_end,data,checksum):

    Rich_Hasher = hashlib.md5()
    for i in range(rich_end):
        Rich_Hasher.update(struct.pack('<I', (data[i] ^ checksum)))
    richHash = Rich_Hasher.hexdigest()

    rule = yara_tools.create_rule(name="RichHash")
    rule.add_import(name="pe")
    rule.add_import(name="hash")
    rule.add_meta(key="description", value="Ref: " + sample_md5)
    rule.set_default_boolean(value='and')
    rule.add_condition(condition="uint16(0x00) == 0x5a4d")
    rule.add_condition(condition='hash.md5(pe.rich_signature.clear_data) == "' + richHash + '"')
    compiled_rule = rule.build_rule()
    return compiled_rule

def RichPV_Yara(sample_md5,pe):

    rule = yara_tools.create_rule(name="RichPV")
    rule.add_import(name="pe")
    rule.add_meta(key="description", value="Ref: " + sample_md5)
    rule.set_default_boolean(value='and')
    rule.add_condition(condition="uint16(0x00) == 0x5a4d")
    
    for richElement in range(0, len(pe.RICH_HEADER.values), 2):
        productID = pe.RICH_HEADER.values[richElement] >> 16
        productVersion = pe.RICH_HEADER.values[richElement] & 0xffff
        rule.add_condition(condition='pe.rich_signature.toolid(%s, %s)' % (productID,productVersion))

    compiled_rule = rule.build_rule()
    return compiled_rule

def main():

    md5_hasher = hashlib.md5()
    with open(sys.argv[1]) as f: md5_hasher.update(f.read())
    sample_md5 = md5_hasher.hexdigest()

    pe = pefile.PE(sys.argv[1])

    rich_data = pe.get_data(0x80)
    data = list(struct.unpack('<%sI' % str(len(rich_data)/4), rich_data))
    checksum = data[1]
    try:
        rich_end = data.index(0x68636952)
    except ValueError:
        print "PE does not have Rich Header"
        sys.exit()

    print Rich_Yara(sample_md5,rich_end,data,checksum)
    print RichPV_Yara(sample_md5,pe)

if __name__ == "__main__":
    main()

