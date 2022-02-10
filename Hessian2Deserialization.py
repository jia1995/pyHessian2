import datetime
import struct
import base64
from re import sub
import json

class Deserialization2Hessian:
    def __init__(self):
        self.types = []
        self.refMap = []
        self.classes = []
        self.refId= 0
        self.pos = 0
        self.isLastChunk = True

    def decoder(self, bstr:str):
        assert isinstance(bstr, str) or isinstance(bstr, bytes), f"The Type {type(bstr)} is illegal!!!"
        if isinstance(bstr, str):
            bstr = base64.b64decode(bstr)
        self.bstr = bstr
        self.len = len(bstr)
        return self.__decoder__()

    def __readCur__(self):
        return self.bstr[self.pos]
    
    def __getCur__(self):
        re = self.__readCur__()
        self.pos+=1
        return re
    
    def __decoder__(self, withType=False):
        if self.pos>=self.len:
            return 
        code = self.__readCur__()
        if 0x80<=code<=0xbf or 0xc0<=code<=0xcf or 0xd0<=code<=0xd7 or code==0x49:
            return self.__getInt__()
        elif 0xd8<=code<=0xff or 0x38<=code<=0x3f or code==0x59 or code==0x4c:
            return self.__getLong__()
        elif code==0x44 or 0x5b<=code<=0x5f:
            return self.__getDouble__()
        elif code in (0x4a, 0x4b):
            return self.__getDate__()
        elif  0x20<=code<=0x2f or code==0x41 or code==0x42 or 0x34<=code<=0x37:
            return self.__getBytes__()
        elif 0x00<=code<=0x1f or 0x30<=code<=0x33 or 0x52<=code<=0x53:
            return self.__getString__()
        elif code==0x43:
            return self.__getClass__()
        elif code==0x4f or 0x60<=code<=0x6f:
            return self.__getObject__(withType)
        elif 0x55<=code<=0x58 or 0x70<=code<=0x7f:
            return self.__getList__(withType)
        elif code==0x48 or code==0x4d:
            return self.__getMap__()
        elif code==0x51:
            return self.__getRef__()
        else:
            code = self.__getCur__()
            re = None
            if code==0x46: re = False
            elif code==0x54: re = True
            return re

    def __KthAdd__(self, k):
        return int.from_bytes(self.__readKBin__(k), byteorder='big')
        
    def __getInt__(self):
        code = self.__getCur__()
        if 0x80 <= code <= 0xbf:
            return code - 0x90
        elif 0xc0 <= code <= 0xcf:
            return ((code - 0xc8) << 8) + self.__getCur__()
        elif 0xd0 <= code <= 0xd7:
            return ((code - 0xd4) << 16) + self.__KthAdd__(2)
        elif code == 0x49:
            return self.__KthAdd__(4)
    
    def __getLong__(self):
        code = self.__getCur__()
        if 0xd8 <= code <= 0xef:
            return int(code - 0xe0)
        elif 0xf0 <= code <= 0xff:
            return int(((code - 0xf8) << 8) + self.__getCur__())
        elif 0x38 <= code <= 0x3f:
            return ((code - 0x3c) << 16) + self.__KthAdd__(2)
        elif code == 0x59:
            return self.__KthAdd__(4)
        elif code == 0x4c:
            return self.__KthAdd__(4)

    def __readKBin__(self, k):
        res = self.bstr[self.pos:self.pos+k]
        self.pos+=k
        return res

    def __getDouble__(self):
        code = self.__getCur__()
        if code == 0x5b:
            return 0.0
        elif code == 0x5c:
            return 1.0
        elif code == 0x5d:
            return float(struct.unpack('>b', self.__readKBin__(1))[0])
        elif code == 0x5e:
            return float(struct.unpack('>h', self.__readKBin__(2))[0])
        elif code == 0x5f:
            return float(struct.unpack('>i', self.__readKBin__(4))[0]*0.001)
        else:
            return float(struct.unpack('>d', self.__readKBin__(8))[0])

    def __getDate__(self):
        code = self.__getCur__()
        re = 0
        if code == 0x4a:
            re = self.__KthAdd__(8)
            return datetime.datetime.strftime(datetime.datetime.fromtimestamp(re/1000),'%Y-%m-%d %H:%M:%S.%f')
        if code == 0x4b:
            re = self.__KthAdd__(4)
            return datetime.datetime.strftime(datetime.datetime.fromtimestamp(re* 60),'%Y-%m-%d %H:%M:%S.%f')

    def __getBytes__(self):
        code = self.__getCur__()
        if 0x20 <= code <= 0x2f:
            lens = code - 0x20
            self.pos+=lens
            return self.bstr[self.pos-lens:self.pos]
        bufs = b''
        # get non-final trunk start with 'A'
        while code == 0x41:
            length=self.__KthAdd__(2)
            bufs+=self.__readKBin__(length)
            code = self.__getCur__()
        if code == 0x42: # get the last trunk start with 'B'
            length = self.__KthAdd__(2)
        elif 0x20 <= code <= 0x2f:
            length = code - 0x20
        elif 0x34 <= code <= 0x37:
            b1 = self.__getCur__()
            length = (code - 0x34) * 256 + b1
        bufs+=self.__readKBin__(length)
        return bufs

    def __readString__(self, length):
        re = ''
        for _ in range(length):
            start = self.__readCur__()
            if start - 0x80<0:
                cur=self.__readKBin__(1)
            elif start&0xe0 == 0xc0:
                cur=self.__readKBin__(2)
            elif start&0xf0 == 0xe0:
                cur= self.__readKBin__(3)
            elif start&0xf8 == 0xf0:
                cur=self.__readKBin__(4)
            re+= str(cur, 'utf8')
        return re

    def __getString__(self):
        str1 = ''
        code = self.__getCur__()
        length=0
        if 0x00<=code<=0x1f:
            self.isLastChunk = True
            length = code - 0x00
        elif 0x30<=code<= 0x33:
            self.isLastChunk = True
            b1 = self.__getCur__()
            length = (code - 0x30) * 256 + b1
        elif code == 0x53:
            self.isLastChunk = True
            length = self.__KthAdd__(2)
        elif code == 0x52:
            self.isLastChunk = False
            length = self.__KthAdd__(2)
        str1 += self.__readString__(length)
        while not self.isLastChunk:
            str1 += self.__getString__()
        return str1

    def __getType__(self):
        code = self.__readCur__()
        if 0x00<=code <= 0x1f or 0x30<= code <= 0x33 or 0x52<=code<=0x53:
            types = self.__getString__()
            self.types.append(types)
        else:
            ref = self.__getInt__()
            types = self.types[ref]
        return types

    def __generateClass__(self, classes, k, v, re):
        mt = sub(r'com\.caucho\.hessian\.io\..*Handle','', classes)
        res = None
        if 'com.google.common.collect.ImmutableMap' in classes:
            dic = {a:b for a,b in zip(v[0],v[1])}
            res = dic
        elif mt=='':
            dic = {a:b for a,b in zip(k,v)}
            res = v[0]
        else:
            dic = {a:b for a,b in zip(k,v)}
            res = dic
        re.update(dic)
        return res

    def __getClass__(self):
        pos = self.pos
        self.__getCur__()
        classes=self.__getString__()
        size=self.__getInt__()
        k = [self.__decoder__() for _ in range(size)]
        self.classes.append({'name':classes, 'fields':k})
        v = self.__getObject__(pos==0)
        return v

    def __getObject__(self, withType=False):
        code = self.__getCur__()
        res = {}
        self.__addRef__(res)
        if code==0x4f:
            ref = self.__getCur__()-0x90
        elif code>=0x60 and code<=0x6f:
            ref = code-0x60
        cf = self.classes[ref]
        classes, fields = cf['name'], cf['fields']
        re = [self.__decoder__(withType=withType) for _ in fields]
        return self.__generateClass__(classes, fields, re, res)
    
    def __addRef__(self, obj):
        self.refMap.append(obj)
        self.refId+=1

    def __readList__(self, length):
        return [self.__decoder__() for _ in range(length)]

    def __readUnTypedList__(self):
        re = []
        while self.__readCur__()!=0x5a:
            re.append(self.__decoder__())
        return re

    def __getList__(self, withType=False):
        code = self.__getCur__()
        length = 0

        if code==0x55 or code==0x56 or 0x70 <= code<=0x77:
            _ = self.__getType__()
        if code==0x56 or code==0x58:
            length = self.__getInt__()
        elif 0x70 <= code<=0x77:
            length = code-0x70
        elif 0x78 <= code<=0x7f:
            length = code-0x78
        if code==0x57 or code==0x55:
            re = self.__readUnTypedList__()
        else:
            re = self.__readList__(length)
        if withType:
            self.__addRef__(re)
        return re

    def __getMapData__(self, maps={}):
        while self.__readCur__()!=0x5a:
            maps[self.__decoder__()] = self.__decoder__()
        self.pos+=1

    def __getRef__(self):
        _ = self.__getCur__()
        lens = self.__decoder__()
        return self.refMap[lens]

    def __getMap__(self):
        code = self.__getCur__()
        res = {}
        if code==0x48: # untyped map ('H')
            self.__getMapData__(res)
        elif code == 0x4d: # map with type ('M')
            length = self.__getCur__()-0x00
            _ = self.__getType__()
            self.__getMapData__(res)
        self.__addRef__(res)
        return res


if __name__=='__main__':
    # enc = 'QzAiY29tLmdlZWtwbHVzLmh5cGVycHVsc2UuSGVzc2lhbkR0b50CcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTADcDExYJGR4eFEP/GZmaAAAABDMCFjb20uY2F1Y2hvLmhlc3NpYW4uaW8uRmxvYXRIYW5kbGWRBl92YWx1ZWFEP/GZmaAAAABfAAAETF8AAARMBHhpeGlUVHIaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3QEeGl4aQRoYWhhcgdbc3RyaW5nBHhpeGkEaGFoYQ=='
    # deserialization2Hessian = Deserialization2Hessian()
    # json.dump(deserialization2Hessian.decoder(enc), open('a1.json','w'), indent=2)
    # enc = 'QzAzY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMud21zLmNvcmUubW9jay5XbXNNb2NrUmVzdWx0kgZyZXN1bHQEZGF0YWAHU1VDQ0VTUwR4aXhp'
    # deserialization2Hessian = Deserialization2Hessian()
    # json.dump(deserialization2Hessian.decoder(enc), open('a2.json','w'), indent=2)
    # enc = 'QzAiY29tLmdlZWtwbHVzLmh5cGVycHVsc2UuSGVzc2lhbkR0b6ECcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTYDcDE3A3AxMANwMTEDcDE0A3AxNWCRkeHhRD/xmZmgAAAAQzAhY29tLmNhdWNoby5oZXNzaWFuLmlvLkZsb2F0SGFuZGxlkQZfdmFsdWVhRD/xmZmgAAAAXwAABExfAAAETAR4aXhpVFRDMCBjb20uY2F1Y2hvLmhlc3NpYW4uaW8uQnl0ZUhhbmRsZZEGX3ZhbHVlYpGRchpqYXZhLnV0aWwuQXJyYXlzJEFycmF5TGlzdAR4aXhpBGhhaGFyB1tzdHJpbmcEeGl4aQRoYWhhQzA1Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVNYXAkU2VyaWFsaXplZEZvcm2SBGtleXMGdmFsdWVzY3IHW29iamVjdALlvKDkuIkC5p2O5ZubcpIC5YyX5LqsAuS4iua1t0oAAAF+nzt8QQ=='
    # deserialization2Hessian = Deserialization2Hessian()
    # json.dump(deserialization2Hessian.decoder(enc), open('a3.json','w'), indent=2,ensure_ascii=False)
    # enc = "QwR0ZW1wlgFhAWQBZgFsAW0CbTJgyIBfAXUgFEMwIWNvbS5jYXVjaG8uaGVzc2lhbi5pby5GbG9hdEhhbmRsZZEGX3ZhbHVlYURBFHmkYAAAAHQaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3SRkpSVQzA1Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVNYXAkU2VyaWFsaXplZEZvcm2SBGtleXMGdmFsdWVzYnIHW29iamVjdANhZHMDZHNmcpFRknOQyDanyEFicZEDZHNjcZFRkw=='#'QwR0ZW1wlwFhAWQBZgFsAmwyAW0CbTJgyIBfAXUgFEMwIWNvbS5jYXVjaG8uaGVzc2lhbi5pby5GbG9hdEhhbmRsZZEGX3ZhbHVlYURBFHmkYAAAAHQaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3SRkpSVc5DINqfIQUMwNWNvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTWFwJFNlcmlhbGl6ZWRGb3JtkgRrZXlzBnZhbHVlc2JyB1tvYmplY3QDYWRzA2RzZnKRUZJRk2JxkQNkc2NxkVGU"
    # deserialization2Hessian = Deserialization2Hessian()
    # json.dump(deserialization2Hessian.decoder(enc), open('a4.json','w'), indent=2,ensure_ascii=False)
    # enc = 'QzAiY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMuSGVzc2lhbkR0b6UCcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTYDcDE3A3AxOANwMTkDcDIwA3AxMANwMTEDcDE0A3AxNQNwMjFgkZHh4UQ/8ZmZoAAAAEMwIWNvbS5jYXVjaG8uaGVzc2lhbi5pby5GbG9hdEhhbmRsZZEGX3ZhbHVlYUQ/8ZmZoAAAAF8AAARMXwAABEwEeGl4aVRUQzAgY29tLmNhdWNoby5oZXNzaWFuLmlvLkJ5dGVIYW5kbGWRBl92YWx1ZWKRkdPzt17zUkTBSl9+gAAAAHIaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3QEeGl4aQRoYWhhcgdbc3RyaW5nBHhpeGkEaGFoYUMwNWNvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTWFwJFNlcmlhbGl6ZWRGb3JtkgRrZXlzBnZhbHVlc2NyB1tvYmplY3QC5byg5LiJAuadjuWbm3KSAuWMl+S6rALkuIrmtbdKAAABftnHtHtjcpICNDUCMjNyklGVUZU='
    # json.dump(deserialization2Hessian.decoder(enc), open('a4.json','w'), indent=2,ensure_ascii=False)
    # enc = 'QwpNeUxpbmtMaXN0kgFhBG5leHRgkVGQ' # circular test case
    # deserialization2Hessian = Deserialization2Hessian()
    # print(deserialization2Hessian.decoder(enc))
    # enc = 'Qxtjb20uZ2Vla3BsdXMuaGVwaGFlc3R1cy5DYXKTBWNvbG9yBW1vZGVsB21pbGVhZ2VgCmFxdWFtYXJpbmUGQmVldGxl1QAA'
    # deserialization2Hessian = Deserialization2Hessian()
    # print(deserialization2Hessian.decoder(enc))
    # enc = 'SKADZmllyQADZm9lkQNmZWVa'
    # deserialization2Hessian = Deserialization2Hessian()
    # json.dump(deserialization2Hessian.decoder(enc), open('a5.json','w'), indent=2,ensure_ascii=False)
    # enc = 'Vgdbc3RyaW5nnAExATIBNAE1ATgBOQEwATQBMgE3ATgBMA=='
    # deserialization2Hessian = Deserialization2Hessian()
    # print(base64.b64decode(enc))
    # print(deserialization2Hessian.decoder(enc))
    # json.dump(deserialization2Hessian.decoder(enc), open('a5.json','w'), indent=2,ensure_ascii=False)
    f = open('test/test.txt')
    for i in f.readlines():
        enc = i
        deserialization2Hessian = Deserialization2Hessian()
        res = deserialization2Hessian.decoder(enc)
        print(res)