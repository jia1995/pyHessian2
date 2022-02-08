import datetime
from email.mime import base
import struct
import base64
from re import sub
import json

def mapTypeJudge(k, v):
    if k!=['keys','values']:
        return False
    if len(set(map(len, v)))!=1:
        return False
    for i in v:
        a = set(map(type, i))
        if len(a)!=1:
            return False
    return True

class Deserialization2Hessian:
    def __init__(self):
        self.types = []
        self.refMap = []
        self.refId= 0
        self.isLastChunk = True

    def decoder(self, bstr:str):
        if isinstance(bstr, str):
            bstr = base64.b64decode(bstr)
        self.bstr = bstr
        self.len = len(bstr)
        self.pos = 0
        re = self.__decoder__()
        return re #[0]
    
    def __decoder__(self, gsize=1, size=1, withType=False):
        if self.pos==self.len:
            return 
        re = []
        while size>0:
            if self.pos<self.len:
                code = self.bstr[self.pos]
                if (code >= 0x80 and code <= 0xbf) or (code >= 0xc0 and code <= 0xcf) or (code >= 0xd0 and code <= 0xd7) or code == 0x49:
                    re.append(self.__getInt__())
                elif ( 0xd8 <= code <= 0xff)or ( 0x38 <= code <= 0x3f) or (code == 0x59) or (code == 0x4c):
                    l = self.__getLong__()
                    re.append(l)
                elif code==0x44 or (0x5b<=code<=0x5f):
                    re.append(self.__getDouble__())
                elif code in (0x4a, 0x4b):
                    re.append(self.__getDate__())
                elif (code >= 0x20 and code <= 0x2f) or (code == 0x41) or (code == 0x42) or (code >= 0x34 and code <= 0x37):
                    re.append( self.__getBytes__())
                elif code in (0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
                        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 
                        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 
                        0x1e, 0x1f,0x30, 0x31, 0x32, 0x33,0x53,0x52):
                    re.append(self.__getString__())
                elif code==0x43:
                    re.append(self.__getClass__())
                elif code==0x4f or 0x60<=code<=0x6f:
                    re.extend(self.__getObject__(size))
                    size=0
                elif 0x55<=code<=0x58 or 0x70<=code<=0x7f:
                    l = self.__getList__(withType)
                    re.append(l)
                elif code==0x48 or code==0x4d:
                    re.append(self.__getMap__())
                elif code==0x5a:
                    self.pos+=1
                elif code==0x4e:
                    re.append(None)
                    self.pos+=1
                elif code==0x46:
                    re.append(False)
                    self.pos+=1
                elif code==0x54:
                    re.append(True)
                    self.pos+=1
                elif code==0x50 or code==0x45 or code==0x47:
                    self.pos+=1
                else:
                    re.append(self.__getRef__())
                if self.pos<self.len:
                    size-=1
                else:
                    return re
        if gsize==0:
            return re
        v = []
        while gsize>0:
            if self.pos<self.len:
                code = self.bstr[self.pos]
                if 0x80<=code<=0xbf or 0xc0<=code<=0xcf or 0xd0<=code<=0xd7 or code==0x49: 
                    v.append(self.__getInt__())
                    gsize-=1
                elif 0xd8<=code<=0xff or 0x38<=code<=0x3f or code==0x59 or code==0x4c:
                    l = self.__getLong__()
                    v.append(l)
                    gsize-=1
                elif code==0x44 or 0x5b<=code<=0x5f:
                    v.append(self.__getDouble__())
                    gsize-=1
                elif code in (0x4a, 0x4b):
                    v.append(self.__getDate__())
                    gsize-=1
                elif 0x20<=code<=0x2f or 0x41<=code<=0x42 or 0x34<=code<=0x37:
                    v.append( self.__getBytes__())
                    gsize-=1
                elif 0x00<=code<=0x1f or 0x30<=code<=0x33 or 0x52<=code<=0x53:
                    v.append(self.__getString__())
                    gsize-=1
                elif code==0x43:
                    x = self.__getClass__()
                    v.append(x)
                    gsize-=1
                elif code==0x4f or 0x60<=code<=0x6f:
                    o = self.__getObject__(gsize, withType=withType)
                    v.extend(o)
                    gsize-=len(o)
                elif 0x55<=code<=0x58 or 0x70<=code<=0x7f:
                    re.append(self.__getList__(withType))
                    gsize-=1
                elif code==0x48 or code==0x4d:
                    gsize-=1
                    v.append(self.__getMap__())
                elif code==0x5a:
                    gsize-=1
                    self.pos+=1
                elif code==0x4e:
                    gsize-=1
                    v.append(None)
                    self.pos+=1
                elif code==0x46:
                    gsize-=1
                    v.append(False)
                    self.pos+=1
                elif code==0x54:
                    gsize-=1
                    v.append(True)
                    self.pos+=1
                elif  code==0x50 or code==0x45 or code==0x47:
                    # gsize-=1
                    self.pos+=1
                else:
                    gsize-=1
                    v.append(self.__getRef__())
            else:
                break
        res = {}
        if mapTypeJudge(re, v):
            for a,b in zip(v[0],v[1]):
                res[a] = b
        else:
            for k,v1 in zip(re, v):
                res[k] = v1
        return res

    def __getInt__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        if code >= 0x80 and code <= 0xbf:
            return code - 0x90
        if code >= 0xc0 and code <= 0xcf:
            self.pos+=1
            return ((code - 0xc8) << 8) + self.bstr[self.pos-1]
        if code >= 0xd0 and code <= 0xd7:
            b1 = self.bstr[self.pos]
            self.pos+=1
            b0 = self.bstr[self.pos]
            self.pos+=1
            return ((code - 0xd4) << 16) + (b1 << 8) + b0
        if code == 0x49:
            self.pos+=1
            return self.bstr[self.pos-1]
    
    def __getLong__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        if 0xd8 <= code <= 0xef:
            return int(code - 0xe0)
        elif code >= 0xf0 and code <= 0xff:
            self.pos+=1
            return int(((code - 0xf8) << 8) + self.bstr[self.pos-1])
        elif code >= 0x38 and code <= 0x3f:
            b1 = self.bstr[self.pos]
            self.pos+=1
            b0 = self.bstr[self.pos]
            self.pos+=1
            return ((code - 0x3c) << 16) + (b1 << 8) + b0
        elif (code == 0x59):
            b1 = self.bstr[self.pos]
            self.pos+=1
            b0 = self.bstr[self.pos]
            self.pos+=1
            return b1<<8+b0
        elif (code == 0x4c):
            re = 0
            for i in range(4):
                re<<=8
                re+=self.bstr[self.pos]
                self.pos+=1
            return re

    def __getDouble__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        if (code == 0x44):
            re = self.bstr[self.pos:self.pos+8][::-1]
            self.pos+=8
            re = struct.unpack('d', re)[0]
            return re
        if (code == 0x5b):
            return 0.0
        if (code == 0x5c):
            return 1.0
        if (code == 0x5d):
            c = self.bstr[self.pos]
            re = float(int(c)) if c<0x80 else c-0xff
            self.pos +=1
            return re
        if (code == 0x5e):
            re = 0
            for i in range(2):
                re<<=8
                re+=self.bstr[self.pos]
                self.pos+=1
            return re if re<0x8000 else re-0xffff
        if (code == 0x5f):
            re = 0
            for i in range(4):
                re<<=8
                re+=self.bstr[self.pos]
                self.pos+=1
            re = re if re<0x80000000 else re-0xffffffff
            return re * 0.001

    def __getDate__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        re = 0
        if (code == 0x4a):
            for i in range(8):
                re<<=8
                re+=self.bstr[self.pos]
                self.pos+=1
            return datetime.datetime.strftime(datetime.datetime.fromtimestamp(re/1000),'%Y-%m-%d %H:%M:%S')
        if (code == 0x4b):
            for i in range(4):
                re<<=8
                re+=self.bstr[self.pos]
                self.pos+=1
            return datetime.datetime.strftime(datetime.datetime.fromtimestamp(re* 60),'%Y-%m-%d %H:%M:%S')

    def __getBytes__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        if (code >= 0x20 and code <= 0x2f):
            lens = code - 0x20
            self.pos+=lens
            return self.bstr[self.pos-lens:self.pos]
        bufs = b''
        # get non-final trunk start with 'A'
        while (code == 0x41):
            length=0
            for i in range(2):
                length<<=8
                length += self.bstr[self.pos]
                self.pos+=1
            bufs+=self.bstr[self.pos:self.pos+length]
            self.pos+=length
            code = self.bstr[self.pos]
            self.pos+=1

        if (code == 0x42):
            # get the last trunk start with 'B'
            length=0
            for i in range(2):
                length<<=8
                length += self.bstr[self.pos]
                self.pos+=1
            bufs+=self.bstr[self.pos:self.pos+length]
            self.pos+=length
        elif (code >= 0x20 and code <= 0x2f):
            length = code - 0x20
            bufs+=self.bstr[self.pos:self.pos+length]
            self.pos+=length
        elif (code >= 0x34 and code <= 0x37):
            b1 = self.bstr[self.pos]
            self.pos+=1
            length = (code - 0x34) * 256 + b1
            bufs+=self.bstr[self.pos:self.pos+length]
            self.pos+=length
        return bufs

    def __bin2Str__(self, bstr):
        try:
            re = str(bstr, encoding='utf8')
        except Exception:
            return None
        return re

    def __getString__(self):
        str1 = ''
        code = self.bstr[self.pos]
        self.pos+=1
        if 0x00<=code<=0x1f:
            self.isLastChunk = True
            length = code - 0x00
            t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            if not t or len(t)!=length:
                length *= 3
                t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            str1 += t
            self.pos+=length
        elif code in [0x30, 0x31, 0x32, 0x33]:
            self._isLastChunk = True
            b1 = self.bstr[self.pos]
            self.pos+=1
            length = (code - 0x30) * 256 + b1
            t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            if not t or len(t)!=length:
                length *= 3
                t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            str1 += t
            self.pos+=length
        elif code == 0x53:
            self._isLastChunk = True
            length=0
            for i in range(2):
                length<<=8
                length += self.bstr[self.pos]
                self.pos+=1
            t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            if not t or len(t)!=length:
                length *= 3
                t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            str1 += t
            self.pos+=length
        elif code == 0x52:
            self._isLastChunk = False
            length=0
            for i in range(2):
                length<<=8
                length += self.bstr[self.pos]
                self.pos+=1
            t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            if not t or len(t)!=length:
                length *= 3
                t = self.__bin2Str__(self.bstr[self.pos:self.pos+length])
            str1 += t
            self.pos+=length
            while not self._isLastChunk:
                str1 += self.__getString__()
        return str1

    def __getType__(self):
        code = self.bstr[self.pos]
        types = ''
        if code in [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x30,0x31,0x32,0x33,0x52,0x53]:
            types = self.__getString__()
            self.types.append(types)
        else:
            ref = self.__getInt__()
            types = self.types[ref]
        return types

    def __getClass__(self):
        pos = self.pos
        self.pos+=1
        classes=self.__decoder__(gsize=0)[0]
        mt = sub(r'com\.caucho\.hessian\.io\..*Handle','', classes)
        idx = self.refId
        self.__addRef__(None)
        size=self.__getInt__()
        re = self.__decoder__(size, size, pos==0)
        self.refMap[idx] = re
        if mt=='':
            re = list(re.values())
            re = re if len(re)>1 else re[0]
        return re

    def __getObject__(self, length=0, withType=False):
        code = self.bstr[self.pos]
        self.pos+=1
        if code==0x4f:
            length = self.bstr[self.pos]-0x90
            self.pos+=1
            return self.__decoder__(gsize=0, size=length, withType=withType)
        elif code>=0x60 and code<=0x6f:
            re = []
            ref = code-0x60
            classes = self.classes[ref]
            re.append(self.__decoder__(size=length, gsize=0, withType=withType))
            return re[0] if len(re)==1 and isinstance(re[0], list) else re
            
    
    def __addRef__(self, obj):
        self.refMap.append(obj)
        self.refId+=1

    def __getList__(self, withType=False):
        code = self.bstr[self.pos]
        self.pos+=1
        re = []
        list_ = []
        types = None
        length = 0
        if code==0x55:
            types = self.__getType__()
        elif code==0x56:
            types = self.__getType__()
        elif code==0x58:
            length = self.__getInt__()
        elif code>=0x70 and code<=0x77:
            types = self.__getType__()
            length = code-0x70
        elif code>=0x78 and code<=0x7f:
            length = code-0x78
        re = self.__decoder__(size=length, gsize=0)
        if withType:
            self.__addRef__(re)
        return re

    def __getMapData__(self, maps={}):
        code = self.bstr[self.pos]
        while code!=0x5a:
            k = self.__decoder__(size=1, gsize=0)
            v = self.__decoder__(size=1, gsize=0)
            maps[k[0]] = v[0]
            code = self.bstr[self.pos]
        self.pos+=1

    def __getRef__(self):
        code = self.bstr[self.pos]
        self.pos +=1
        lens = self.__decoder__(size=1,gsize=0)[0]
        return self.refMap[lens]

    def __getMap__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        res = {}
        if code==0x48: # untyped map ('H')
            self.__getMapData__(res)
        elif code == 0x4d: # map with type ('M')
            length = self.bstr[self.pos]-0x00
            self.pos+=1
            _ = self.__getType__()
            self.__getMapData__(res)
        self.__addRef__(res)
        return res


if __name__=='__main__':
    enc = 'QzAiY29tLmdlZWtwbHVzLmh5cGVycHVsc2UuSGVzc2lhbkR0b50CcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTADcDExYJGR4eFEP/GZmaAAAABDMCFjb20uY2F1Y2hvLmhlc3NpYW4uaW8uRmxvYXRIYW5kbGWRBl92YWx1ZWFEP/GZmaAAAABfAAAETF8AAARMBHhpeGlUVHIaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3QEeGl4aQRoYWhhcgdbc3RyaW5nBHhpeGkEaGFoYQ=='
    bstr = base64.b64decode(enc)
    deserialization2Hessian = Deserialization2Hessian()
    # json.dump(deserialization2Hessian.decoder(enc), open('a1.json','w'), indent=2)
    # enc = 'QzAzY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMud21zLmNvcmUubW9jay5XbXNNb2NrUmVzdWx0kgZyZXN1bHQEZGF0YWAHU1VDQ0VTUwR4aXhp'
    # json.dump(deserialization2Hessian.decoder(enc), open('a2.json','w'), indent=2)
    # enc = 'QzAiY29tLmdlZWtwbHVzLmh5cGVycHVsc2UuSGVzc2lhbkR0b6ECcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTYDcDE3A3AxMANwMTEDcDE0A3AxNWCRkeHhRD/xmZmgAAAAQzAhY29tLmNhdWNoby5oZXNzaWFuLmlvLkZsb2F0SGFuZGxlkQZfdmFsdWVhRD/xmZmgAAAAXwAABExfAAAETAR4aXhpVFRDMCBjb20uY2F1Y2hvLmhlc3NpYW4uaW8uQnl0ZUhhbmRsZZEGX3ZhbHVlYpGRchpqYXZhLnV0aWwuQXJyYXlzJEFycmF5TGlzdAR4aXhpBGhhaGFyB1tzdHJpbmcEeGl4aQRoYWhhQzA1Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVNYXAkU2VyaWFsaXplZEZvcm2SBGtleXMGdmFsdWVzY3IHW29iamVjdALlvKDkuIkC5p2O5ZubcpIC5YyX5LqsAuS4iua1t0oAAAF+nzt8QQ=='
    # # print(base64.b64decode(enc))
    # json.dump(deserialization2Hessian.decoder(enc), open('a3.json','w'), indent=2,ensure_ascii=False)
    enc = "QwR0ZW1wlgFhAWQBZgFsAW0CbTJgyIBfAXUgFEMwIWNvbS5jYXVjaG8uaGVzc2lhbi5pby5GbG9hdEhhbmRsZZEGX3ZhbHVlYURBFHmkYAAAAHQaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3SRkpSVQzA1Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVNYXAkU2VyaWFsaXplZEZvcm2SBGtleXMGdmFsdWVzYnIHW29iamVjdANhZHMDZHNmcpFRknOQyDanyEFicZEDZHNjcZFRkw=='#'QwR0ZW1wlwFhAWQBZgFsAmwyAW0CbTJgyIBfAXUgFEMwIWNvbS5jYXVjaG8uaGVzc2lhbi5pby5GbG9hdEhhbmRsZZEGX3ZhbHVlYURBFHmkYAAAAHQaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3SRkpSVc5DINqfIQUMwNWNvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTWFwJFNlcmlhbGl6ZWRGb3JtkgRrZXlzBnZhbHVlc2JyB1tvYmplY3QDYWRzA2RzZnKRUZJRk2JxkQNkc2NxkVGU"
    print(base64.b64decode(enc))
    json.dump(deserialization2Hessian.decoder(enc), open('a4.json','w'), indent=2,ensure_ascii=False)
    # enc = 'QzAiY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMuSGVzc2lhbkR0b6UCcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTYDcDE3A3AxOANwMTkDcDIwA3AxMANwMTEDcDE0A3AxNQNwMjFgkZHh4UQ/8ZmZoAAAAEMwIWNvbS5jYXVjaG8uaGVzc2lhbi5pby5GbG9hdEhhbmRsZZEGX3ZhbHVlYUQ/8ZmZoAAAAF8AAARMXwAABEwEeGl4aVRUQzAgY29tLmNhdWNoby5oZXNzaWFuLmlvLkJ5dGVIYW5kbGWRBl92YWx1ZWKRkdPzt17zUkTBSl9+gAAAAHIaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3QEeGl4aQRoYWhhcgdbc3RyaW5nBHhpeGkEaGFoYUMwNWNvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTWFwJFNlcmlhbGl6ZWRGb3JtkgRrZXlzBnZhbHVlc2NyB1tvYmplY3QC5byg5LiJAuadjuWbm3KSAuWMl+S6rALkuIrmtbdKAAABftnHtHtjcpICNDUCMjNyklGVUZU='
    # json.dump(deserialization2Hessian.decoder(enc), open('a4.json','w'), indent=2,ensure_ascii=False)