import datetime
import struct
import base64
from re import sub

class Deserialization2Hessian:
    def __init__(self):
        self.types = []
        self.refMap = {}
        self.refId= 0

    def decoder(self, bstr:str):
        if isinstance(bstr, str):
            bstr = base64.b64decode(bstr)
        self.bstr = bstr
        self.len = len(bstr)
        self.pos = 0
        re = self.__decoder__()
        return re
    
    def __decoder__(self, gsize=1, size=1):
        if self.pos==self.len:
            return 
        re = []
        while size>0:
            if self.pos<self.len:
                code = self.bstr[self.pos]
                if (code >= 0x80 and code <= 0xbf) or (code >= 0xc0 and code <= 0xcf) or (code >= 0xd0 and code <= 0xd7) or code == 0x49:
                    size = self.__getInt__()
                    re.append(size)
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
                elif code==0x4f or 0x60<code<=0x6f:
                    re.append(self.__getObject__())
                elif 0x55<=code<=0x58 or 0x70<=code<=0x7f:
                    re.append(self.__getList__())
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
                elif code==0x60 or code==0x50 or code==0x45 or code==0x47:
                    self.pos+=1
                else:
                    re.append(self.__getRef__())
                if self.pos<self.len:
                    size-=1
                else:
                    return re if len(re)>1 else re[0]
        if gsize==0:
            return re if len(re)>1 else re[0]
        v = []
        while gsize>0:
            if self.pos<self.len:
                code = self.bstr[self.pos]
                if (code >= 0x80 and code <= 0xbf) or (code >= 0xc0 and code <= 0xcf) or (code >= 0xd0 and code <= 0xd7) or code == 0x49:
                    size = self.__getInt__()
                    v.append(size)
                elif ( 0xd8 <= code <= 0xff)or ( 0x38 <= code <= 0x3f) or (code == 0x59) or (code == 0x4c):
                    l = self.__getLong__()
                    v.append(l)
                elif code==0x44 or (0x5b<=code<=0x5f):
                    v.append(self.__getDouble__())
                elif code in (0x4a, 0x4b):
                    v.append(self.__getDate__())
                elif (code >= 0x20 and code <= 0x2f) or (code == 0x41) or (code == 0x42) or (code >= 0x34 and code <= 0x37):
                    v.append( self.__getBytes__())
                elif code in (0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
                        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 
                        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 
                        0x1e, 0x1f,0x30, 0x31, 0x32, 0x33,0x53,0x52):
                    v.append(self.__getString__())
                elif code==0x43:
                    x = self.__getClass__()
                    v.append(x)
                elif code==0x4f or 0x60<code<=0x6f:
                    v.append(self.__getObject__())
                elif 0x55<=code<=0x58 or 0x70<=code<=0x7f:
                    v.append(self.__getList__())
                elif code==0x48 or code==0x4d:
                    v.append(self.__getMap__())
                elif code==0x5a:
                    self.pos+=1
                elif code==0x4e:
                    v.append(None)
                    self.pos+=1
                elif code==0x46:
                    v.append(False)
                    self.pos+=1
                elif code==0x54:
                    v.append(True)
                    self.pos+=1
                elif  code==0x50 or code==0x45 or code==0x47 or code==0x60:
                    self.pos+=1
                else:
                    v.append(self.__getRef__())
                if self.pos<self.len and len(v)!=0:
                    gsize-=1
            if self.pos==self.len:
                break
        res = {}
        l1,l2 = len(re), len(v)
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
            return datetime.datetime.strftime(datetime.datetime.fromtimestamp(re),'%Y-%m-%d %H:%M:%S')
        if (code == 0x4b):
            for i in range(4):
                re<<=8
                re+=self.bstr[self.pos]
                self.pos+=1
            return datetime.datetime.strftime(datetime.datetime.fromtimestamp(re* 60000),'%Y-%m-%d %H:%M:%S')

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

    def __getString__(self):
        str1 = ''
        code = self.bstr[self.pos]
        self.pos+=1
        if code in [0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 
                    0x1e, 0x1f]:
            self.isLastChunk = True
            length = code - 0x00
            str1 += str(self.bstr[self.pos:self.pos+length], encoding='utf8')
            self.pos+=length
        elif code in [0x30, 0x31, 0x32, 0x33]:
            self._isLastChunk = True
            b1 = self.bstr[self.pos]
            self.pos+=1
            length = (code - 0x30) * 256 + b1
            str1 += str(self.bstr[self.pos:self.pos+length], encoding='utf8')
            self.pos+=length
        elif code == 0x53:
            self._isLastChunk = True
            length=0
            for i in range(2):
                length<<=8
                length += self.bstr[self.pos]
                self.pos+=1
            str1 += str(self.bstr[self.pos:self.pos+length], encoding='utf8')
            self.pos+=length
        elif code == 0x52:
            self._isLastChunk = False
            length=0
            for i in range(2):
                length<<=8
                length += self.bstr[self.pos]
                self.pos+=1
            str1 += str(self.bstr[self.pos:self.pos+length], encoding='utf8')
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
        self.pos+=1
        code = self.bstr[self.pos]
        self.pos+=1
        length=self.bstr[self.pos]-0x00
        self.pos+=1
        classes = str(self.bstr[self.pos:self.pos+length],encoding='utf8')
        self.pos+=length
        size=self.__getInt__()
        re = self.__decoder__(size, size)
        mt = sub(r'com\.caucho\.hessian\.io\..*Handle','', classes)
        if mt=='':
            re = list(re.values())
            re = re if len(re)>1 else re[0]
        return re

    def __getObject__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        re = []
        if code==0x4f:
            length = self.bstr[self.pos]-0x90
            self.pos+=1
            return self.__decoder__(gsize=0, size=length)
        elif code>=0x60 and code<=0x6f:
            while code>=0x60 and code<=0x6f:
                length = code-0x60
                d = self.__decoder__(size=length, gsize=0)
                re.append(d)
                if self.pos<self.len:
                    code = self.bstr[self.pos]
                    self.pos+=1
                if self.pos==self.len:
                    return re if len(re)>1 else re[0]
            else:
                self.pos-=1
                return re if len(re)>1 else re[0]
    
    def __addRef__(self, obj):
        self.refMap[self.refId] = obj
        self.refId+=1

    def __getList__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        re = []
        list_ = []
        types = None
        length = None
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
        return self.__decoder__(size=length, gsize=0)

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
        lens = self.__decoder__(size=1,gsize=0)
        return self.refMap[lens]

    def __getMap__(self):
        code = self.bstr[self.pos]
        self.pos+=1
        res = {}
        self.__addRef__(res)
        if code==0x48: # untyped map ('H')
            self.__getMapData__(res)
        elif code == 0x4d: # map with type ('M')
            length = self.bstr[self.pos]-0x00
            self.pos+=1
            types = self.__getType__()
            self.__addRef__(res)
            self.__getMapData__(res)
        return res


if __name__=='__main__':
    enc = 'QzAiY29tLmdlZWtwbHVzLmh5cGVycHVsc2UuSGVzc2lhbkR0b50CcDECcDICcDMCcDQCcDUCcDYCcDcCcDgCcDkDcDEyA3AxMwNwMTADcDExYJGR4eFEP/GZmaAAAABDMCFjb20uY2F1Y2hvLmhlc3NpYW4uaW8uRmxvYXRIYW5kbGWRBl92YWx1ZWFEP/GZmaAAAABfAAAETF8AAARMBHhpeGlUVHIaamF2YS51dGlsLkFycmF5cyRBcnJheUxpc3QEeGl4aQRoYWhhcgdbc3RyaW5nBHhpeGkEaGFoYQ=='
    str1 = base64.b64decode(enc)
    # print(str1)
    # print(str1.count(b'D'))
    d = Deserialization2Hessian()
    print(d.decoder(str1))
    print(d.decoder(enc))