import base64
from struct import unpack
from types import FunctionType
from typing import Dict, List, Tuple
from utils import HessianDict
from datetime import datetime

DECODER = [None]*256
def Decode(codes:Tuple[Tuple,...]):
    def register(f:FunctionType):
        for code in codes:
            if type(code) == int:
                DECODER[code] = f
            elif code.__class__ == tuple and len(code) == 2:
                for i in range(code[0], code[1]+1):
                    DECODER[i] = f
        return f
    return register

KX = []
for start in range(0x00, 0xff):
    if start < 0x80:
        KX.append(1)
    elif 0xc0<=start <=0xdf:
        KX.append(2)
    elif 0xe0<=start<=0xef:
        KX.append(3)
    elif 0xf0<=start<= 0xf7:
        KX.append(4)
    else:
        KX.append(0)


class Deserialization2Hessian:
    def __init__(self):
        self.types = []
        self.refMap = []
        self.classes = []
        self.pos = 0
        
    def decoder(self, bstr:str):
        assert bstr.__class__ in (str, bytes), f"The Type {type(bstr)} is illegal!!!"
        if bstr.__class__ == str:
            bstr = base64.b64decode(bstr)
        self.bstr = bstr
        _, res = DECODER[self.bstr[self.pos]](self)
        return res
    
    @Decode((ord('N'),))
    def __getNull__(self, isFlag=False):
        self.pos+=1
        return 'None',None
    
    @Decode((0x54, 0x46))
    def __getBoolean__(self, isFlag=False):
        re = self.bstr[self.pos]
        self.pos+=1
        return 'bool',re==0x54
    
    @Decode(((0x80, 0xd7), 0x49)) 
    def __getInt__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        if 0x80 <= code <= 0xbf:
            return 'int',code - 0x90
        elif 0xc0 <= code <= 0xcf:
            re = self.bstr[self.pos]
            self.pos+=1
            return 'int',((code - 0xc8)* 256) + re
        elif 0xd0 <= code <= 0xd7:
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            return 'int',((code - 0xd4) *65536) + unpack('>H', res)[0]
        elif code == 0x49:
            res = self.bstr[self.pos:self.pos+4]
            self.pos+=4
            return 'int', unpack('>i', res)[0]
    
    @Decode(((0xd8, 0xff),(0x38, 0x3f), 0x59, 0x4c))
    def __getLong__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        if 0xd8 <= code <= 0xef:
            return 'long',int(code - 0xe0)
        elif 0xf0 <= code <= 0xff:
            re = self.bstr[self.pos]
            self.pos+=1
            return 'long',int(((code - 0xf8) *256) + re)
        elif 0x38 <= code <= 0x3f:
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            return 'long',((code - 0x3c) *65536) + unpack('>H', res)[0]
        elif code == 0x59:
            res = self.bstr[self.pos:self.pos+4]
            self.pos+=4
            return 'long',unpack('>i', res)[0]
        elif code == 0x4c:
            res = self.bstr[self.pos:self.pos+8]
            self.pos+=8
            return 'long',unpack('>q', res)[0]
    
    @Decode(((0x5b, 0x5f),0x44)) 
    def __getDouble__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        if code == 0x5b:
            return 'double',0.0
        elif code == 0x5c:
            return 'double',1.0
        elif code == 0x5d:
            res = self.bstr[self.pos:self.pos+1]
            self.pos+=1
            return 'double',float(unpack('>b', res)[0])
        elif code == 0x5e:
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            return 'double',float(unpack('>h', res)[0])
        elif code == 0x5f:
            res = self.bstr[self.pos:self.pos+4]
            self.pos+=4
            return 'double',float(unpack('>i', res)[0]*0.001)
        else:
            res = self.bstr[self.pos:self.pos+8]
            self.pos+=8
            return 'double',float(unpack('>d', res)[0])
    
    @Decode((0x4a, 0x4b))
    def __getDate__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        re = 0
        if code == 0x4a:
            res = self.bstr[self.pos:self.pos+8]
            self.pos+=8
            re = int.from_bytes(res, byteorder='big')
            return 'date',datetime.strftime(datetime.fromtimestamp(re/1000),'%Y-%m-%d %H:%M:%S.%f')
        res = self.bstr[self.pos:self.pos+4]
        self.pos+=4
        re = int.from_bytes(res, byteorder='big')
        return 'date',datetime.strftime(datetime.fromtimestamp(re* 60),'%Y-%m-%d %H:%M:%S.%f')

    @Decode(((0x20, 0x2f),(0x34,0x37), 0x41, 0x42))
    def __getBytes__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        if 0x20 <= code <= 0x2f:
            lens = code - 0x20
            self.pos+=lens
            return 'byte',self.bstr[self.pos-lens:self.pos]
        bufs = b''
        # get non-final trunk start with 'A'
        while code == 0x41:
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            length=int.from_bytes(res, byteorder='big')
            bufs+=self.bstr[self.pos:self.pos+length]
            self.pos+=length
            code = self.bstr[self.pos]
            self.pos+=1
        if code == 0x42: # get the last trunk start with 'B'
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            length = int.from_bytes(res, byteorder='big')
        elif 0x20 <= code <= 0x2f:
            length = code - 0x20
        elif 0x34 <= code <= 0x37:
            b1 = self.bstr[self.pos]
            self.pos+=1
            length = (code - 0x34) * 256 + b1
        bufs+=self.bstr[self.pos:self.pos+length]
        self.pos+=length
        return 'byte',bufs

    @Decode(((0x00,0x1f),(0x30,0x33),0x52,0x53))
    def __getString__(self, isFlag=False):
        str1 = ''
        code = self.bstr[self.pos]
        self.pos+=1
        self.isLastChunk = True
        if 0x00<=code<=0x1f:
            length = code - 0x00
        elif 0x30<=code<= 0x33:
            b1 = self.bstr[self.pos]
            self.pos+=1
            length = (code - 0x30) * 256 + b1
        elif code == 0x53:
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            length = int.from_bytes(res, byteorder='big')
        elif code == 0x52:
            self.isLastChunk = False
            res = self.bstr[self.pos:self.pos+2]
            self.pos+=2
            length = int.from_bytes(res, byteorder='big')

        bstr = self.pos
        for _ in range(length):
            self.pos+=KX[self.bstr[self.pos]]
        str1 += str(self.bstr[bstr:self.pos], 'utf8')
        while not self.isLastChunk:
            str1 += self.__getString__()[1]
        return 'string', str1
    
    def __getType__(self, isFlag=False):
        _, t = DECODER[self.bstr[self.pos]](self)
        if t.__class__ == int: return self.types[t]
        self.types.append(t)
        return t

    def __generateClass2__(self, classes:str, re:HessianDict):
        v = list(re.values())
        if classes.endswith('Handle'):
            return v[0]
        elif classes == 'java.math.BigDecimal':
            b = v[0]
            if '.' in b: return float(b)
            else: return int(b)
        else:
            k = list(re.keys())
            if len(k)==1 and k==['name']:
                return v[0]
            return re
    
    @Decode((0x43,))
    def __getClass__(self, isFlag=False):
        self.pos+=1
        _,classes=self.__getString__()
        _,size=self.__getInt__()
        k = [DECODER[self.bstr[self.pos]](self)[1] for _ in range(size)]
        self.classes.append({'name':classes, 'fields':k,'type':[]})
        _, v = self.__getObject__()
        return classes, v

    @Decode(((0x60, 0x6f), 0x4f))
    def __getObject__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        res = HessianDict()
        rem = {'data':res,'type':''}
        self.refMap.append(rem)
        if code==0x4f:
            ref = self.bstr[self.pos]-0x90
            self.pos+=1
        else:
            ref = code-0x60
        cf = self.classes[ref]
        classes, fields = cf['name'], cf['fields']
        rem['type']=classes
        isFlag = 'com.google.common.collect.ImmutableMap' in classes
        if not self.classes[ref]['type']:
            re1 = [DECODER[self.bstr[self.pos]](self, isFlag) for _ in fields]
            re = [i[1] for i in re1]
            self.classes[ref]['type'] = [i[0] for i in re1]
        else:
            re = [DECODER[self.bstr[self.pos]](self, isFlag)[1] for _ in fields]
        
        if isFlag:
            for a,b in zip(*re):
                res[a] = b
            return classes,res
        elif classes.endswith('Handle'):
            for a,b in zip(fields,re):
                res[a] = b
            return classes, re[0]
        elif classes == 'java.math.BigDecimal':
            b = re[0]
            if '.' in b: b = float(b)
            else: b= int(b)
            res[fields[0]]=b
            return classes,b
        else:
            if len(fields)==1 and fields==['name']:
                res[fields[0]] = re[0]
                return classes,re[0]
            for a,b in zip(fields,re):
                res[a] = b
            return classes,res
    
    def __readList__(self, length:int):
        return [DECODER[self.bstr[self.pos]](self)[1] for _ in range(length)]

    def __readUnTypedList__(self):
        re = []
        while self.bstr[self.pos]!=0x5a:
            re.append(DECODER[self.bstr[self.pos]](self)[1])
        self.pos+=1
        return re
    
    @Decode(((0x55, 0x58),(0x70, 0x7f)))
    def __getList__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        length = 0
        re = []
        rem = {'data':re, 'type':'list'}
        if not isFlag:
            self.refMap.append(rem)
        if code==0x55 or code==0x56 or 0x70 <= code<=0x77:
            rem['type'] = self.__getType__()
        if code==0x56 or code==0x58:
            _,length = self.__getInt__()
        elif 0x70 <= code<=0x77:
            length = code-0x70
        else:
            length = code-0x78
        if code==0x57 or code==0x55:
            re.extend(self.__readUnTypedList__())
        else:
            re.extend(self.__readList__(length))
        return 'list',re

    @Decode((0x51,))
    def __getRef__(self, isFlag=False):
        self.pos+=1
        _, lens = DECODER[self.bstr[self.pos]](self)
        rem = self.refMap[lens]
        res = rem['data']
        types = rem['type']
        if not res.__class__ in (list, tuple):
            res = self.__generateClass2__(types, res)
        return types,res

    @Decode((0x48, 0x4d))
    def __getMap__(self, isFlag=False):
        code = self.bstr[self.pos]
        self.pos+=1
        res = HessianDict()
        rem = {'data':res, 'type':'map'}
        self.refMap.append(rem)
        if code == 0x4d: # map with type ('M')
            rem['type'] = self.__getType__()
            self.refMap.append(rem)
        while self.bstr[self.pos]!=0x5a:
            k = DECODER[self.bstr[self.pos]](self)[1]
            res[k] = DECODER[self.bstr[self.pos]](self)[1]
        self.pos+=1
        return 'map',res


if __name__=='__main__':
    f = open('test/test.txt')
    for i in f.readlines():
        enc = i
        deserialization2Hessian = Deserialization2Hessian()
        res = deserialization2Hessian.decoder(enc)
        print(res)
    # enc = 'SAFhkQFiTAAAAEvFasuXAWNfRUPhmgFkV5GTlJWWWgFlSALkvYbmmK8D5Y+R5Yqo5py6Wlo='
    # deserialization2Hessian = Deserialization2Hessian()
    # # print(base64.b64decode(enc))
    # print(deserialization2Hessian.decoder(enc))