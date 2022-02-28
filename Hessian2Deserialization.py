import datetime
import struct
import base64
from re import sub
from types import FunctionType
from typing import Dict, List, Tuple
from utils import HessianDict

DECODER = [None]*256

def Decode(codes:Tuple[Tuple,...]):
    def register(f:FunctionType):
        for code in codes:
            if type(code) == int:
                DECODER[code] = f
            elif isinstance(code, tuple) and len(code) == 2:
                for i in range(code[0], code[1]+1):
                    DECODER[i] = f
        return f
    return register

class Deserialization2Hessian:
    def __init__(self):
        self.types = []
        self.refMap = []
        self.classes = []
        self.refId= 0
        self.pos = 0

    def decoder(self, bstr:str):
        assert isinstance(bstr, str) or isinstance(bstr, bytes), f"The Type {type(bstr)} is illegal!!!"
        if isinstance(bstr, str):
            bstr = base64.b64decode(bstr)
        self.bstr = bstr
        self.len = len(bstr)
        self.__decoder__()
        return self.refMap[0]['data']

    def __readCur__(self):
        return self.bstr[self.pos]
    
    def __getCur__(self):
        re = self.__readCur__()
        self.pos+=1
        return re
    
    def __decoder__(self, withType:str='', isFlag=False):
        if self.pos>=self.len:
            return 
        code = self.__readCur__()
        return DECODER[code](self, withType, isFlag)

    @Decode((ord('N'),))
    def __getNull__(self, withType:str='', isFlag=False):
        self.__getCur__()
        return 'None',None
    
    @Decode((0x54, 0x46))
    def __getBoolean__(self, withType:str='', isFlag=False):
        return 'bool',self.__getCur__()==0x54

    def __KthAdd__(self, k):
        return int.from_bytes(self.__readKBin__(k), byteorder='big')
    
    @Decode(((0x80, 0xd7), 0x49)) 
    def __getInt__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        if 0x80 <= code <= 0xbf:
            return 'int',code - 0x90
        elif 0xc0 <= code <= 0xcf:
            return 'int',((code - 0xc8) << 8) + self.__getCur__()
        elif 0xd0 <= code <= 0xd7:
            return 'int',((code - 0xd4) << 16) + self.__KthAdd__(2)
        elif code == 0x49:
            return 'int',self.__KthAdd__(4)
    
    @Decode(((0xd8, 0xff),(0x38, 0x3f), 0x59, 0x4c))
    def __getLong__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        if 0xd8 <= code <= 0xef:
            return 'long',int(code - 0xe0)
        elif 0xf0 <= code <= 0xff:
            return 'long',int(((code - 0xf8) << 8) + self.__getCur__())
        elif 0x38 <= code <= 0x3f:
            return 'long',((code - 0x3c) << 16) + self.__KthAdd__(2)
        elif code == 0x59:
            return 'long',self.__KthAdd__(4)
        elif code == 0x4c:
            return 'long',self.__KthAdd__(8)

    def __readKBin__(self, k:int):
        res = self.bstr[self.pos:self.pos+k]
        self.pos+=k
        return res
    
    @Decode(((0x5b, 0x5f),0x44)) 
    def __getDouble__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        if code == 0x5b:
            return 'double',0.0
        elif code == 0x5c:
            return 'double',1.0
        elif code == 0x5d:
            return 'double',float(struct.unpack('>b', self.__readKBin__(1))[0])
        elif code == 0x5e:
            return 'double',float(struct.unpack('>h', self.__readKBin__(2))[0])
        elif code == 0x5f:
            return 'double',float(struct.unpack('>i', self.__readKBin__(4))[0]*0.001)
        else:
            return 'double',float(struct.unpack('>d', self.__readKBin__(8))[0])

    @Decode((0x4a, 0x4b))
    def __getDate__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        re = 0
        if code == 0x4a:
            re = self.__KthAdd__(8)
            return 'date',datetime.datetime.strftime(datetime.datetime.fromtimestamp(re/1000),'%Y-%m-%d %H:%M:%S.%f')
        if code == 0x4b:
            re = self.__KthAdd__(4)
            return 'date',datetime.datetime.strftime(datetime.datetime.fromtimestamp(re* 60),'%Y-%m-%d %H:%M:%S.%f')

    @Decode(((0x20, 0x2f),(0x34,0x37), 0x41, 0x42))
    def __getBytes__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        if 0x20 <= code <= 0x2f:
            lens = code - 0x20
            self.pos+=lens
            return 'byte',self.bstr[self.pos-lens:self.pos]
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
        return 'byte',bufs

    def __readString__(self, length:int):
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

    @Decode(((0x00,0x1f),(0x30,0x33),0x52,0x53))
    def __getString__(self, withType:str='', isFlag=False):
        str1 = ''
        code = self.__getCur__()
        length=0
        self.isLastChunk = True
        if 0x00<=code<=0x1f:
            length = code - 0x00
        elif 0x30<=code<= 0x33:
            b1 = self.__getCur__()
            length = (code - 0x30) * 256 + b1
        elif code == 0x53:
            length = self.__KthAdd__(2)
        elif code == 0x52:
            self.isLastChunk = False
            length = self.__KthAdd__(2)
        str1 += self.__readString__(length)
        while not self.isLastChunk:
            str1 += self.__getString__()[1]
        return 'string', str1

    def __getType__(self, withType:str='', isFlag=False):
        code = self.__readCur__()
        if 0x00<=code <= 0x1f or 0x30<= code <= 0x33 or 0x52<=code<=0x53:
            _, types = self.__getString__()
            self.types.append(types)
        else:
            _, ref = self.__getInt__()
            types = self.types[ref]
        return types

    def __generateClass__(self, classes:str, k:List[str], v:List, re:Dict):
        mt = sub(r'com\.caucho\.hessian\.io\..*Handle','', classes)
        res = None
        if 'com.google.common.collect.ImmutableMap' in classes:
            dic = {a:b for a,b in zip(v[0],v[1])}
            res = dic
        elif sub(r'com\.caucho\.hessian\.io\..*Handle','', classes)=='':
            dic = {a:b for a,b in zip(k,v)}
            res = v[0]
        elif sub(r'java.math.BigDecimal','', classes)=='':
            dic = {a:int(b) for a,b in zip(k,v)}
            res = int(v[0])
        else:
            dic = {a:b for a,b in zip(k,v)}
            res = dic
            if len(k)==1 and k==['name']:
                res = v[0]
        re.update(dic)
        return res

    @Decode((0x43,))
    def __getClass__(self, withType:str='', isFlag=False):
        pos = self.pos
        self.__getCur__()
        _,classes=self.__getString__()
        _,size=self.__getInt__()
        k = [self.__decoder__()[1] for _ in range(size)]
        self.classes.append({'name':classes, 'fields':k,'type':[]})
        _, v = self.__getObject__()
        return classes, v

    @Decode(((0x60, 0x6f), 0x4f))
    def __getObject__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        res = HessianDict()
        rem = {'data':res,'type':''}
        self.__addRef__(rem)
        if code==0x4f:
            ref = self.__getCur__()-0x90
        elif code>=0x60 and code<=0x6f:
            ref = code-0x60
        cf = self.classes[ref]
        classes, fields = cf['name'], cf['fields']
        rem['type']=classes
        isFlag = 'com.google.common.collect.ImmutableMap' in classes
        if self.classes[ref]['type']==[]:
            re1 = [self.__decoder__(isFlag=isFlag) for _ in fields]
            re = [i[1] for i in re1]
            self.classes[ref]['type'] = [i[0] for i in re1]
        else:
            re = [self.__decoder__(withType=_,isFlag=isFlag)[1] for _ in cf['type']]
        return classes, self.__generateClass__(classes, fields, re, res)
    
    def __addRef__(self, obj):
        self.refMap.append(obj)
        self.refId+=1

    def __readList__(self, length:int):
        return [self.__decoder__()[1] for _ in range(length)]

    def __readUnTypedList__(self):
        re = []
        while self.__readCur__()!=0x5a:
            re.append(self.__decoder__()[1])
        self.__getCur__()
        return re

    @Decode(((0x55, 0x58),(0x70, 0x7f)))
    def __getList__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        length = 0
        rem = {'data':[], 'type':'list'}
        if code==0x55 or code==0x56 or 0x70 <= code<=0x77:
            _ = self.__getType__()
        if code==0x56 or code==0x58:
            _,length = self.__getInt__()
        elif 0x70 <= code<=0x77:
            length = code-0x70
        elif 0x78 <= code<=0x7f:
            length = code-0x78
        if code==0x57 or code==0x55:
            re = self.__readUnTypedList__()
        else:
            re = self.__readList__(length)
        rem['data'] = re
        if not isFlag:
            self.__addRef__(rem)
        return 'list',re

    def __getMapData__(self, maps:Dict=HessianDict()):
        while self.__readCur__()!=0x5a:
            k = self.__decoder__()[1]
            v = self.__decoder__()[1]
            maps[k] = v
        self.__getCur__()

    @Decode((0x51,))
    def __getRef__(self, withType:str='', isFlag=False):
        _ = self.__getCur__()
        _, lens = self.__decoder__()
        rem = self.refMap[lens]
        if withType and rem['type']!=withType:
            rem = self.refMap[lens-1]
        res = rem['data']
        if len(res)==1 and (isinstance(res, dict) and list(res.keys()) == ['name']):
            res = res['name']
            # if isinstance(res, HessianDict):
            #     res = self.__generateClass__(rem['type'], res.keys(), res.values(), HessianDict())
        return 'ref',res

    @Decode((0x48, 0x4d))
    def __getMap__(self, withType:str='', isFlag=False):
        code = self.__getCur__()
        res = HessianDict()
        rem = {'data':res, 'type':'map'}
        self.__addRef__(rem)
        if code == 0x4d: # map with type ('M')
            length = self.__getCur__()-0x00
            _ = self.__getType__()
            self.__addRef__(rem)
        self.__getMapData__(res)
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