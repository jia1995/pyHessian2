import datetime
import struct
import base64
from re import sub
from types import FunctionType
from typing import Dict, List, Tuple

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
    
    def __decoder__(self, withType:str=''):
        if self.pos>=self.len:
            return 
        code = self.__readCur__()
        return DECODER[code](self)

    @Decode((ord('N'),))
    def __getNull__(self, withType:str=''):
        self.__getCur__()
        return 'None',None
    
    @Decode((0x54, 0x46))
    def __getBoolean__(self, withType:str=''):
        return 'bool',self.__getCur__()==0x54

    def __KthAdd__(self, k):
        return int.from_bytes(self.__readKBin__(k), byteorder='big')
    
    @Decode(((0x80, 0xd7), 0x49)) 
    def __getInt__(self, withType:str=''):
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
    def __getLong__(self, withType:str=''):
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
    def __getDouble__(self, withType:str=''):
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
    def __getDate__(self, withType:str=''):
        code = self.__getCur__()
        re = 0
        if code == 0x4a:
            re = self.__KthAdd__(8)
            return 'date',datetime.datetime.strftime(datetime.datetime.fromtimestamp(re/1000),'%Y-%m-%d %H:%M:%S.%f')
        if code == 0x4b:
            re = self.__KthAdd__(4)
            return 'date',datetime.datetime.strftime(datetime.datetime.fromtimestamp(re* 60),'%Y-%m-%d %H:%M:%S.%f')

    @Decode(((0x20, 0x2f),(0x34,0x37), 0x41, 0x42))
    def __getBytes__(self, withType:str=''):
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
    def __getString__(self, withType:str=''):
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

    def __getType__(self, withType:str=''):
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
        elif mt=='':
            dic = {a:b for a,b in zip(k,v)}
            res = v[0]
        else:
            dic = {a:b for a,b in zip(k,v)}
            res = dic
            if len(k)==1 and k==['name']:
                res = v[0]
        re.update(dic)
        return res

    @Decode((0x43,))
    def __getClass__(self, withType:str=''):
        pos = self.pos
        self.__getCur__()
        _,classes=self.__getString__()
        _,size=self.__getInt__()
        k = [self.__decoder__()[1] for _ in range(size)]
        self.classes.append({'name':classes, 'fields':k,'type':[]})
        _, v = self.__getObject__()
        return classes, v

    @Decode(((0x60, 0x6f), 0x4f))
    def __getObject__(self, withType:str=''):
        code = self.__getCur__()
        res = {}
        rem = {'data':res,'type':''}
        self.__addRef__(rem)
        if code==0x4f:
            ref = self.__getCur__()-0x90
        elif code>=0x60 and code<=0x6f:
            ref = code-0x60
        cf = self.classes[ref]
        classes, fields = cf['name'], cf['fields']
        rem['type']=classes
        if self.classes[ref]['type']==[]:
            re1 = [self.__decoder__() for _ in fields]
            re = [i[1] for i in re1]
            self.classes[ref]['type'] = [i[0] for i in re1]
        else:
            re = [self.__decoder__(withType=_)[1] for _ in cf['type']]
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
    def __getList__(self, withType:str=''):
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
        self.__addRef__(rem)
        return 'list',re

    def __getMapData__(self, maps:Dict={}):
        while self.__readCur__()!=0x5a:
            k = self.__decoder__()[1]
            maps[k] = self.__decoder__()[1]
        self.__getCur__()

    @Decode((0x51,))
    def __getRef__(self, withType:str=''):
        _ = self.__getCur__()
        _, lens = self.__decoder__()
        rem = self.refMap[lens]
        if rem['type']!=withType:
            rem = self.refMap[lens-1]
        res = rem['data']
        if len(res)==1 and (isinstance(res, dict) and list(res.keys()) == ['name']):
            res = res['name']
        return 'ref',res

    @Decode((0x48, 0x4d))
    def __getMap__(self, withType:str=''):
        code = self.__getCur__()
        res = {}
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
    # enc = 'QzBEY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMucm1zLmNvcmUuc29ydGluZy5jYWdlLlNvcnRpbmdDYWdlVGFza0NvbnRleHSXBWNhZ2VzD3BhY2thZ2VTdGF0aW9ucw5zd2l0Y2hTdGF0aW9ucwtjYWdlU3RvcmFnZQZjaHV0ZXMFdGFza3MKdGFza0NvbmZpZ2BYyKhDMDljb20uZ2Vla3BsdXMuaGVwaGFlc3R1cy5ybXMuY29yZS5zb3J0aW5nLmNhZ2UuU29ydGluZ0NhZ2WZAmlkDmZ1bGxQZXJjZW50YWdlEWNhZ2VDb250YWluZXJUeXBlB3BvaW50SWQFZmxvb3IKY2FnZVN0YXR1cw9kZXN0aW5hdGlvbkxpc3QJcG9pbnRUeXBlCGxvY2F0aW9uYQRBMTM0WwIxMAdzbG90MTkzkUMwP2NvbS5nZWVrcGx1cy5oZXBoYWVzdHVzLnJtcy5jb3JlLnNvcnRpbmcuY2FnZS5Tb3J0aW5nQ2FnZVN0YXR1c5EEbmFtZWIFRW1wdHl4QzA+Y29tLmdlZWtwbHVzLmhlcGhhZXN0dXMucm1zLmNvcmUuc29ydGluZy5jYWdlLlNvcnRpbmdQb2ludFR5cGWRBG5hbWVjC0NhZ2VTdG9yYWdlQzAzY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMucm1zLmNvcmUubWFwLlBvaW50M0QkRFBvaW50kwF6AXgBeWSRXSJdGWEEQTAxNlsCMTAHc2xvdDA3OZFRk3hRlWSRXVBdD2EEQTMwMVsCMTAHc2xvdDE1M5FRk3hRlWSRXSBdGGEEQTE0MVsCMTAHc2xvdDE5MpFRk3hRlWSRXSBdGWEEQTMzOFsCMTAHc2xvdDA1M5FRk3hRlWSRXVJdC2EEQTA1OFsCMTAHc2xvdDEzM5FRk3hRlWSRXVZdFWEEQTAwMlsCMTAHc2xvdDA1NpFRk3hRlWSRXVddC2EEQTI0OVsCMTAHc2xvdDA5MpFRk3hRlWSRXRpdEWEEQTM0N1sCMTAHc2xvdDE3MZFRk3hRlWSRXURdGGEEQTE5NFsCMTAHc2xvdDEzMZFRk3hRlWSRXVRdFWEEQTIwNVsCMTAHc2xvdDE0N5FRk3hRlWSRXRldGGEEQTI0NFsCMTAHc2xvdDAyN5FRk3hRlWSRXVZdB2EEQTA2NFsCMTAHc2xv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dDEyOZFRk3hRlWSRXVFdFWEEQTMzNVsCMTAHc2xvdDA4OJFRk3hRlWSRXVRdEGEEQTE2OFsCMTAHc2xvdDAwMpFRk3hRlWSRXRldBWEEQTMxM1sCMTAHc2xvdDA5NZFRk3hRlWSRXR5dEWEEQTAzM1sCMTAHc2xvdDA2OJFRk3hRlWSRXVFdDWEEQTMxOVsCMTAHc2xvdDEwN5FRk3hRlWSRXRhdE3h4eFikQzA6Y29tLmdlZWtwbHVzLmhlcGhhZXN0dXMucm1zLmNvcmUuc29ydGluZy5jYWdlLlNvcnRpbmdDaHV0ZZoCaWQJY2h1dGVUeXBlBWZsb29yBmNhZ2VJZAhwcmlvcml0eQxkZWxpdmVyZWROdW0ObWF4RGVsaXZlcnlOdW0Vc3VwcG9ydENvbnRhaW5lclR5cGVzD2Rlc3RpbmF0aW9uTGlzdAhsb2NhdGlvbmUEQzAxOE6RTpGQkHkCMTB4ZJFdRF0VZQRDMDI3TpFOkZCQeQIxMHhkkV0qXRNlBEMwMDROkU6RkJB5AjEweGSRXShdFWUEQzAwNk6RTpGQkHkCMTB4ZJFdLF0VZQRDMDMzTpFOkZCQeQIxMHhkkV02XRNlBEMwMTZOkU6RkJB5AjEweGSRXUBdFWUEQzAzNE6RTpGQkHkCMTB4ZJFdOF0TZQRDMDI4TpFOkZCQeQIxMHhkkV0sXRNlBEMwMTBOkU6RkJB5AjEweGSRXTRdFWUEQzAzNU6RTpGQkHkCMTB4ZJFdOl0TZQRDMDI1TpFOkZCQeQIxMHhkkV0mXRNlBEMwMzJOkU6RkJB5AjEweGSRXTRdE2UEQzAzMU6RTpGQkHkCMTB4ZJFdMl0TZQRDMDEzTpFOkZCQeQIxMHhkkV06XRVlBEMwMTFOkU6RkJB5AjEweGSRXTZdFWUEQzAxMk6RTpGQkHkCMTB4ZJFdOF0VZQRDMDE0TpFOkZCQeQIxMHhkkV08XRVlBEMwMzBOkU6RkJB5AjEweGSRXTBdE2UEQzAyOU6RTpGQkHkCMTB4ZJFdLl0TZQRDMDA5TpFOkZCQeQIxMHhkkV0yXRV4QzBDY29tLmdlZWtwbHVzLmhlcGhhZXN0dXMucm1zLmNvcmUuc29ydGluZy5jYWdlLlNvcnRpbmdDYWdlVGFza0NvbmZpZ5gTbWF4Q2FnZVN0b3JhZ2VVc2FnZQ1tYXhSb2JvdFVzYWdlDW1heENodXRlVXNhZ2UabWF4UGFja2luZ1N0YXRpb25TbG90VXNhZ2UZbWF4U3dpdGNoU3RhdGlvblNsb3RVc2FnZRJuZWVkU3dpdGNoQ2FnZVR5cGUUbmVlZFN3aXRjaENhZ2VOdW1iZXITc29ydGluZ0NhZ2VUYXNrTW9kZWZJf////0l/////SX////9Jf////0l/////Tk5DMEFjb20uZ2Vla3BsdXMuaGVwaGFlc3R1cy5ybXMuY29yZS5zb3J0aW5nLmNhZ2UuU29ydGluZ0NhZ2VUYXNrTW9kZZEEbmFtZWcRRW1wdHlDYWdlRGVsaXZlcnk='
    # deserialization2Hessian = Deserialization2Hessian()
    # # print(base64.b64decode(enc))
    # print(deserialization2Hessian.decoder(enc))