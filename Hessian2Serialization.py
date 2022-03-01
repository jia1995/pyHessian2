import datetime
import time
import struct
import base64
class ClassDef:
    def __init__(self, type, fieldNames) :
        self.type = type
        self.fieldNames = fieldNames
    def __str__(self) :
        return 'ClassDef : ' + self.type + ' [' + ','.join(self.fieldNames) + ']'

ENCODERS = {}

def encoderFor(data_type):
    def register(f):
        # register function `f` to encode type `data_type`
        ENCODERS[data_type] = f
        return f
    return register

class Hessian2Output:
    def __init__(self) :
        self.output = b''
        self.types = []
        self.classDefs = []
        self.refs = []

    def writeObject(self, value) :
        self.__mWriteObject(value)
        return base64.b64encode(self.output).decode()

    def getLength(self) :
        return len(self.output.getvalue())

    def __write(self, value) :
        if isinstance(value, int): value = chr(value)
        if isinstance(value, str): value = value.encode('ISO_8859_1')
        self.output+= value

    def __pack(self, formatStr, value) :
        self.__write(struct.pack(formatStr, value))

    def __mWriteObject(self, obj) :
        if type(obj) in (int, bytes, float, str, type(None), bool, datetime.datetime, time.struct_time, list, tuple, dict) :
            encoder = ENCODERS[type(obj)]
            encoder(self, obj)
        else :
            encoder = ENCODERS[object]
            encoder(self, obj)

    @encoderFor(type(None))
    def __encodeNull(self, value) :
        self.__write('N')

    @encoderFor(bool)
    def __encodeBoolean(self, value) :
        if value :
            self.__write('T')
        else :
            self.__write('F')

    @encoderFor(int)
    def __encodeInt(self, value) :
        '''
        int ::= 'I' b3 b2 b1 b0
            ::= [x80-xbf]       
            -16 <= value <= 47  value = code - 0x90
            ::= [xc0-xcf] b0    
            -2048 <= value <= 2047  value = ((code - 0xc8) << 8) + b0
            ::= [xd0-xd7] b1 b0
            -262144 <= value <= 262143  value = ((code - 0xd4) << 16) + (b1 << 8) + b0
        '''
        if -16 <= value <= 47:
            self.__write(value+0x90)
        elif -2048 <= value <= 2047 :
            self.__write(0xc8+value >> 8)
            self.__write(value & 0xff)
        elif -262144 <= value <= 262143 :
            self.__write(0xd4+(value >> 16))
            self.__pack('>H', (value >> 8))
        elif  -0x80000000 <= value <= 0x7fffffff:
            self.__write('I')
            self.__pack('>i', value)
        else:
            self.__write('L')
            self.__pack('>q', value)

    @encoderFor(float)
    def __encodeFloat(self, value) :
        '''
        double ::= D b7 b6 b5 b4 b3 b2 b1 b0
               ::= x5b      value = 0.0
               ::= x5c      value = 1.0
               ::= x5d b0   
                -128.0 <= value <= 127.0    value = (double) b0
               ::= x5e b1 b0
                -32768.0 <= value <= 32767.0, value = (double)(256 * b1 + b0)
               ::= x5f b3 b2 b1 b0
                32bit float
        '''
        intValue = int(value)
        if intValue == value :
            if intValue == 0 :
                self.__write(0x5b)
            elif intValue == 1 :
                self.__write(0x5c)
            elif -128 <= intValue <= 127 :
                self.__write(0x5d)
                self.__write(value & 0xff)
            elif -32768 <= value <= 32767 :
                self.__write(0x5e)
                self.__pack('>h', value)
            return
        mills = int(value * 1000);
        if (0.001 * mills) == value :
            self.__write(0x5f)
            self.__pack('>f', value)
        else :
            self.__write('D')
            self.__pack('>d', value)
            

    @encoderFor(datetime.datetime)
    def __encodeDate(self, value) :
        '''
            date ::= x4a b7 b6 b5 b4 b3 b2 b1 b0
                a 64-bit long of milliseconds since Jan 1 1970 00:00H, UTC.
                 ::= x4b b4 b3 b2 b1 b0
                a 32-bit int of minutes since Jan 1 1970 00:00H, UTC.
        '''
        if value.second == 0 and value.microsecond / 1000 == 0 :
            self.__write(0x4b)
            minutes = int(time.mktime(value.timetuple())) / 60
            self.__pack('>i', minutes)
        else :
            self.__write(0x4a)
            milliseconds = int(time.mktime(value.timetuple())) * 1000 
            milliseconds += value.microsecond / 1000
            self.__pack('>q', milliseconds)

    @encoderFor(time.struct_time)
    def __encodeDate2(self, value) :
        '''
            date ::= x4a b7 b6 b5 b4 b3 b2 b1 b0
                a 64-bit long of milliseconds since Jan 1 1970 00:00H, UTC.
                 ::= x4b b4 b3 b2 b1 b0
                a 32-bit int of minutes since Jan 1 1970 00:00H, UTC.
        '''
        if value.second == 0 and value.microsecond / 1000 == 0 :
            self.__write(0x4b)
            minutes = int(time.mktime(value)) / 60
            self.__pack('>i', minutes)
        else :
            self.__write(0x4a)
            milliseconds = int(time.mktime(value)) * 1000 
            milliseconds += value.microsecond / 1000
            self.__pack('>q', milliseconds)

    @encoderFor(str)
    def __encodeUnicode(self, value) :
        '''
        string ::= x52 b1 b0 <utf8-data> string
               ::= S b1 b0 <utf8-data>
               ::= [x00-x1f] <utf8-data>
               ::= [x30-x33] b0 <utf8-data>
        '''
        length = len(value)
        
        while length > 65535 :
            self.__write(0x52)
            self.__pack('>H', 65535)
            self.__write(value[:65535].encode('utf8'))
            value = value[65535:]
            length -= 65535
        
        if length <= 31 :
            self.__write(chr(length))
        elif length <= 1023 :
            self.__write(0x30+(length >> 8))
            self.__write(chr(length & 0xff))
        else :
            self.__write('S')
            self.__pack('>H', length)
        
        if length > 0 :
            self.__write(value.encode('utf8'))

    def __addRef(self, value) :
        refId = 0
        for ref in self.refs :
            if value is ref :
                self.__write(0x51)
                self.__encodeInt(refId)
                return True
            refId += 1

        self.refs.append(value)
        return False

    @encoderFor(list)
    def __encodeList(self, value) :
        ''' list ::= x57 value* 'Z'        # variable-length untyped list '''
        if self.__addRef(value) :
            return

        self.__write(0x57)
        for element in value :
            self.__mWriteObject(element)
        self.__write('Z')

    @encoderFor(tuple)
    def __encodeTuple(self, value) :
        '''
            ::= x58 int value*        # fixed-length untyped list
            ::= [x78-7f] value*       # fixed-length untyped list
        '''
        if self.__addRef(value) :
            return

        if len(value) <= 7 :
            self.__write(0x78)
            self.__write(chr(len(value)))
        else :
            self.__write(0x58)
            self.__encodeInt(len(value))
        for element in value :
            self.__mWriteObject(element)

    @encoderFor(dict)
    def __encodeDict(self, value) :
        '''
            map ::= 'M' type (value value)* 'Z'
                ::= 'H' (value value)* 'Z'
        '''
        if self.__addRef(value) :
            return

        self.__write('H')
        for (k, v) in value.items() :
            self.__mWriteObject(k)
            self.__mWriteObject(v)
        self.__write('Z')

    @encoderFor(bytes)
    def __encodeBinary(self, value) :
        '''
            binary ::= x41 b1 b0 <binary-data> binary
                   ::= B b1 b0 <binary-data>
                   ::= [x20-x2f] <binary-data>
                   ::= [x34-x37] b0 <binary-data>
        '''
        bvalue = value.value
        
        while len(value) > 65535 :
            self.__write(0x41)
            self.__pack('>H', 65535)
            self.__write(value[:65535])
            value = value[65535:]

        if len(value) <= 15 :
            self.__write(0x20+(len(value)))
        elif len(value) <= 1023 :
            self.__write(0x34+value >> 8)
            self.__write(value & 0xff)
        else :
            self.__write('')
            self.__pack('>H', len(value))
        
        self.__write(value)

    def __addClassDef(self, value) :
        classDefId = 0
        type = value.__class__

        for classDef in self.classDefs :
            if type == classDef.type :
                return classDefId
            classDefId += 1

        self.__write('C')
        self.__mWriteObject(str(type))

        fieldNames = value.__dict__.keys()
        
        self.__encodeInt(len(fieldNames))
        for fieldName in fieldNames :
            self.__mWriteObject(fieldName)

        self.classDefs.append(ClassDef(type, fieldNames))

        return len(self.classDefs) - 1

    @encoderFor(object)
    def __encodeObject(self, value) :
        if self.__addRef(value) :
            return

        classDefId = self.__addClassDef(value)

        if classDefId <= 15 :
            self.__write(0x60)
            self.__write(classDefId+0x90)
        else :
            self.__write('O')
            self.__encodeInt(classDefId)

        for fieldName in self.classDefs[classDefId].fieldNames :
            self.__mWriteObject(value.__dict__[fieldName])
            
if __name__ == '__main__':
    str1 = {'a':1, 'b':325434657687, 'c':3134.1, 'd':[1,3,4,5,6],'e':{'但是':'发动机'}}
    ho = Hessian2Output()
    print(ho.writeObject(str1))