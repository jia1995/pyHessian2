# Python Implement of Hessian2 Serialization and Deserialization
A python deserialization implementation for Hessian2 (Java) serialized data and serialization for python data.

### requirements
python(>=3.7)

### Hessian 2.0 Serialization Protocol
The list of Hessian2 protocal can be accessed at http://hessian.caucho.com/doc/hessian-serialization.html#toc

#### Usage
1. Serialization
```python
from Hessian2Serialization import Hessian2Output
data = {'a':1, 'b':2}
serialization = Hessian2Output()
res = serialization.writeObject(data)
```
The serialized result is `SAFhkQFiklo=`.

2. Deserialization
```python
from Hessian2Deserialization import Deserialization2Hessian
data = 'SAFhkQFiklo='
deserialization = Deserialization2Hessian()
res = deserialization.decoder(data)
```
The deserialized result is `{"a":1,"b":2}`.