from __future__ import annotations

from typing import Mapping, overload,MutableMapping,Generic, TypeVar, Iterator
import json
_KT = TypeVar("_KT")
_VT = TypeVar("_VT")
_T = TypeVar("_T")
def hashable(data):
    if isinstance(data, list):
        return hash(tuple(data))
    elif isinstance(data, dict):
        return hash(json.dumps(data))
    else:
        return hash(data)

class HessianDict(MutableMapping[_KT,_VT], Generic[_KT,_VT]):
    def __init__(self, **kargs):
        self.data = {}
        self.key = {}
        for k,v in kargs:
            t = hashable(k)
            self.data[t] = v
            self.key[t] = k
        
    def keys(self):
        return self.key.values()
    
    def values(self):
        return self.data.values()

    def items(self):
        return [(k,v) for k,v in zip(self.keys(), self.values())]
    
    def get(self, __key: _KT, __default: _VT | _T=...)-> _VT | _T:
        key = hashable(__key)
        if key not in self.data:
            if isinstance(__default,type(...)):
                raise ValueError(f'{__key} not in dict!!')
            return __default
        else:
            return self.data[key]

    def pop(self, __key: _KT, __default: _VT | _T=...)-> _VT | _T:
        key = hashable(__key)
        if key not in self.data:
            if isinstance(__default,type(...)):
                raise ValueError(f'{__key} not in dict!!')
            return __default
        else:
            v = self.data.pop(key)
            k = self.key.pop(key)
            return (k.values()[0], v.values()[0])
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, __k):
        key = hashable(__k)
        if key not in self.data:
            raise ValueError(f'{__k} not in dict!!')
        else:
            return self.data[key]
    
    def __setitem__(self, __k, __v):
        k = hashable(__k)
        self.data[k] = __v
        self.key[k] = __k
    
    def __delitem__(self, __k):
        key = hashable(__k)
        if key not in self.data:
            raise ValueError(f'{__k} not in dict!!')
        else:
            v = self.data.pop(key)
            k = self.key.pop(key)

    def __iter__(self) -> Iterator[_KT]: ...
    
    def __hash__(self):
        return hashable(self.data)
    
    def update(self, other=(), /, **kwds):
        if isinstance(other, Mapping):
            for key in other:
                self.__setitem__(key, other[key])
        elif hasattr(other, "keys"):
            for key in other.keys():
                self.__setitem__(key, other[key])
        else:
            for key, value in other.items():
                self.__setitem__(key, value)
        for key, value in kwds.items():
            self.__setitem__(key, value)

    def __repr__(self):
        return '{'+','.join([f'{a}:{b}' for a,b in zip(self.keys(), self.values())])+'}'