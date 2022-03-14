from __future__ import annotations

from typing import Mapping,MutableMapping,Generic, TypeVar, Iterator
from json import dumps
_KT = TypeVar("_KT")
_VT = TypeVar("_VT")
_T = TypeVar("_T")

def hashable(data:_T) -> int:
    dclass = data.__class__
    if dclass not in (list, dict, HessianDict):
        return hash(dclass)
    if dclass == list:
        return hash(tuple(data))
    elif dclass == HessianDict:
        return hash(dumps(data.data))
    return hash(dumps(data))

def str2re(a:_T) -> str:
    if a.__class__ == str:
        return f'"{a}"'
    else:
        return f'{a}'

class HessianDict(MutableMapping[_KT,_VT], Generic[_KT,_VT]):
    def __init__(self, **kargs):
        self.data = {}
        self.key = {}
        if kargs:
            for k,v in kargs.items():
                t = hashable(k)
                self.data[t] = v
                self.key[t] = k
    
    def keys(self) -> None:
        return list(self.key.values())
    
    def values(self) -> None:
        return list(self.data.values())

    def items(self) -> None:
        return [(k,v) for k,v in zip(self.key.values(), self.data.values())]
    
    def get(self, __key: _KT, __default: _VT | _T=...)-> _VT | _T:
        key = hashable(__key)
        if key not in self.data:
            if __default.__class__ == Ellipsis:
                raise ValueError(f'{__key} not in dict!!')
            return __default
        else:
            return self.data[key]

    def pop(self, __key: _KT, __default: _VT | _T=...)-> _VT | _T:
        key = hashable(__key)
        if key not in self.data:
            if __default.__class__ == Ellipsis:
                raise ValueError(f'{__key} not in dict!!')
            return __default
        else:
            self.key.pop(key)
            return self.data.pop(key)
    
    def __len__(self) -> None:
        return len(self.data)
    
    def __getitem__(self, __k:_KT) -> _VT:
        key = hashable(__k)
        if key not in self.data:
            raise ValueError(f'{__k} not in dict!!')
        else:
            return self.data.get(key)
    
    def __setitem__(self, __k: _KT, __v:_VT) -> None:
        k = hashable(__k)
        self.data[k] = __v
        self.key[k] = __k
    
    def __delitem__(self, __k: _KT) -> None:
        key = hashable(__k)
        if key not in self.data:
            raise ValueError(f'{__k} not in dict!!')
        else:
            self.data.pop(key)
            self.key.pop(key)

    def __iter__(self) -> Iterator[_KT]:
        for key in self.key:
            yield (self.key[key], self.data[key])
    
    def copy(self) -> HessianDict:
        new_HD = HessianDict()
        new_HD.data = self.data.copy()
        new_HD.key = self.key.copy()
        return new_HD

    def update(self, other=(), /, **kwds) -> None:
        if other.__class__ == HessianDict:
            for key, value in other.items():
                k = hashable(key)
                self.data[k] = value
                self.key[k] = key
        elif other.__class__ == Mapping:
            for key in other:
                k = hashable(key)
                self.data[k] = other[key]
                self.key[k] = key
        else:
            for key, value in other.items():
                k = hashable(key)
                self.data[k] = value
                self.key[k] = key
        for key, value in kwds.items():
            k = hashable(key)
            self.data[k] = value
            self.key[k] = key

    def __repr__(self) -> str:
        re = []
        k,v = self.key.values(), self.data.values()
        for a,b in zip(k,v):
            if id(b)==id(self):
                re.append(f'{str2re(a)}'+': {...}')
            else:
                re.append(f'{str2re(a)}: {str2re(b)}')
        return '{'+', '.join(re)+'}'