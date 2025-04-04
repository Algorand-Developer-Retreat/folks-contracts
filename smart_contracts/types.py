from algopy.arc4 import Byte, StaticArray, UInt64 as ARC4UInt64
from typing import Literal, TypeAlias

Bytes32: TypeAlias = StaticArray[Byte, Literal[32]]
