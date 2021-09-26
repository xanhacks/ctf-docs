---
title: Introduction
description: Introduction Python programming language
---

# Introduction

## Basic information

**Wiki :**

- First appeared : February 20, 1991
- Author : Guido van Rossum

**Principle :**

- Interpreted
- High-level
- Garbage collector
- Dynamically-typed
- Multi-paradigm

**Paradigm :**

- Object-oriented
- Procedural (imperative)
- Functional 
- Structured
- Reflective

**Why python ?**

- Open Source
- Wide community
- Easy to learn

**Interpreter :**

Source (.py) -> Compilation -> Bytecode (.pyo) -> Interpreter -> Execution

**2 modes :**

- REPL (Read, Eval, Print, Loop) - ex: IPython
- Scripts - ex: example.py

## Basic syntax

```python
>>> print("hello world !")
hello world !
```

## Variables

### List

More [docs](https://www.tutorialspoint.com/python/python_lists.htm).

```python
>>> l1 = [1, 2, 3]
>>> l1.append(4)
>>> l1
[1, 2, 3, 4]
>>> del l1[1]
>>> l1
[1, 3, 4]
>>> len(l1)
3
>>> 4 in l1
True
>>> 2 in l1
False
>>> [0]*10
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

>>> l2 = ["infosec", 0xA, 32, "wiki"]
>>> for element in l2: print(element)
infosec
10
32
wiki

# Access with index (positive or negative)

>>> l1[0]
1
>>> l1[-1]
4
>>> l1[-2]
3

# list[start:end:step]

>>> l1[0:3]
[1, 2, 3]
>>> l1[:3]
[1, 2, 3]
>>> l1[3:]
[4]
>>> l1[::2]
[1, 3]
>>> l1[:]
[1, 2, 3, 4]
```

### Dict

### Set

### Frozenset

## Magic methods

### Introduction

Magic methods are called under the hood and can be redefined by the developer.

### \_\_add\_\_

```python
# Implementation already defined in the Integer class

>>> 5+3
8
>>> (5).__add__(3)
8

# User implementation of "+" comportment

>>> class Num:
...     def __init__(self, number):
...             self.number = number
...     def __add__(self, obj):
...             return Num(self.number + obj.number)
...
>>> num1 = Num(5)
>>> num2 = Num(10)
>>> num3 = num1 + num2
>>> num3.number
15
```

### \_\_str\_\_

```python
class Employee:

    def __init__(self):

        self.name = "xanhacks"
        self.salary = 10000

class SuperEmployee(Employee):

    def __str__(self):
        return f"Name: {self.name}, Salary: {self.salary}"

e = Employee()
print(e)

se = SuperEmployee()
print(se)
```

```python
<__main__.Employee object at 0x7f5cdff8c730>
Name: xanhacks, Salary: 10000
```



## Mutable / Immutable


| Mutable       | Immutable     |
| ------------- | ------------- |
| Lists         | Numbers (Integer, Rational, Float, Decimal, Complex, Booleans) |
| Sets          | Strings       |
| Dictionaries  | Tuples        |
|               | Frozen Sets   |

User-Defined Classes can be mutable or immutable depending on the class.

### Integer (Immutable)

There will be only one Integer object with a specific value of X thanks to cache optimization.

```python
>>> var1 = 50
>>> var2 = 50
>>> id(var1)
140386274742096
>>> id(var2)
140386274742096

>>> var1 = 30
>>> var2
50
>>> id(var1) == id(var2)
False

>>> var1 = 50
>>> id(var1) == id(var2)
True
```

### List (mutable)

```python
>>> l1 = [1, 2, 3]
>>> l2 = l1
>>> l2.append(4)
>>> l1
[1, 2, 3, 4]
>>> l2
[1, 2, 3, 4]
>>> l1 == l2
True
>>> id(l1) == id(l2)
True
```

## Built-in function

### dir

```
dir(...)
    dir([object]) -> list of strings
    
    If called without an argument, return the names in the current scope.
    Else, return an alphabetized list of names comprising (some of) the attributes
    of the given object, and of attributes reachable from it.
```

```python
>>> dir(int)
['__abs__', '__add__', '__and__', '__bool__', '__ceil__', '__class__', '__delattr__', '__dir__', '__divmod__', '__doc__', '__eq__', '__float__', '__floor__', '__floordiv__', '__format__', '__ge__', '__getattribute__', '__getnewargs__', '__gt__', '__hash__', '__index__', '__init__', '__init_subclass__', '__int__', '__invert__', '__le__', '__lshift__', '__lt__', '__mod__', '__mul__', '__ne__', '__neg__', '__new__', '__or__', '__pos__', '__pow__', '__radd__', '__rand__', '__rdivmod__', '__reduce__', '__reduce_ex__', '__repr__', '__rfloordiv__', '__rlshift__', '__rmod__', '__rmul__', '__ror__', '__round__', '__rpow__', '__rrshift__', '__rshift__', '__rsub__', '__rtruediv__', '__rxor__', '__setattr__', '__sizeof__', '__str__', '__sub__', '__subclasshook__', '__truediv__', '__trunc__', '__xor__', 'as_integer_ratio', 'bit_length', 'conjugate', 'denominator', 'from_bytes', 'imag', 'numerator', 'real', 'to_bytes']
```
