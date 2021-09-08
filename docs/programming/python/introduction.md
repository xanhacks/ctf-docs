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