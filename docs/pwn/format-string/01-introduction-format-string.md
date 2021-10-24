---
title: Introduction - Format string
description: Introduction to binary exploitation with format string.
---

# Introduction - Format string

- `%d` or `%i`: Argument will be used as decimal integer (signed or unsigned)
- `%o`: An octal unsigned integer
- `%u`: An unsigned decimal integer - this means negative numbers will wrap around
- `%x` or `%X`: An unsigned hexadecimal integer
- `%f`,  `%g`  or  `%G`: A floating-point number. %f defaults to 6 places after the decimal point (which is locale-dependent - e.g. in de_DE it will be a ,). %g and %G will trim trailing zeroes and switch to scientific notation (like %e) if the numbers get small or large enough.
- `%e` or `%E`: A floating-point number in scientific (XXXeYY) notation
- `%s`: A string
- `%b`: As a string, interpreting backslash escapes, except that octal escapes are of the form 0 or 0ooo.
- `%n`: Write the number of characters printed thus far to an `int` variable