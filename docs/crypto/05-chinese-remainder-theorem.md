---
title: Chinese remainder theorem
description: Chinese remainder theorem
---

# Chinese remainder theorem

## Introduction

The **Chinese remainder theorem** states that if one knows the remainders of the Euclidean division of an integer `n` by several integers, then one can determine uniquely the remainder of the division of `n` by the product of these integers, under the condition that the divisors are pairwise coprime (no two divisors share a common factor other than 1).

More information on [Wikipedia](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) and [brilliant.org](https://brilliant.org/wiki/chinese-remainder-theorem/).

## Maths example

For example, if we know that the remainder of `n` divided by 3 is 2, the remainder of `n` divided by 5 is 3, and the remainder of `n` divided by 7 is 2, then without knowing the value of `n`, we can determine that the remainder of `n` divided by 105 (the product of 3, 5, and 7) is 23. Importantly, this tells us that if `n` is a natural number less than 105, then 23 is the only possible value of `n`.

Let's solve this system :

$$
\begin{equation}
    \begin{cases}
        x \equiv 2 [3]\\
        x \equiv 3 [5]\\
        x \equiv 2 [7]\\
    \end{cases}\\
\end{equation}
$$

$$
\begin{equation}
    \begin{cases}
        x = 7 \times j_{1} + 2\\
        x = 5 \times j_{2} + 3\\
        x = 3 \times j_{3} + 2\\
    \end{cases}\\
\end{equation}
$$

Let's solve the first equation :

$$
7 \times j_{1} + 2 \equiv 3 [5]
$$
$$
7 \times j_{1} \equiv 1 [5]
$$
$$
j_{1} \equiv 3[5]
$$
$$
j_{1} = k_{1} \times 5 + 3
$$

We can inject `j1` :

$$
x = 7 \times (k_{1} \times 5 + 3) + 2
$$
$$
x = 35 \times k_{1} + 23
$$

Let's solve the last equation :

$$
35 \times k_{1} + 23 \equiv 2 [3]
$$
$$
k_{1} \equiv 0 [3]
$$
$$
k_{1} = 3 \times l
$$

We can inject `k1` :

$$
x = 35 \times (3 \times l) + 23
$$
$$
x = 105 \times l + 23
$$
$$
x = 23 [105]
$$

In conclusion :

$$
\begin{equation}
    x =
    \begin{cases}
        23, & \text{if}\ x < 105\\
        \equiv 23 [105], & \text{ otherwise}\\
    \end{cases}\\
\end{equation}
$$