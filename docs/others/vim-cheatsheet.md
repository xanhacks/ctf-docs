---
title: Vim cheatsheet
description: Vim shortcut combinaison and description.
---

# Vim - Vi IMproved

## sed

### Using groups

Before :

```
- first_group second_group
- hello world
```

sed command :

```
:%s/- \(.*\) \(.*\)$/- \2 \1/g
```

After :

```
- second_group first_group
- world hello
```

### New lines

Before :

```
hello:world:!
```

sed command :

```
:%s/:/^M/g
```

Where the `^M` is typed by pressing control-V (control-Q on Windows) followed by the Enter/Return key.

After :

```
hello
world
!
```

To go back you can do this command :

```
:%s/\n/:/g
```

Output :

```
hello:world:!:
```