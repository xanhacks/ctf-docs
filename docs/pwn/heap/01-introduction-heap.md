---
title: Introduction - Heap
description: Introduction to binary exploitation on the heap.
---

# Introduction - Heap

## C Functions

- **void* malloc(size_t size)** allocates the requested memory and returns a pointer to it (or NULL if the request fails).
	- **size** − This is the size of the memory block, in bytes.
- **void* calloc(size_t nitems, size_t size)** allocates the requested memory and returns a pointer to it (or NULL if the request fails).
	- **nitems** − This is the number of elements to be allocated.
	- **size** − This is the size of elements.
- **void free(void *ptr)** deallocates the memory previously allocated by a call to calloc, malloc, or realloc.
	- **ptr** − This is the pointer to a memory block previously allocated with malloc, calloc or realloc to be deallocated. If a null pointer is passed as argument, no action occurs.
- **void* realloc(void *ptr, size_t size)** attempts to resize the memory block pointed to by **ptr** that was previously allocated with a call to `malloc` or `calloc`.
	- **ptr** − This is the pointer to a memory block previously allocated with malloc, calloc or realloc to be reallocated. If this is NULL, a new block is allocated and a pointer to it is returned by the function.
	- **size** − This is the new size for the memory block, in bytes. If it is 0 and ptr points to an existing block of memory, the memory block pointed by ptr is deallocated and a NULL pointer is returned.

> Source [tutorialspoint](https://www.tutorialspoint.com/c_standard_library/c_function_malloc.htm).

!!! warning
	The difference in `malloc()` and `calloc()` is that `malloc` does not set the memory to zero where as calloc sets allocated memory to zero.

!!! warning
    The `free()` function does not delete the contents of the allocated chunk.

