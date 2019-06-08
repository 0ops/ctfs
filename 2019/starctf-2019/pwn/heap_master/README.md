1. Unsorted bin attack to rewrite global_max_fast.
2. Fastbin attack to rewrite pointer in stdout to leak libc and heap address.
3. Fastbin attack to control __free_hook.
    1. fastbin attack to rewrite __free_hook with heap ptr
    2. rewrite ptr->fd with arbitrary value
    3. malloc(magic_size)
