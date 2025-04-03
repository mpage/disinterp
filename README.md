# Disinterp

Tools for analyzing the generated machine code of CPython's interpreter loop. Only tested
on x86-64 Linux.

## `distinterp.py`

This overlays source lines and containing bytecode instruction on top of disassembly
of the interpreter loop. For example, the following shows the dump of the assembly for
the `LOAD_FAST_BORROW` opcode:

```
/root/src/cpython/Python/generated_cases.c.h:9080 [LOAD_FAST_BORROW]
            frame->instr_ptr = next_instr;

          19b589: mov    -0x258(%rbp),%rbx

/root/src/cpython/./Include/internal/pycore_stackref.h:348 [None]
    return (_PyStackRef){ .bits = stackref.bits | Py_TAG_DEFERRED };

          19b590: movslq -0x280(%rbp),%rax

/root/src/cpython/Python/generated_cases.c.h:9081 [LOAD_FAST_BORROW]
            next_instr += 1;

          19b597: lea    0x2(%r13),%rcx
          19b59b: mov    %rcx,-0x260(%rbp)
          19b5a2: movq   %rcx,%xmm4

/root/src/cpython/./Include/internal/pycore_stackref.h:348 [None]
    return (_PyStackRef){ .bits = stackref.bits | Py_TAG_DEFERRED };

          19b5a7: mov    0x50(%rbx,%rax,8),%rax

/root/src/cpython/Python/generated_cases.c.h:9080 [LOAD_FAST_BORROW]
            frame->instr_ptr = next_instr;

          19b5ac: mov    %r13,0x38(%rbx)

/root/src/cpython/./Include/internal/pycore_stackref.h:348 [None]
    return (_PyStackRef){ .bits = stackref.bits | Py_TAG_DEFERRED };

          19b5b0: or     $0x1,%rax

/root/src/cpython/Python/generated_cases.c.h:9086 [LOAD_FAST_BORROW]
            stack_pointer[0] = value;

          19b5b4: mov    %rax,(%r12)

/root/src/cpython/Python/generated_cases.c.h:9087 [LOAD_FAST_BORROW]
            stack_pointer += 1;

          19b5b8: lea    0x8(%r12),%rax
          19b5bd: mov    %rax,-0x278(%rbp)

/root/src/cpython/./Include/cpython/pyatomic_gcc.h:363 [None]
{ return __atomic_load_n(obj, __ATOMIC_RELAXED); }

          19b5c4: movzwl 0x2(%r13),%eax

/root/src/cpython/Python/generated_cases.c.h:9089 [LOAD_FAST_BORROW]
            DISPATCH();

          19b5c9: movzbl %ah,%ebx
          19b5cc: movzbl %al,%eax
          19b5cf: mov    %ebx,-0x280(%rbp)
          19b5d5: mov    -0x288(%rbp),%rbx
          19b5dc: movhps -0x278(%rbp),%xmm4
          19b5e3: movaps %xmm4,-0x270(%rbp)
          19b5ea: mov    -0x268(%rbp),%r12
          19b5f1: mov    -0x270(%rbp),%r13
          19b5f8: mov    (%rbx,%rax,8),%rdx
          19b5fc: mov    %r12,-0x290(%rbp)
          19b603: jmp    *%rdx
          19b605: endbr64
```

Use the `--dispatch-only` flag to restrict output to code that is generated
for `DISPATCH()` statements.

Use the `--replace-src` flag if you need to disassemble a binary whose source lives at different
location than what is recorded in the debug info in the binary:

```
python ../interpdump/interpdump.py --dispatch-only --replace-src /root/src,/home/mpage/local/ ./python
```

## `parse_gcc_ipa_inline_dump.py`

This parses the dump files from GCC's IPA inlining pass and print all of the calls that we inlined
into the interpreter loop:

1. Compile CPython with `CFLAGS="-fdump-ipa-inline"`.
2. Run the script on the resulting dumpfile.
