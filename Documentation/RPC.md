# RPC specification files

`event_rpcgen.py` generates C structures and marshaling code from `.rpc` files.
Each file defines message fields and their numeric tags. RPC methods are
declared and registered in C using the generated request and reply types;
see `include/event2/rpc.h`.

## Generating C code

From the Libevent source directory:

```sh
python3 event_rpcgen.py messages.rpc
```

This writes `messages.gen.h` and `messages.gen.c` next to `messages.rpc`.
Compile the generated `.c` file with your application and include the generated
header. The generator overwrites both files on each run.

One output argument names the C file; the header name is derived by replacing
`.c` with `.h`. With two output arguments, the header comes first:

```sh
python3 event_rpcgen.py messages.rpc protocol.c
python3 event_rpcgen.py --quiet messages.rpc protocol.h protocol.c
```

Output filenames must end in `.h` and `.c`, respectively. The generated C file
includes only the basename of the header, so keep them in the same directory or
add the header directory to the compiler's include path. `--quiet` suppresses
progress messages.

## Example

Save this as `messages.rpc`:

```c
#define TOKEN_SIZE 16

struct message {
	int sequence = 1;
	string sender = 2;
	optional int64 timestamp = 3;
	optional bytes payload = 4;
	optional bytes token[TOKEN_SIZE] = 5;
	optional struct[metadata] details = 6;
	array string labels = 7;
	array struct[metadata] items = 0x0a;
}

struct metadata {
	string name = 1;
	optional string value = 2;
}
```

`sequence` and `sender` are required. If `details` or an element of `items` is
present, its `name` field is also required.

## Syntax

A file contains one or more structure definitions:

```text
struct NAME {
    TYPE FIELD = TAG;
    optional TYPE FIELD = TAG;
    array TYPE FIELD = TAG;
}
```

Use C identifiers, with unique structure names in the file and unique field
names within each structure. Generated tag constants use uppercase names, so
avoid names that differ only in case.

- Put `struct NAME {` on its own line, with the opening brace on that line.
- End fields with `;`. Put the closing `}` on its own line, without a trailing
  semicolon.
- Separate the type, field name, `=` and tag with whitespace. In particular,
  write `sequence = 1`, not `sequence=1`.
- Keep `struct[NAME]` and `FIELD[LENGTH]` together without internal whitespace.
- Blank lines, `/* ... */` comments and `//` comments are supported.
- End the file with a newline.

### Field types

| Declaration                     | Meaning                         | Generated C storage                        |
|---------------------------------|---------------------------------|--------------------------------------------|
| `int count = 1;`                | Unsigned 32-bit integer         | `ev_uint32_t`                              |
| `int64 count = 1;`              | Unsigned 64-bit integer         | `ev_uint64_t`                              |
| `string name = 1;`              | NUL-terminated string           | `char *`                                   |
| `bytes data = 1;`               | Variable-length binary data     | `ev_uint8_t *` and an `ev_uint32_t` length |
| `bytes data[16] = 1;`           | Exactly 16 bytes of binary data | `ev_uint8_t[16]`                           |
| `struct[metadata] details = 1;` | Nested message                  | `struct metadata *`                        |

These are the only supported field types. Use `bytes` for binary data that
may contain NUL bytes.

A referenced structure must be defined in the same `.rpc` file; forward
references are supported. Structures are declared at file scope, not inside
other structures.

The length suffix applies only to `bytes`. It accepts a positive integer or a
C constant expression without whitespace, such as `TOKEN_SIZE` in the example.
The generator copies the expression into C code, so any macros it uses must
be available in the generated header.

### Required, optional and array fields

An unqualified field is required and must be assigned, even when its value is
zero or an empty string. `NAME_complete()` returns `0` when all required
fields, including those in nested messages, are set, and `-1` otherwise.
Unmarshaling checks completeness; when calling `NAME_marshal()` directly,
call `NAME_complete()` first.

An `optional` field is omitted when unset and has no default value. Use
`EVTAG_HAS` to check whether it is present.

`array` describes zero or more values. It is supported for `int`, `int64`,
`string` and `struct[NAME]`, but not for either form of `bytes`. Each element
is encoded with the field's tag, and element order is preserved. Combining
`optional` and `array` is an error. Arrays cannot have a fixed length or
multiple dimensions.

### Tags and compatibility

The number after `=` is the field's wire tag, not a default value. Tags must be
unique within a structure; different structures can reuse the same tags.
Use unsigned 32-bit values written as decimal integers without leading zeros
or as hexadecimal integers with a `0x` prefix. Tags need not be consecutive,
and zero is allowed.

Field names do not appear in the encoded message. Keep each field's tag, type
and modifiers consistent between sender and receiver.
The generated decoder accepts fields in any order, but rejects unknown tags
and repeated tags for non-array fields. An older decoder therefore rejects
messages containing a newly added field even if that field is optional.

### Preprocessor directives

The generator recognizes a limited set of directives outside structures:

| Directive                                  | Destination                                               |
|--------------------------------------------|-----------------------------------------------------------|
| `#define NAME value`                       | Generated header, before its includes and declarations    |
| `#include "file.h"` or `#include <file.h>` | Generated C file, before the generated header is included |
| `#if ...`, `#ifdef ...`, `#endif`          | Generated C file, alongside the copied includes           |

The generator copies these directives without evaluating them. Includes do not
import `.rpc` files. Conditionals apply to copied includes, not to structure
or field definitions. Other directives, including `#else`, `#elif`, `#ifndef`
and `#undef`, are not supported. Each directive must fit on one line.

See `test/regress.rpc` and `rpc_test()` in `test/regress_rpc.c` for an example
of generating and using messages.
