NeoLite Unpacker
================

This uses the data header provided by neolite packing process to attempt to reconstruct the original DLL,
or at least a workable version. If the executable is packed with the reversible option, this should produce
a byte by byte reproduction of the original.

It supports v1 and v2 including zlib compression, bzip2 compression and the neocomp compression algorithms.

See:

https://web.archive.org/web/20010207200556/http://www.neoworx.com/products/neolite/

Usage
=====

Displaying info:

    ./neolite_unpack <input_dll>

Unpacking:

    ./neolite_unpack <input_dll> <output_dll>
