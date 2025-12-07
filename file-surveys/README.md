# File surveys

`fanotify_mime_type` listens for fanotify permission events and records MIME
usage. It holds each permission event long enough to ask libfapolicyd for the
file's MIME type via `get_file_type_from_fd`, increments an in-memory counter
for that MIME type, then always allows the access to continue. On `SIGINT` or
`SIGTERM` the program unhooks from fanotify, sorts the collected MIME types by
count, and prints the top 100 as tab-separated columns.

## Building

The program relies on `libfapolicyd` and `libmagic`. After configuring and
building the repository, you can build the tool against the produced library:

```
gcc -std=gnu11 -I../src -I../src/library \
    fanotify_mime_type.c ../src/.libs/libfapolicyd.a -lmagic -o fanotify_mime_type
```

Run the binary as root so it can subscribe to fanotify permission events and
write its findings after it receives `SIGINT` (Ctrl+C) or `SIGTERM`.
