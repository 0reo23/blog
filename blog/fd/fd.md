# fd

this program illustrates the use of file descriptors
with the `read()` syscall. the key lines are 10 and 12.

```{.c .numberLines}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```

a file descriptor in linux is a number that represents an open file.
each process has its own set of file descriptors, and they correspond to
different types of data streams:

0 - standard input

1 - standard output

2 - standard error

`read()` attempts to read a specified number of bytes
from a file descriptor (usually stdin) into a buffer, and returns the number of bytes read if successful.
since `fd` is initialized with `atoi(argv[1]) - 0x1234`, we can pass an ascii integer as an argument to arbitrarily assign the
file descriptor ourselves. if we set `fd` to 0, then `read()` will prompt text from stdin and write it to `buf`.

```markdown
$ echo $((0x1234))
4660
$ echo $((4660 - 0x1234))
0
$ ./fd 4660
LETMEWIN
good job :)
Mama! Now_I_understand_what_file_descriptors_are!
```
