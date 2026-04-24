# collision

md5 (message-digest 5) is a cryptographic hash function designed to deterministically convert a 
varible-length input value to a fixed-length output value. however, it has been proven to be [vulnerable](https://en.wikipedia.org/wiki/MD5#Overview_of_security_issues)
against collision attacks, and is thus considered insecure for hashing sensitive data.
a collistion occurs when more than one input is found to hash to the same output. the idea is demonstrated below.

```{.c .numberLines}
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                setregid(getegid(), getegid());
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

to get the flag, we need to pass an argument to `main()` that makes
`check_password()` return a value that is equivalent to `hashcode`.
the catch is that the argument is checked to be 20 bytes in size, so we can't pass
the hashcode itself since `0x21DD09EC` is only 4 bytes. also, `check_password()`
calculates `res` by iterating over 5 blocks of 4-byte values and incrementing `res` by each block,
basically taking the cumulative sum of the 20-byte input.

we can represent the 4-byte hashcode in 20 bytes by doing some hexademical arithmetic. since `res`
is incremented in 4-byte blocks, I crafted the input by padding the first 16 bytes with ones,
and just subtracted the padding from the original hashcode for the remaining 4 bytes:

```markdown
$ col=$((0x21dd09ec - (0x01010101 * 4)))
$ printf "%x\n" $col
1dd905e8
```

note that we cannot simply pad with zeros instead because bash command substitution ignores null bytes (`\x00`)—the
shell reserves this value for terminating command-line strings.

we can verify that the 20-byte input is actually equivalent to `hashcode` by adding back the 16 bytes of ones to `col`:

```markdown
$ printf "%x\n" $(( (0x01010101 * 4) + $col))
21dd09ec
```

the last thing to account for is making sure the value we pass to `argv[1]` conforms to little-endian architecture:

```markdown
$ file col
setgid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2,
BuildID[sha1]=48d83f055c56d12dc4762db539bf8840e5b4f6cc, for GNU/Linux 3.2.0, not stripped
```

reverse the order of the input such that the LSB is stored first in the array:

```markdown
$ ./col $(perl -e 'print "\x01\x01\x01\x01" x 4 . "\xe8\x05\xd9\x1d"')
Two_hash_collision_Nicely
```
