Two `mingw-w64-openssl` packages, one built with binutils-**2.42** installed, the other with **2.43**. These builds were done back to back, the _only_ command run in between was to update binutils (`pacman -U mingw-w64-binutils-2.43-1-x86_64.pkg.tar.zst`). This was done on an (otherwise) up-to-date Arch Linux machine, and reproduced on another up-to-date Arch Linux machine.

The files in the `/usr/x86_64-w64-mingw32/lib/` and `/usr/i686-w64-mingw32/lib/` directories are abnormally large in the package built with **2.43**. For example:

```Shell
[~/binutils_issue/built_with_2.42] $ tar --wildcards -tvf mingw-w64-openssl-3.4.1-1-any.pkg.tar.zst '*/libcrypto.dll.a'
-rwxr-xr-x root/root   3917886 2025-02-17 11:05 usr/i686-w64-mingw32/lib/libcrypto.dll.a
-rwxr-xr-x root/root   3872194 2025-02-17 11:05 usr/x86_64-w64-mingw32/lib/libcrypto.dll.a
[~/binutils_issue/built_with_2.42] $ cd ../built_with_2.43/
[~/binutils_issue/built_with_2.43] $ tar --wildcards -tvf mingw-w64-openssl-3.4.1-1-any.pkg.tar.zst '*/libcrypto.dll.a'
-rwxr-xr-x root/root 120048726 2025-02-17 11:14 usr/i686-w64-mingw32/lib/libcrypto.dll.a
-rwxr-xr-x root/root 119957566 2025-02-17 11:14 usr/x86_64-w64-mingw32/lib/libcrypto.dll.a
```

As can be seen from the package sizes, the large libraries compress _very_ well: the bad package is hardly bigger than the working package. A quick glance at one of the objects inside the `libcrypto.dll.a` archive with a hexeditor, shows large chunks of `\00`s inserted in the object.

---

Programs linked against the **2.43** library do not seem to work.

```Shell
[~/programming/tests/openssl_tests] $ cat OPENSSL_AES_ENCRYPTION.cc
#include <memory>
#include <iostream>

#include <openssl/evp.h>

int main()
{
  std::cout << "OpenSSL version:  " << OPENSSL_VERSION_TEXT << std::endl;

  std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &::EVP_CIPHER_CTX_free);
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

  std::cout << "Done" << std::endl;
  return 0;
}
[~/programming/tests/openssl_tests] $ x86_64-w64-mingw32-g++ -Wall -Wextra -Woverloaded-virtual -Wshadow -c -pedantic -std=c++23 -D_WIN32_WINNT=0x600 -I/usr/x86_64-w64-mingw32/include/ -O3 -flto -o openssl_test.exe OPENSSL_AES_ENCRYPTION.cc
[~/programming/tests/openssl_tests] $
```

With binutils **2.42** this gives:
```Shell
[~/programming/tests/openssl_tests] $ ls -lh openssl_test.exe
-rw-r--r-- 1 svandijk svandijk 19K feb 15 15:37 openssl_test.exe
```
and running it on Windows works as expected:
```
C:\Users\User>S:\openssl_test.exe
OpenSSL version:  OpenSSL 3.4.1 11 Feb 2025
Done

C:\Users\User>
```

With **2.43**, the program again balloons in size:
```Shell
[~/programming/tests/openssl_tests] $ ls -lh openssl_test.exe
-rw-r--r-- 1 svandijk svandijk 19M feb 15 15:37 openssl_test.exe
```

And running it on Windows shows no output whatsoever.
