Two `mingw-w64-openssl` packages, one built with binutils-**2.42** installed, the other with **2.43**. These builds were done back to back, the _only_ command run in between was to update binutils (`pacman -U mingw-w64-binutils-2.43-1-x86_64.pkg.tar.zst`). The build process was simply to download the mingw-w64-openssl [PKGBUILD](https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=mingw-w64-openssl), save it in a directory and run `makepkg -rsc`. This was done on an (otherwise) up-to-date Arch Linux machine, and reproduced on another up-to-date Arch Linux machine.

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

---

# Update

Reverting the following commit fixes all issues: https://sourceware.org/git/?p=binutils-gdb.git;a=commitdiff;h=121a3f4b4f4;hp=b35013e29f3bcf9028aa22291f378010420322fe

I've not rewound the entire source tree to before that commit, I've only undone the specific changes in that one commit (manually), skipping changes to the `.texi` file. The full diff is pasted here for completeness:

```diff
diff -ru binutils-2.43_orig/binutils/objcopy.c binutils-2.43_edit/binutils/objcopy.c
--- binutils-2.43_orig/binutils/objcopy.c	2024-08-04 01:00:00.000000000 +0200
+++ binutils-2.43_edit/binutils/objcopy.c	2025-02-17 18:19:50.451322036 +0100
@@ -2956,7 +2956,7 @@
 	  pset = find_section_list (padd->name, false,
 				    SECTION_CONTEXT_SET_FLAGS);
 	  if (pset != NULL)
-	    {	      
+	    {
 	      flags = pset->flags | SEC_HAS_CONTENTS;
 	      flags = check_new_section_flags (flags, obfd, padd->name);
 	    }
@@ -4122,50 +4122,6 @@
   return true;
 }
 
-static inline signed int
-power_of_two (bfd_vma val)
-{
-  signed int result = 0;
-
-  if (val == 0)
-    return 0;
-
-  while ((val & 1) == 0)
-    {
-      val >>= 1;
-      ++result;
-    }
-
-  if (val != 1)
-    /* Number has more than one 1, i.e. wasn't a power of 2.  */
-    return -1;
-
-  return result;
-}
-
-static unsigned int
-image_scn_align (unsigned int alignment)
-{
-  switch (alignment)
-    {
-    case 8192: return IMAGE_SCN_ALIGN_8192BYTES;
-    case 4096: return IMAGE_SCN_ALIGN_4096BYTES;
-    case 2048: return IMAGE_SCN_ALIGN_2048BYTES;
-    case 1024: return IMAGE_SCN_ALIGN_1024BYTES;
-    case  512: return IMAGE_SCN_ALIGN_512BYTES;
-    case  256: return IMAGE_SCN_ALIGN_256BYTES;
-    case  128: return IMAGE_SCN_ALIGN_128BYTES;
-    case   64: return IMAGE_SCN_ALIGN_64BYTES;
-    case   32: return IMAGE_SCN_ALIGN_32BYTES;
-    case   16: return IMAGE_SCN_ALIGN_16BYTES;
-    case    8: return IMAGE_SCN_ALIGN_8BYTES;
-    case    4: return IMAGE_SCN_ALIGN_4BYTES;
-    case    2: return IMAGE_SCN_ALIGN_2BYTES;
-    case    1: return IMAGE_SCN_ALIGN_1BYTES;
-    default: return 0;
-    }
-}
-
 /* Create a section in OBFD with the same
    name and attributes as ISECTION in IBFD.  */
 
@@ -4289,8 +4245,6 @@
   if (!bfd_set_section_size (osection, size))
     err = _("failed to set size");
 
-  bool vma_set_by_user = false;
-
   vma = bfd_section_vma (isection);
   p = find_section_list (bfd_section_name (isection), false,
 			 SECTION_CONTEXT_ALTER_VMA | SECTION_CONTEXT_SET_VMA);
@@ -4300,7 +4254,6 @@
 	vma = p->vma_val;
       else
 	vma += p->vma_val;
-      vma_set_by_user = true;
     }
   else
     vma += change_section_address;
@@ -4308,8 +4261,6 @@
   if (!bfd_set_section_vma (osection, vma))
     err = _("failed to set vma");
 
-  bool lma_set_by_user = false;
-
   lma = isection->lma;
   p = find_section_list (bfd_section_name (isection), false,
 			 SECTION_CONTEXT_ALTER_LMA | SECTION_CONTEXT_SET_LMA);
@@ -4319,7 +4270,6 @@
 	lma += p->lma_val;
       else
 	lma = p->lma_val;
-      lma_set_by_user = true;
     }
   else
     lma += change_section_address;
@@ -4330,25 +4280,6 @@
 			 SECTION_CONTEXT_SET_ALIGNMENT);
   if (p != NULL)
     alignment = p->alignment;
-  else if (pe_section_alignment != (bfd_vma) -1
-	   && bfd_get_flavour (ibfd) == bfd_target_coff_flavour
-	   && bfd_get_flavour (obfd) == bfd_target_coff_flavour)
-    {
-      alignment = power_of_two (pe_section_alignment);
-
-      if (coff_section_data (ibfd, isection))
-	{
-	  struct pei_section_tdata * pei_data = pei_section_data (ibfd, isection);
-
-	  if (pei_data != NULL)
-	    {
-	      /* Set the alignment flag of the input section, which will
-		 be copied to the output section later on.  */
-	      pei_data->pe_flags &= ~IMAGE_SCN_ALIGN_POWER_BIT_MASK;
-	      pei_data->pe_flags |= image_scn_align (pe_section_alignment);
-	    }
-	}
-    }
   else
     alignment = bfd_section_alignment (isection);
 
@@ -4357,36 +4288,6 @@
   if (!bfd_set_section_alignment (osection, alignment))
     err = _("failed to set alignment");
 
-  /* If the output section's VMA is not aligned
-     and the alignment has changed
-     and the VMA was not set by the user
-     and the section does not have relocations associated with it
-     then warn the user.  */
-  if (osection->vma != 0
-      && (alignment >= sizeof (bfd_vma) * CHAR_BIT
-	  || (osection->vma & (((bfd_vma) 1 << alignment) - 1)) != 0)
-      && alignment != bfd_section_alignment (isection)
-      && change_section_address == 0
-      && ! vma_set_by_user
-      && bfd_get_reloc_upper_bound (ibfd, isection) < 1)
-    {
-      non_fatal (_("output section %s's alignment does not match its VMA"), name);
-    }
-
-  /* Similar check for a non-aligned LMA.
-     FIXME: Since this is only an LMA, maybe it does not matter if
-     it is not aligned ?  */
-  if (osection->lma != 0
-      && (alignment >= sizeof (bfd_vma) * CHAR_BIT
-	  || (osection->lma & (((bfd_vma) 1 << alignment) - 1)) != 0)
-      && alignment != bfd_section_alignment (isection)
-      && change_section_address == 0
-      && ! lma_set_by_user
-      && bfd_get_reloc_upper_bound (ibfd, isection) < 1)
-    {
-      non_fatal (_("output section %s's alignment does not match its LMA"), name);
-    }
-
   /* Copy merge entity size.  */
   osection->entsize = isection->entsize;
 
@@ -5819,8 +5720,13 @@
 	      fatal (_("bad format for --set-section-alignment: numeric argument needed"));
 
 	    /* Convert integer alignment into a power-of-two alignment.  */
-	    palign = power_of_two (align);
-	    if (palign == -1)
+            palign = 0;
+            while ((align & 1) == 0)
+              {
+                align >>=1;
+                ++palign;
+              }
+            if (align != 1)
 	      fatal (_("bad format for --set-section-alignment: alignment is not a power of two"));
 
 	    /* Add the alignment setting to the section list.  */
@@ -6037,11 +5943,6 @@
 	case OPTION_PE_SECTION_ALIGNMENT:
 	  pe_section_alignment = parse_vma (optarg,
 					    "--section-alignment");
-	  if (power_of_two (pe_section_alignment) == -1)
-	    {
-	      non_fatal (_("--section-alignment argument is not a power of two: %s - ignoring"), optarg);
-	      pe_section_alignment = (bfd_vma) -1;
-	    }
 	  break;
 
 	case OPTION_SUBSYSTEM:
diff -ru binutils-2.43_orig/binutils/od-pe.c binutils-2.43_edit/binutils/od-pe.c
--- binutils-2.43_orig/binutils/od-pe.c	2024-08-04 01:00:00.000000000 +0200
+++ binutils-2.43_edit/binutils/od-pe.c	2025-02-17 15:35:05.000000000 +0100
@@ -283,49 +283,49 @@
 
       data = bfd_h_get_16 (abfd, fhdr->e_cp);
       printf (_("Pages In File:\t\t\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_crlc);
       printf (_("Relocations:\t\t\t%d\n"), data);
 
       data = bfd_h_get_16 (abfd, fhdr->e_cparhdr);
       printf (_("Size of header in paragraphs:\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_minalloc);
       printf (_("Min extra paragraphs needed:\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_maxalloc);
       printf (_("Max extra paragraphs needed:\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_ss);
       printf (_("Initial (relative) SS value:\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_sp);
       printf (_("Initial SP value:\t\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_csum);
       printf (_("Checksum:\t\t\t%#x\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_ip);
       printf (_("Initial IP value:\t\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_cs);
       printf (_("Initial (relative) CS value:\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_lfarlc);
       printf (_("File address of reloc table:\t%d\n"), data);
-      
+
       data = bfd_h_get_16 (abfd, fhdr->e_ovno);
       printf (_("Overlay number:\t\t\t%d\n"), data);
 
       data = bfd_h_get_16 (abfd, fhdr->e_oemid);
       printf (_("OEM identifier:\t\t\t%d\n"), data);
-  
+
       data = bfd_h_get_16 (abfd, fhdr->e_oeminfo);
       printf (_("OEM information:\t\t%#x\n"), data);
-  
+
       ldata = bfd_h_get_32 (abfd, fhdr->e_lfanew);
       printf (_("File address of new exe header:\t%#lx\n"), ldata);
-        
+
       /* Display the first string found in the stub.
 	 FIXME: Look for more than one string ?
 	 FIXME: Strictly speaking we may not have read the full stub, since
@@ -336,7 +336,7 @@
       unsigned int i;
       unsigned int seen_count = 0;
       unsigned int string_start = 0;
-  
+
       for (i = 0; i < len; i++)
 	{
 	  if (ISPRINT (message[i]))
@@ -392,7 +392,7 @@
       time_t t = timedat;
       fputs (ctime (&t), stdout);
     }
-  
+
   printf (_("Symbol table offset:\t\t%#08lx\n"),
 	  (long) bfd_h_get_32 (abfd, ihdr->f_symptr));
   printf (_("Number of symbols:\t\t\%ld\n"),
@@ -423,7 +423,7 @@
 	  data = (int) bfd_h_get_16 (abfd, xhdr.standard.magic);
 	  printf (_("Magic:\t\t\t\t%x\t\t- %s\n"), data,
 		    data == 0x020b ? "PE32+" : _("Unknown"));
-	  
+
 	  printf (_("Version:\t\t\t%x\n"),
 		  (int) bfd_h_get_16 (abfd, xhdr.standard.vstamp));
 
@@ -508,7 +508,7 @@
 	  data = (int) bfd_h_get_16 (abfd, xhdr.standard.magic);
 	  printf (_("Magic:\t\t\t\t%x\t\t- %s\n"), data,
 		    data == 0x010b ? "PE32" : _("Unknown"));
-	  
+
 	  printf (_("Version:\t\t\t%x\n"),
 		  (int) bfd_h_get_16 (abfd, xhdr.standard.vstamp));
 
@@ -591,43 +591,6 @@
     printf (_("\n  Optional header not present\n"));
 }
 
-static void
-dump_alignment (unsigned int flags)
-{
-  flags &= IMAGE_SCN_ALIGN_POWER_BIT_MASK;
-
-  if (flags == IMAGE_SCN_ALIGN_8192BYTES)
-    printf (_("Align: 8192 "));
-  else if (flags == IMAGE_SCN_ALIGN_4096BYTES)
-    printf (_("Align: 4096 "));
-  else if (flags == IMAGE_SCN_ALIGN_2048BYTES)
-    printf (_("Align: 2048 "));
-  else if (flags == IMAGE_SCN_ALIGN_1024BYTES)
-    printf (_("Align: 1024 "));
-  else if (flags == IMAGE_SCN_ALIGN_512BYTES)
-    printf (_("Align: 512 "));
-  else if (flags == IMAGE_SCN_ALIGN_256BYTES)
-    printf (_("Align: 256 "));
-  else if (flags == IMAGE_SCN_ALIGN_128BYTES)
-    printf (_("Align: 128 "));
-  else if (flags == IMAGE_SCN_ALIGN_64BYTES)
-    printf (_("Align: 64 "));
-  else if (flags == IMAGE_SCN_ALIGN_32BYTES)
-    printf (_("Align: 32 "));
-  else if (flags == IMAGE_SCN_ALIGN_16BYTES)
-    printf (_("Align: 16 "));
-  else if (flags == IMAGE_SCN_ALIGN_8BYTES)
-    printf (_("Align: 8 "));
-  else if (flags == IMAGE_SCN_ALIGN_4BYTES)
-    printf (_("Align: 4 "));
-  else if (flags == IMAGE_SCN_ALIGN_2BYTES)
-    printf (_("Align: 2 "));
-  else if (flags == IMAGE_SCN_ALIGN_1BYTES)
-    printf (_("Align: 1 "));
-  else
-    printf (_("Align: *unknown* "));
-}
-
 /* Dump the section's header.  */
 
 static void
@@ -639,7 +602,7 @@
   unsigned int n_scns = (int) bfd_h_get_16 (abfd, ihdr->f_nscns);
   unsigned int off;
 
-  /* The section header starts after the file, image and optional headers.  */  
+  /* The section header starts after the file, image and optional headers.  */
   if (fhdr == NULL)
     off = sizeof (struct external_filehdr) + opthdr;
   else
@@ -693,15 +656,13 @@
       else
 	printf (_("\n            Flags: %08x: "), flags);
 
-      if (flags & IMAGE_SCN_ALIGN_POWER_BIT_MASK)
+      if (flags != 0)
 	{
-	  dump_alignment (flags);
+          /* Skip the alignment bits. */
 	  flags &= ~ IMAGE_SCN_ALIGN_POWER_BIT_MASK;
+          dump_flags(section_flag_xlat, flags);
 	}
 
-      if (flags != 0)
-	dump_flags (section_flag_xlat, flags);
-
       putchar ('\n');
     }
 }
@@ -715,7 +676,7 @@
 {
   if (options[OPT_FILE_HEADER].selected)
     dump_pe_file_header (abfd, fhdr, ihdr);
-  
+
   if (options[OPT_SECTIONS].selected)
     dump_pe_sections_header (abfd, fhdr, ihdr);
 }
@@ -763,7 +724,7 @@
 		     signature);
 	  return;
 	}
-  
+
       dump_pe (abfd, &fhdr, &ihdr);
     }
   /* See if we recognise this particular PE object file.  */
diff -ru binutils-2.43_orig/binutils/testsuite/binutils-all/objcopy.exp binutils-2.43_edit/binutils/testsuite/binutils-all/objcopy.exp
--- binutils-2.43_orig/binutils/testsuite/binutils-all/objcopy.exp	2024-08-04 01:00:00.000000000 +0200
+++ binutils-2.43_edit/binutils/testsuite/binutils-all/objcopy.exp	2025-02-17 15:35:49.000000000 +0100
@@ -1463,7 +1463,6 @@
 run_dump_test "pr23633"
 
 run_dump_test "set-section-alignment"
-run_dump_test "section-alignment"
 
 setup_xfail "hppa*-*-*"
 setup_xfail "spu-*-*"
Only in binutils-2.43_orig/binutils/testsuite/binutils-all: section-alignment.d
```

And running it on Windows shows no output whatsoever.
