
/* ===== _DT_INIT @ 00101000 ===== */


void _DT_INIT(void)

{
  if (PTR___gmon_start___00104fe8 != (undefined *)0x0) {
    (*(code *)PTR___gmon_start___00104fe8)();
  }
  return;
}



/* ===== FUN_00101020 @ 00101020 ===== */


void FUN_00101020(void)

{
  (*(code *)PTR_00104f28)();
  return;
}



/* ===== getenv @ 00101030 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * getenv(char *__name)

{
  char *pcVar1;

  pcVar1 = (char *)(*(code *)PTR_getenv_00104f30)();
  return pcVar1;
}



/* ===== __errno_location @ 00101040 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int * __errno_location(void)

{
  int *piVar1;

  piVar1 = (int *)(*(code *)PTR___errno_location_00104f38)();
  return piVar1;
}



/* ===== _exit @ 00101050 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void _exit(int __status)

{
  (*(code *)PTR__exit_00104f40)();
  return;
}



/* ===== puts @ 00101060 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;

  iVar1 = (*(code *)PTR_puts_00104f48)();
  return iVar1;
}



/* ===== write @ 00101070 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t write(int __fd,void *__buf,size_t __n)

{
  ssize_t sVar1;

  sVar1 = (*(code *)PTR_write_00104f50)();
  return sVar1;
}



/* ===== strlen @ 00101080 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
  size_t sVar1;

  sVar1 = (*(code *)PTR_strlen_00104f58)();
  return sVar1;
}



/* ===== __stack_chk_fail @ 00101090 ===== */


void __stack_chk_fail(void)

{
  (*(code *)PTR___stack_chk_fail_00104f60)();
  return;
}



/* ===== mmap @ 001010a0 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * mmap(void *__addr,size_t __len,int __prot,int __flags,int __fd,__off_t __offset)

{
  void *pvVar1;

  pvVar1 = (void *)(*(code *)PTR_mmap_00104f68)();
  return pvVar1;
}



/* ===== alarm @ 001010d0 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

uint alarm(uint __seconds)

{
  uint uVar1;

  uVar1 = (*(code *)PTR_alarm_00104f80)();
  return uVar1;
}



/* ===== read @ 001010f0 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;

  sVar1 = (*(code *)PTR_read_00104f90)();
  return sVar1;
}



/* ===== prctl @ 00101100 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int prctl(int __option,...)

{
  int iVar1;

  iVar1 = (*(code *)PTR_prctl_00104f98)();
  return iVar1;
}



/* ===== __printf_chk @ 00101120 ===== */


void __printf_chk(void)

{
  (*(code *)PTR___printf_chk_00104fa8)();
  return;
}



/* ===== setvbuf @ 00101130 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
  int iVar1;

  iVar1 = (*(code *)PTR_setvbuf_00104fb0)();
  return iVar1;
}



/* ===== unsetenv @ 00101160 ===== */


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int unsetenv(char *__name)

{
  int iVar1;

  iVar1 = (*(code *)PTR_unsetenv_00104fc8)();
  return iVar1;
}



/* ===== getrandom @ 00101170 ===== */


void getrandom(void)

{
  (*(code *)PTR_getrandom_00104fd0)();
  return;
}



/* ===== __cxa_finalize @ 00101180 ===== */


void __cxa_finalize(void)

{
  (*(code *)PTR___cxa_finalize_00104ff8)();
  return;
}



/* ===== FUN_00101190 @ 00101190 ===== */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00101190(void)

{
  char cVar1;
  byte bVar2;
  char *__s;
  size_t sVar4;
  long lVar5;
  int iVar6;
  ulong uVar7;
  char *pcVar8;
  char *unaff_R12;
  char *unaff_R13;
  long in_FS_OFFSET;
  undefined2 local_128 [4];
  undefined8 *local_120;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined4 local_84;
  undefined8 local_80;
  undefined4 local_78;
  undefined4 local_74;
  undefined2 local_70;
  undefined2 local_6e;
  undefined4 local_6c;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_40;
  char cVar3;

  pcVar8 = "UNDERTOW_SEAL";
  local_40 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0xb4);
  __s = getenv("UNDERTOW_SEAL");
  if (__s != (char *)0x0) {
    sVar4 = strlen(__s);
    unaff_R12 = __s;
    if (sVar4 == 0x20) {
      lVar5 = 0;
      do {
        cVar1 = __s[lVar5 * 2];
        if ((byte)(cVar1 - 0x30U) < 10) {
          cVar3 = __s[lVar5 * 2 + 1];
          iVar6 = cVar1 + -0x30;
          if ((byte)(cVar3 - 0x30U) < 10) goto LAB_001012ab;
LAB_00101255:
          if (5 < (byte)(cVar3 + 0x9fU)) goto LAB_0010125e;
LAB_001012ce:
          bVar2 = cVar3 + 0xa9;
        }
        else {
          if ((byte)(cVar1 + 0x9fU) < 6) {
            cVar3 = __s[lVar5 * 2 + 1];
            iVar6 = cVar1 + -0x57;
            if (9 < (byte)(cVar3 - 0x30U)) {
              if ((byte)(cVar3 + 0x9fU) < 6) goto LAB_001012ce;
              goto LAB_0010125e;
            }
          }
          else {
            if (5 < (byte)(cVar1 + 0xbfU)) {
              cVar3 = __s[lVar5 * 2 + 1];
              if ((9 < (byte)(cVar3 - 0x30U)) && (5 < (byte)(cVar3 + 0x9fU))) {
                iVar6 = -1;
LAB_0010125e:
                if (((byte)(cVar3 + 0xbfU) < 6) && (bVar2 = cVar3 - 0x37, iVar6 != -1))
                goto LAB_00101277;
              }
              goto LAB_00101b6e;
            }
            cVar3 = __s[lVar5 * 2 + 1];
            iVar6 = cVar1 + -0x37;
            if (9 < (byte)(cVar3 - 0x30U)) goto LAB_00101255;
          }
LAB_001012ab:
          bVar2 = cVar3 - 0x30;
        }
LAB_00101277:
        *(byte *)((long)&DAT_00105080 + lVar5) = bVar2 | (byte)(iVar6 << 4);
        lVar5 = lVar5 + 1;
      } while (lVar5 != 0x10);
      iVar6 = unsetenv("UNDERTOW_SEAL");
      if (iVar6 == 0) {
        unaff_R13 = "901 1 2 3 4 5 6 7 8 9";
        _DAT_00105070 = DAT_00105080 ^ 0x6d8f2a41c395e7b0;
        unaff_R12 = "900";
        pcVar8 = &DAT_001030d4;
        DAT_00105068 = (DAT_00105088 ^ 0xb47c19e25a603df8) << 0x1d |
                       (DAT_00105088 ^ 0xb47c19e25a603df8) >> 0x23;
        uVar7 = DAT_00105080 ^ DAT_00105088 ^ 0x91e4b37ac6205df8;
        _DAT_00105060 = uVar7 << 0x17 | uVar7 >> 0x29;
        uVar7 = DAT_00105080 + DAT_00105088 + 0x3ad7f16c805e294b;
        _DAT_00105058 = uVar7 * 0x80000000 | uVar7 >> 0x21;
        FUN_00102210(&DAT_00105050);
        puts("100 6");
        __printf_chk(1,"101 %016llx\n",DAT_00105050);
        goto LAB_001013a8;
      }
    }
  }
LAB_00101b6e:
  do {
    do {
      FUN_00102030();
      local_e8 = 0x101000015;
      local_d8 = 0xd901000015;
      local_c8 = 0x3c01000015;
      local_b8 = 0xe701000015;
      local_a8 = 0x1b508000015;
      local_118 = 0x400000020;
      local_a0 = 0x1000000020;
      local_98 = 0x906000015;
      local_110 = 0xc000003e00010015;
      local_90 = 0x2000000020;
      local_f0 = 0x7fff000000000006;
      local_e0 = 0x7fff000000000006;
      local_d0 = 0x7fff000000000006;
      local_c0 = 0x7fff000000000006;
      local_b0 = 0x7fff000000000006;
      local_84 = (undefined4)(DAT_001050d8 + 0x3f00);
      local_80 = 0x2400000020;
      local_58 = 0x7fff000000000006;
      local_120 = &local_118;
      local_108 = 0x8000000000000006;
      local_74 = (undefined4)((ulong)(DAT_001050d8 + 0x3f00) >> 0x20);
      local_68 = 0x1800010015;
      local_60 = 0x8000000000000006;
      local_100 = 0x20;
      local_f8 = 0x1000015;
      local_88 = 0x4000015;
      local_78 = 0x2000015;
      local_70 = 0x20;
      local_6e = 0;
      local_6c = 0x28;
      local_128[0] = 0x19;
      iVar6 = prctl(0x26,1,0,0,0);
    } while (iVar6 != 0);
    iVar6 = prctl(0x16,2,local_128);
  } while (iVar6 != 0);
  _DAT_00105044 = 1;
  puts("110");
LAB_001013a8:
  while( true ) {
    puts(unaff_R13);
    puts(unaff_R12);
    uVar7 = FUN_00102040();
    if (uVar7 < 10) break;
    puts("990");
  }
                    /* WARNING: Could not recover jumptable at 0x001013cf. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)(pcVar8 + *(int *)(pcVar8 + uVar7 * 4)))();
  return;
}



/* ===== entry @ 00101e80 ===== */


void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];

  (*(code *)PTR___libc_start_main_00104fd8)
            (FUN_00101190,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



/* ===== FUN_00101eb0 @ 00101eb0 ===== */


/* WARNING: Removing unreachable block (ram,0x00101ec3) */
/* WARNING: Removing unreachable block (ram,0x00101ecf) */

void FUN_00101eb0(void)

{
  return;
}



/* ===== FUN_00101ee0 @ 00101ee0 ===== */


/* WARNING: Removing unreachable block (ram,0x00101f04) */
/* WARNING: Removing unreachable block (ram,0x00101f10) */

void FUN_00101ee0(void)

{
  return;
}



/* ===== _FINI_0 @ 00101f20 ===== */


void _FINI_0(void)

{
  if (DAT_00105038 == '\0') {
    if (PTR___cxa_finalize_00104ff8 != (undefined *)0x0) {
      __cxa_finalize(PTR_LOOP_00105008);
    }
    FUN_00101eb0();
    DAT_00105038 = 1;
    return;
  }
  return;
}



/* ===== _INIT_0 @ 00101f60 ===== */


void _INIT_0(void)

{
  FUN_00101ee0();
  return;
}



/* ===== FUN_00101f70 @ 00101f70 ===== */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong FUN_00101f70(long param_1)

{
  byte bVar1;
  ulong uVar2;
  long lVar3;
  long lVar4;
  long *plVar5;
  ulong uVar6;

  plVar5 = (long *)(param_1 + 0x40);
  uVar2 = _DAT_00105070 ^ 0x4f17b2c39a68de05;
  lVar3 = 0;
  uVar6 = DAT_00105068;
  do {
    uVar6 = uVar6 + 0x6a09e667f3bcc909;
    lVar4 = *plVar5;
    plVar5 = plVar5 + 1;
    uVar2 = lVar4 + uVar6 ^ uVar2;
    lVar4 = lVar3 + 7;
    bVar1 = (char)lVar3 + (char)(lVar3 / 0x2f) * -0x2f + 9U & 0x3f;
    uVar2 = (uVar2 << bVar1 | uVar2 >> 0x40 - bVar1) * -0x61c8864e7a143579;
    uVar2 = uVar2 ^ uVar2 >> 0x1d;
    lVar3 = lVar4;
  } while (lVar4 != 0x38);
  return (DAT_00105068 << 0x11 | DAT_00105068 >> 0x2f) ^ uVar2 ^ 0xc2b2ae3d27d4eb4f;
}



/* ===== FUN_00102030 @ 00102030 ===== */


void FUN_00102030(void)

{
                    /* WARNING: Subroutine does not return */
  _exit(1);
}



/* ===== FUN_00102040 @ 00102040 ===== */


long FUN_00102040(void)

{
  bool bVar1;
  bool bVar2;
  ssize_t sVar3;
  long lVar4;
  long in_FS_OFFSET;
  byte local_31;
  long local_30;

  bVar1 = false;
  lVar4 = 0;
  bVar2 = false;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
LAB_00102070:
  sVar3 = read(0,&local_31,1);
  if (sVar3 < 1) {
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  if (local_31 != 10) goto code_r0x00102091;
  if (bVar1) {
    if (bVar2) {
      lVar4 = -lVar4;
    }
    goto LAB_001020df;
  }
  goto LAB_001020d8;
code_r0x00102091:
  if (local_31 != 0xd) {
    if (local_31 == 0x2d) {
      if ((!bVar1) && (lVar4 == 0)) {
        bVar2 = true;
        lVar4 = 0;
        goto LAB_00102070;
      }
    }
    else if (((byte)(local_31 - 0x30) < 10) && (lVar4 < 0xf4241)) {
      bVar1 = true;
      lVar4 = (long)(int)(local_31 - 0x30) + lVar4 * 10;
      goto LAB_00102070;
    }
LAB_001020d8:
    lVar4 = -1;
LAB_001020df:
    if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return lVar4;
  }
  goto LAB_00102070;
}



/* ===== FUN_00102130 @ 00102130 ===== */


void FUN_00102130(void *param_1,size_t param_2)

{
  ssize_t sVar1;

  if (param_2 == 0) {
    return;
  }
  do {
    sVar1 = read(0,param_1,param_2);
    if (sVar1 < 1) {
                    /* WARNING: Subroutine does not return */
      _exit(0);
    }
    param_1 = (void *)((long)param_1 + sVar1);
    param_2 = param_2 - sVar1;
  } while (param_2 != 0);
  return;
}



/* ===== FUN_00102180 @ 00102180 ===== */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00102180(undefined8 param_1,undefined4 param_2)

{
  long lVar1;
  undefined8 *puVar2;
  ulong uVar3;
  ulong uVar4;

  puVar2 = DAT_001050a0;
  uVar3 = DAT_00105090;
  if (1 < DAT_00105090) {
    uVar4 = _DAT_001050a8 & 0xffffffff;
    _DAT_001050a8 = CONCAT44(uRam00000000001050bc,_DAT_001050b8);
    DAT_001050a0 = (undefined8 *)_DAT_001050b0;
    _DAT_001050b0 = param_1;
    _DAT_001050b8 = param_2;
    *puVar2 = *(undefined8 *)(&DAT_001050c0 + uVar4 * 8);
    uVar3 = (ulong)puVar2 ^ _DAT_00105060;
    *(ulong *)(&DAT_001050c0 + uVar4 * 8) = (uVar3 << 7 | uVar3 >> 0x39) + _DAT_00105058;
    return;
  }
  lVar1 = DAT_00105090 * 2;
  DAT_00105090 = DAT_00105090 + 1;
  (&DAT_001050a0)[lVar1] = (undefined8 *)param_1;
  (&DAT_001050a8)[uVar3 * 4] = param_2;
  return;
}



/* ===== FUN_00102210 @ 00102210 ===== */


void FUN_00102210(long param_1)

{
  long lVar1;
  int *piVar2;
  long lVar3;

  lVar3 = 8;
  do {
    while( true ) {
      lVar1 = getrandom(param_1,lVar3,0);
      if (lVar1 < 0) break;
      if (lVar1 == 0) goto LAB_00102246;
      param_1 = param_1 + lVar1;
      lVar3 = lVar3 - lVar1;
      if (lVar3 == 0) {
        return;
      }
    }
    piVar2 = __errno_location();
  } while (*piVar2 == 4);
LAB_00102246:
  FUN_00102030();
  return;
}



/* ===== FUN_00102260 @ 00102260 ===== */


void FUN_00102260(void)

{
  int *piVar1;
  void *pvVar2;
  int iVar3;
  long in_FS_OFFSET;
  ulong local_38;
  long local_30;

  iVar3 = 0x20;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  do {
    FUN_00102210(&local_38);
    pvVar2 = mmap((void *)((local_38 & 0x1fffffff) << 0xc | 0x200000000000),0x4000,3,0x100022,-1,0);
    if (pvVar2 != (void *)0xffffffffffffffff) {
      if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
      }
      goto LAB_00102315;
    }
    piVar1 = __errno_location();
  } while (((*piVar1 == 0x11) || (*piVar1 == 0x16)) && (iVar3 = iVar3 + -1, iVar3 != 0));
  FUN_00102030();
LAB_00102315:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



/* ===== FUN_00102320 @ 00102320 ===== */


void FUN_00102320(void *param_1,size_t param_2)

{
  ssize_t sVar1;

  if (param_2 == 0) {
    return;
  }
  do {
    sVar1 = write(1,param_1,param_2);
    if (sVar1 < 1) {
                    /* WARNING: Subroutine does not return */
      _exit(0);
    }
    param_1 = (void *)((long)param_1 + sVar1);
    param_2 = param_2 - sVar1;
  } while (param_2 != 0);
  return;
}



/* ===== _DT_FINI @ 00102404 ===== */


void _DT_FINI(void)

{
  return;
}



/* ===== getenv @ 00106000 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * getenv(char *__name)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __libc_start_main @ 00106008 ===== */


/* WARNING: Control flow encountered bad instruction data */

void __libc_start_main(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __errno_location @ 00106010 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int * __errno_location(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== _ITM_deregisterTMCloneTable @ 00106018 ===== */


/* WARNING: Control flow encountered bad instruction data */

void _ITM_deregisterTMCloneTable(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== _exit @ 00106020 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void _exit(int __status)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== puts @ 00106028 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== write @ 00106030 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t write(int __fd,void *__buf,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== strlen @ 00106038 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __stack_chk_fail @ 00106040 ===== */


/* WARNING: Control flow encountered bad instruction data */

void __stack_chk_fail(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== mmap @ 00106048 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * mmap(void *__addr,size_t __len,int __prot,int __flags,int __fd,__off_t __offset)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== dup2 @ 00106050 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int dup2(int __fd,int __fd2)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== memset @ 00106058 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * memset(void *__s,int __c,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== alarm @ 00106060 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

uint alarm(uint __seconds)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== close @ 00106068 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int close(int __fd)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== read @ 00106070 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __gmon_start__ @ 00106078 ===== */


/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== prctl @ 00106080 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int prctl(int __option,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== malloc @ 00106088 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * malloc(size_t __size)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __printf_chk @ 00106090 ===== */


/* WARNING: Control flow encountered bad instruction data */

void __printf_chk(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== setvbuf @ 00106098 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== mprotect @ 001060a0 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int mprotect(void *__addr,size_t __len,int __prot)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== open @ 001060a8 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int open(char *__file,int __oflag,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== unsetenv @ 001060b0 ===== */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int unsetenv(char *__name)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== _ITM_registerTMCloneTable @ 001060b8 ===== */


/* WARNING: Control flow encountered bad instruction data */

void _ITM_registerTMCloneTable(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== getrandom @ 001060c0 ===== */


/* WARNING: Control flow encountered bad instruction data */

void getrandom(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __cxa_finalize @ 001060c8 ===== */


/* WARNING: Control flow encountered bad instruction data */

void __cxa_finalize(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
