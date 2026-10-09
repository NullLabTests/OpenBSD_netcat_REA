
/* ===== 0x102a90  FUN_00102a90 (main) ===== */
/* WARNING: Type propagation algorithm not settling */

int FUN_00102a90(int param_1,char **param_2)

{
  undefined2 uVar1;
  byte *__s;
  bool bVar2;
  undefined2 uVar3;
  ushort uVar4;
  short sVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  servent *psVar13;
  ushort **ppuVar14;
  char *pcVar15;
  sockaddr *psVar16;
  size_t sVar17;
  size_t sVar18;
  undefined8 *puVar19;
  undefined8 *puVar20;
  long lVar21;
  ulong uVar22;
  long lVar23;
  ssize_t sVar24;
  int *piVar25;
  char *pcVar26;
  long lVar27;
  char *pcVar28;
  undefined8 extraout_RDX;
  undefined8 uVar29;
  undefined **ppuVar30;
  addrinfo *__ai;
  msghdr *pmVar31;
  uint uVar32;
  undefined8 *puVar33;
  char **ppcVar34;
  undefined **ppuVar35;
  long in_FS_OFFSET;
  byte bVar36;
  undefined8 uVar37;
  undefined1 auVar38 [16];
  int local_12f8;
  int local_12f4;
  long *local_12e0;
  int local_12d0;
  char *local_12c8;
  int local_12c0;
  undefined4 local_12bc;
  char *local_12b8;
  sockaddr *local_12a8;
  undefined4 local_12a0;
  undefined1 local_1289;
  long local_1288;
  pollfd local_1280;
  iovec local_1278;
  undefined8 local_1268;
  undefined8 uStack_1260;
  iovec *local_1258;
  size_t sStack_1250;
  sockaddr *local_1248;
  size_t sStack_1240;
  undefined8 local_1238;
  undefined8 uStack_1230;
  msghdr local_1208;
  short local_11c8;
  undefined2 local_11c6;
  undefined4 local_11c4;
  ulong local_11c0;
  sockaddr local_1148 [16];
  sockaddr local_1048;
  int local_1038;
  undefined4 local_1034;
  sockaddr local_c48;
  undefined *local_c38;
  undefined4 local_c30;
  undefined *local_c28;
  undefined4 local_c20;
  undefined *local_c18;
  undefined4 local_c10;
  undefined *local_c08;
  undefined4 local_c00;
  undefined *local_bf8;
  undefined4 local_bf0;
  undefined *local_be8;
  undefined4 local_be0;
  undefined *local_bd8;
  undefined4 local_bd0;
  undefined *local_bc8;
  undefined4 local_bc0;
  undefined *local_bb8;
  undefined4 local_bb0;
  undefined *local_ba8;
  undefined4 local_ba0;
  undefined *local_b98;
  undefined4 local_b90;
  char *local_b88;
  undefined4 local_b80;
  undefined *local_b78;
  undefined *local_b68;
  undefined4 local_b60;
  undefined *local_b58;
  undefined4 local_b50;
  undefined *local_b48;
  undefined4 local_b40;
  undefined *local_b38;
  undefined4 local_b30;
  undefined *local_b28;
  undefined4 local_b20;
  undefined *local_b18;
  undefined4 local_b10;
  undefined *local_b08;
  undefined4 local_b00;
  undefined *local_af8;
  undefined4 local_af0;
  char *local_ae8;
  undefined4 local_ae0;
  char *local_ad8;
  undefined4 local_ad0;
  char *local_ac8;
  undefined4 local_ac0;
  char *local_ab8;
  undefined4 local_ab0;
  char *local_aa8;
  undefined4 local_aa0;
  char *local_a98;
  undefined4 local_a90;
  undefined4 local_a80;
  undefined4 local_448;
  undefined8 local_444;
  undefined2 local_434;
  long local_40;
  
  bVar36 = 0;
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  signal(0xd,(__sighandler_t)0x1);
  local_12b8 = (char *)0x0;
  local_12c0 = 5;
LAB_00102b00:
  iVar6 = getopt(param_1,param_2,"46bCDdFhI:i:klM:m:NnO:P:p:q:rSs:T:tUuV:vW:w:X:x:Zz");
  psVar16 = optarg;
  if (iVar6 != -1) {
    switch(iVar6) {
    case 0x34:
      DAT_0018a19c = 2;
      break;
    default:
      FUN_001054d0(1);
      break;
    case 0x36:
      DAT_0018a19c = 10;
      break;
    case 0x43:
      DAT_0018a194 = 1;
      break;
    case 0x44:
      DAT_0018a138 = 1;
      break;
    case 0x46:
      DAT_0018a18c = 1;
      break;
    case 0x49:
      DAT_0018a134 = strtonum(optarg,1,0x40000000,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"TCP receive window %s: %s",local_1288,optarg);
      }
      break;
    case 0x4d:
      DAT_0010a020 = strtonum(optarg,0,0xff,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"ttl is %s");
      }
      break;
    case 0x4f:
      DAT_0018a130 = strtonum(optarg,1,0x40000000,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"TCP send window %s: %s",local_1288,optarg);
      }
      break;
    case 0x50:
      DAT_0018a170 = optarg;
      break;
    case 0x53:
      lVar27 = readpassphrase("TCP MD5SIG password: ",&DAT_0018a0e0,0x50,2);
      if (lVar27 == 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"Unable to read TCP MD5SIG password");
      }
      DAT_0018a0c8 = 1;
      break;
    case 0x54:
      ppuVar35 = (undefined **)&local_c48;
      local_1288 = 0;
      piVar25 = __errno_location();
      *piVar25 = 0;
      psVar16 = optarg;
      pcVar26 = "af11";
      ppuVar30 = (undefined **)&local_c48;
      for (lVar27 = 0x3a; lVar27 != 0; lVar27 = lVar27 + -1) {
        *ppuVar30 = (undefined *)0x0;
        ppuVar30 = ppuVar30 + (ulong)bVar36 * 0xfffffffffffffffe + 1;
      }
      local_c48.sa_data[6] = '(';
      local_c48.sa_data[7] = '\0';
      local_c48.sa_data[8] = '\0';
      local_c48.sa_data[9] = '\0';
      local_c48._0_8_ = &DAT_001071c9;
      local_c38 = &DAT_0010735f;
      local_c28 = &DAT_00107364;
      local_c18 = &DAT_00107369;
      local_c08 = &DAT_0010736e;
      local_bf8 = &DAT_00107373;
      local_be8 = &DAT_00107378;
      local_bd8 = &DAT_0010737d;
      local_bc8 = &DAT_00107382;
      local_bb8 = &DAT_00107387;
      local_ba8 = &DAT_0010738c;
      local_b98 = &DAT_00107391;
      local_b88 = "critical";
      local_b78 = &DAT_0010739f;
      local_c30 = 0x30;
      local_c20 = 0x38;
      local_c10 = 0x48;
      local_c00 = 0x50;
      local_bf0 = 0x58;
      local_be0 = 0x68;
      local_bd0 = 0x70;
      local_bc0 = 0x78;
      local_bb0 = 0x88;
      local_ba0 = 0x90;
      local_b90 = 0x98;
      local_b80 = 0xa0;
      local_b68 = &DAT_001073a3;
      local_b58 = &DAT_001073a7;
      local_b48 = &DAT_001073ab;
      local_b38 = &DAT_001073af;
      local_b28 = &DAT_001073b3;
      local_b18 = &DAT_001073b7;
      local_b08 = &DAT_001073bb;
      local_af8 = &DAT_001073bf;
      local_ae8 = "inetcontrol";
      local_ad8 = "lowcost";
      local_ac8 = "lowdelay";
      local_ab8 = "netcontrol";
      local_aa8 = "reliability";
      local_b60 = 0x20;
      local_b50 = 0x40;
      local_b40 = 0x60;
      local_b30 = 0x80;
      local_b20 = 0xa0;
      local_b10 = 0xc0;
      local_b00 = 0xe0;
      local_af0 = 0xb8;
      local_ae0 = 0xc0;
      local_ad0 = 2;
      local_ac0 = 0x10;
      local_ab0 = 0xe0;
      local_aa0 = 4;
      local_a98 = "throughput";
      local_a90 = 8;
      local_a80 = 0xffffffff;
      do {
        iVar6 = strcmp((char *)psVar16,pcVar26);
        if (iVar6 == 0) {
          DAT_0010a010 = *(uint *)(ppuVar35 + 1);
          goto LAB_00102b00;
        }
        pcVar26 = ppuVar35[2];
        ppuVar35 = ppuVar35 + 2;
      } while (pcVar26 != (char *)0x0);
      sVar17 = strlen((char *)psVar16);
      if (((sVar17 < 2) || ((char)psVar16->sa_family != '0')) ||
         (*(char *)((long)&psVar16->sa_family + 1) != 'x')) {
        DAT_0010a010 = strtonum(psVar16,0,0xff,&local_1288);
      }
      else {
        DAT_0010a010 = __isoc23_strtol(psVar16,0,0x10);
      }
      if (((0xff < DAT_0010a010) || (local_1288 != 0)) || (*piVar25 != 0)) {
                    /* WARNING: Subroutine does not return */
        errx(1,"illegal tos value %s",optarg);
      }
      break;
    case 0x55:
      DAT_0018a19c = 1;
      break;
    case 0x56:
                    /* WARNING: Subroutine does not return */
      errx(1,"no alternate routing table support available");
    case 0x57:
      DAT_0018a144 = strtonum(optarg,1,0x7fffffff,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"receive limit %s: %s",local_1288,optarg);
      }
      break;
    case 0x58:
      iVar6 = strcasecmp((char *)optarg,"connect");
      if (iVar6 == 0) {
        local_12c0 = -1;
      }
      else {
        iVar6 = strcmp((char *)psVar16,"4");
        if (iVar6 == 0) {
          local_12c0 = 4;
        }
        else {
          iVar6 = strcasecmp((char *)psVar16,"4A");
          if (iVar6 == 0) {
            local_12c0 = 0x2c;
          }
          else {
            iVar6 = strcmp((char *)psVar16,"5");
            if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
              errx(1,"unsupported proxy protocol");
            }
            local_12c0 = 5;
          }
        }
      }
      break;
    case 0x5a:
      DAT_0018a14c = 1;
      break;
    case 0x62:
      DAT_0018a198 = 1;
      break;
    case 100:
      DAT_0018a190 = 1;
      break;
    case 0x68:
      fwrite("OpenBSD netcat (Debian patchlevel 1.234-1)\n",1,0x2b,stderr);
      FUN_001054d0(0);
      fwrite("\tCommand Summary:\n\t\t-4\t\tUse IPv4\n\t\t-6\t\tUse IPv6\n\t\t-b\t\tAllow broadcast\n\t\t-C\t\tSend CRLF as line-ending\n\t\t-D\t\tEnable the debug socket option\n\t\t-d\t\tDetach from stdin\n\t\t-F\t\tPass socket fd\n\t\t-h\t\tThis help text\n\t\t-I length\tTCP receive buffer length\n\t\t-i interval\tDelay interval for lines sent, ports scanned\n\t\t-k\t\tKeep inbound sockets open for multiple connects\n\t\t-l\t\tListen mode, for inbound connects\n\t\t-M ttl\t\tOutgoing TTL / Hop Limit\n\t\t-m minttl\tMinimum incoming TTL / Hop Limit\n\t\t-N\t\tShutdown the network socket after EOF on stdin\n\t\t-n\t\tSuppress name/port resolutions\n\t\t-O length\tTCP send buffer length\n\t\t-P proxyuser\tUsername for proxy authentication\n\t\t-p port\t\tSpecify local port for remote connects\n\t\t-q secs\t\tquit after EOF on stdin and delay of secs\n\t\t-r\t\tRandomize remote ports\n\t\t-S\t\tEnable the TCP MD5 signature option\n\t\t-s sourceaddr\tLocal source address\n\t\t-T keyword\tTOS value\n\t\t-t\t\tAnswer TELNET negotiation\n\t\t-U\t\tUse UNIX domain socket\n\t\t-u\t\tUDP mode\n\t\t-V rtable\tSpecify alternate routing table\n\t\t-v\t\tVerbose\n\t\t-W recvlimit\tTerminate after receiving a number of packets\n\t\t-w timeout\tTimeout for connects and final net reads\n\t\t-X proto\tProxy protocol: \"4\", \"4A\", \"5\" (SOCKS) or \"connect\"\n\t\t-x addr[:port]\tSpecify proxy address and port\n\t\t-Z\t\tDCCP mode\n\t\t-z\t\tZero-I/O mode [used for scanning]\n\tPort numbers can be individual or ranges: lo-hi [inclusive]\n"
             ,1,0x550,stderr);
                    /* WARNING: Subroutine does not return */
      exit(0);
    case 0x69:
      DAT_0018a188 = strtonum(optarg,0,0xffffffff,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"interval %s: %s",local_1288,optarg);
      }
      break;
    case 0x6b:
      DAT_0018a184 = 1;
      break;
    case 0x6c:
      DAT_0018a180 = 1;
      break;
    case 0x6d:
      DAT_0010a01c = strtonum(optarg,0,0xff,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"minttl is %s");
      }
      break;
    case 0x6e:
      DAT_0018a178 = 1;
      break;
    case 0x70:
      DAT_0018a168 = optarg;
      break;
    case 0x71:
      DAT_0010a018 = strtonum(optarg,0xffffffff80000000,0x7fffffff,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"quit timer %s: %s",local_1288,optarg);
      }
      if (DAT_0010a018 < 0) break;
    case 0x4e:
      DAT_0018a17c = 1;
      break;
    case 0x72:
      DAT_0018a160 = 1;
      break;
    case 0x73:
      DAT_0018a158 = optarg;
      break;
    case 0x74:
      DAT_0018a154 = 1;
      break;
    case 0x75:
      DAT_0018a150 = 1;
      break;
    case 0x76:
      DAT_0018a148 = 1;
      break;
    case 0x77:
      DAT_0010a014 = strtonum(optarg,0,0x20c49b,&local_1288);
      if (local_1288 != 0) {
                    /* WARNING: Subroutine does not return */
        errx(1,"timeout %s: %s",local_1288,optarg);
      }
      DAT_0010a014 = DAT_0010a014 * 1000;
      break;
    case 0x78:
      goto switchD_00102b2a_caseD_78;
    case 0x7a:
      DAT_0018a13c = 1;
    }
    goto LAB_00102b00;
  }
  uVar32 = param_1 - optind;
  puVar33 = (undefined8 *)(ulong)uVar32;
  if (uVar32 == 0) {
    if (DAT_0018a180 == 0) goto LAB_0010333c;
    local_12a8 = DAT_0018a158;
    if (DAT_0018a19c != 1) {
      if (DAT_0018a168 == (sockaddr *)0x0) goto LAB_00104b9e;
      param_2 = (char **)&DAT_0018a168;
      psVar16 = DAT_0018a168;
LAB_001033fd:
      iVar6 = DAT_0018a180;
      if (DAT_0018a13c != 0) goto LAB_0010340a;
      goto LAB_001032e5;
    }
    ppcVar34 = (char **)&DAT_0018a168;
LAB_00103494:
    if (DAT_0018a14c != 0) goto LAB_00103776;
    if (*ppcVar34 != (char *)0x0) {
                    /* WARNING: Subroutine does not return */
      errx(1,"cannot use port with -U");
    }
  }
  else {
    param_2 = param_2 + optind;
    if (uVar32 != 1) {
      if ((int)uVar32 < 2) goto LAB_0010333c;
      if ((DAT_0018a180 != 0) &&
         (((DAT_0018a168 != (sockaddr *)0x0 || (DAT_0018a158 != (sockaddr *)0x0)) || (uVar32 != 2)))
         ) {
        FUN_001054d0(1);
      }
      local_12a8 = (sockaddr *)*param_2;
      ppcVar34 = param_2 + 1;
      if (DAT_0018a19c == 1) goto LAB_00103494;
      psVar16 = (sockaddr *)param_2[1];
      if (psVar16 == (sockaddr *)0x0) goto LAB_00104b9e;
      param_2 = ppcVar34;
      if (DAT_0018a180 != 0) goto LAB_001033fd;
      iVar6 = 0;
      if (DAT_0018a184 != 0) goto LAB_0010521c;
LAB_001032e5:
      piVar25 = (int *)&local_1238;
      for (lVar27 = 0xc; lVar27 != 0; lVar27 = lVar27 + -1) {
        *piVar25 = 0;
        piVar25 = piVar25 + (ulong)bVar36 * -2 + 1;
      }
      if (DAT_0018a150 == 0) {
        if (DAT_0018a14c == 0) {
          local_12c8._0_4_ = 6;
          local_12bc = 1;
        }
        else {
          local_12c8._0_4_ = 0x21;
          local_12bc = 6;
        }
      }
      else {
        local_12c8._0_4_ = 0x11;
        local_12bc = 2;
      }
      ppcVar34 = param_2;
      if (DAT_0018a178 == 0) {
        if (DAT_0018a140 != 0) {
          local_12a0 = 0;
          local_12f4 = DAT_0018a19c;
          goto LAB_00103798;
        }
        uVar8 = 0;
        local_12a0 = 0;
        if (iVar6 == 0) goto LAB_00103462;
LAB_00103a74:
        local_1280.fd = 1;
        local_1238 = CONCAT44(DAT_0018a19c,uVar8);
        uStack_1230 = CONCAT44(local_12c8._0_4_,local_12bc);
        piVar25 = (int *)&local_1238;
        pmVar31 = &local_1208;
        for (lVar27 = 0xc; lVar27 != 0; lVar27 = lVar27 + -1) {
          *(int *)&pmVar31->msg_name = *piVar25;
          piVar25 = piVar25 + (ulong)bVar36 * -2 + 1;
          pmVar31 = (msghdr *)((long)pmVar31 + (ulong)bVar36 * -8 + 4);
        }
        local_1208.msg_name = (void *)(CONCAT44(local_1208.msg_name._4_4_,uVar8) | 1);
        if ((local_12a8 == (sockaddr *)0x0) && (DAT_0018a19c == 0)) {
          local_1208.msg_name = (void *)CONCAT44(2,(socklen_t)local_1208.msg_name);
        }
        iVar6 = getaddrinfo((char *)local_12a8,(char *)psVar16,(addrinfo *)&local_1208,
                            (addrinfo **)&local_1268);
        if (iVar6 != 0) goto LAB_00104d6b;
        uVar22 = CONCAT44(local_1268._4_4_,(int)local_1268);
        iVar6 = -1;
        __ai = (addrinfo *)0x0;
        if (uVar22 != 0) {
LAB_00103b10:
          iVar6 = socket(*(int *)(uVar22 + 4),*(int *)(uVar22 + 8),*(int *)(uVar22 + 0xc));
          if (iVar6 == -1) goto LAB_00103bab;
          iVar12 = setsockopt(iVar6,1,2,&local_1280,4);
          if (iVar12 == -1) {
            warn("Couldn\'t set SO_REUSEADDR");
          }
          iVar12 = setsockopt(iVar6,1,0xf,&local_1280,4);
          if (iVar12 == -1) goto LAB_00104f2d;
          do {
            FUN_001055b0(iVar6,*(undefined8 *)(uVar22 + 0x18));
            iVar12 = bind(iVar6,*(sockaddr **)(uVar22 + 0x18),*(socklen_t *)(uVar22 + 0x10));
            uVar32 = DAT_0018a150;
            if (iVar12 == 0) {
              if ((DAT_0018a150 == 0) && (iVar12 = listen(iVar6,1), iVar12 == -1))
              goto LAB_00105081;
              bVar2 = true;
            }
            else {
              piVar25 = __errno_location();
              iVar12 = *piVar25;
              close(iVar6);
              *piVar25 = iVar12;
LAB_00103bab:
              uVar22 = *(ulong *)(uVar22 + 0x28);
              if (uVar22 != 0) goto LAB_00103b10;
              iVar6 = -1;
              bVar2 = false;
              uVar32 = DAT_0018a150;
            }
            uVar22 = (ulong)uVar32;
            if ((DAT_0018a148 == 0) || (!bVar2)) {
LAB_00103c1f:
              __ai = (addrinfo *)CONCAT44(local_1268._4_4_,(int)local_1268);
              break;
            }
            local_1278.iov_base = (void *)CONCAT44(local_1278.iov_base._4_4_,0x80);
            iVar12 = getsockname(iVar6,&local_c48,(socklen_t *)&local_1278);
            if (iVar12 != -1) {
              if (uVar32 == 0) {
                pcVar26 = "Listening";
              }
              else {
                pcVar26 = "Bound";
              }
              FUN_00106b00(pcVar26,&local_c48,(ulong)local_1278.iov_base & 0xffffffff,0);
              goto LAB_00103c1f;
            }
            err(1,"getsockname");
LAB_00104f2d:
            warn("Couldn\'t set SO_REUSEPORT");
          } while( true );
        }
        freeaddrinfo(__ai);
LAB_0010350e:
        if (iVar6 < 0) {
LAB_00104d90:
          err(1,0);
          goto LAB_00104d9e;
        }
        do {
          while (DAT_0018a150 != 0) {
            if (DAT_0018a184 == 0) {
              local_1208.msg_name = (void *)CONCAT44(local_1208.msg_name._4_4_,0x80);
              sVar24 = recvfrom(iVar6,&local_c48,0x800,2,&local_1048,(socklen_t *)&local_1208);
              if ((int)sVar24 == -1) goto LAB_00104e75;
              iVar12 = connect(iVar6,&local_1048,(socklen_t)local_1208.msg_name);
              if (iVar12 == -1) goto LAB_00104e62;
              if (DAT_0018a148 != 0) {
                psVar16 = (sockaddr *)0x0;
                if (DAT_0018a19c == 1) {
                  psVar16 = local_12a8;
                }
                FUN_00106b00("Connection received",&local_1048,
                             (ulong)local_1208.msg_name & 0xffffffff,psVar16);
              }
            }
            FUN_00106300(iVar6);
            if (DAT_0018a184 == 0) goto LAB_00103663;
          }
          local_1208.msg_name = (void *)CONCAT44(local_1208.msg_name._4_4_,0x80);
          iVar12 = accept4(iVar6,local_1148,(socklen_t *)&local_1208,0x800);
          if (iVar12 == -1) {
            err(1,"accept");
LAB_00104e62:
            err(1,"connect");
LAB_00104e75:
            sVar24 = err(1,"recvfrom");
            goto LAB_00104e88;
          }
          if (DAT_0018a148 != 0) {
            psVar16 = (sockaddr *)0x0;
            if (DAT_0018a19c == 1) {
              psVar16 = local_12a8;
            }
            FUN_00106b00("Connection received",local_1148,(ulong)local_1208.msg_name & 0xffffffff,
                         psVar16);
          }
          FUN_00106300(iVar12);
          close(iVar12);
        } while (DAT_0018a184 != 0);
LAB_00103663:
        local_12d0 = DAT_0018a184;
        close(iVar6);
LAB_0010366b:
        close(iVar6);
      }
      else {
        if (DAT_0018a140 == 0) {
          if (iVar6 != 0) {
            uVar8 = 4;
            goto LAB_00103a74;
          }
          local_12a0 = 4;
LAB_00103462:
          pcVar26 = (char *)0x0;
          pcVar28 = "udp";
          iVar12 = DAT_0018a19c;
          if (DAT_0018a150 == 0) {
            if (DAT_0018a14c == 0) {
              pcVar28 = "tcp";
            }
            else {
              pcVar28 = "dccp";
            }
          }
        }
        else {
          local_12a0 = 4;
          local_12f4 = DAT_0018a19c;
LAB_00103798:
          if (DAT_0018a150 != 0) {
LAB_00104f07:
                    /* WARNING: Subroutine does not return */
            errx(1,"no proxy support for UDP mode");
          }
LAB_001037a5:
          iVar12 = DAT_0018a19c;
          if (DAT_0018a14c != 0) {
                    /* WARNING: Subroutine does not return */
            errx(1,"no proxy support for DCCP mode");
          }
          if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
            errx(1,"no proxy support for listen");
          }
          if (local_12f4 == 1) {
                    /* WARNING: Subroutine does not return */
            errx(1,"no proxy support for unix sockets");
          }
          if (DAT_0018a158 != (sockaddr *)0x0) goto LAB_00105035;
          if (*local_12b8 == '[') {
            local_12b8 = local_12b8 + 1;
            pcVar28 = strchr(local_12b8,0x5d);
            if (pcVar28 == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
              errx(1,"missing closing bracket in proxy");
            }
            *pcVar28 = '\0';
            pcVar26 = (char *)0x0;
            if (pcVar28[1] != '\0') {
              if (pcVar28[1] != ':') goto LAB_00105094;
              pcVar26 = pcVar28 + 2;
            }
          }
          else {
            pcVar26 = strrchr(local_12b8,0x3a);
            if (pcVar26 != (char *)0x0) {
              *pcVar26 = '\0';
              pcVar26 = pcVar26 + 1;
            }
          }
          piVar25 = (int *)&local_1268;
          for (lVar27 = 0xc; lVar27 != 0; lVar27 = lVar27 + -1) {
            *piVar25 = 0;
            piVar25 = piVar25 + (ulong)bVar36 * -2 + 1;
          }
          pcVar28 = "tcp";
          local_12f8 = (uint)(DAT_0018a178 != 0) << 2;
        }
        pcVar15 = *ppcVar34;
        if (pcVar15 != (char *)0x0) {
          iVar6 = 0;
          puVar33 = &DAT_0010a0c0;
          do {
            psVar13 = getservbyname(pcVar15,pcVar28);
            if (psVar13 == (servent *)0x0) {
              ppuVar14 = __ctype_b_loc();
              uVar32 = DAT_0018a150;
              __s = (byte *)*ppcVar34;
              if (((*(byte *)((long)*ppuVar14 + (ulong)*__s * 2 + 1) & 8) == 0) ||
                 (pcVar15 = strchr((char *)__s,0x2d), pcVar15 == (char *)0x0)) {
                uVar32 = FUN_00105510(__s,uVar32);
                goto LAB_00103881;
              }
              *pcVar15 = '\0';
              iVar7 = FUN_00105510(pcVar15 + 1,uVar32);
              iVar10 = FUN_00105510(*ppcVar34,DAT_0018a150);
              iVar9 = iVar10;
              if (iVar7 < iVar10) {
                iVar9 = iVar7;
                iVar7 = iVar10;
              }
              puVar19 = &DAT_0010a0c0 + iVar6;
              iVar10 = iVar9;
              do {
                iVar11 = iVar10;
                iVar10 = __asprintf_chk(puVar19,2,&DAT_0010757f,iVar11);
                if (iVar10 == -1) goto LAB_00105022;
                puVar19 = puVar19 + 1;
                iVar10 = iVar11 + 1;
              } while (iVar11 + 1 <= iVar7);
              iVar6 = iVar6 + 1 + (iVar11 - iVar9);
            }
            else {
              uVar4 = (ushort)psVar13->s_port;
              uVar32 = (uint)(ushort)(uVar4 << 8 | uVar4 >> 8);
LAB_00103881:
              iVar7 = __asprintf_chk(&DAT_0010a0c0 + iVar6,2,&DAT_0010757f,uVar32);
              if (iVar7 < 0) {
LAB_00105022:
                err(1,"asprintf");
LAB_00105035:
                    /* WARNING: Subroutine does not return */
                errx(1,"no proxy support for local source address");
              }
              iVar6 = iVar6 + 1;
            }
            pcVar15 = ppcVar34[1];
            ppcVar34 = ppcVar34 + 1;
          } while (pcVar15 != (char *)0x0);
          if ((DAT_0018a160 != 0) && (0 < iVar6 + -1)) {
            lVar27 = (long)(iVar6 + -1);
            do {
              iVar6 = arc4random_uniform((int)lVar27 + 1);
              if (iVar6 != (int)lVar27) {
                uVar37 = (&DAT_0010a0c0)[lVar27];
                (&DAT_0010a0c0)[lVar27] = (&DAT_0010a0c0)[iVar6];
                (&DAT_0010a0c0)[iVar6] = uVar37;
              }
              lVar27 = lVar27 + -1;
            } while (0 < (int)lVar27);
          }
        }
        local_12d0 = 1;
        if (DAT_0010a0c0 != 0) {
          local_12e0 = &DAT_0010a0c0;
          local_12d0 = 1;
          uVar37 = CONCAT44(local_12c8._0_4_,local_12bc);
LAB_00103d40:
          do {
            psVar16 = DAT_0018a170;
            lVar27 = *local_12e0;
            if (DAT_0018a140 == 0) {
              local_1238 = CONCAT44(iVar12,local_12a0);
              uStack_1230 = uVar37;
              iVar6 = FUN_00105c60(local_12a8,lVar27,&local_c48);
              if (iVar6 != -1) {
LAB_0010423b:
                puVar33 = (undefined8 *)(ulong)DAT_0018a148;
                if (DAT_0018a148 == 0) {
                  if (DAT_0018a13c == 0) {
LAB_001043b8:
                    if (DAT_0018a18c == 0) goto LAB_001043c6;
                    goto LAB_00104c19;
                  }
                  if (DAT_0018a150 == 0) goto LAB_00104267;
LAB_00104387:
                  sVar24 = write(iVar6,&DAT_001074af,1);
                  if (sVar24 == 1) {
LAB_001047d4:
                    sVar24 = write(iVar6,&DAT_001074af,1);
                    if ((sVar24 == 1) || (piVar25 = __errno_location(), *piVar25 != 0x6f)) {
                      if (DAT_0010a014 == -1) {
                        puVar33 = (undefined8 *)0x3;
LAB_0010481d:
                        iVar7 = 0;
                        do {
                          sleep(1);
                          sVar24 = write(iVar6,&DAT_001074af,1);
                          if ((sVar24 != 1) && (piVar25 = __errno_location(), *piVar25 == 0x6f))
                          goto LAB_001043a5;
                          iVar7 = iVar7 + 1;
                        } while (iVar7 != (int)puVar33);
                      }
                      else if (999 < DAT_0010a014) {
                        puVar33 = (undefined8 *)((long)DAT_0010a014 / 1000 & 0xffffffff);
                        goto LAB_0010481d;
                      }
                      if (DAT_0018a150 == 0) goto LAB_00104267;
                      pcVar28 = "udp";
                      goto LAB_00104281;
                    }
                  }
LAB_001043a5:
                  local_12d0 = 1;
                }
                else {
                  if (DAT_0018a150 != 0) {
                    if ((DAT_0018a13c != 0) || (iVar7 = isatty(0), iVar7 != 0)) goto LAB_00104387;
                    goto LAB_001043b8;
                  }
LAB_00104267:
                  pcVar28 = "tcp";
                  if (DAT_0018a14c != 0) {
                    pcVar28 = "dccp";
                  }
LAB_00104281:
                  puVar33 = (undefined8 *)*local_12e0;
                  if (DAT_0018a178 == 0) {
                    uVar4 = __isoc23_strtol(puVar33,0,10);
                    psVar13 = getservbyport((uint)(ushort)(uVar4 << 8 | uVar4 >> 8),pcVar28);
                    if (psVar13 == (servent *)0x0) goto LAB_0010429b;
                    pcVar15 = psVar13->s_name;
                  }
                  else {
LAB_0010429b:
                    pcVar15 = "*";
                  }
                  __fprintf_chk(stderr,2,"Connection to %s",local_12a8);
                  if ((DAT_0018a178 == 0 && DAT_0018a140 == 0) &&
                     (iVar7 = strcmp((char *)local_12a8,(char *)&local_c48), iVar7 != 0)) {
                    __fprintf_chk(stderr,2," (%s)",&local_c48);
                  }
                  __fprintf_chk(stderr,2," %s port [%s/%s] succeeded!\n",puVar33,pcVar28,pcVar15);
                  if (DAT_0018a18c != 0) {
LAB_00104c19:
                    local_1289 = 0;
                    iVar12 = isatty(1);
                    if (iVar12 != 0) {
                    /* WARNING: Subroutine does not return */
                      errx(1,"Cannot pass file descriptor to tty");
                    }
                    local_1048.sa_family = 0x14;
                    local_1048.sa_data[0] = '\0';
                    local_1048.sa_data[1] = '\0';
                    local_1048.sa_data[2] = '\0';
                    local_1048.sa_data[3] = '\0';
                    local_1048.sa_data[4] = '\0';
                    local_1048.sa_data[5] = '\0';
                    pmVar31 = &local_1208;
                    for (lVar27 = 0xe; lVar27 != 0; lVar27 = lVar27 + -1) {
                      *(undefined4 *)&pmVar31->msg_name = 0;
                      pmVar31 = (msghdr *)((long)pmVar31 + (ulong)bVar36 * -8 + 4);
                    }
                    local_1208.msg_control = &local_1048;
                    local_1034 = 0;
                    local_1208.msg_controllen = 0x18;
                    local_1048.sa_data[6] = '\x01';
                    local_1048.sa_data[7] = '\0';
                    local_1048.sa_data[8] = '\0';
                    local_1048.sa_data[9] = '\0';
                    local_1048.sa_data[10] = '\x01';
                    local_1048.sa_data[0xb] = '\0';
                    local_1048.sa_data[0xc] = '\0';
                    local_1048.sa_data[0xd] = '\0';
                    local_1278.iov_base = &local_1289;
                    local_1208.msg_iov = &local_1278;
                    local_1278.iov_len = 1;
                    local_1208.msg_iovlen = 1;
                    local_1280.revents = 0;
                    local_1280.fd = 1;
                    local_1280.events = 4;
                    local_1038 = iVar6;
                    do {
                      sVar24 = sendmsg(1,&local_1208,0);
                      if (sVar24 != -1) {
                        if (sVar24 == 1) {
                    /* WARNING: Subroutine does not return */
                          exit(0);
                        }
LAB_00104e88:
                    /* WARNING: Subroutine does not return */
                        errx(1,"sendmsg: unexpected return value %zd",sVar24);
                      }
                      piVar25 = __errno_location();
                      if ((*piVar25 != 0xb) && (*piVar25 != 4)) {
                        err(1,"sendmsg");
LAB_00105081:
                        err(1,"listen");
LAB_00105094:
                    /* WARNING: Subroutine does not return */
                        errx(1,"garbage proxy port delimiter");
                      }
                      iVar6 = poll(&local_1280,1,-1);
                      if (iVar6 == -1) {
                        iVar6 = err(1,&DAT_001077ce);
LAB_00104d6b:
                        pcVar26 = gai_strerror(iVar6);
                    /* WARNING: Subroutine does not return */
                        errx(1,"getaddrinfo: %s",pcVar26);
                      }
                    } while( true );
                  }
                  if (DAT_0018a13c == 0) {
LAB_001043c6:
                    FUN_00106300(iVar6);
                  }
                  local_12d0 = 0;
                }
                local_12e0 = local_12e0 + 1;
                if (*local_12e0 == 0) goto LAB_0010366b;
                close(iVar6);
                goto LAB_00103d40;
              }
            }
            else {
              local_1268._0_4_ = local_12f8;
              local_1268._4_4_ = local_12f4;
              uStack_1260 = 0x600000001;
              local_1208.msg_name = (void *)CONCAT44(local_12f4,local_12f8);
              local_1208.msg_namelen = 1;
              local_1208._12_4_ = 6;
              local_1208.msg_iov = local_1258;
              local_1208.msg_iovlen = sStack_1250;
              local_1208.msg_control = local_1248;
              local_1208.msg_controllen = sStack_1240;
              local_12c8 = pcVar26;
              if ((pcVar26 == (char *)0x0) && (local_12c8 = "3128", local_12c0 != -1)) {
                local_12c8 = "1080";
              }
              local_11c8 = 0;
              local_11c6 = 0;
              local_11c4 = 0;
              iVar6 = FUN_001059d0("0.0.0.0",lVar27,&local_11c8,1,1);
              uVar3 = local_11c6;
              if (iVar6 == -1) {
                    /* WARNING: Subroutine does not return */
                errx(1,"unknown port \"%.64s\"",lVar27);
              }
              iVar7 = 1;
              while (iVar6 = FUN_00105c60(local_12b8,local_12c8,0), -1 < iVar6) {
                if (local_12c0 == 5) {
                  iVar7 = FUN_001059d0(local_12a8,lVar27,&local_11c8,0,1);
                  uVar8 = local_11c4;
                  uVar1 = local_11c6;
                  sVar5 = 0;
                  if (iVar7 != -1) {
                    sVar5 = local_11c8;
                  }
                  local_448 = CONCAT13(local_448._3_1_,0x105);
                  lVar21 = FUN_00105340(write,iVar6,&local_448,3);
                  if (lVar21 == 3) {
                    lVar21 = FUN_00105340(read,iVar6,&local_448,2);
                    if (lVar21 == 2) {
                      if (local_448._1_1_ == -1) {
                    /* WARNING: Subroutine does not return */
                        errx(1,"authentication method negotiation failed");
                      }
                      if (sVar5 == 2) {
                        lVar21 = 10;
                        local_448 = 0x1000105;
                        local_444 = CONCAT44(CONCAT22(local_444._6_2_,uVar1),uVar8);
                      }
                      else if (sVar5 == 10) {
                        local_444 = local_11c0;
                        lVar21 = 0x16;
                        local_448 = 0x4000105;
                        local_434 = uVar1;
                      }
                      else {
                        if (sVar5 != 0) {
                    /* WARNING: Subroutine does not return */
                          errx(1,"internal error: silly AF");
                        }
                        sVar17 = strlen((char *)local_12a8);
                        if (0xff < sVar17) goto LAB_0010518d;
                        local_448 = 0x3000105;
                        local_444 = CONCAT71(local_444._1_7_,(char)sVar17);
                        memcpy((void *)((long)&local_444 + 1),local_12a8,sVar17);
                        *(undefined2 *)((long)&local_444 + sVar17 + 1) = uVar3;
                        lVar21 = sVar17 + 7;
                      }
                      lVar23 = FUN_00105340(write,iVar6,&local_448,lVar21);
                      if (lVar21 != lVar23) goto LAB_00105174;
                      lVar21 = FUN_00105340(read,iVar6,&local_448,4);
                      if (lVar21 == 4) {
                        if (local_448._1_1_ == '\0') {
                          if (local_448._3_1_ == '\x01') {
                            lVar27 = FUN_00105340(read,iVar6,&local_444,6);
                            if (lVar27 == 6) goto LAB_0010423b;
                            err(1,"read failed (%zu/6)",lVar27);
                            goto LAB_001047d4;
                          }
                          if (local_448._3_1_ != '\x04') {
                    /* WARNING: Subroutine does not return */
                            errx(1,"connection failed, unsupported address type");
                          }
                          lVar21 = FUN_00105340(read,iVar6,&local_444,0x12);
                          if (lVar21 != 0x12) {
                            err(1,"read failed (%zu/18)",lVar21);
                            goto LAB_001046a8;
                          }
                          goto LAB_0010423b;
                        }
                        switch(local_448._1_1_) {
                        case '\x01':
                          pcVar26 = "General SOCKS server failure";
                          break;
                        case '\x02':
                          pcVar26 = "Connection not allowed by ruleset";
                          break;
                        case '\x03':
                          pcVar26 = "Network unreachable";
                          break;
                        case '\x04':
                          pcVar26 = "Host unreachable";
                          break;
                        case '\x05':
                          pcVar26 = "Connection refused";
                          break;
                        case '\x06':
                          pcVar26 = "TTL expired";
                          break;
                        case '\a':
                          pcVar26 = "Command not supported";
                          break;
                        case '\b':
                          pcVar26 = "Address type not supported";
                          break;
                        default:
                          goto switchD_001050f9_default;
                        }
                      }
                      else {
                        err(1,"read failed (%zu/4)",lVar21);
switchD_001050f9_default:
                        pcVar26 = "Unknown error";
                      }
                    /* WARNING: Subroutine does not return */
                      errx(1,"connection failed, SOCKSv5 error: %s",pcVar26);
                    }
                    lVar21 = err(1,"read failed (%zu/3)",lVar21);
                  }
                  err(1,"write failed (%zu/3)",lVar21);
                  goto LAB_00105022;
                }
                if ((0x200000000020U >> ((char)local_12c0 + 1U & 0x3f) & 1) != 0) {
LAB_001046a8:
                  if (local_12c0 == 4) {
                    lVar21 = 9;
                    FUN_001059d0(local_12a8,lVar27,&local_11c8,1,0);
                    local_448 = CONCAT22(local_11c6,0x104);
                    local_444 = CONCAT44((int)(local_444 >> 0x20),local_11c4) & 0xffffff00ffffffff;
                  }
                  else {
                    local_448 = CONCAT22(uVar3,0x104);
                    local_444 = CONCAT35(local_444._5_3_,0x1000000);
                    uVar22 = strlcpy((long)&local_444 + 5,local_12a8,0x3f7);
                    if (0x3f6 < uVar22) goto LAB_001050ce;
                    sVar17 = strlen((char *)local_12a8);
                    lVar21 = sVar17 + 10;
                  }
                  lVar23 = FUN_00105340(write,iVar6,&local_448,lVar21);
                  if (lVar21 != lVar23) {
LAB_00105174:
                    err(1,"write failed (%zu/%zu)",lVar23,lVar21);
LAB_0010518d:
                    /* WARNING: Subroutine does not return */
                    errx(1,"host name too long for SOCKS5");
                  }
                  lVar27 = FUN_00105340(read,iVar6,&local_448,8);
                  if (lVar27 != 8) {
                    err(1,"read failed (%zu/8)",lVar27);
LAB_001050ce:
                    /* WARNING: Subroutine does not return */
                    errx(1,"hostname too big");
                  }
                  if (local_448._1_1_ != 'Z') {
                    if (local_448._1_1_ == '\\') {
                      pcVar26 = "SOCKS server cannot connect to identd on the client";
                    }
                    else if (local_448._1_1_ == ']') {
                      pcVar26 = "Client program and identd report different user-ids";
                    }
                    else if (local_448._1_1_ == '[') {
                      pcVar26 = "Request rejected or failed";
                    }
                    else {
                      pcVar26 = "Unknown error";
                    }
                    /* WARNING: Subroutine does not return */
                    errx(1,"connection failed, SOCKSv4 error: %s",pcVar26);
                  }
                  goto LAB_0010423b;
                }
                sVar17 = strcspn((char *)local_12a8,"\r\n\t []");
                sVar18 = strlen((char *)local_12a8);
                if (sVar17 != sVar18) goto LAB_00104e0f;
                pcVar28 = strchr((char *)local_12a8,0x3a);
                if (pcVar28 == (char *)0x0) {
                  pcVar28 = "CONNECT %s:%d HTTP/1.0\r\n";
                }
                else {
                  pcVar28 = "CONNECT [%s]:%d HTTP/1.0\r\n";
                }
                uVar32 = __snprintf_chk(&local_448,0x400,2,0x400,pcVar28,local_12a8,
                                        CONCAT11((char)uVar3,(char)((ushort)uVar3 >> 8)));
                if (0x3ff < uVar32) {
                    /* WARNING: Subroutine does not return */
                  errx(1,"hostname too long");
                }
                puVar19 = (undefined8 *)strlen((char *)&local_448);
                puVar20 = (undefined8 *)FUN_00105340(write,iVar6,&local_448,puVar19);
                if (puVar19 != puVar20) {
LAB_00104f6c:
                  err(1,"write failed (%zu/%d)",puVar20,(ulong)puVar19 & 0xffffffff);
LAB_00104f82:
                    /* WARNING: Subroutine does not return */
                  errx(1,"Proxy auth response too long");
                }
                if (iVar7 != 1) {
                  pcVar28 = local_12b8;
                  __snprintf_chk(&local_1048,0x200,2,0x200,"Proxy password for %s@%s: ",psVar16);
                  auVar38 = readpassphrase(&local_1048,local_1148,0x100,2);
                  if (auVar38._0_8_ == 0) {
                    /* WARNING: Subroutine does not return */
                    errx(1,"Unable to read proxy passphrase",auVar38._8_8_,pcVar28);
                  }
                  uVar32 = __snprintf_chk(&local_448,0x400,2,0x400,"%s:%s",psVar16,local_1148);
                  __explicit_bzero_chk(local_1148,0x100,0x100);
                  uVar29 = 0x103f74;
                  if (0x3ff < uVar32) {
LAB_00104f95:
                    /* WARNING: Subroutine does not return */
                    errx(1,"Proxy username/password too long",uVar29);
                  }
                  sVar17 = strlen((char *)&local_448);
                  iVar9 = __b64_ntop(&local_448,sVar17,&local_1048,0x400);
                  uVar29 = extraout_RDX;
                  if (iVar9 == -1) goto LAB_00104f95;
                  iVar9 = __snprintf_chk(&local_448,0x400,2,0x400,
                                         "Proxy-Authorization: Basic %s\r\n",&local_1048);
                  if (0x3ff < iVar9) goto LAB_00104f82;
                  puVar33 = (undefined8 *)strlen((char *)&local_448);
                  puVar20 = (undefined8 *)FUN_00105340(write,iVar6,&local_448,puVar33);
                  puVar19 = puVar33;
                  if (puVar33 != puVar20) goto LAB_00104f6c;
                  __explicit_bzero_chk(local_1148,0x100,0x100);
                  __explicit_bzero_chk(&local_448,0x400,0x400);
                }
                lVar21 = FUN_00105340(write,iVar6,"\r\n");
                if (lVar21 != 2) {
                  puVar20 = (undefined8 *)err(1,"write failed (%zu/2)",lVar21);
                  puVar19 = puVar33;
                  goto LAB_00104f6c;
                }
                FUN_00105440(iVar6,&local_448);
                if ((psVar16 == (sockaddr *)0x0) ||
                   ((iVar9 = strncmp((char *)&local_448,"HTTP/1.0 407 ",0xd), iVar9 != 0 &&
                    (iVar9 = strncmp((char *)&local_448,"HTTP/1.1 407 ",0xd), iVar9 != 0)))) {
                  iVar7 = strncmp((char *)&local_448,"HTTP/1.0 200 ",0xd);
                  if ((iVar7 != 0) &&
                     (iVar7 = strncmp((char *)&local_448,"HTTP/1.1 200 ",0xd), iVar7 != 0)) {
                    /* WARNING: Subroutine does not return */
                    errx(1,"Proxy error: \"%s\"",&local_448);
                  }
                  iVar7 = 0x40;
                  while( true ) {
                    FUN_00105440();
                    if ((char)local_448 == '\0') break;
                    iVar7 = iVar7 + -1;
                    if (iVar7 == 0) {
                    /* WARNING: Subroutine does not return */
                      errx(1,"Too many proxy headers received");
                    }
                  }
                  goto LAB_0010423b;
                }
                if (iVar7 == 1) {
                  iVar7 = 2;
                  close(iVar6);
                }
                else {
                  iVar7 = iVar7 + 1;
                  fwrite("Proxy authentication failed\n",1,0x1c,stderr);
                  close(iVar6);
                  if (iVar7 == 5) {
                    /* WARNING: Subroutine does not return */
                    errx(1,"Too many authentication failures");
                  }
                }
              }
            }
            local_12e0 = local_12e0 + 1;
          } while (*local_12e0 != 0);
        }
      }
LAB_00103673:
      if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
        return local_12d0;
      }
LAB_00104d9e:
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    if (DAT_0018a168 != (sockaddr *)0x0) {
LAB_0010333c:
      FUN_001054d0(1);
      if (DAT_0018a19c != 1) {
LAB_00104b9e:
                    /* WARNING: Subroutine does not return */
        errx(1,"missing port number");
      }
      if (DAT_0018a14c != 0) {
LAB_00103776:
                    /* WARNING: Subroutine does not return */
        errx(1,"cannot use -Z and -U");
      }
      goto LAB_00103360;
    }
    local_12a8 = DAT_0018a158;
    if (DAT_0018a158 == (sockaddr *)0x0) {
      if (DAT_0018a19c != 1) {
        if ((DAT_0018a180 == 0) || (psVar16 = (sockaddr *)*param_2, psVar16 == (sockaddr *)0x0))
        goto LAB_00104b9e;
        goto LAB_001033fd;
      }
    }
    else if (((DAT_0018a19c != 1) || (DAT_0018a150 == 0)) || (DAT_0018a180 != 0)) goto LAB_0010333c;
    local_12a8 = (sockaddr *)*param_2;
    ppcVar34 = (char **)0x0;
    if (DAT_0018a14c != 0) goto LAB_00103776;
  }
  if (local_12a8 == (sockaddr *)0x0) {
LAB_00103360:
                    /* WARNING: Subroutine does not return */
    errx(1,"missing socket pathname");
  }
  if (DAT_0018a180 == 0) {
    if (DAT_0018a184 != 0) {
LAB_0010521c:
                    /* WARNING: Subroutine does not return */
      errx(1,"must use -l with -k");
    }
    if (DAT_0018a18c != 0) goto LAB_00104ecb;
    if (DAT_0018a150 == 0) {
      local_12f4 = 1;
      iVar6 = 0;
      if (DAT_0018a140 != 0) goto LAB_001037a5;
    }
    else {
      psVar16 = DAT_0018a158;
      if (DAT_0018a158 == (sockaddr *)0x0) {
        strlcpy(&local_1048,&DAT_001074a2,0x19);
        pcVar26 = mkdtemp((char *)&local_1048);
        if (pcVar26 == (char *)0x0) goto LAB_00104dfe;
        strlcat(&local_1048,"/recv.sock",0x19);
        psVar16 = &local_1048;
      }
      DAT_0018a0c0 = psVar16;
      if (DAT_0018a140 != 0) goto LAB_00104f07;
    }
    iVar6 = FUN_00105bb0(local_12a8,&local_c48,&local_1208);
    if (iVar6 == -1) {
LAB_00104db9:
      local_12d0 = 1;
      warn("%s",local_12a8);
    }
    else {
      if (DAT_0018a150 == 0) {
        iVar6 = socket(1,0x80001,0);
        if (iVar6 == -1) goto LAB_00104db9;
      }
      else {
        iVar6 = FUN_00106c20(DAT_0018a0c0,0x80000);
        if (iVar6 == -1) {
          err(1,"%s",DAT_0018a0c0);
LAB_00104dfe:
          err(1,"mkdtemp");
LAB_00104e0f:
                    /* WARNING: Subroutine does not return */
          errx(1,"Invalid hostname");
        }
      }
      iVar12 = connect(iVar6,&local_c48,(socklen_t)local_1208.msg_name);
      if (iVar12 == -1) {
        piVar25 = __errno_location();
        iVar12 = *piVar25;
        close(iVar6);
        *piVar25 = iVar12;
        goto LAB_00104db9;
      }
      if (iVar6 < 1) goto LAB_00104db9;
      if (DAT_0018a13c == 0) {
        FUN_00106300(iVar6);
      }
      close(iVar6);
      local_12d0 = 0;
    }
    psVar16 = DAT_0018a0c0;
    if ((DAT_0018a150 != 0) && (DAT_0018a158 == (sockaddr *)0x0)) {
      unlink((char *)DAT_0018a0c0);
      pcVar26 = strrchr((char *)psVar16,0x2f);
      if (pcVar26 != (char *)0x0) {
        *pcVar26 = '\0';
        rmdir((char *)psVar16);
      }
    }
    goto LAB_00103673;
  }
  if (DAT_0018a13c != 0) {
LAB_0010340a:
                    /* WARNING: Subroutine does not return */
    errx(1,"cannot use -z and -l");
  }
  if (DAT_0018a18c != 0) {
LAB_00104ecb:
                    /* WARNING: Subroutine does not return */
    errx(1,"cannot use -F and -U");
  }
  if (DAT_0018a140 != 0) {
    local_12f4 = 1;
    iVar6 = DAT_0018a180;
    goto LAB_00103798;
  }
  if (DAT_0018a150 != 0) {
    iVar6 = FUN_00106c20(local_12a8,0);
    goto LAB_0010350e;
  }
  iVar6 = FUN_00106c20(local_12a8,0);
  if (iVar6 != -1) {
    iVar12 = listen(iVar6,5);
    if (iVar12 != -1) {
      if (DAT_0018a148 != 0) {
        FUN_00106b00("Listening",0,0,local_12a8);
      }
      goto LAB_0010350e;
    }
    close(iVar6);
  }
  goto LAB_00104d90;
switchD_00102b2a_caseD_78:
  DAT_0018a140 = 1;
  local_12b8 = strdup((char *)optarg);
  if (local_12b8 == (char *)0x0) goto LAB_00104d90;
  goto LAB_00102b00;
}

/* ===== 0x102020  FUN_00102020 ===== */
void FUN_00102020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}

/* ===== 0x102840  FUN_00102840 ===== */
void FUN_00102840(void)

{
  err(1,"proxy read");
                    /* WARNING: Subroutine does not return */
  errx(1,"proxy read too long");
}

/* ===== 0x102866  FUN_00102866 ===== */
void FUN_00102866(void)

{
                    /* WARNING: Subroutine does not return */
  errx(1,"service \"%s\" unknown");
}

/* ===== 0x102895  FUN_00102895 ===== */
int FUN_00102895(void)

{
  ulong *puVar1;
  char *__service;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  char *pcVar6;
  long lVar7;
  int unaff_EBX;
  long unaff_RBP;
  undefined8 *puVar8;
  timeval *__timeout;
  undefined *puVar9;
  socklen_t unaff_R14D;
  long unaff_R15;
  addrinfo *__ai;
  long in_FS_OFFSET;
  byte bVar10;
  
  bVar10 = 0;
  err(1,0);
  err(1,"set TCP send buffer size");
  err(1,"set TCP receive buffer size");
  err(1,"set IP TTL");
  err(1,"set IP ToS");
  err(1,"set IPv6 traffic class");
  err(1,"set IPv6 min hop count");
  err(1,"set IPv6 unicast hops");
  err(1,"set IP min TTL");
FUN_0010293b:
  warn("can\'t set O_NONBLOCK - timeout not available");
  iVar2 = connect(unaff_EBX,*(sockaddr **)(unaff_RBP + -0x118),unaff_R14D);
LAB_00105e70:
  if (iVar2 == 0) {
    __ai = *(addrinfo **)(unaff_RBP + -0x100);
LAB_0010602f:
    freeaddrinfo(__ai);
    if (*(long *)(unaff_RBP + -0x38) != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return unaff_EBX;
  }
LAB_00105e79:
  puVar9 = &DAT_00107023;
  if ((DAT_0018a150 == 0) && (puVar9 = &DAT_00107027, DAT_0018a14c != 0)) {
    puVar9 = &DAT_001070f1;
  }
  if (DAT_0018a148 != 0) {
    if (((DAT_0018a178 == 0) && (*(char **)(unaff_RBP + -0x128) != (char *)0x0)) &&
       (iVar2 = strncmp(*(char **)(unaff_RBP + -0x130),*(char **)(unaff_RBP + -0x128),0x401),
       iVar2 != 0)) goto LAB_001029f3;
    warn("connect to %s port %s (%s) %s",*(undefined8 *)(unaff_RBP + -0x130),
         *(undefined8 *)(unaff_RBP + -0x138),puVar9);
  }
  do {
    piVar5 = __errno_location();
    iVar2 = *piVar5;
    close(unaff_EBX);
    *piVar5 = iVar2;
    do {
      unaff_R15 = *(long *)(unaff_R15 + 0x28);
      if (unaff_R15 == 0) {
        __ai = *(addrinfo **)(unaff_RBP + -0x100);
        unaff_EBX = -1;
        goto LAB_0010602f;
      }
      unaff_EBX = socket(*(int *)(unaff_R15 + 4),*(uint *)(unaff_R15 + 8) | 0x800,
                         *(int *)(unaff_R15 + 0xc));
      __service = DAT_0018a168;
      pcVar6 = DAT_0018a158;
      iVar2 = DAT_0018a150;
    } while (unaff_EBX == -1);
    if ((DAT_0018a158 == (char *)0x0) && (DAT_0018a168 == (char *)0x0)) {
LAB_00105d58:
      FUN_001055b0(unaff_EBX,*(undefined8 *)(unaff_R15 + 0x18));
      if (*(char **)(unaff_RBP + -0x128) == (char *)0x0) goto LAB_00105da1;
      iVar2 = getnameinfo(*(sockaddr **)(unaff_R15 + 0x18),*(socklen_t *)(unaff_R15 + 0x10),
                          *(char **)(unaff_RBP + -0x128),0x401,(char *)0x0,0,1);
      if (iVar2 != -0xb) break;
      err(1,"getnameinfo");
    }
    else {
      *(undefined1 (*) [16])(unaff_RBP + -0xf0) = (undefined1  [16])0x0;
      *(undefined1 (*) [16])(unaff_RBP + -0xe0) = (undefined1  [16])0x0;
      *(undefined1 (*) [16])(unaff_RBP + -0xd0) = (undefined1  [16])0x0;
      *(undefined4 *)(unaff_RBP + -0xec) = *(undefined4 *)(unaff_R15 + 4);
      if (iVar2 == 0) {
        if (DAT_0018a14c == 0) {
          *(undefined8 *)(unaff_RBP + -0xe8) = 0x600000001;
        }
        else {
          *(undefined8 *)(unaff_RBP + 0x18) = 0x2100000006;
        }
      }
      else {
        *(undefined8 *)(unaff_RBP + -0xe8) = 0x1100000002;
      }
      *(undefined4 *)(unaff_RBP + -0xf0) = 1;
      iVar2 = getaddrinfo(pcVar6,__service,(addrinfo *)(unaff_RBP + -0xf0),
                          (addrinfo **)(unaff_RBP + -0xf8));
      if (iVar2 != 0) {
        pcVar6 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
        errx(1,"getaddrinfo: %s",pcVar6);
      }
      iVar2 = bind(unaff_EBX,*(sockaddr **)(*(long *)(unaff_RBP + -0xf8) + 0x18),
                   *(socklen_t *)(*(long *)(unaff_RBP + -0xf8) + 0x10));
      if (iVar2 != -1) {
        freeaddrinfo(*(addrinfo **)(unaff_RBP + -0xf8));
        goto LAB_00105d58;
      }
    }
    err(1,"bind failed");
LAB_001029f3:
    warn("connect to %s (%s) port %s (%s) %s",*(undefined8 *)(unaff_RBP + -0x130),
         *(undefined8 *)(unaff_RBP + -0x128),*(undefined8 *)(unaff_RBP + -0x138));
  } while( true );
  if (iVar2 != 0) {
    pcVar6 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
    errx(1,"getnameinfo: %s",pcVar6);
  }
LAB_00105da1:
  iVar2 = DAT_0010a014;
  unaff_R14D = *(socklen_t *)(unaff_R15 + 0x10);
  *(undefined8 *)(unaff_RBP + -0x118) = *(undefined8 *)(unaff_R15 + 0x18);
  uVar3 = fcntl(unaff_EBX,3,0);
  *(uint *)(unaff_RBP + -0x11c) = uVar3;
  iVar4 = fcntl(unaff_EBX,4,(ulong)uVar3 | 0x800);
  if (iVar4 < 0) goto FUN_0010293b;
  __timeout = (timeval *)0x0;
  if (0 < iVar2) {
    *(undefined8 *)(unaff_RBP + -0xe8) = 0;
    __timeout = (timeval *)(unaff_RBP + -0xf0);
    *(long *)(unaff_RBP + -0xf0) = (long)(iVar2 / 1000);
  }
  iVar2 = connect(unaff_EBX,*(sockaddr **)(unaff_RBP + -0x118),unaff_R14D);
  *(int *)(unaff_RBP + -0x104) = iVar2;
  if ((iVar2 == 0) || (piVar5 = __errno_location(), *piVar5 != 0x73)) goto LAB_00105e4d;
  puVar8 = (undefined8 *)(unaff_RBP + -0xc0);
  for (lVar7 = 0x10; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + (ulong)bVar10 * -2 + 1;
  }
  lVar7 = __fdelt_chk((long)unaff_EBX);
  *(long *)(unaff_RBP + -0x118) = unaff_R15;
  puVar1 = (ulong *)(unaff_RBP + -0xc0 + lVar7 * 8);
  *puVar1 = *puVar1 | 1L << ((byte)unaff_EBX & 0x3f);
  while( true ) {
    iVar2 = select(unaff_EBX + 1,(fd_set *)0x0,(fd_set *)(unaff_RBP + -0xc0),(fd_set *)0x0,__timeout
                  );
    *(int *)(unaff_RBP + -0x104) = iVar2;
    if (-1 < iVar2) break;
    if (*piVar5 != 4) {
      pcVar6 = strerror(*piVar5);
                    /* WARNING: Subroutine does not return */
      errx(1,"select error: %s",pcVar6);
    }
  }
  unaff_R15 = *(long *)(unaff_RBP + -0x118);
  if (iVar2 != 0) goto code_r0x00105fb6;
  goto LAB_00105e79;
code_r0x00105fb6:
  *(undefined4 *)(unaff_RBP + -0xf8) = 4;
  iVar2 = getsockopt(unaff_EBX,1,4,(void *)(unaff_RBP + -0x104),(socklen_t *)(unaff_RBP + -0xf8));
  if (iVar2 < 0) {
    pcVar6 = strerror(*piVar5);
                    /* WARNING: Subroutine does not return */
    errx(1,"getsockopt error: %s",pcVar6);
  }
  if (*(int *)(unaff_RBP + -0x104) != 0) {
    *piVar5 = *(int *)(unaff_RBP + -0x104);
  }
LAB_00105e4d:
  fcntl(unaff_EBX,4,(ulong)*(uint *)(unaff_RBP + -0x11c));
  iVar2 = *(int *)(unaff_RBP + -0x104);
  goto LAB_00105e70;
}

/* ===== 0x10293b  FUN_0010293b ===== */
int FUN_0010293b(void)

{
  ulong *puVar1;
  char *__service;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  char *pcVar6;
  long lVar7;
  int unaff_EBX;
  long unaff_RBP;
  undefined8 *puVar8;
  timeval *__timeout;
  undefined *puVar9;
  socklen_t unaff_R14D;
  long unaff_R15;
  addrinfo *__ai;
  long in_FS_OFFSET;
  byte bVar10;
  
  bVar10 = 0;
code_r0x0010293b:
  warn("can\'t set O_NONBLOCK - timeout not available");
  iVar2 = connect(unaff_EBX,*(sockaddr **)(unaff_RBP + -0x118),unaff_R14D);
LAB_00105e70:
  if (iVar2 == 0) {
    __ai = *(addrinfo **)(unaff_RBP + -0x100);
LAB_0010602f:
    freeaddrinfo(__ai);
    if (*(long *)(unaff_RBP + -0x38) != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return unaff_EBX;
  }
LAB_00105e79:
  puVar9 = &DAT_00107023;
  if ((DAT_0018a150 == 0) && (puVar9 = &DAT_00107027, DAT_0018a14c != 0)) {
    puVar9 = &DAT_001070f1;
  }
  if (DAT_0018a148 != 0) {
    if (((DAT_0018a178 == 0) && (*(char **)(unaff_RBP + -0x128) != (char *)0x0)) &&
       (iVar2 = strncmp(*(char **)(unaff_RBP + -0x130),*(char **)(unaff_RBP + -0x128),0x401),
       iVar2 != 0)) goto LAB_001029f3;
    warn("connect to %s port %s (%s) %s",*(undefined8 *)(unaff_RBP + -0x130),
         *(undefined8 *)(unaff_RBP + -0x138),puVar9);
  }
  do {
    piVar5 = __errno_location();
    iVar2 = *piVar5;
    close(unaff_EBX);
    *piVar5 = iVar2;
    do {
      unaff_R15 = *(long *)(unaff_R15 + 0x28);
      if (unaff_R15 == 0) {
        __ai = *(addrinfo **)(unaff_RBP + -0x100);
        unaff_EBX = -1;
        goto LAB_0010602f;
      }
      unaff_EBX = socket(*(int *)(unaff_R15 + 4),*(uint *)(unaff_R15 + 8) | 0x800,
                         *(int *)(unaff_R15 + 0xc));
      __service = DAT_0018a168;
      pcVar6 = DAT_0018a158;
      iVar2 = DAT_0018a150;
    } while (unaff_EBX == -1);
    if ((DAT_0018a158 == (char *)0x0) && (DAT_0018a168 == (char *)0x0)) {
LAB_00105d58:
      FUN_001055b0(unaff_EBX,*(undefined8 *)(unaff_R15 + 0x18));
      if (*(char **)(unaff_RBP + -0x128) == (char *)0x0) goto LAB_00105da1;
      iVar2 = getnameinfo(*(sockaddr **)(unaff_R15 + 0x18),*(socklen_t *)(unaff_R15 + 0x10),
                          *(char **)(unaff_RBP + -0x128),0x401,(char *)0x0,0,1);
      if (iVar2 != -0xb) break;
      err(1,"getnameinfo");
    }
    else {
      *(undefined1 (*) [16])(unaff_RBP + -0xf0) = (undefined1  [16])0x0;
      *(undefined1 (*) [16])(unaff_RBP + -0xe0) = (undefined1  [16])0x0;
      *(undefined1 (*) [16])(unaff_RBP + -0xd0) = (undefined1  [16])0x0;
      *(undefined4 *)(unaff_RBP + -0xec) = *(undefined4 *)(unaff_R15 + 4);
      if (iVar2 == 0) {
        if (DAT_0018a14c == 0) {
          *(undefined8 *)(unaff_RBP + -0xe8) = 0x600000001;
        }
        else {
          *(undefined8 *)(unaff_RBP + 0x18) = 0x2100000006;
        }
      }
      else {
        *(undefined8 *)(unaff_RBP + -0xe8) = 0x1100000002;
      }
      *(undefined4 *)(unaff_RBP + -0xf0) = 1;
      iVar2 = getaddrinfo(pcVar6,__service,(addrinfo *)(unaff_RBP + -0xf0),
                          (addrinfo **)(unaff_RBP + -0xf8));
      if (iVar2 != 0) {
        pcVar6 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
        errx(1,"getaddrinfo: %s",pcVar6);
      }
      iVar2 = bind(unaff_EBX,*(sockaddr **)(*(long *)(unaff_RBP + -0xf8) + 0x18),
                   *(socklen_t *)(*(long *)(unaff_RBP + -0xf8) + 0x10));
      if (iVar2 != -1) {
        freeaddrinfo(*(addrinfo **)(unaff_RBP + -0xf8));
        goto LAB_00105d58;
      }
    }
    err(1,"bind failed");
LAB_001029f3:
    warn("connect to %s (%s) port %s (%s) %s",*(undefined8 *)(unaff_RBP + -0x130),
         *(undefined8 *)(unaff_RBP + -0x128),*(undefined8 *)(unaff_RBP + -0x138));
  } while( true );
  if (iVar2 != 0) {
    pcVar6 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
    errx(1,"getnameinfo: %s",pcVar6);
  }
LAB_00105da1:
  iVar2 = DAT_0010a014;
  unaff_R14D = *(socklen_t *)(unaff_R15 + 0x10);
  *(undefined8 *)(unaff_RBP + -0x118) = *(undefined8 *)(unaff_R15 + 0x18);
  uVar3 = fcntl(unaff_EBX,3,0);
  *(uint *)(unaff_RBP + -0x11c) = uVar3;
  iVar4 = fcntl(unaff_EBX,4,(ulong)uVar3 | 0x800);
  if (iVar4 < 0) goto code_r0x0010293b;
  __timeout = (timeval *)0x0;
  if (0 < iVar2) {
    *(undefined8 *)(unaff_RBP + -0xe8) = 0;
    __timeout = (timeval *)(unaff_RBP + -0xf0);
    *(long *)(unaff_RBP + -0xf0) = (long)(iVar2 / 1000);
  }
  iVar2 = connect(unaff_EBX,*(sockaddr **)(unaff_RBP + -0x118),unaff_R14D);
  *(int *)(unaff_RBP + -0x104) = iVar2;
  if ((iVar2 == 0) || (piVar5 = __errno_location(), *piVar5 != 0x73)) goto LAB_00105e4d;
  puVar8 = (undefined8 *)(unaff_RBP + -0xc0);
  for (lVar7 = 0x10; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + (ulong)bVar10 * -2 + 1;
  }
  lVar7 = __fdelt_chk((long)unaff_EBX);
  *(long *)(unaff_RBP + -0x118) = unaff_R15;
  puVar1 = (ulong *)(unaff_RBP + -0xc0 + lVar7 * 8);
  *puVar1 = *puVar1 | 1L << ((byte)unaff_EBX & 0x3f);
  while( true ) {
    iVar2 = select(unaff_EBX + 1,(fd_set *)0x0,(fd_set *)(unaff_RBP + -0xc0),(fd_set *)0x0,__timeout
                  );
    *(int *)(unaff_RBP + -0x104) = iVar2;
    if (-1 < iVar2) break;
    if (*piVar5 != 4) {
      pcVar6 = strerror(*piVar5);
                    /* WARNING: Subroutine does not return */
      errx(1,"select error: %s",pcVar6);
    }
  }
  unaff_R15 = *(long *)(unaff_RBP + -0x118);
  if (iVar2 != 0) goto code_r0x00105fb6;
  goto LAB_00105e79;
code_r0x00105fb6:
  *(undefined4 *)(unaff_RBP + -0xf8) = 4;
  iVar2 = getsockopt(unaff_EBX,1,4,(void *)(unaff_RBP + -0x104),(socklen_t *)(unaff_RBP + -0xf8));
  if (iVar2 < 0) {
    pcVar6 = strerror(*piVar5);
                    /* WARNING: Subroutine does not return */
    errx(1,"getsockopt error: %s",pcVar6);
  }
  if (*(int *)(unaff_RBP + -0x104) != 0) {
    *piVar5 = *(int *)(unaff_RBP + -0x104);
  }
LAB_00105e4d:
  fcntl(unaff_EBX,4,(ulong)*(uint *)(unaff_RBP + -0x11c));
  iVar2 = *(int *)(unaff_RBP + -0x104);
  goto LAB_00105e70;
}

/* ===== 0x102a32  FUN_00102a32 ===== */
void FUN_00102a32(void)

{
  char cVar1;
  ulong uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  long lVar6;
  char *pcVar7;
  undefined1 uVar8;
  uint __fd;
  long unaff_RBP;
  int unaff_R12D;
  int unaff_R13D;
  char *unaff_R14;
  char *pcVar9;
  char *unaff_R15;
  long in_FS_OFFSET;
  
  err(1,"write failed (%zu/2)");
FUN_00102a48:
  err(1);
  do {
    warn("Write Error!");
    pcVar9 = unaff_R14;
LAB_00106a2d:
    do {
      do {
        pcVar7 = unaff_R14 + 1;
        if (unaff_R15 <= pcVar7) {
LAB_0010657e:
          if ((*(byte *)(unaff_RBP + -0x8052) & 4) != 0) goto LAB_00106660;
LAB_0010658b:
          if (*(int *)(unaff_RBP + -0x8070) == -1) goto LAB_001066c0;
LAB_00106598:
          __fd = *(uint *)(unaff_RBP + -0x8060);
          if (__fd == 0xffffffff) goto LAB_00106788;
LAB_001065a7:
          if (((((*(uint *)(unaff_RBP + -0x8070) & __fd) == 0xffffffff) &&
               (*(long *)(unaff_RBP + -0x8080) == 0 && *(long *)(unaff_RBP + -0x8078) == 0)) ||
              ((*(uint *)(unaff_RBP + -0x8068) & *(uint *)(unaff_RBP + -0x8058)) == 0xffffffff)) ||
             (((DAT_0018a180 != 0 && (__fd == 0xffffffff)) &&
              (*(long *)(unaff_RBP + -0x8080) == 0 && *(long *)(unaff_RBP + -0x8078) == 0)))) {
            if ((int)DAT_0010a018 < 1) goto LAB_0010692a;
            close(unaff_R12D);
            signal(0xe,FUN_00105330);
            alarm(DAT_0010a018);
          }
          iVar3 = poll((pollfd *)(unaff_RBP + -0x8070),4,DAT_0010a014);
          unaff_R14 = pcVar9;
          if (iVar3 == -1) goto FUN_00102a48;
          if (iVar3 == 0) {
LAB_0010692a:
            if (*(long *)(unaff_RBP + -0x38) == *(long *)(in_FS_OFFSET + 0x28)) {
              return;
            }
                    /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          puVar5 = (undefined4 *)(unaff_RBP + -0x8070);
          do {
            if ((*(byte *)((long)puVar5 + 6) & 0x28) != 0) {
              *puVar5 = 0xffffffff;
            }
            puVar5 = puVar5 + 2;
          } while (puVar5 != (undefined4 *)(unaff_RBP + -0x8050));
          if ((*(uint *)(unaff_RBP + -0x806c) & 0x110001) == 0x100001) {
            *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
          }
          if ((*(uint *)(unaff_RBP + -0x805c) & 0x110001) == 0x100001) {
            *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
          }
          iVar3 = *(int *)(unaff_RBP + -0x8068);
          if ((*(byte *)(unaff_RBP + -0x8062) & 0x10) == 0) {
            if ((*(byte *)(unaff_RBP + -0x8052) & 0x10) == 0) {
              iVar4 = *(int *)(unaff_RBP + -0x8058);
              if (iVar3 == -1) goto LAB_001067a6;
              goto LAB_00106774;
            }
            *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
            if (iVar3 == -1) {
              *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
            }
LAB_001064b0:
            if (*(int *)(unaff_RBP + -0x8060) != -1) {
              shutdown(*(int *)(unaff_RBP + -0x8060),0);
            }
            *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
          }
          else {
            if ((iVar3 != -1) && (DAT_0018a17c != 0)) {
              shutdown(iVar3,1);
            }
            *(undefined4 *)(unaff_RBP + -0x8068) = 0xffffffff;
            if ((*(byte *)(unaff_RBP + -0x8052) & 0x10) != 0) {
              *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
              *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
              goto LAB_001064b0;
            }
            iVar4 = *(int *)(unaff_RBP + -0x8058);
LAB_001067a6:
            *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
LAB_00106774:
            if (iVar4 == -1) goto LAB_001064b0;
          }
          if ((*(byte *)(unaff_RBP + -0x806a) & 1) == 0) {
            if ((*(byte *)(unaff_RBP + -0x8062) & 4) == 0) goto LAB_00106560;
            if (*(long *)(unaff_RBP + -0x8080) != 0) goto LAB_001064f3;
            if ((*(byte *)(unaff_RBP + -0x805a) & 1) == 0) goto LAB_00106638;
LAB_0010656d:
            if (0x3fff < *(ulong *)(unaff_RBP + -0x8078)) goto LAB_0010657e;
            pcVar7 = (char *)(unaff_RBP - 0x4040);
            lVar6 = FUN_00105b40(*(undefined4 *)(unaff_RBP + -0x8060),pcVar7,unaff_RBP + -0x8078);
            if (lVar6 == -1) {
LAB_00106aa7:
              *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
              unaff_R13D = -1;
            }
            else {
              unaff_R13D = *(int *)(unaff_RBP + -0x8060);
              if (lVar6 == 0) {
                shutdown(unaff_R13D,0);
                goto LAB_00106aa7;
              }
            }
            if ((DAT_0018a144 < 1) || (DAT_0010a0a0 = DAT_0010a0a0 + 1, DAT_0010a0a0 < DAT_0018a144)
               ) {
              uVar2 = *(ulong *)(unaff_RBP + -0x8078);
              if (uVar2 == 0) goto LAB_0010658b;
              *(undefined2 *)(unaff_RBP + -0x8054) = 4;
              if (uVar2 == 0x4000) {
                *(undefined2 *)(unaff_RBP + -0x805c) = 0;
                if ((unaff_R13D == -1) || (DAT_0018a154 == 0)) goto LAB_0010657e;
                unaff_R15 = (char *)(unaff_RBP - 0x42);
              }
              else if ((((unaff_R13D == -1) || (DAT_0018a154 == 0)) || ((uint)uVar2 < 3)) ||
                      (unaff_R15 = (char *)(unaff_RBP + -0x4042 + (uVar2 & 0xffffffff)),
                      unaff_R15 <= pcVar7)) goto LAB_0010657e;
              goto LAB_00106a3a;
            }
            if (unaff_R13D != -1) {
              shutdown(unaff_R13D,0);
            }
            *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
            *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
            if (*(long *)(unaff_RBP + -0x8078) != 0) {
              *(undefined2 *)(unaff_RBP + -0x8054) = 4;
              if (*(long *)(unaff_RBP + -0x8078) == 0x4000) {
                *(undefined2 *)(unaff_RBP + -0x805c) = 0;
              }
              goto LAB_0010657e;
            }
          }
          else {
            if (*(ulong *)(unaff_RBP + -0x8080) < 0x4000) {
              lVar6 = FUN_00105b40(*(undefined4 *)(unaff_RBP + -0x8070),unaff_RBP + -0x8040,
                                   unaff_RBP + -0x8080);
              if (lVar6 + 1U < 2) {
                *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
              }
              if (*(long *)(unaff_RBP + -0x8080) == 0) goto LAB_00106560;
              *(undefined2 *)(unaff_RBP + -0x8064) = 4;
              if (*(long *)(unaff_RBP + -0x8080) == 0x4000) {
                unaff_R15 = (char *)0x0;
                *(undefined2 *)(unaff_RBP + -0x806c) = 0;
              }
            }
            if ((*(byte *)(unaff_RBP + -0x8062) & 4) != 0) {
LAB_001064f3:
              lVar6 = FUN_00106120(*(undefined4 *)(unaff_RBP + -0x8068),unaff_RBP + -0x8040,
                                   unaff_RBP + -0x8080,DAT_0018a194 != 0 || DAT_0018a188 != 0);
              if (lVar6 == -1) {
                *(undefined4 *)(unaff_RBP + -0x8068) = 0xffffffff;
              }
              if (*(ulong *)(unaff_RBP + -0x8080) == 0) {
                pcVar9 = (char *)0x0;
                *(undefined2 *)(unaff_RBP + -0x8064) = 0;
              }
              else if (0x3fff < *(ulong *)(unaff_RBP + -0x8080)) goto LAB_00106560;
              unaff_R13D = 1;
              *(undefined2 *)(unaff_RBP + -0x806c) = 1;
            }
LAB_00106560:
            if ((*(byte *)(unaff_RBP + -0x805a) & 1) != 0) goto LAB_0010656d;
LAB_00106638:
            if (((*(byte *)(unaff_RBP + -0x8052) & 4) == 0) || (*(long *)(unaff_RBP + -0x8078) == 0)
               ) goto LAB_0010658b;
LAB_00106660:
            lVar6 = FUN_00106120(*(undefined4 *)(unaff_RBP + -0x8058),unaff_RBP + -0x4040,
                                 unaff_RBP + -0x8078,0);
            if (lVar6 == -1) {
              *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
            }
            if (*(ulong *)(unaff_RBP + -0x8078) == 0) {
              *(undefined2 *)(unaff_RBP + -0x8054) = 0;
            }
            else if (0x3fff < *(ulong *)(unaff_RBP + -0x8078)) goto LAB_0010658b;
            *(undefined2 *)(unaff_RBP + -0x805c) = 1;
            if (*(int *)(unaff_RBP + -0x8070) != -1) goto LAB_00106598;
          }
LAB_001066c0:
          if (*(long *)(unaff_RBP + -0x8080) == 0) {
            if ((*(int *)(unaff_RBP + -0x8068) != -1) && (DAT_0018a17c != 0)) {
              shutdown(*(int *)(unaff_RBP + -0x8068),1);
            }
            *(undefined4 *)(unaff_RBP + -0x8068) = 0xffffffff;
            if (DAT_0018a180 != 0 || DAT_0018a150 != 0) {
              __fd = *(uint *)(unaff_RBP + -0x8060);
              if (__fd != 0xffffffff) goto code_r0x00106710;
LAB_00106788:
              if (*(long *)(unaff_RBP + -0x8078) == 0) goto LAB_00106750;
              goto LAB_00106794;
            }
          }
          goto LAB_00106598;
        }
LAB_00106a3a:
        unaff_R14 = pcVar7;
      } while (*pcVar7 != -1);
      cVar1 = pcVar7[1];
      *(undefined1 *)(unaff_RBP + -0x8044) = 0xff;
      if ((byte)(cVar1 + 5U) < 2) {
        uVar8 = 0xfe;
      }
      else {
        uVar8 = 0xfc;
        if (1 < (byte)(cVar1 + 3U)) {
          unaff_R14 = pcVar7 + 1;
          goto LAB_00106a2d;
        }
      }
      unaff_R14 = pcVar7 + 2;
      cVar1 = pcVar7[2];
      *(undefined1 *)(unaff_RBP + -0x8043) = uVar8;
      *(char *)(unaff_RBP + -0x8042) = cVar1;
      lVar6 = FUN_00105340(write,unaff_R13D,unaff_RBP + -0x8044);
      pcVar9 = unaff_R14;
    } while (lVar6 == 3);
  } while( true );
code_r0x00106710:
  if ((-1 < (int)DAT_0010a018) && (*(long *)(unaff_RBP + -0x8078) == 0)) {
    shutdown(__fd,0);
    *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
    DAT_0018a184 = 0;
LAB_00106750:
    *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
LAB_00106794:
    __fd = 0xffffffff;
  }
  goto LAB_001065a7;
}

/* ===== 0x102a48  FUN_00102a48 ===== */
void FUN_00102a48(void)

{
  char cVar1;
  ulong uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  long lVar6;
  char *pcVar7;
  undefined1 uVar8;
  uint __fd;
  long unaff_RBP;
  int unaff_R12D;
  int unaff_R13D;
  char *unaff_R14;
  char *pcVar9;
  char *unaff_R15;
  long in_FS_OFFSET;
  
code_r0x00102a48:
  err(1);
  do {
    warn("Write Error!");
    pcVar9 = unaff_R14;
LAB_00106a2d:
    do {
      do {
        pcVar7 = unaff_R14 + 1;
        if (unaff_R15 <= pcVar7) {
LAB_0010657e:
          if ((*(byte *)(unaff_RBP + -0x8052) & 4) != 0) goto LAB_00106660;
LAB_0010658b:
          if (*(int *)(unaff_RBP + -0x8070) == -1) goto LAB_001066c0;
LAB_00106598:
          __fd = *(uint *)(unaff_RBP + -0x8060);
          if (__fd == 0xffffffff) goto LAB_00106788;
LAB_001065a7:
          if (((((*(uint *)(unaff_RBP + -0x8070) & __fd) == 0xffffffff) &&
               (*(long *)(unaff_RBP + -0x8080) == 0 && *(long *)(unaff_RBP + -0x8078) == 0)) ||
              ((*(uint *)(unaff_RBP + -0x8068) & *(uint *)(unaff_RBP + -0x8058)) == 0xffffffff)) ||
             (((DAT_0018a180 != 0 && (__fd == 0xffffffff)) &&
              (*(long *)(unaff_RBP + -0x8080) == 0 && *(long *)(unaff_RBP + -0x8078) == 0)))) {
            if ((int)DAT_0010a018 < 1) goto LAB_0010692a;
            close(unaff_R12D);
            signal(0xe,FUN_00105330);
            alarm(DAT_0010a018);
          }
          iVar3 = poll((pollfd *)(unaff_RBP + -0x8070),4,DAT_0010a014);
          unaff_R14 = pcVar9;
          if (iVar3 == -1) goto code_r0x00102a48;
          if (iVar3 == 0) {
LAB_0010692a:
            if (*(long *)(unaff_RBP + -0x38) == *(long *)(in_FS_OFFSET + 0x28)) {
              return;
            }
                    /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          puVar5 = (undefined4 *)(unaff_RBP + -0x8070);
          do {
            if ((*(byte *)((long)puVar5 + 6) & 0x28) != 0) {
              *puVar5 = 0xffffffff;
            }
            puVar5 = puVar5 + 2;
          } while (puVar5 != (undefined4 *)(unaff_RBP + -0x8050));
          if ((*(uint *)(unaff_RBP + -0x806c) & 0x110001) == 0x100001) {
            *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
          }
          if ((*(uint *)(unaff_RBP + -0x805c) & 0x110001) == 0x100001) {
            *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
          }
          iVar3 = *(int *)(unaff_RBP + -0x8068);
          if ((*(byte *)(unaff_RBP + -0x8062) & 0x10) == 0) {
            if ((*(byte *)(unaff_RBP + -0x8052) & 0x10) == 0) {
              iVar4 = *(int *)(unaff_RBP + -0x8058);
              if (iVar3 == -1) goto LAB_001067a6;
              goto LAB_00106774;
            }
            *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
            if (iVar3 == -1) {
              *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
            }
LAB_001064b0:
            if (*(int *)(unaff_RBP + -0x8060) != -1) {
              shutdown(*(int *)(unaff_RBP + -0x8060),0);
            }
            *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
          }
          else {
            if ((iVar3 != -1) && (DAT_0018a17c != 0)) {
              shutdown(iVar3,1);
            }
            *(undefined4 *)(unaff_RBP + -0x8068) = 0xffffffff;
            if ((*(byte *)(unaff_RBP + -0x8052) & 0x10) != 0) {
              *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
              *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
              goto LAB_001064b0;
            }
            iVar4 = *(int *)(unaff_RBP + -0x8058);
LAB_001067a6:
            *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
LAB_00106774:
            if (iVar4 == -1) goto LAB_001064b0;
          }
          if ((*(byte *)(unaff_RBP + -0x806a) & 1) == 0) {
            if ((*(byte *)(unaff_RBP + -0x8062) & 4) == 0) goto LAB_00106560;
            if (*(long *)(unaff_RBP + -0x8080) != 0) goto LAB_001064f3;
            if ((*(byte *)(unaff_RBP + -0x805a) & 1) == 0) goto LAB_00106638;
LAB_0010656d:
            if (0x3fff < *(ulong *)(unaff_RBP + -0x8078)) goto LAB_0010657e;
            pcVar7 = (char *)(unaff_RBP - 0x4040);
            lVar6 = FUN_00105b40(*(undefined4 *)(unaff_RBP + -0x8060),pcVar7,unaff_RBP + -0x8078);
            if (lVar6 == -1) {
LAB_00106aa7:
              *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
              unaff_R13D = -1;
            }
            else {
              unaff_R13D = *(int *)(unaff_RBP + -0x8060);
              if (lVar6 == 0) {
                shutdown(unaff_R13D,0);
                goto LAB_00106aa7;
              }
            }
            if ((DAT_0018a144 < 1) || (DAT_0010a0a0 = DAT_0010a0a0 + 1, DAT_0010a0a0 < DAT_0018a144)
               ) {
              uVar2 = *(ulong *)(unaff_RBP + -0x8078);
              if (uVar2 == 0) goto LAB_0010658b;
              *(undefined2 *)(unaff_RBP + -0x8054) = 4;
              if (uVar2 == 0x4000) {
                *(undefined2 *)(unaff_RBP + -0x805c) = 0;
                if ((unaff_R13D == -1) || (DAT_0018a154 == 0)) goto LAB_0010657e;
                unaff_R15 = (char *)(unaff_RBP - 0x42);
              }
              else if ((((unaff_R13D == -1) || (DAT_0018a154 == 0)) || ((uint)uVar2 < 3)) ||
                      (unaff_R15 = (char *)(unaff_RBP + -0x4042 + (uVar2 & 0xffffffff)),
                      unaff_R15 <= pcVar7)) goto LAB_0010657e;
              goto LAB_00106a3a;
            }
            if (unaff_R13D != -1) {
              shutdown(unaff_R13D,0);
            }
            *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
            *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
            if (*(long *)(unaff_RBP + -0x8078) != 0) {
              *(undefined2 *)(unaff_RBP + -0x8054) = 4;
              if (*(long *)(unaff_RBP + -0x8078) == 0x4000) {
                *(undefined2 *)(unaff_RBP + -0x805c) = 0;
              }
              goto LAB_0010657e;
            }
          }
          else {
            if (*(ulong *)(unaff_RBP + -0x8080) < 0x4000) {
              lVar6 = FUN_00105b40(*(undefined4 *)(unaff_RBP + -0x8070),unaff_RBP + -0x8040,
                                   unaff_RBP + -0x8080);
              if (lVar6 + 1U < 2) {
                *(undefined4 *)(unaff_RBP + -0x8070) = 0xffffffff;
              }
              if (*(long *)(unaff_RBP + -0x8080) == 0) goto LAB_00106560;
              *(undefined2 *)(unaff_RBP + -0x8064) = 4;
              if (*(long *)(unaff_RBP + -0x8080) == 0x4000) {
                unaff_R15 = (char *)0x0;
                *(undefined2 *)(unaff_RBP + -0x806c) = 0;
              }
            }
            if ((*(byte *)(unaff_RBP + -0x8062) & 4) != 0) {
LAB_001064f3:
              lVar6 = FUN_00106120(*(undefined4 *)(unaff_RBP + -0x8068),unaff_RBP + -0x8040,
                                   unaff_RBP + -0x8080,DAT_0018a194 != 0 || DAT_0018a188 != 0);
              if (lVar6 == -1) {
                *(undefined4 *)(unaff_RBP + -0x8068) = 0xffffffff;
              }
              if (*(ulong *)(unaff_RBP + -0x8080) == 0) {
                pcVar9 = (char *)0x0;
                *(undefined2 *)(unaff_RBP + -0x8064) = 0;
              }
              else if (0x3fff < *(ulong *)(unaff_RBP + -0x8080)) goto LAB_00106560;
              unaff_R13D = 1;
              *(undefined2 *)(unaff_RBP + -0x806c) = 1;
            }
LAB_00106560:
            if ((*(byte *)(unaff_RBP + -0x805a) & 1) != 0) goto LAB_0010656d;
LAB_00106638:
            if (((*(byte *)(unaff_RBP + -0x8052) & 4) == 0) || (*(long *)(unaff_RBP + -0x8078) == 0)
               ) goto LAB_0010658b;
LAB_00106660:
            lVar6 = FUN_00106120(*(undefined4 *)(unaff_RBP + -0x8058),unaff_RBP + -0x4040,
                                 unaff_RBP + -0x8078,0);
            if (lVar6 == -1) {
              *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
            }
            if (*(ulong *)(unaff_RBP + -0x8078) == 0) {
              *(undefined2 *)(unaff_RBP + -0x8054) = 0;
            }
            else if (0x3fff < *(ulong *)(unaff_RBP + -0x8078)) goto LAB_0010658b;
            *(undefined2 *)(unaff_RBP + -0x805c) = 1;
            if (*(int *)(unaff_RBP + -0x8070) != -1) goto LAB_00106598;
          }
LAB_001066c0:
          if (*(long *)(unaff_RBP + -0x8080) == 0) {
            if ((*(int *)(unaff_RBP + -0x8068) != -1) && (DAT_0018a17c != 0)) {
              shutdown(*(int *)(unaff_RBP + -0x8068),1);
            }
            *(undefined4 *)(unaff_RBP + -0x8068) = 0xffffffff;
            if (DAT_0018a180 != 0 || DAT_0018a150 != 0) {
              __fd = *(uint *)(unaff_RBP + -0x8060);
              if (__fd != 0xffffffff) goto code_r0x00106710;
LAB_00106788:
              if (*(long *)(unaff_RBP + -0x8078) == 0) goto LAB_00106750;
              goto LAB_00106794;
            }
          }
          goto LAB_00106598;
        }
LAB_00106a3a:
        unaff_R14 = pcVar7;
      } while (*pcVar7 != -1);
      cVar1 = pcVar7[1];
      *(undefined1 *)(unaff_RBP + -0x8044) = 0xff;
      if ((byte)(cVar1 + 5U) < 2) {
        uVar8 = 0xfe;
      }
      else {
        uVar8 = 0xfc;
        if (1 < (byte)(cVar1 + 3U)) {
          unaff_R14 = pcVar7 + 1;
          goto LAB_00106a2d;
        }
      }
      unaff_R14 = pcVar7 + 2;
      cVar1 = pcVar7[2];
      *(undefined1 *)(unaff_RBP + -0x8043) = uVar8;
      *(char *)(unaff_RBP + -0x8042) = cVar1;
      lVar6 = FUN_00105340(write,unaff_R13D,unaff_RBP + -0x8044);
      pcVar9 = unaff_R14;
    } while (lVar6 == 3);
  } while( true );
code_r0x00106710:
  if ((-1 < (int)DAT_0010a018) && (*(long *)(unaff_RBP + -0x8078) == 0)) {
    shutdown(__fd,0);
    *(undefined4 *)(unaff_RBP + -0x8060) = 0xffffffff;
    DAT_0018a184 = 0;
LAB_00106750:
    *(undefined4 *)(unaff_RBP + -0x8058) = 0xffffffff;
LAB_00106794:
    __fd = 0xffffffff;
  }
  goto LAB_001065a7;
}

/* ===== 0x102a6e  FUN_00102a6e ===== */
void FUN_00102a6e(void)

{
  long unaff_RBP;
  long in_FS_OFFSET;
  
  warn("getnameinfo");
  if (*(long *)(unaff_RBP + -0x18) == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

/* ===== 0x105270  FUN_00105270 ===== */
/* WARNING: Removing unreachable block (ram,0x00105283) */
/* WARNING: Removing unreachable block (ram,0x0010528f) */

void FUN_00105270(void)

{
  return;
}

/* ===== 0x1052a0  FUN_001052a0 ===== */
/* WARNING: Removing unreachable block (ram,0x001052c4) */
/* WARNING: Removing unreachable block (ram,0x001052d0) */

void FUN_001052a0(void)

{
  return;
}

/* ===== 0x105330  FUN_00105330 ===== */
void FUN_00105330(void)

{
                    /* WARNING: Subroutine does not return */
  exit(0);
}

/* ===== 0x105340  FUN_00105340 ===== */
ulong FUN_00105340(code *param_1,int param_2,long param_3,ulong param_4)

{
  int iVar1;
  long lVar2;
  int *piVar3;
  ulong uVar4;
  long in_FS_OFFSET;
  pollfd local_48;
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  local_48.events = (ushort)(param_1 != read) * 3 + 1;
  local_48.fd = param_2;
  if (param_4 == 0) {
LAB_0010540e:
    uVar4 = 0;
  }
  else {
    uVar4 = 0;
    do {
      lVar2 = (*param_1)(param_2,param_3 + uVar4,param_4 - uVar4);
      if (lVar2 == -1) {
        piVar3 = __errno_location();
        iVar1 = *piVar3;
        if (iVar1 != 4) {
          if ((iVar1 != 0xb) && (iVar1 != 0x69)) goto LAB_0010540e;
          poll(&local_48,1,-1);
        }
      }
      else {
        if (lVar2 == 0) {
          piVar3 = __errno_location();
          *piVar3 = 0x20;
          break;
        }
        uVar4 = uVar4 + lVar2;
      }
    } while (uVar4 < param_4);
  }
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar4;
}

/* ===== 0x105440  FUN_00105440 ===== */
void FUN_00105440(undefined4 param_1,char *param_2)

{
  long lVar1;
  long lVar2;
  char *pcVar3;
  
  lVar2 = 0;
  pcVar3 = param_2;
  while( true ) {
    lVar1 = FUN_00105340(read,param_1,pcVar3,1);
    if (lVar1 != 1) break;
    if (*pcVar3 != '\r') {
      if (*pcVar3 == '\n') {
        *pcVar3 = '\0';
        return;
      }
      lVar2 = lVar2 + 1;
      if (lVar2 == 0x400) goto LAB_00102853;
      pcVar3 = param_2 + lVar2;
    }
  }
  err(1,"proxy read");
LAB_00102853:
                    /* WARNING: Subroutine does not return */
  errx(1,"proxy read too long");
}

/* ===== 0x1054d0  FUN_001054d0 ===== */
void FUN_001054d0(int param_1)

{
  fwrite("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n\t  [destination] [port]\n"
         ,1,0x122,stderr);
  if (param_1 == 0) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}

/* ===== 0x105510  FUN_00105510 ===== */
ulong FUN_00105510(char *param_1,int param_2)

{
  ushort uVar1;
  ulong uVar2;
  int *piVar3;
  servent *psVar4;
  char *__proto;
  long in_FS_OFFSET;
  long local_38;
  long local_30;
  
  __proto = "tcp";
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_2 != 0) {
    __proto = "udp";
  }
  uVar2 = strtonum(param_1,1,0xffff,&local_38);
  if (local_38 != 0) {
    piVar3 = __errno_location();
    if (*piVar3 != 0x16) {
                    /* WARNING: Subroutine does not return */
      errx(1,"port number %s: %s",local_38,param_1);
    }
    psVar4 = getservbyname(param_1,__proto);
    if (psVar4 == (servent *)0x0) {
                    /* WARNING: Subroutine does not return */
      errx(1,"service \"%s\" unknown",param_1);
    }
    uVar1 = (ushort)psVar4->s_port;
    uVar2 = (ulong)(ushort)(uVar1 << 8 | uVar1 >> 8);
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

/* ===== 0x1055b0  FUN_001055b0 ===== */
ulong FUN_001055b0(int param_1,timeval *param_2)

{
  undefined1 auVar1 [8];
  int iVar2;
  uint uVar3;
  int iVar4;
  ulong uVar5;
  size_t sVar6;
  int *piVar7;
  char *pcVar8;
  long lVar9;
  uint __fd;
  __fd_mask *p_Var10;
  __fd_mask *p_Var11;
  fd_set *pfVar12;
  timeval *__timeout;
  undefined *puVar13;
  socklen_t unaff_R14D;
  long unaff_R15;
  long in_FS_OFFSET;
  byte bVar14;
  undefined8 uStackY_140;
  char *pcStackY_138;
  char *pcStackY_130;
  long lStack_120;
  undefined8 local_110;
  addrinfo *paStack_108;
  undefined8 uStack_100;
  undefined1 local_f8 [8];
  __suseconds_t _Stack_f0;
  timeval local_e8;
  timeval local_d8;
  fd_set local_c8;
  long lStack_40;
  long local_20;
  
  bVar14 = 0;
  __fd = (uint)(ushort)param_2->tv_sec;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  uStack_100._4_4_ = 1;
  if ((DAT_0018a198 == 0) ||
     (local_110 = param_2, iVar2 = setsockopt(param_1,1,6,(void *)((long)&uStack_100 + 4),4),
     param_2 = local_110, iVar2 != -1)) {
    if (DAT_0018a0c8 != 0) {
      _local_f8 = *param_2;
      p_Var10 = local_c8.fds_bits + 10;
      for (lVar9 = 0xb; lVar9 != 0; lVar9 = lVar9 + -1) {
        *p_Var10 = 0;
        p_Var10 = p_Var10 + (ulong)bVar14 * -2 + 1;
      }
      local_e8 = param_2[1];
      local_d8 = param_2[2];
      local_c8.fds_bits[0] = param_2[3].tv_sec;
      local_c8.fds_bits[1] = param_2[3].tv_usec;
      local_c8.fds_bits[2] = param_2[4].tv_sec;
      local_c8.fds_bits[3] = param_2[4].tv_usec;
      local_c8.fds_bits[4] = param_2[5].tv_sec;
      local_c8.fds_bits[5] = param_2[5].tv_usec;
      local_c8.fds_bits[6] = param_2[6].tv_sec;
      local_c8.fds_bits[7] = param_2[6].tv_usec;
      local_c8.fds_bits[8] = param_2[7].tv_sec;
      local_c8.fds_bits[9] = param_2[7].tv_usec;
      sVar6 = strlen((char *)&DAT_0018a0e0);
      uVar3 = (uint)sVar6;
      local_c8.fds_bits[10]._2_2_ = (undefined2)sVar6;
      if (uVar3 < 8) {
        if ((sVar6 & 4) == 0) {
          if (uVar3 != 0) {
            local_c8.fds_bits[0xb]._0_4_ =
                 CONCAT31(local_c8.fds_bits[0xb]._1_3_,(char)(undefined4)DAT_0018a0e0);
            if ((sVar6 & 2) != 0) {
              *(undefined2 *)((long)local_c8.fds_bits + (sVar6 & 0xffffffff) + 0x56) =
                   *(undefined2 *)(&DAT_0018a0de + (sVar6 & 0xffffffff));
            }
          }
        }
        else {
          local_c8.fds_bits[0xb]._0_4_ = (undefined4)DAT_0018a0e0;
          *(undefined4 *)((long)local_c8.fds_bits + (sVar6 & 0xffffffff) + 0x54) =
               *(undefined4 *)(&DAT_0018a0dc + (sVar6 & 0xffffffff));
        }
      }
      else {
        *(undefined8 *)((long)local_c8.fds_bits + (sVar6 & 0xffffffff) + 0x50) =
             *(undefined8 *)(&DAT_0018a0d8 + (sVar6 & 0xffffffff));
        p_Var10 = &DAT_0018a0e0;
        p_Var11 = local_c8.fds_bits + 0xb;
        for (uVar5 = (ulong)(uVar3 - 1 >> 3); uVar5 != 0; uVar5 = uVar5 - 1) {
          *p_Var11 = *p_Var10;
          p_Var10 = p_Var10 + (ulong)bVar14 * -2 + 1;
          p_Var11 = p_Var11 + (ulong)bVar14 * -2 + 1;
        }
      }
      local_c8.fds_bits[10]._0_1_ = 1;
      iVar2 = setsockopt(param_1,6,0x20,local_f8,0xd8);
      if (iVar2 == -1) {
        uVar5 = FUN_00102895();
        return uVar5;
      }
    }
    if ((DAT_0018a138 != 0) &&
       (iVar2 = setsockopt(param_1,1,1,(void *)((long)&uStack_100 + 4),4), iVar2 == -1)) {
      uVar5 = FUN_00102895();
      return uVar5;
    }
    if (DAT_0010a010 != -1) {
      if (__fd == 2) {
        iVar2 = setsockopt(param_1,0,1,&DAT_0010a010,4);
        if (iVar2 != -1) goto LAB_00105623;
        goto LAB_001028dc;
      }
      if ((__fd != 10) || (iVar2 = setsockopt(param_1,0x29,0x43,&DAT_0010a010,4), iVar2 != -1))
      goto LAB_00105623;
      goto LAB_001028ef;
    }
LAB_00105623:
    if ((DAT_0018a134 != 0) && (iVar2 = setsockopt(param_1,1,8,&DAT_0018a134,4), iVar2 == -1))
    goto LAB_001028b6;
    if ((DAT_0018a130 != 0) && (iVar2 = setsockopt(param_1,1,7,&DAT_0018a130,4), iVar2 == -1))
    goto LAB_001028a3;
    if (DAT_0010a020 == -1) {
      if (DAT_0010a01c == -1) goto LAB_0010565a;
      if (__fd == 2) goto LAB_00105939;
      if (__fd != 10) goto LAB_0010565a;
LAB_00105697:
      iVar2 = setsockopt(param_1,0x29,0x49,&DAT_0010a01c,4);
      if (iVar2 == 0) goto LAB_0010565a;
      goto LAB_00102902;
    }
    if (__fd == 2) {
      iVar2 = setsockopt(param_1,0,2,&DAT_0010a020,4);
      if (iVar2 == 0) {
        if (DAT_0010a01c == -1) goto LAB_0010565a;
LAB_00105939:
        iVar2 = setsockopt(param_1,0,0x15,&DAT_0010a01c,4);
        if (iVar2 == 0) {
LAB_0010565a:
          if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          return 0;
        }
        goto LAB_00102928;
      }
      goto LAB_001028c9;
    }
    if (__fd != 10) goto LAB_0010565a;
    iVar2 = setsockopt(param_1,0x29,0x10,&DAT_0010a020,4);
    if (iVar2 == 0) {
      if (DAT_0010a01c == -1) goto LAB_0010565a;
      goto LAB_00105697;
    }
  }
  else {
    err(1,0);
LAB_001028a3:
    err(1,"set TCP send buffer size");
LAB_001028b6:
    err(1,"set TCP receive buffer size");
LAB_001028c9:
    err(1,"set IP TTL");
LAB_001028dc:
    err(1,"set IP ToS");
LAB_001028ef:
    err(1,"set IPv6 traffic class");
LAB_00102902:
    err(1,"set IPv6 min hop count");
  }
  err(1,"set IPv6 unicast hops");
LAB_00102928:
  err(1,"set IP min TTL");
  lStack_120 = unaff_R15;
FUN_0010293b:
  warn("can\'t set O_NONBLOCK - timeout not available");
  iVar2 = connect(__fd,(sockaddr *)0x10294c,unaff_R14D);
LAB_00105e70:
  if (iVar2 == 0) {
LAB_0010602f:
    freeaddrinfo(paStack_108);
    if (lStack_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return (ulong)__fd;
  }
LAB_00105e79:
  puVar13 = &DAT_00107023;
  if ((DAT_0018a150 == 0) && (puVar13 = &DAT_00107027, DAT_0018a14c != 0)) {
    puVar13 = &DAT_001070f1;
  }
  if (DAT_0018a148 != 0) {
    if (((DAT_0018a178 == 0) && (pcStackY_130 != (char *)0x0)) &&
       (iVar2 = strncmp(pcStackY_138,pcStackY_130,0x401), iVar2 != 0)) goto LAB_001029f3;
    warn("connect to %s port %s (%s) %s",pcStackY_138,uStackY_140,puVar13);
  }
  do {
    pcVar8 = pcStackY_130;
    piVar7 = __errno_location();
    iVar2 = *piVar7;
    close(__fd);
    *piVar7 = iVar2;
    do {
      lStack_120 = *(long *)(lStack_120 + 0x28);
      if (lStack_120 == 0) {
        __fd = 0xffffffff;
        goto LAB_0010602f;
      }
      __fd = socket(*(int *)(lStack_120 + 4),*(uint *)(lStack_120 + 8) | 0x800,
                    *(int *)(lStack_120 + 0xc));
    } while (__fd == 0xffffffff);
    if ((DAT_0018a158 == (char *)0x0) && (DAT_0018a168 == (char *)0x0)) {
LAB_00105d58:
      FUN_001055b0(__fd,*(undefined8 *)(lStack_120 + 0x18));
      if (pcStackY_130 == (char *)0x0) goto LAB_00105da1;
      pcStackY_130 = (char *)0x105d8d;
      iVar2 = getnameinfo(*(sockaddr **)(lStack_120 + 0x18),*(socklen_t *)(lStack_120 + 0x10),pcVar8
                          ,0x401,(char *)0x0,0,1);
      if (iVar2 != -0xb) break;
      err(1,"getnameinfo");
    }
    else {
      local_e8.tv_sec = 0;
      local_e8.tv_usec = 0;
      local_d8.tv_sec = 0;
      local_d8.tv_usec = 0;
      local_f8 = (undefined1  [8])((ulong)*(uint *)(lStack_120 + 4) << 0x20);
      auVar1 = local_f8;
      _Stack_f0 = 0;
      local_f8._4_4_ = *(uint *)(lStack_120 + 4);
      if (DAT_0018a150 == 0) {
        if (DAT_0018a14c == 0) {
          _Stack_f0 = 0x600000001;
          _local_f8 = (timeval)CONCAT88(_Stack_f0,auVar1);
        }
      }
      else {
        _Stack_f0 = 0x1100000002;
        _local_f8 = (timeval)CONCAT88(_Stack_f0,auVar1);
      }
      local_f8._0_4_ = 1;
      iVar2 = getaddrinfo(DAT_0018a158,DAT_0018a168,(addrinfo *)local_f8,(addrinfo **)&uStack_100);
      if (iVar2 != 0) {
        pcVar8 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
        errx(1,"getaddrinfo: %s",pcVar8);
      }
      iVar2 = bind(__fd,*(sockaddr **)(CONCAT44(uStack_100._4_4_,(socklen_t)uStack_100) + 0x18),
                   *(socklen_t *)(CONCAT44(uStack_100._4_4_,(socklen_t)uStack_100) + 0x10));
      if (iVar2 != -1) {
        freeaddrinfo((addrinfo *)CONCAT44(uStack_100._4_4_,(socklen_t)uStack_100));
        goto LAB_00105d58;
      }
    }
    err(1,"bind failed");
LAB_001029f3:
    warn("connect to %s (%s) port %s (%s) %s",pcStackY_138,pcStackY_130,uStackY_140);
  } while( true );
  if (iVar2 != 0) {
    pcVar8 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
    errx(1,"getnameinfo: %s",pcVar8);
  }
LAB_00105da1:
  iVar2 = DAT_0010a014;
  unaff_R14D = *(socklen_t *)(lStack_120 + 0x10);
  uVar3 = fcntl(__fd,3,0);
  iVar4 = fcntl(__fd,4,(ulong)uVar3 | 0x800);
  if (iVar4 < 0) goto FUN_0010293b;
  __timeout = (timeval *)0x0;
  if (0 < iVar2) {
    __timeout = (timeval *)local_f8;
    _Stack_f0 = 0;
    local_f8 = (undefined1  [8])(long)(iVar2 / 1000);
  }
  iVar2 = connect(__fd,(sockaddr *)0x105de0,unaff_R14D);
  local_110 = (timeval *)CONCAT44(iVar2,(undefined4)local_110);
  if ((iVar2 == 0) || (piVar7 = __errno_location(), *piVar7 != 0x73)) goto LAB_00105e4d;
  pfVar12 = &local_c8;
  for (lVar9 = 0x10; lVar9 != 0; lVar9 = lVar9 + -1) {
    pfVar12->fds_bits[0] = 0;
    pfVar12 = (fd_set *)((long)pfVar12 + ((ulong)bVar14 * -2 + 1) * 8);
  }
  lVar9 = __fdelt_chk((long)(int)__fd);
  local_c8.fds_bits[lVar9] = local_c8.fds_bits[lVar9] | 1L << ((byte)__fd & 0x3f);
  while( true ) {
    lStack_120 = 0x105fa3;
    iVar2 = select(__fd + 1,(fd_set *)0x0,&local_c8,(fd_set *)0x0,__timeout);
    local_110 = (timeval *)CONCAT44(iVar2,(undefined4)local_110);
    if (-1 < iVar2) break;
    if (*piVar7 != 4) {
      pcVar8 = strerror(*piVar7);
                    /* WARNING: Subroutine does not return */
      errx(1,"select error: %s",pcVar8);
    }
  }
  if (iVar2 != 0) goto code_r0x00105fb6;
  goto LAB_00105e79;
code_r0x00105fb6:
  uStack_100._0_4_ = 4;
  iVar2 = getsockopt(__fd,1,4,(void *)((long)&local_110 + 4),(socklen_t *)&uStack_100);
  if (iVar2 < 0) {
    pcVar8 = strerror(*piVar7);
                    /* WARNING: Subroutine does not return */
    errx(1,"getsockopt error: %s",pcVar8);
  }
  if (local_110._4_4_ != 0) {
    *piVar7 = local_110._4_4_;
    lStack_120 = 0x105fa3;
  }
LAB_00105e4d:
  fcntl(__fd,4,uVar3);
  iVar2 = local_110._4_4_;
  goto LAB_00105e70;
}

/* ===== 0x1059d0  FUN_001059d0 ===== */
undefined4 FUN_001059d0(char *param_1,char *param_2,undefined8 *param_3,int param_4,int param_5)

{
  uint uVar1;
  int __ecode;
  undefined4 uVar2;
  char *pcVar3;
  ulong uVar4;
  sockaddr *psVar5;
  long in_FS_OFFSET;
  byte bVar6;
  addrinfo *local_70;
  undefined1 local_68 [28];
  undefined1 local_4c [16];
  undefined4 local_3c;
  long local_30;
  
  bVar6 = 0;
  local_68._4_4_ = param_4 * 2;
  local_68._0_4_ = param_5 * 4;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  local_3c = 0;
  local_68._8_4_ = 1;
  local_68._12_16_ = (undefined1  [16])0x0;
  local_4c = (undefined1  [16])0x0;
  __ecode = getaddrinfo(param_1,param_2,(addrinfo *)local_68,&local_70);
  if (__ecode == 0) {
    uVar1 = local_70->ai_addrlen;
    uVar4 = (ulong)uVar1;
    if (0x80 < uVar1) {
      freeaddrinfo(local_70);
                    /* WARNING: Subroutine does not return */
      errx(1,"internal error: addrlen < res->ai_addrlen");
    }
    psVar5 = local_70->ai_addr;
    uVar2 = 0;
    if (uVar1 < 8) {
      if ((uVar1 & 4) == 0) {
        if ((uVar1 != 0) && (*(char *)param_3 = (char)psVar5->sa_family, (uVar1 & 2) != 0)) {
          *(undefined2 *)((long)param_3 + (uVar4 - 2)) =
               *(undefined2 *)(psVar5->sa_data + (uVar4 - 4));
        }
      }
      else {
        *(undefined4 *)param_3 = *(undefined4 *)psVar5;
        *(undefined4 *)((long)param_3 + (uVar4 - 4)) =
             *(undefined4 *)(psVar5->sa_data + (uVar4 - 6));
      }
      freeaddrinfo(local_70);
    }
    else {
      *(undefined8 *)((long)param_3 + (uVar4 - 8)) = *(undefined8 *)(psVar5->sa_data + (uVar4 - 10))
      ;
      for (uVar4 = (ulong)(uVar1 - 1 >> 3); uVar4 != 0; uVar4 = uVar4 - 1) {
        *param_3 = *(undefined8 *)psVar5;
        psVar5 = (sockaddr *)(psVar5[-(ulong)bVar6].sa_data + 6);
        param_3 = param_3 + (ulong)bVar6 * -2 + 1;
      }
      freeaddrinfo(local_70);
    }
  }
  else {
    if (param_5 == 0) {
      pcVar3 = gai_strerror(__ecode);
                    /* WARNING: Subroutine does not return */
      errx(1,"getaddrinfo(\"%.64s\", \"%.64s\"): %s",param_1,param_2,pcVar3);
    }
    uVar2 = 0xffffffff;
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

/* ===== 0x105b40  FUN_00105b40 ===== */
ulong FUN_00105b40(int param_1,long param_2,long *param_3)

{
  ulong uVar1;
  int *piVar2;
  
  if (param_1 == -1) {
    return 0xffffffffffffffff;
  }
  uVar1 = read(param_1,(void *)(param_2 + *param_3),0x4000 - *param_3);
  if (uVar1 != 0xffffffffffffffff) {
    if (0 < (long)uVar1) {
      *param_3 = *param_3 + uVar1;
    }
    return uVar1;
  }
  piVar2 = __errno_location();
  return ~(ulong)(*piVar2 == 0xb || *piVar2 == 4);
}

/* ===== 0x105bb0  FUN_00105bb0 ===== */
undefined8 FUN_00105bb0(char *param_1,undefined2 *param_2,int *param_3)

{
  uint uVar1;
  size_t sVar2;
  int *piVar3;
  undefined8 uVar4;
  
  *param_3 = 2;
  *param_2 = 1;
  if (*param_1 == '\0') {
    piVar3 = __errno_location();
    *piVar3 = 0x16;
LAB_00105c45:
    uVar4 = 0xffffffff;
  }
  else {
    if (*param_1 == '@') {
      sVar2 = strlen(param_1);
      uVar1 = (uint)sVar2;
      if (0x6c < uVar1) goto LAB_00105c3a;
      *(undefined1 *)(param_2 + 1) = 0;
      strncpy((char *)((long)param_2 + 3),param_1 + 1,(long)(int)(uVar1 - 1));
      *param_3 = *param_3 + uVar1;
    }
    else {
      uVar1 = strlcpy(param_2 + 1,param_1,0x6c);
      if (0x6b < uVar1) {
LAB_00105c3a:
        piVar3 = __errno_location();
        *piVar3 = 0x24;
        goto LAB_00105c45;
      }
      *param_3 = *param_3 + uVar1 + 1;
    }
    uVar4 = 0;
  }
  return uVar4;
}

/* ===== 0x105c60  FUN_00105c60 ===== */
int FUN_00105c60(char *param_1,char *param_2,char *param_3)

{
  socklen_t __len;
  sockaddr *__addr;
  undefined1 auVar1 [8];
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  char *pcVar7;
  long lVar8;
  fd_set *pfVar9;
  timeval *__timeout;
  undefined *puVar10;
  addrinfo *paVar11;
  long in_FS_OFFSET;
  byte bVar12;
  int iStack0000000000000010;
  int iStack0000000000000014;
  int local_10c;
  addrinfo *local_108;
  undefined8 local_100;
  undefined1 local_f8 [8];
  __suseconds_t _Stack_f0;
  undefined1 local_e8 [16];
  undefined1 local_d8 [16];
  fd_set local_c8;
  long local_40;
  
  bVar12 = 0;
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  iVar2 = getaddrinfo(param_1,param_2,(addrinfo *)&stack0x00000008,&local_108);
  if (iVar2 != 0) {
    pcVar7 = gai_strerror(iVar2);
                    /* WARNING: Subroutine does not return */
    errx(1,"getaddrinfo for host \"%s\" port %s: %s",param_1,param_2,pcVar7);
  }
  paVar11 = local_108;
  if (local_108 == (addrinfo *)0x0) {
    iVar2 = -1;
  }
  else {
    do {
      iVar2 = socket(paVar11->ai_family,paVar11->ai_socktype | 0x800,paVar11->ai_protocol);
      if (iVar2 != -1) {
        if ((DAT_0018a158 == (char *)0x0) && (DAT_0018a168 == (char *)0x0)) {
LAB_00105d58:
          FUN_001055b0(iVar2,paVar11->ai_addr);
          if (param_3 != (char *)0x0) {
            iVar3 = getnameinfo(paVar11->ai_addr,paVar11->ai_addrlen,param_3,0x401,(char *)0x0,0,1);
            if (iVar3 == -0xb) {
              err(1,"getnameinfo");
              goto LAB_001029e0;
            }
            if (iVar3 != 0) {
              pcVar7 = gai_strerror(iVar3);
                    /* WARNING: Subroutine does not return */
              errx(1,"getnameinfo: %s",pcVar7);
            }
          }
          iVar3 = DAT_0010a014;
          __addr = paVar11->ai_addr;
          __len = paVar11->ai_addrlen;
          uVar4 = fcntl(iVar2,3,0);
          iVar5 = fcntl(iVar2,4,(ulong)uVar4 | 0x800);
          if (iVar5 < 0) {
            warn("can\'t set O_NONBLOCK - timeout not available");
            iVar3 = connect(iVar2,__addr,__len);
LAB_00105e70:
            if (iVar3 == 0) goto LAB_0010602f;
          }
          else {
            __timeout = (timeval *)0x0;
            if (0 < iVar3) {
              __timeout = (timeval *)local_f8;
              _Stack_f0 = 0;
              local_f8 = (undefined1  [8])(long)(iVar3 / 1000);
            }
            local_10c = connect(iVar2,__addr,__len);
            if ((local_10c == 0) || (piVar6 = __errno_location(), *piVar6 != 0x73)) {
LAB_00105e4d:
              fcntl(iVar2,4,(ulong)uVar4);
              iVar3 = local_10c;
              goto LAB_00105e70;
            }
            pfVar9 = &local_c8;
            for (lVar8 = 0x10; lVar8 != 0; lVar8 = lVar8 + -1) {
              pfVar9->fds_bits[0] = 0;
              pfVar9 = (fd_set *)((long)pfVar9 + ((ulong)bVar12 * -2 + 1) * 8);
            }
            lVar8 = __fdelt_chk((long)iVar2);
            local_c8.fds_bits[lVar8] = local_c8.fds_bits[lVar8] | 1L << ((byte)iVar2 & 0x3f);
            while( true ) {
              local_10c = select(iVar2 + 1,(fd_set *)0x0,&local_c8,(fd_set *)0x0,__timeout);
              if (-1 < local_10c) break;
              if (*piVar6 != 4) {
                pcVar7 = strerror(*piVar6);
                    /* WARNING: Subroutine does not return */
                errx(1,"select error: %s",pcVar7);
              }
            }
            if (local_10c != 0) {
              local_100._0_4_ = 4;
              iVar3 = getsockopt(iVar2,1,4,&local_10c,(socklen_t *)&local_100);
              if (iVar3 < 0) {
                pcVar7 = strerror(*piVar6);
                    /* WARNING: Subroutine does not return */
                errx(1,"getsockopt error: %s",pcVar7);
              }
              if (local_10c != 0) {
                *piVar6 = local_10c;
              }
              goto LAB_00105e4d;
            }
          }
          puVar10 = &DAT_00107023;
          if ((DAT_0018a150 == 0) && (puVar10 = &DAT_00107027, DAT_0018a14c != 0)) {
            puVar10 = &DAT_001070f1;
          }
          if (DAT_0018a148 != 0) {
            if (((DAT_0018a178 == 0) && (param_3 != (char *)0x0)) &&
               (iVar3 = strncmp(param_1,param_3,0x401), iVar3 != 0)) goto LAB_001029f3;
            warn("connect to %s port %s (%s) %s",param_1,param_2,puVar10);
          }
        }
        else {
          local_e8 = (undefined1  [16])0x0;
          local_d8 = (undefined1  [16])0x0;
          local_f8 = (undefined1  [8])((ulong)(uint)paVar11->ai_family << 0x20);
          auVar1 = local_f8;
          _Stack_f0 = 0;
          local_f8._4_4_ = paVar11->ai_family;
          if (DAT_0018a150 == 0) {
            if (DAT_0018a14c == 0) {
              _Stack_f0 = 0x600000001;
              _local_f8 = (timeval)CONCAT88(_Stack_f0,auVar1);
            }
            else {
              iStack0000000000000010 = 6;
              iStack0000000000000014 = 0x21;
            }
          }
          else {
            _Stack_f0 = 0x1100000002;
            _local_f8 = (timeval)CONCAT88(_Stack_f0,auVar1);
          }
          local_f8._0_4_ = 1;
          iVar3 = getaddrinfo(DAT_0018a158,DAT_0018a168,(addrinfo *)local_f8,(addrinfo **)&local_100
                             );
          if (iVar3 != 0) {
            pcVar7 = gai_strerror(iVar3);
                    /* WARNING: Subroutine does not return */
            errx(1,"getaddrinfo: %s",pcVar7);
          }
          iVar3 = bind(iVar2,*(sockaddr **)(CONCAT44(local_100._4_4_,(socklen_t)local_100) + 0x18),
                       *(socklen_t *)(CONCAT44(local_100._4_4_,(socklen_t)local_100) + 0x10));
          if (iVar3 != -1) {
            freeaddrinfo((addrinfo *)CONCAT44(local_100._4_4_,(socklen_t)local_100));
            goto LAB_00105d58;
          }
LAB_001029e0:
          err(1,"bind failed");
LAB_001029f3:
          warn("connect to %s (%s) port %s (%s) %s",param_1,param_3,param_2);
        }
        piVar6 = __errno_location();
        iVar3 = *piVar6;
        close(iVar2);
        *piVar6 = iVar3;
      }
      paVar11 = paVar11->ai_next;
    } while (paVar11 != (addrinfo *)0x0);
    iVar2 = -1;
  }
LAB_0010602f:
  freeaddrinfo(local_108);
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar2;
}

/* ===== 0x106120  FUN_00106120 ===== */
size_t FUN_00106120(int param_1,void *param_2,size_t *param_3,int param_4)

{
  void *pvVar1;
  int *piVar2;
  long lVar3;
  size_t __n;
  size_t sVar4;
  
  if (param_1 == -1) {
    return 0xffffffffffffffff;
  }
  sVar4 = *param_3;
  if ((param_4 == 0) || (pvVar1 = memchr(param_2,10,sVar4), pvVar1 == (void *)0x0)) {
    if ((long)sVar4 < 1) goto joined_r0x00106223;
    param_4 = 0;
LAB_001061cb:
    sVar4 = write(param_1,param_2,sVar4);
    if (sVar4 == 0xffffffffffffffff) goto LAB_001061df;
    if ((long)sVar4 < 1) {
      return sVar4;
    }
    if (param_4 != 1) goto LAB_00106249;
  }
  else {
    if (DAT_0018a194 == 0) {
LAB_00106210:
      sVar4 = (long)pvVar1 + (1 - (long)param_2);
      if (0 < (long)sVar4) goto LAB_001061cb;
joined_r0x00106223:
      if (sVar4 != 0xffffffffffffffff) {
        return sVar4;
      }
LAB_001061df:
      piVar2 = __errno_location();
      return ~(ulong)(*piVar2 == 0xb || *piVar2 == 4);
    }
    if (param_2 == pvVar1) {
      sVar4 = 1;
    }
    else {
      sVar4 = (long)pvVar1 - (long)param_2;
      if (*(char *)((long)pvVar1 + -1) == '\r') goto LAB_00106210;
      if ((long)sVar4 < 1) goto joined_r0x00106223;
      sVar4 = write(param_1,param_2,sVar4);
      if (sVar4 == 0xffffffffffffffff) goto LAB_001061df;
      if ((long)sVar4 < 0) {
        return sVar4;
      }
      sVar4 = sVar4 + 1;
    }
    lVar3 = FUN_00105340(write,param_1,"\r\n",2);
    if (lVar3 != 2) {
      sVar4 = FUN_00102a32();
      return sVar4;
    }
  }
  if (DAT_0018a188 != 0) {
    sleep(DAT_0018a188);
  }
LAB_00106249:
  __n = *param_3 - sVar4;
  if (0 < (long)__n) {
    memmove(param_2,(void *)((long)param_2 + sVar4),__n);
    __n = *param_3 - sVar4;
  }
  *param_3 = __n;
  return sVar4;
}

/* ===== 0x106300  FUN_00106300 ===== */
void FUN_00106300(uint param_1)

{
  undefined1 *puVar1;
  undefined1 uVar2;
  int iVar3;
  pollfd *ppVar4;
  long lVar5;
  char *pcVar6;
  char *pcVar7;
  uint uVar8;
  undefined1 *puVar9;
  uint unaff_R13D;
  char *unaff_R14;
  char *unaff_R15;
  long in_FS_OFFSET;
  ulong local_8088;
  ulong local_8080;
  pollfd local_8078;
  uint local_8070;
  undefined2 local_806c;
  byte local_806a;
  uint local_8068;
  uint local_8064;
  uint local_8060;
  undefined2 local_805c;
  byte local_805a;
  pollfd local_8058;
  undefined1 local_804c;
  undefined1 local_804b;
  char local_804a;
  undefined1 local_8048 [24];
  undefined1 local_8030 [16358];
  char acStack_404a [16384];
  char local_4a [10];
  long local_40;
  
  puVar1 = &stack0xffffffffffffffd0;
  do {
    puVar9 = puVar1;
    *(undefined8 *)(puVar9 + -0x1000) = *(undefined8 *)(puVar9 + -0x1000);
    puVar1 = puVar9 + -0x1000;
  } while (puVar9 + -0x1000 != local_8030);
  local_8078.fd = -(uint)(DAT_0018a190 != 0);
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  local_8078.events = 1;
  local_8080 = 0;
  local_8088 = 0;
  local_806c = 0;
  local_8064 = CONCAT22(local_8064._2_2_,1);
  local_8060 = 1;
  local_805c = 0;
  local_8070 = param_1;
  local_8068 = param_1;
  uVar8 = param_1;
  if ((local_8078.fd & param_1) == 0xffffffff) goto LAB_001065b8;
LAB_001063c0:
  if ((local_8070 & local_8060) == 0xffffffff) goto LAB_001065d0;
  if (((DAT_0018a180 != 0) && (uVar8 == 0xffffffff)) && (local_8088 == 0 && local_8080 == 0)) {
    if (0 < (int)DAT_0010a018) goto LAB_001065de;
LAB_0010692a:
    if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      *(undefined **)(puVar9 + -0x1060) = &UNK_00106af7;
      __stack_chk_fail();
    }
    return;
  }
  do {
    *(undefined8 *)(puVar9 + -0x1060) = 0x1063ff;
    iVar3 = poll(&local_8078,4,DAT_0010a014);
    if (iVar3 == -1) {
      *(undefined8 *)(puVar9 + -0x1060) = 0x102a5b;
      err(1);
      pcVar7 = unaff_R14;
      goto LAB_00102a5b;
    }
    if (iVar3 == 0) goto LAB_0010692a;
    ppVar4 = &local_8078;
    do {
      if ((ppVar4->revents & 0x28) != 0) {
        ppVar4->fd = -1;
      }
      ppVar4 = ppVar4 + 1;
    } while (ppVar4 != &local_8058);
    if ((local_8078._4_4_ & 0x110001) == 0x100001) {
      local_8078.fd = 0xffffffff;
    }
    if ((local_8064 & 0x110001) == 0x100001) {
      local_8068 = 0xffffffff;
    }
    if ((local_806a & 0x10) == 0) {
      if ((local_805a & 0x10) == 0) {
        if (local_8070 == 0xffffffff) goto LAB_001067a6;
        goto LAB_00106774;
      }
      local_8060 = 0xffffffff;
      if (local_8070 == 0xffffffff) {
        local_8078.fd = 0xffffffff;
      }
LAB_001064b0:
      if (local_8068 != 0xffffffff) {
        *(undefined8 *)(puVar9 + -0x1060) = 0x1064c2;
        shutdown(local_8068,0);
      }
      local_8068 = 0xffffffff;
    }
    else {
      if ((local_8070 != 0xffffffff) && (DAT_0018a17c != 0)) {
        *(undefined8 *)(puVar9 + -0x1060) = 0x106a6a;
        shutdown(local_8070,1);
      }
      local_8070 = 0xffffffff;
      if ((local_805a & 0x10) != 0) {
        local_8060 = 0xffffffff;
        local_8078.fd = 0xffffffff;
        goto LAB_001064b0;
      }
LAB_001067a6:
      local_8078.fd = 0xffffffff;
LAB_00106774:
      if (local_8060 == 0xffffffff) goto LAB_001064b0;
    }
    if ((local_8078._4_4_ & 0x10000) == 0) {
      if ((local_806a & 4) == 0) goto LAB_00106560;
      if (local_8088 != 0) goto LAB_001064f3;
      if ((local_8064 & 0x10000) != 0) goto LAB_0010656d;
LAB_00106638:
      if (((local_805a & 4) != 0) && (local_8080 != 0)) {
LAB_00106660:
        *(undefined8 *)(puVar9 + -0x1060) = 0x10667b;
        lVar5 = FUN_00106120(local_8060,acStack_404a + 2,&local_8080,0);
        if (lVar5 == -1) {
          local_8060 = 0xffffffff;
        }
        if (local_8080 == 0) {
          local_805c = 0;
        }
        else if (0x3fff < local_8080) goto joined_r0x001066b7;
        local_8064 = CONCAT22(local_8064._2_2_,1);
      }
joined_r0x001066b7:
      if (local_8078.fd == 0xffffffff) goto LAB_001066c0;
LAB_00106598:
      uVar8 = local_8068;
      if (local_8068 == 0xffffffff) {
LAB_00106788:
        if (local_8080 == 0) goto LAB_00106750;
        goto LAB_00106794;
      }
    }
    else {
      if (local_8088 < 0x4000) {
        *(undefined8 *)(puVar9 + -0x1060) = 0x1068b9;
        lVar5 = FUN_00105b40(local_8078.fd,local_8048,&local_8088);
        if (lVar5 + 1U < 2) {
          local_8078.fd = 0xffffffff;
        }
        if (local_8088 == 0) goto LAB_00106560;
        local_806c = 4;
        if (local_8088 == 0x4000) {
          unaff_R15 = (char *)0x0;
          local_8078._4_4_ = local_8078._4_4_ & 0xffff0000;
        }
      }
      if ((local_806a & 4) != 0) {
LAB_001064f3:
        *(undefined8 *)(puVar9 + -0x1060) = 0x10651d;
        lVar5 = FUN_00106120(local_8070,local_8048,&local_8088,
                             DAT_0018a194 != 0 || DAT_0018a188 != 0);
        if (lVar5 == -1) {
          local_8070 = 0xffffffff;
        }
        if (local_8088 == 0) {
          unaff_R14 = (char *)0x0;
          local_806c = 0;
        }
        else if (0x3fff < local_8088) goto LAB_00106560;
        unaff_R13D = 1;
        local_8078.events = 1;
      }
LAB_00106560:
      if ((local_8064 & 0x10000) == 0) goto LAB_00106638;
LAB_0010656d:
      if (0x3fff < local_8080) {
LAB_0010657e:
        if ((local_805a & 4) != 0) goto LAB_00106660;
        goto joined_r0x001066b7;
      }
      pcVar6 = acStack_404a + 2;
      *(undefined8 *)(puVar9 + -0x1060) = 0x1067fc;
      lVar5 = FUN_00105b40(local_8068,pcVar6,&local_8080);
      if (lVar5 == -1) {
LAB_00106aa7:
        local_8068 = 0xffffffff;
      }
      else if (lVar5 == 0) {
        *(undefined8 *)(puVar9 + -0x1060) = 0x106aa7;
        shutdown(local_8068,0);
        goto LAB_00106aa7;
      }
      unaff_R13D = local_8068;
      if ((DAT_0018a144 < 1) || (DAT_0010a0a0 = DAT_0010a0a0 + 1, DAT_0010a0a0 < DAT_0018a144)) {
        if (local_8080 != 0) {
          local_805c = 4;
          if (local_8080 == 0x4000) {
            local_8064 = local_8064 & 0xffff0000;
            if ((local_8068 != 0xffffffff) && (DAT_0018a154 != 0)) {
              unaff_R15 = local_4a;
LAB_00106a3a:
              do {
                pcVar7 = pcVar6;
                if (*pcVar6 == -1) {
                  local_804c = 0xff;
                  if ((byte)(pcVar6[1] + 5U) < 2) {
                    uVar2 = 0xfe;
                  }
                  else {
                    uVar2 = 0xfc;
                    if (1 < (byte)(pcVar6[1] + 3U)) {
                      pcVar7 = pcVar6 + 1;
                      goto LAB_00106a2d;
                    }
                  }
                  local_804b = uVar2;
                  pcVar7 = pcVar6 + 2;
                  local_804a = pcVar6[2];
                  *(undefined8 *)(puVar9 + -0x1060) = 0x106a20;
                  lVar5 = FUN_00105340(write,unaff_R13D,&local_804c,3);
                  unaff_R14 = pcVar7;
                  if (lVar5 != 3) {
LAB_00102a5b:
                    *(undefined8 *)(puVar9 + -0x1060) = 0x102a69;
                    warn("Write Error!");
                    unaff_R14 = pcVar7;
                  }
                }
LAB_00106a2d:
                pcVar6 = pcVar7 + 1;
              } while (pcVar6 < unaff_R15);
            }
          }
          else if ((((local_8068 != 0xffffffff) && (DAT_0018a154 != 0)) && (2 < (uint)local_8080))
                  && (unaff_R15 = acStack_404a + (local_8080 & 0xffffffff), pcVar6 < unaff_R15))
          goto LAB_00106a3a;
          goto LAB_0010657e;
        }
        goto joined_r0x001066b7;
      }
      if (local_8068 != 0xffffffff) {
        *(undefined8 *)(puVar9 + -0x1060) = 0x10684b;
        shutdown(local_8068,0);
      }
      local_8068 = 0xffffffff;
      local_8078.fd = 0xffffffff;
      if (local_8080 != 0) {
        local_805c = 4;
        if (local_8080 == 0x4000) {
          local_8064 = local_8064 & 0xffff0000;
        }
        goto LAB_0010657e;
      }
LAB_001066c0:
      if (local_8088 != 0) goto LAB_00106598;
      if ((local_8070 != 0xffffffff) && (DAT_0018a17c != 0)) {
        *(undefined8 *)(puVar9 + -0x1060) = 0x106a92;
        shutdown(local_8070,1);
      }
      local_8070 = 0xffffffff;
      if (DAT_0018a180 == 0 && DAT_0018a150 == 0) goto LAB_00106598;
      if (local_8068 == 0xffffffff) goto LAB_00106788;
      uVar8 = local_8068;
      if (((int)DAT_0010a018 < 0) || (local_8080 != 0)) goto LAB_001065a7;
      *(undefined8 *)(puVar9 + -0x1060) = 0x106733;
      shutdown(local_8068,0);
      local_8068 = 0xffffffff;
      DAT_0018a184 = 0;
LAB_00106750:
      local_8060 = 0xffffffff;
LAB_00106794:
      uVar8 = 0xffffffff;
    }
LAB_001065a7:
    if ((local_8078.fd & uVar8) != 0xffffffff) goto LAB_001063c0;
LAB_001065b8:
    if (local_8088 != 0 || local_8080 != 0) goto LAB_001063c0;
LAB_001065d0:
    if ((int)DAT_0010a018 < 1) goto LAB_0010692a;
LAB_001065de:
    *(undefined8 *)(puVar9 + -0x1060) = 0x1065e6;
    close(param_1);
    *(undefined8 *)(puVar9 + -0x1060) = 0x1065f7;
    signal(0xe,FUN_00105330);
    *(undefined8 *)(puVar9 + -0x1060) = 0x106602;
    alarm(DAT_0010a018);
  } while( true );
}

/* ===== 0x106b00  FUN_00106b00 ===== */
void FUN_00106b00(undefined8 param_1,sockaddr *param_2,socklen_t param_3,long param_4)

{
  int __ecode;
  char *pcVar1;
  long in_FS_OFFSET;
  char local_448 [32];
  char local_428 [1032];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_4 == 0) {
    __ecode = getnameinfo(param_2,param_3,local_428,0x401,local_448,0x20,3 - (DAT_0018a178 == 0));
    if (__ecode == -0xb) {
      warn("getnameinfo");
    }
    else if (__ecode == 0) {
      __fprintf_chk(stderr,2,"%s on %s %s\n",param_1,local_428,local_448);
    }
    else {
      pcVar1 = gai_strerror(__ecode);
      warnx("getnameinfo: %s",pcVar1);
    }
    if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
  }
  else if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    __fprintf_chk(stderr,2,"%s on %s\n",param_1,param_4);
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

/* ===== 0x106c20  FUN_00106c20 ===== */
int FUN_00106c20(char *param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  long in_FS_OFFSET;
  socklen_t local_ac;
  sockaddr local_a8 [7];
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = FUN_00105bb0(param_1,local_a8,&local_ac);
  if (iVar1 != -1) {
    iVar1 = socket(1,2 - (DAT_0018a150 == 0) | param_2,0);
    if (iVar1 != -1) {
      if (*param_1 != '@') {
        unlink(param_1);
      }
      iVar2 = bind(iVar1,local_a8,local_ac);
      if (iVar2 != -1) {
        if (DAT_0018a148 != 0) {
          FUN_00106b00("Bound",0,0,param_1);
        }
        goto LAB_00106cb1;
      }
      piVar3 = __errno_location();
      iVar2 = *piVar3;
      close(iVar1);
      *piVar3 = iVar2;
    }
  }
  iVar1 = -1;
LAB_00106cb1:
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
