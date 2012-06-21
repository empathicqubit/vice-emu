
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* #define DEBUG */

#ifdef DEBUG
#define DBG(_x) printf _x
#else
#define DBG(_x)
#endif

typedef struct _ITEM
{
    struct _ITEM *next;
    char *string;
    char *desc;
    int flags;
} ITEM;

ITEM *list_findstr(ITEM *list, char *str)
{
    ITEM *itm = list;
    while (itm) {
        /* DBG((">%s|%s\n",itm->string, str)); */
        if (itm->string) {
            if (!strcasecmp(itm->string, str)) {
                return itm;
            }
        }
        itm = itm->next;
    }
    return NULL;
}

ITEM *list_addstr(ITEM *list, char *str)
{
    ITEM *itm;

    if ((str == NULL) || (*str == 0)) {
        return list;
    }

    itm = list_findstr(list, str);
    if (itm) {
        return itm;
    }
    itm = malloc(sizeof(ITEM));
    itm->flags=0;
    itm->desc=NULL;
    itm->string = strdup(str);
    itm->next = list->next;
    list->next = itm;
    return itm;
}

int skipblank(FILE *f)
{
    int c;
    while(!feof(f)) {
        c = fgetc(f);
        if (c == EOF) {
            return 0;
        }
        if ((c != ' ') && (c != '\n') && (c != '\t')) {
            break;
        }
    }
    return c;
}

int skipuntil(FILE *f, int s)
{
    int c;
    while(!feof(f)) {
        c = fgetc(f);
        if (c == s) {
            break;
        }
    }
    return c;
}

int getstr(FILE *f, char *str)
{
    int c;
    while(!feof(f)) {
        c = fgetc(f);
        if ((c == EOF) || (c == ' ') || (c == '\n') || (c == '\t') || (c == ',') || (c == '=')) {
            break;
        }
        *str++ = c;
    }
    *str = 0;
    return c;
}

#define IS_PLUS4        (1<<0)
#define IS_CBM2         (1<<1)
#define IS_B500         (1<<2)
#define IS_PET          (1<<3)
#define IS_VIC20        (1<<4)
#define IS_DTV          (1<<5)
#define IS_C128         (1<<6)
#define IS_VSID         (1<<7)
#define IS_C64          (1<<8)
#define IS_C64SC        (1<<9)

#define IS_CARTCONV     (1<<10)
#define IS_PETCAT       (1<<11)
#define IS_C1541        (1<<12)

const char *emustring[0x10] = {
    "PLUS4",
    "CBM-II",
    "CBM-II-5x0",
    "PET",
    "VIC20",
    "C64DTV",
    "C128",
    "VSID",
    "C64",
    "C64SC",
    "cartconv",
    "petcat",
    "c1541"
};

/* ignore these when listing resources with no description */
const char *nodescexcept[] = {
    "Drive11RAM8000",
    "Drive11RAM6000",
    "Drive11RAM4000",
    "Drive11RAM2000",
    "Drive10RAMA000",
    "Drive10RAM8000",
    "Drive10RAM6000",
    "Drive10RAM4000",
    "Drive10RAM2000",
    "Drive9RAMA000",
    "Drive9RAM8000",
    "Drive9RAM6000",
    "Drive9RAM4000",
    "Drive9RAM2000",
    "Drive8RAMA000",
    "Drive8RAM8000",
    "Drive8RAM6000",
    "Drive8RAM4000",
    "Drive8RAM2000",
    "DosName1001",
    "DosName4040",
    "DosName3040",
    "DosName2040",
    "DosName2031",
    "DosName4000",
    "DosName2000",
    "DosName1581",
    "DosName1571cr",
    "DosName1571",
    "DosName1570",
    "DosName1541ii",
    "DosName1541",
    "Drive10IdleMethod",
    "Drive9IdleMethod",
    "Drive8IdleMethod",
    "Drive10ExtendImagePolicy",
    "Drive9ExtendImagePolicy",
    "Drive8ExtendImagePolicy",
    "Drive10ProfDOS",
    "Drive9ProfDOS",
    "Drive8ProfDOS",
    "Drive10ParallelCable",
    "Drive9ParallelCable",
    "Drive8ParallelCable",
    "Drive11Type",
    "Drive10Type",
    "Drive9Type",
    "Drive8Type",
    "FSDevice10Dir",
    "FSDevice9Dir",
    "FSDevice8Dir",
    "FSDevice10HideCBMFiles",
    "FSDevice9HideCBMFiles",
    "FSDevice8HideCBMFiles",
    "FSDevice10SaveP00",
    "FSDevice9SaveP00",
    "FSDevice8SaveP00",
    "FSDevice10ConvertP00",
    "FSDevice9ConvertP00",
    "FSDevice8ConvertP00",
    "KeymapBusinessDESymFile",
    "KeymapGraphicsSymFile",
    "KeymapBusinessUKSymFile",
    "JoyDevice3",
    "JoyDevice2",
    "JoyDevice1",
    "RsDevice3Baud",
    "RsDevice2Baud",
    "RsDevice1Baud",
    "RsDevice3",
    "RsDevice2",
    "RsDevice1",
    "Printer4Output",
    "Printer4Driver",
    "Printer4",
    "Printer4TextDevice",
    "PrinterTextDevice2",
    "PrinterTextDevice1",
    "IDE64AutodetectSize3",
    "IDE64AutodetectSize2",
    "IDE64AutodetectSize1",
    "IDE64Sectors3",
    "IDE64Sectors2",
    "IDE64Sectors1",
    "IDE64Heads3",
    "IDE64Heads2",
    "IDE64Heads1",
    "IDE64Cylinders3",
    "IDE64Cylinders2",
    "IDE64Cylinders1",
    "IDE64Image3",
    "IDE64Image2",
    "IDE64Image1",
    "GenericCartridgeFileA000",
    "GenericCartridgeFile6000",
    "GenericCartridgeFile4000",
    "GenericCartridgeFile2000",
    "RAMBlock3",
    "RAMBlock2",
    "RAMBlock1",
    "RAMBlock0",
    "Cart4Name",
    "Cart2Name",
    "Cart1Name",
    "Cart6Name",
    "Ram6",
    "Ram4",
    "Ram2",
    "Ram1",
    "Ram08",
    "Window1Xpos",
    "Window1Height",
    "Window1Width",
    "Window0Xpos",
    "Window0Height",
    "Window0Width",
    "CIA1Model",
    "KeySet2West",
    "KeySet2SouthWest",
    "KeySet2South",
    "KeySet2SouthEast",
    "KeySet2East",
    "KeySet2NorthEast",
    "KeySet2North",
    "KeySet2NorthWest",
    "KeySet1West",
    "KeySet1SouthWest",
    "KeySet1South",
    "KeySet1SouthEast",
    "KeySet1East",
    "KeySet1NorthEast",
    "KeySet1North",
    "KeySet1NorthWest",
    "RomsetDosName1571cr",
    "RomsetDosName1001",
    "RomsetDosName4040",
    "RomsetDosName3040",
    "RomsetDosName2040",
    "RomsetDosName2031",
    "RomsetDosName4000",
    "RomsetDosName2000",
    "RomsetDosName1581",
    "RomsetDosName1571",
    "RomsetDosName1570",
    "RomsetDosName1541ii",
    "RomsetDosName1541",
    "RomsetKernal64Name",
    "RomsetBasicHiName",
    "RomsetBasicLoName",
    "RomsetKernalSEName",
    "RomsetKernalNOName",
    "RomsetKernalITName",
    "RomsetKernalFRName",
    "RomsetKernalFIName",
    "RomsetKernalDEName",
    "RomsetKernalIntName",
    "RomsetChargenSEName",
    "RomsetChargenFRName",
    "RomsetChargenDEName",
    "RomsetChargenIntName",
    "RomsetCart4Name",
    "RomsetCart2Name",
    "RomsetCart1Name",
    "RomsetH6809RomEName",
    "RomsetH6809RomDName",
    "RomsetH6809RomCName",
    "RomsetH6809RomBName",
    "RomsetH6809RomAName",
    "RomsetRomModuleBName",
    "RomsetRomModuleAName",
    "RomsetRomModule9Name",
    "RomsetEditorName",
    "RomsetFunctionLowName",
    "RomsetBasicName",
    "RomsetKernalName",
    "AttachDevice8Readonly",
    "AttachDevice9Readonly",
    "AttachDevice10Readonly",
    "IECDevice10",
    "IECDevice9",
    "IECDevice8",
    "IECDevice4",
    "FileSystemDevice8",
    "FileSystemDevice9",
    "FileSystemDevice10",
    "H6809RomAName",
    "H6809RomBName",
    "H6809RomCName",
    "H6809RomDName",
    "H6809RomEName",
    "BasicLoName",
    "KernalNOName",
    "KernalITName",
    "KernalFRName",
    "KernalFIName",
    "KernalDEName",
    "KernalIntName",
    "ChargenFRName",
    "ChargenDEName",
    "ChargenIntName",

    NULL
};

ITEM reslistrc = { NULL, NULL, 0};
ITEM reslisttex = { NULL, NULL, 0};
ITEM reslisttexitm = { NULL, NULL, 0};
ITEM reslistnew = { NULL, NULL, 0};

ITEM optlistvice = { NULL, NULL, 0};
ITEM optlisttex = { NULL, NULL, 0};
ITEM optlisttex2 = { NULL, NULL, 0};
ITEM optlisttexitm = { NULL, NULL, 0};
ITEM optlistnew = { NULL, NULL, 0};

int readtexi(FILE *tf)
{
    int c,cl = 0;
    char tmp[0x100];
    char tmp1[0x10][0x100];
    char tmp2[0x100];
    char tmpc[0x100];
    char tmpmsg[0x100];
    char *msg,*str;
    char *t;
    int status = 0;
    ITEM *itm;
    int itmcnt;
    int n;

    msg = &tmpmsg[0];
    itmcnt = 0;
    while(!feof(tf)) {
        c = fgetc(tf);
        /* printf("[%c:%02x]",c,c); */
        if (c == '@')
        {
            fscanf(tf, "%s ", tmp);
            cl = 0;
            if (!strcmp(tmp, "vindex")) {
                itmcnt = 0;
                c = getstr(tf, tmp1[itmcnt]);
                DBG(("resource '%s'\n",tmp1[itmcnt]));
                list_addstr(&reslisttex, tmp1[itmcnt]);
                if (c != '\n') c = skipuntil(tf, '\n');
                status = 0x01;
                itmcnt++;
            } else if (!strcmp(tmp, "cindex")) {
                c = getstr(tf, tmp1[itmcnt]);
                if ((tmp1[itmcnt][0] == '-') || (tmp1[itmcnt][0] == '+')) {
                    list_addstr(&optlisttex, tmp1[itmcnt]);
                    DBG(("option '%s' ",tmp1[itmcnt]));
                    itmcnt++;
                    if (c == ',') {
                        tmp1[itmcnt][0] = skipblank(tf);
                        c = getstr(tf, &tmp1[itmcnt][1]);
                        list_addstr(&optlisttex, tmp1[itmcnt]);
                        DBG(("/ '%s' ",tmp1[itmcnt]));
                        itmcnt++;
                    }
                    DBG(("\n"));
                } else {
                    list_addstr(&optlisttex2, tmpc);
                }
                if (c != '\n') c = skipuntil(tf, '\n');
                status = 0x02;
            } else if (!strcmp(tmp, "item")) {
                c = getstr(tf, tmp2);
                DBG(("item '%s'\n",tmp2));
                if ((tmp2[0] == '-') || (tmp2[0] == '+')) {
                    list_addstr(&optlisttexitm, tmp2);
                } else {
                    list_addstr(&reslisttexitm, tmp2);
                }
                if (c != '\n') c = skipuntil(tf, '\n');
                status |= 0x10;
            } else if (!strcmp(tmp, "itemx")) {
                c = getstr(tf, tmp2);
                DBG(("itemx '%s'\n",tmp2));
                if ((tmp2[0] == '-') || (tmp2[0] == '+')) {
                    list_addstr(&optlisttexitm, tmp2);
                } else {
                    list_addstr(&reslisttexitm, tmp2);
                }
                if (c != '\n') c = skipuntil(tf, '\n');
                status |= 0x20;
            } else if (!strcmp(tmp, "c")) {
                skipuntil(tf, '\n');
                status = 0;
            } else {
                goto checkmsg;
            }
        } else {
checkmsg:
            if ((status & 0xf00) != 0) {
                    /* DBG(("<%02x %02x>\n",status,c)); */
                if (c == '\n') {
                    /* DBG(("<MSG STOP>\n")); */
                    *msg++ = 0;
                    for (n=0;n<itmcnt;n++) {
                        /* printf("%02x %s\n\t%s\n",status,tmp1[n],tmpmsg); */
                        if ((status & 0x0f) == 1) {
                            itm = list_findstr(&reslisttex, tmp1[n]);
                        } else if ((status & 0x0f) == 2) {
                            itm = list_findstr(&optlisttex, tmp1[n]);
                        }
                        if (itm) {
                            if (itm->desc) {
                                free(itm->desc);
                            }
                            itm->desc = strdup(tmpmsg);
                        }
                    }
                    itmcnt = 0;
                    status = 0;
                } else {
                    *msg++ = c;
                }
            } else {
                if( ((status & 0x00f) != 0) &&
                    ((status & 0x0f0) != 0) &&
                    ((status & 0xf00) == 0)
                    ) {
                        status |= 0x100;
                        /* DBG(("<MSG START %02x '%c'>\n",status,c)); */
                        msg = &tmpmsg[0];
                        *msg++ = c;
                    }
            }
        }

    }
}

int readvicerc(FILE *tf, char *emu, int tag)
{
    char tmp[0x100];
    int c;
    ITEM *itm;
    fseek(tf,0,SEEK_SET);
    while(!feof(tf)) {
        skipuntil(tf, '[');
        c = fscanf(tf,"%s",tmp);
        if (c < 1) {
            break;
        }
        tmp[strlen(tmp)-1]=0;
        DBG(("tag %d '%s'\n",c,tmp));
        if (!strcmp(emu, tmp)) {
            break;
        }
    }

    while(!feof(tf)) {
        c = skipblank(tf);
        if (c == '[') {
            break;
        }
        tmp[0] = c;
        c = getstr(tf, &tmp[1]);
        DBG(("resource '%s'\n",tmp));
        itm = list_addstr(&reslistrc, tmp);
        itm->flags |= tag;
        skipuntil(tf, '\n');
    }

}

int readviceopt(FILE *tf, char *emu, int tag)
{
    char tmp[0x100];
    int c;
    ITEM *itm;
    DBG(("reading opts for '%s'\n",emu));
    fseek(tf,0,SEEK_SET);
    while(!feof(tf)) {
        skipuntil(tf, '[');
        c = fscanf(tf,"%s",tmp);
        if (c < 1) {
            break;
        }
        tmp[strlen(tmp)-1]=0;
        DBG(("tag %d '%s'\n",c,tmp));
        if (!strcasecmp(emu, tmp)) {
            break;
        }
    }

    while(!feof(tf)) {
        c = skipblank(tf);
        if (c == '[') {
            break;
        }
        DBG(("option '%c'\n",c));

        if ((c=='-')||(c=='+')) {
            tmp[0] = c;
            c = getstr(tf, &tmp[1]);

            DBG(("option '%s'\n",tmp));
            itm = list_addstr(&optlistvice, tmp);
            itm->flags |= tag;
        } else {
            c = getstr(tf, &tmp[0]);
            DBG(("not option '%s'\n",tmp));
        }
        skipuntil(tf, '\n');
    }

}

int printlist(ITEM *list, char *hdr, int flags)
{
    int i = 0,ii,n = 0;
    while (list) {
        if (list->string) {
            if (flags) {
                if (list->flags == flags) {
                    if ( 1
                        && (strcmp(list->string, "-<version>") != 0)
                        ) {
                        if (i == 0) {
                            printf("\n[%s]\n\n", hdr);i++;
                        }
                        printf("%s\n", list->string);
                    }
                }
            } else {
                if (1
                    && (list->flags != IS_C64SC)
                    && (list->flags != IS_C64)
                    && (list->flags != IS_VSID)
                    && (list->flags != IS_C128)
                    && (list->flags != IS_DTV)
                    && (list->flags != IS_VIC20)
                    && (list->flags != IS_PET)
                    && (list->flags != IS_B500)
                    && (list->flags != IS_PLUS4)
                    && (list->flags != IS_CBM2)
                    && (list->flags != IS_CARTCONV)
                    && (list->flags != IS_PETCAT)
                    && (list->flags != IS_C1541)
                    ){
                    if (i == 0) {
                        printf("\n%s\n\n", hdr);i++;
                    }
                    printf("%-40s", list->string);
                    for (i=0;i<10;i++) {
                        if (list->flags & (1<<i)) {
                            printf("%s  ", emustring[i]);
                        } else {
                            for (ii=0;ii<(strlen(emustring[i])+2);ii++) {
                                printf(" ");
                            }
                        }
                    }
                    printf("\n");
                }
            }
            n++;
        }
        list = list->next;
    }
    return n;
}

int strinlist(char *str, const char *list[])
{
    while (*list) {
        if (!strcmp(str, *list)) {
            return 1;
        }
        ++list;
    }
    return 0;
}

void checkresources(void)
{
    ITEM *list1, *itm, *itm2;
    int i;

    printf("\n** checking resources...\n\n");

    printf("The following resources are incorrectly marked '@cindex'\n"
           "fix them first to use '@vindex' and then check again:\n\n");

    list1 = &reslistrc;
    i = 0;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&optlisttex2, list1->string);
            if (itm) {
                printf("%s\n", list1->string);
                i++;
            }
        }
        list1 = list1->next;
    }
    if (i == 0) {
        printf("none - well done.\n");
    }

    printf("\nThe following resources do not appear in '@vindex'.\n"
           "fix them first to use '@vindex' and then check again:\n\n");

    list1 = &reslisttexitm;
    i = 0;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&reslistrc, list1->string);
            if (itm) {
                itm = list_findstr(&reslisttex, list1->string);
                if (!itm) {
                    printf("%s\n", list1->string);
                    i++;
                }
            }
        }
        list1 = list1->next;
    }
    if (i == 0) {
        printf("none - well done.\n");
    } else {
        printf("\nnote: each resource should get a seperate '@vindex' entry\n"
                 "      in the form '@vindex resourcename'.\n");
    }
    printf("\n");

    list1 = &reslistrc;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&reslisttex, list1->string);
            if (itm) {
                DBG(("found resource: %s\n", list1->string));
            } else {
                DBG(("'%s'\n", list1->string));
                itm2=list_addstr(&reslistnew, list1->string);
                DBG(("'%s'\n", itm2->string));
                itm2->flags=list1->flags;
            }
        }
        list1 = list1->next;
    }
    printf("The following resources appear in vicerc but not in the documentation, so\n"
           "they might be missing in the documentation:\n\n");
    i = 0;
    i += printlist(&reslistnew, "global", 0);
    i += printlist(&reslistnew, "C64SC", IS_C64SC);
    i += printlist(&reslistnew, "C64", IS_C64);
    i += printlist(&reslistnew, "VSID", IS_VSID);
    i += printlist(&reslistnew, "C128", IS_C128);
    i += printlist(&reslistnew, "C64DTV", IS_DTV);
    i += printlist(&reslistnew, "VIC20", IS_VIC20);
    i += printlist(&reslistnew, "PET", IS_PET);
    i += printlist(&reslistnew, "CBM-II-5x0", IS_B500);
    i += printlist(&reslistnew, "CBM-II", IS_CBM2);
    i += printlist(&reslistnew, "PLUS4", IS_PLUS4);

    if (i == 0) {
        printf("none - well done.\n");
    }
    printf("\n");
    
    printf("The following resources appear to have no description: ");

    list1 = &reslisttex;
    i = 0;
    while (list1) {
        if (list1->string) {
            if (list1->desc == NULL) {
                if (!strinlist(list1->string, nodescexcept)) {
                    i++;
                }
            }
        }
        list1 = list1->next;
    }
    printf("(%d)\n\n", i);

    list1 = &reslisttex;
    i = 0;
    while (list1) {
        if (list1->string) {
            if (list1->desc == NULL) {
                if (!strinlist(list1->string, nodescexcept)) {
                    printf("%s\n", list1->string);
                    i++;
                }
            }
        }
        list1 = list1->next;
    }

    if (i == 0) {
        printf("none - well done.\n");
    }
    printf("\n");

    printf("The following resources appear in the documentation but not in vicerc, so\n"
           "they might be outdated or spelled incorrectly:\n\n");

    list1 = &reslisttex;
    i = 0;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&reslistrc, list1->string);
            if (itm) {
                DBG(("found: %s\n", list1->string));
            } else {
                printf("%-40s", list1->string);
                if(0
                    || !strcmp(list1->string, "MITSHM")
                    || !strcmp(list1->string, "UseXSync")
                  ) {
                    printf("(might be disabled)");
                } else {
                    i++;
                }
                printf("\n");
            }
        }
        list1 = list1->next;
    }
    printf("\n");

    if (i == 0) {
        printf("none - well done.\n");
    }
}

void checkoptions(void)
{
    ITEM *list1, *itm, *itm2;
    int i;

    printf("\n** checking command line options...\n\n");

    printf("The following look like options, but they do not appear in '@cindex'.\n"
           "fix them first to use '@cindex' and then check again:\n\n");

    list1 = &optlisttexitm;
    i = 0;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&optlisttex, list1->string);
            if (!itm) {
                if ( 1
                    && (strcmp(list1->string,"--") != 0)
                    && (strcmp(list1->string,"----") != 0)
                    && (strcmp(list1->string,"-<version>") != 0)
                ) {
                    printf("%s\n", list1->string);
                    i++;
                }
            }
        }
        list1 = list1->next;
    }
    if (i == 0) {
        printf("none - well done.\n");
    }
    printf("\n");

    list1 = &optlistvice;
    i = 0;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&optlisttex, list1->string);
            if (itm) {
                DBG(("found option: %s\n", list1->string));
            } else {
                if ( 1
                    && (strcmp(list1->string,"--") != 0)
                    && (strcmp(list1->string,"-<version>") != 0)
                ) {
                    DBG(("'%s'\n", list1->string));
                    itm2=list_addstr(&optlistnew, list1->string);
                    DBG(("'%s'\n", itm2->string));
                    itm2->flags=list1->flags;
                    i++;
                }
            }
        }
        list1 = list1->next;
    }
    printf("The following options appear in vice but not in the documentation, so\n"
           "they might be missing in the documentation (%d):\n\n", i);

    if (i == 0) {
        printf("none - well done.\n");
    } else {
        printlist(&optlistnew, "global", 0);
        printlist(&optlistnew, "C64SC", IS_C64SC);
        printlist(&optlistnew, "C64", IS_C64);
        printlist(&optlistnew, "VSID", IS_VSID);
        printlist(&optlistnew, "C128", IS_C128);
        printlist(&optlistnew, "C64DTV", IS_DTV);
        printlist(&optlistnew, "VIC20", IS_VIC20);
        printlist(&optlistnew, "PET", IS_PET);
        printlist(&optlistnew, "CBM-II-5x0", IS_B500);
        printlist(&optlistnew, "CBM-II", IS_CBM2);
        printlist(&optlistnew, "PLUS4", IS_PLUS4);

        printlist(&optlistnew, "petcat", IS_PETCAT);
        printlist(&optlistnew, "cartconv", IS_CARTCONV);
        printlist(&optlistnew, "c1541", IS_C1541);
    }

    printf("\nThe following options appear to have no description: ");

    list1 = &optlisttex;
    i = 0;
    while (list1) {
        if (list1->string) {
            if (list1->desc == NULL) {
                i++;
            }
        }
        list1 = list1->next;
    }
    printf("(%d)\n\n", i);

    list1 = &optlisttex;
    i = 0;
    while (list1) {
        if (list1->string) {
            if (list1->desc == NULL) {
                printf("%s\n", list1->string);
                i++;
            }
        }
        list1 = list1->next;
    }

    if (i == 0) {
        printf("none - well done.\n");
    }
    printf("\n");

    printf("The following options appear in the documentation but not in vice, so\n"
           "they might be outdated or spelled incorrectly:\n\n");

    list1 = &optlisttex;
    i = 0;
    while (list1) {
        DBG(("check: %s\n", list1->string));
        if (list1->string) {
            itm = list_findstr(&optlistvice, list1->string);
            if (itm) {
                DBG(("found: %s\n", list1->string));
            } else {
                printf("%-40s", list1->string);
                if(0
                    || !strcmp(list1->string, "-xsync")
                    || !strcmp(list1->string, "+xsync")
                    || !strcmp(list1->string, "-mitshm")
                    || !strcmp(list1->string, "+mitshm")
                  ) {
                    printf("(might be disabled)");
                } else {
                    i++;
                }
                printf("\n");
            }
        }
        list1 = list1->next;
    }
    printf("\n");

    if (i == 0) {
        printf("none - well done.\n");
    }
}

char *vicercname;
char *viceoptname;
char *vicetexiname;
int checkopt = 0;
int checkres = 0;

int main(int argc, char *argv[])
{
FILE *tf;
    
    if (argc != 5) {
        printf("checkdoc - scan vice.texi for some common problems\n\n");
        printf("usage: checkdoc [-all | -opt | -res] texifile vicerc optsfile\n");
        exit(-1);
    }

    if (!strcmp(argv[1],"-all")) {
        checkopt++;
        checkres++;
    }
    if (!strcmp(argv[1],"-opt")) {
        checkopt++;
    }
    if (!strcmp(argv[1],"-res")) {
        checkres++;
    }

    vicetexiname = argv[2];
    vicercname = argv[3];
    viceoptname = argv[4];

    printf("** initializing...\n\n");

    tf = fopen(vicetexiname,"rb");
    if (!tf) {
        fprintf(stderr, "error: couldn't open %s.\n", vicetexiname);
        exit(-1);
    }
    printf("reading %s.\n", vicetexiname);
    readtexi(tf);
    fclose(tf);

    tf = fopen(vicercname,"rb");
    if (!tf) {
        fprintf(stderr, "error: couldn't open %s.\n", vicercname);
        exit(-1);
    }
    printf("reading %s.\n", vicercname);
    readvicerc(tf,"PLUS4", IS_PLUS4);
    readvicerc(tf,"CBM-II", IS_CBM2);
    readvicerc(tf,"CBM-II-5x0", IS_B500);
    readvicerc(tf,"PET", IS_PET);
    readvicerc(tf,"VIC20", IS_VIC20);
    readvicerc(tf,"C64DTV", IS_DTV);
    readvicerc(tf,"C128", IS_C128);
    readvicerc(tf,"VSID", IS_VSID);
    readvicerc(tf,"C64", IS_C64);
    readvicerc(tf,"C64SC", IS_C64SC);
    fclose(tf);

    tf = fopen(viceoptname,"rb");
    if (!tf) {
        fprintf(stderr, "error: couldn't open %s.\n", viceoptname);
        exit(-1);
    }
    printf("reading %s.\n", viceoptname);
    readviceopt(tf,"PLUS4", IS_PLUS4);
    readviceopt(tf,"CBM-II", IS_CBM2);
    readviceopt(tf,"CBM-II-5x0", IS_B500);
    readviceopt(tf,"PET", IS_PET);
    readviceopt(tf,"VIC20", IS_VIC20);
    readviceopt(tf,"C64DTV", IS_DTV);
    readviceopt(tf,"C128", IS_C128);
    readviceopt(tf,"VSID", IS_VSID);
    readviceopt(tf,"C64", IS_C64);
    readviceopt(tf,"C64SC", IS_C64SC);
    readviceopt(tf,"petcat", IS_PETCAT);
    readviceopt(tf,"cartconv", IS_CARTCONV);
    readviceopt(tf,"c1541", IS_C1541);
    fclose(tf);

    if (checkres) {
        checkresources();
    }
    if (checkopt) {
        checkoptions();
    }
    return 0;
}
