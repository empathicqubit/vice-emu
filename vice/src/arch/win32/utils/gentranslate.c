/*
 * gentranslate - win32 translate.h and translate_table.h generation
 *                helper program.
 *
 * Written by
 *  Marco van den Heuvel <blackystardust68@yahoo.com>
 *
 * This file is part of VICE, the Versatile Commodore Emulator.
 * See README for copyright notice.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307  USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* found definitions */
#define UNKNOWN  0
#define FOUND_ID 1

static char line_buffer[512];

int getline(FILE *file)
{
    char c = 0;
    int counter = 0;

    while (c != '\n' && !feof(file) && counter < 511) {
        c = fgetc(file);
        if (c != 0xd) {
            line_buffer[counter++] = c;
        }
    }
    line_buffer[counter] = 0;

    if (!strncmp(line_buffer, "ID", 2)) {
        line_buffer[counter - 1] = 0;
        return FOUND_ID;
    }

    return UNKNOWN;
}

void generate_translate_h(char *in_filename, char *out_filename)
{
    FILE *infile, *outfile;
    int found = UNKNOWN;

    infile = fopen(in_filename,"rb");
    if (infile == NULL) {
        printf("cannot open %s for reading\n", in_filename);
        return;
    }

    outfile = fopen(out_filename,"wb");
    if (outfile == NULL) {
        printf("cannot open %s for writing\n", out_filename);
        fclose(infile);
        return;
    }

    fprintf(outfile, "/*\n");
    fprintf(outfile, " * translate.h - Global internationalization routines.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " * Autogenerated by gentranslate, DO NOT EDIT !!!\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " * Written by\n");
    fprintf(outfile, " *  Marco van den Heuvel <blackystardust68@yahoo.com>\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " * This file is part of VICE, the Versatile Commodore Emulator.\n");
    fprintf(outfile, " * See README for copyright notice.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " *  This program is free software; you can redistribute it and/or modify\n");
    fprintf(outfile, " *  it under the terms of the GNU General Public License as published by\n");
    fprintf(outfile, " *  the Free Software Foundation; either version 2 of the License, or\n");
    fprintf(outfile, " *  (at your option) any later version.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " *  This program is distributed in the hope that it will be useful,\n");
    fprintf(outfile, " *  but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    fprintf(outfile, " *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    fprintf(outfile, " *  GNU General Public License for more details.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " *  You should have received a copy of the GNU General Public License\n");
    fprintf(outfile, " *  along with this program; if not, write to the Free Software\n");
    fprintf(outfile, " *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA\n");
    fprintf(outfile, " *  02111-1307  USA.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " */\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "#ifndef VICE_TRANSLATE_H\n");
    fprintf(outfile, "#define VICE_TRANSLATE_H\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "#include \"translate_funcs.h\"\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "#define USE_PARAM_STRING   0\n");
    fprintf(outfile, "#define USE_PARAM_ID       1\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "#define USE_DESCRIPTION_STRING   0\n");
    fprintf(outfile, "#define USE_DESCRIPTION_ID       1\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "#define IDGS_UNUSED IDCLS_UNUSED\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "enum { ID_START_65536=65536,\n");
    fprintf(outfile, "IDCLS_UNUSED,\n");
    fprintf(outfile, "\n");

    while (!feof(infile)) {
        found = getline(infile);
        if (found == FOUND_ID) {
            fprintf(outfile, "%s,\n", line_buffer);
            fprintf(outfile, "%s_DA,\n", line_buffer);
            fprintf(outfile, "%s_DE,\n", line_buffer);
            fprintf(outfile, "%s_FR,\n", line_buffer);
            fprintf(outfile, "%s_HU,\n", line_buffer);
            fprintf(outfile, "%s_IT,\n", line_buffer);
            fprintf(outfile, "%s_NL,\n", line_buffer);
            fprintf(outfile, "%s_PL,\n", line_buffer);
            fprintf(outfile, "%s_SV,\n", line_buffer);
            fprintf(outfile, "%s_TR,\n", line_buffer);
        } else {
            if (!feof(infile)) {
                fprintf(outfile, "%s", line_buffer);
            }
        }
    }
    fprintf(outfile, "};\n");
    fprintf(outfile, "#endif\n");

    fclose(infile);
    fclose(outfile);
    return;
}

void generate_translate_table_h(char *in_filename, char *out_filename)
{
    FILE *infile, *outfile;
    int found = UNKNOWN;

    infile = fopen(in_filename, "rb");
    if (infile == NULL) {
        printf("cannot open %s for reading\n", in_filename);
        return;
    }

    outfile = fopen(out_filename, "wb");
    if (outfile == NULL) {
        printf("cannot open %s for writing\n", out_filename);
        fclose(infile);
        return;
    }

    fprintf(outfile, "/*\n");
    fprintf(outfile, " * translate_table.h - Translation table.");
    fprintf(outfile, " *\n");
    fprintf(outfile, " * Autogenerated by gentranslate, DO NOT EDIT !!!\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " * Written by\n");
    fprintf(outfile, " *  Marco van den Heuvel <blackystardust68@yahoo.com>\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " * This file is part of VICE, the Versatile Commodore Emulator.\n");
    fprintf(outfile, " * See README for copyright notice.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " *  This program is free software; you can redistribute it and/or modify\n");
    fprintf(outfile, " *  it under the terms of the GNU General Public License as published by\n");
    fprintf(outfile, " *  the Free Software Foundation; either version 2 of the License, or\n");
    fprintf(outfile, " *  (at your option) any later version.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " *  This program is distributed in the hope that it will be useful,\n");
    fprintf(outfile, " *  but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    fprintf(outfile, " *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    fprintf(outfile, " *  GNU General Public License for more details.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " *  You should have received a copy of the GNU General Public License\n");
    fprintf(outfile, " *  along with this program; if not, write to the Free Software\n");
    fprintf(outfile, " *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA\n");
    fprintf(outfile, " *  02111-1307  USA.\n");
    fprintf(outfile, " *\n");
    fprintf(outfile, " */\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "/* GLOBAL STRING ID TRANSLATION TABLE */\n");
    fprintf(outfile, "\n");
    fprintf(outfile, "static int translate_text_table[][countof(language_table)] = {\n");

    while (!feof(infile)) {
        found = getline(infile);
        if (found == FOUND_ID) {
            fprintf(outfile, "/* en */ {%s,\n", line_buffer);
            fprintf(outfile, "/* da */  %s_DA,\n", line_buffer);
            fprintf(outfile, "/* de */  %s_DE,\n", line_buffer);
            fprintf(outfile, "/* fr */  %s_FR,\n", line_buffer);
            fprintf(outfile, "/* hu */  %s_HU,\n", line_buffer);
            fprintf(outfile, "/* it */  %s_IT,\n", line_buffer);
            fprintf(outfile, "/* nl */  %s_NL,\n", line_buffer);
            fprintf(outfile, "/* pl */  %s_PL,\n", line_buffer);
            fprintf(outfile, "/* sv */  %s_SV,\n", line_buffer);
            fprintf(outfile, "/* tr */  %s_TR},\n", line_buffer);
        } else {
            if (!feof(infile)) {
                fprintf(outfile, "%s", line_buffer);
            }
        }
    }
    fprintf(outfile, "};\n");

    fclose(infile);
    fclose(outfile);
    return;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("too few arguments\n");
        exit(1);
    }

    generate_translate_h(argv[1], argv[2]);
    generate_translate_table_h(argv[1], argv[3]);

    return 0;
}
