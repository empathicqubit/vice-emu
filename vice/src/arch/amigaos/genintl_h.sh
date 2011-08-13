#!/bin/sh
#
# genintl_h.sh - intl.h generator script for the AmigaOS ports
#
# written by Marco van den Heuvel <blackystardust68@yahoo.com>

DEBUGBUILD=0

echo "/*"
echo " * intl.h - Localization routines for Amiga."
echo " *"
echo " * Autogenerated by genintl_h.sh, DO NOT EDIT !!!"
echo " *"
echo " * Written by"
echo " *  Marco van den Heuvel <blackystardust68@yahoo.com>"
echo " *"
echo " * This file is part of VICE, the Versatile Commodore Emulator."
echo " * See README for copyright notice."
echo " *"
echo " *  This program is free software; you can redistribute it and/or modify"
echo " *  it under the terms of the GNU General Public License as published by"
echo " *  the Free Software Foundation; either version 2 of the License, or"
echo " *  (at your option) any later version."
echo " *"
echo " *  This program is distributed in the hope that it will be useful,"
echo " *  but WITHOUT ANY WARRANTY; without even the implied warranty of"
echo " *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
echo " *  GNU General Public License for more details."
echo " *"
echo " *  You should have received a copy of the GNU General Public License"
echo " *  along with this program; if not, write to the Free Software"
echo " *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA"
echo " *  02111-1307  USA."
echo " *"
echo " */"
echo ""
echo "#ifndef VICE_INTL_H"
echo "#define VICE_INTL_H"
echo ""
echo "#include \"intl_funcs.h\""
echo ""
echo "enum { ID_START_0=0,"
echo ""

# generating the debug version of intl.h takes
# alot more time, so it only gets done when
# --enable-debug is given.

if test x"$DEBUGBUILD" = "x1"; then
  count=1
  while read data
  do
    ok="no"
    case ${data%%_*} in
      ID*)
           echo $data", /* "$count" */"
           count=`expr $count + 1`
           echo $data"_DA, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_DE, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_FR, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_HU, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_IT, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_KO, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_NL, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_PL, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_RU, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_SV, /* "$count" */"
           count=`expr $count + 1`
           echo $data"_TR, /* "$count" */"
           count=`expr $count + 1`
           ok="yes"
      ;;
    esac
    if test $ok = "no";
    then
      echo "$data"
    fi
  done
else
  while read data
  do
    ok="no"
    case ${data%%_*} in
      ID*)
           echo $data","
           echo $data"_DA,"
           echo $data"_DE,"
           echo $data"_FR,"
           echo $data"_HU,"
           echo $data"_IT,"
           echo $data"_KO,"
           echo $data"_NL,"
           echo $data"_PL,"
           echo $data"_RU,"
           echo $data"_SV,"
           echo $data"_TR,"
           ok="yes"
      ;;
    esac
    if test $ok = "no";
    then
      echo "$data"
    fi
  done
fi

echo "};"
echo "#endif"
