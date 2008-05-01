#!/bin/sh

echo "/*"
echo " * intl_table.h - Translation table for Amiga."
echo " *"
echo " * Autogenerated by genintltable.sh, DO NOT EDIT !!!"
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
echo "static int intl_translate_text_table[][countof(language_table)] = {"

while read data
do
  ok="no"
  case ${data%%_*} in
    ID*)
           echo "/* en */ {"$data","
           echo "/* de */  "$data"_DE,"
           echo "/* fr */  "$data"_FR,"
           echo "/* hu */  "$data"_HU,"
           echo "/* it */  "$data"_IT,"
           echo "/* nl */  "$data"_NL,"
           echo "/* pl */  "$data"_PL,"
           echo "/* sv */  "$data"_SV},"
           echo ""
           ok="yes"
    ;;
  esac
  if test $ok = "no";
  then
    echo "$data"
  fi
done

echo "};"
