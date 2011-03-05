#!/bin/sh
#
# geninfocontrib_h.sh - infocontrib.h generator script
#
# written by Marco van den Heuvel <blackystardust68@yahoo.com>

echo "/*"
echo " * infocontrib.h - Text of contributors to VICE, as used in info.c"
echo " *"
echo " * Autogenerated by geninfocontrib_h.sh, DO NOT EDIT !!!"
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
echo "#ifndef VICE_INFOCONTRIB_H"
echo "#define VICE_INFOCONTRIB_H"
echo ""
echo "const char info_contrib_text[] ="

checkoutput()
{
  dooutput=yes
  case "$data" in
      @c*|"@itemize @bullet"|@item|"@end itemize") dooutput=no ;;
  esac
}

outputok=no
while read data
do
  if test x"$data" = "x@node Copyright, Contacts, Acknowledgments, Top"; then
    echo "\"\\n\";"
    echo "#endif"
    outputok=no
  fi
  if test x"$outputok" = "xyes"; then
    checkoutput
    if test x"$dooutput" = "xyes"; then
      if test x"$data" = "x"; then
        echo "\"\\n\""
      else
        echo "\"  $data\\n\""
      fi
    fi
  fi
  if test x"$data" = "x@chapter Acknowledgments"; then
    outputok=yes
  fi
done
