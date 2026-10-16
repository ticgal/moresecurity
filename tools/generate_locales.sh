#!/bin/bash

#
# -------------------------------------------------------------------------
# More Security plugin for GLPI
# Copyright (C) 2026 by the TICGAL Team.
# https://www.tic.gal
# -------------------------------------------------------------------------
# LICENSE
# This file is part of the More Security plugin.
# More Security plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# More Security plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with More Security. If not, see <http://www.gnu.org/licenses/>.
# -------------------------------------------------------------------------
# @author    the TICGAL team
# @copyright Copyright (c) 2022-2026 TICGAL team
# @license   AGPL License 3.0 or (at your option) any later version
# @link      https://www.tic.gal
# @package   More Security
# @since     2022
#            http://www.gnu.org/licenses/agpl-3.0-standalone.html
# -------------------------------------------------------------------------
#

CUR_PATH="`dirname \"$0\"`"

cd "$CUR_PATH/.."

xgettext *.php */*.php -o locales/moresecurity.pot -L PHP --add-comments=TRANS --from-code=UTF-8 --force-po -k --keyword=__:1,2t --keyword=_x:1,2,3t --keyword=__s:1,2t --keyword=_sx:1,2,3t --keyword=_n:1,2,3,4t --keyword=_sn:1,2t --keyword=_nx:1,2,3t --copyright-holder "TICgal"

cd locales

sed -i "s/SOME DESCRIPTIVE TITLE/Gapp Extended Glpi Plugin/" moresecurity.pot
sed -i "s/FIRST AUTHOR <EMAIL@ADDRESS>, YEAR./TICgal, $(date +%Y)/" moresecurity.pot
sed -i "s/YEAR/$(date +%Y)/" moresecurity.pot

localazy upload
localazy download

for a in $(ls *.po); do
	msgmerge -U $a moresecurity.pot
	msgfmt $a -o "${a%.*}.mo"
done
rm -f *.po~