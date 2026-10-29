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

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PARENT_FOLDER_PATH=$(dirname "$SCRIPT_DIR")
PLUGINNAME=$(basename "$PARENT_FOLDER_PATH")

POTFILE=$PLUGINNAME.pot
LOCALES=$PARENT_FOLDER_PATH/locales

# check if xgettext is installed
if ! command -v xgettext &>/dev/null; then
    echo "Error: xgettext is not installed"
    exit 1
fi

# if no exist locales folder, create it
if [ ! -d "$LOCALES" ]; then
    mkdir $LOCALES
fi

INIT_PWD=$PWD
if [ ! "$PARENT_FOLDER_PATH" = "$INIT_PWD" ]; then
    cd $PARENT_FOLDER_PATH
fi

# Clean existing file
rm -f $LOCALES/$POTFILE && touch $LOCALES/$POTFILE >/dev/null

# LC_ALL=C evita que las referencias de Twig salgan como "entrada estándar:N".
export LC_ALL=C
echo Searching PHP files...
# Append locales from PHP
xgettext $(find . \( -path ./vendor -o -path ./tools -o -path ./docs \) -prune -o -type f -name "*.php" -print) -o $LOCALES/$POTFILE -L PHP --add-comments=TRANS --from-code=UTF-8 --force-po --join-existing \
    --keyword=__:1,2t -d $PLUGINNAME --copyright-holder "TICgal" >/dev/null 2>&1

echo Searching JS files...
# Append locales from JavaScript
xgettext $(find . \( -path ./vendor -o -path ./tools -o -path ./docs \) -prune -o -type f -name "*.js" -print) -o $LOCALES/$POTFILE -L JavaScript --add-comments=TRANS --from-code=UTF-8 --force-po --join-existing \
    --keyword=__:1,2t -d $PLUGINNAME --copyright-holder "TICgal" >/dev/null 2>&1

echo Searching TWIG files...
# Append locales from Twig templates
for file in $(find ./templates -type f -name "*.twig"); do
    # 1. Convert file content to replace "{{ function(.*) }}" by "<?php function(.*); ?>" and extract strings via std input
    # 2. Replace "standard input:line_no" by file location in po file comments
    contents=$(cat $file | sed -r "s|\{\{\s*([a-z0-9_]+\(.*\))\s*\}\}|<?php \1; ?>|gi")
    cat $file | perl -0pe "s/\{\{(.*?)\}\}/<?php \1; ?>/gism" | xgettext - -o $LOCALES/$POTFILE -L PHP --add-comments=TRANS --from-code=UTF-8 --force-po --join-existing \
        --keyword=__:1,2t -d $PLUGINNAME --copyright-holder "TICgal"
    sed -i -r "s|standard input:([0-9]+)|$(echo $file | sed "s|./||"):\1|g" $LOCALES/$POTFILE
done

#Update main language
LANG=C msginit --no-translator -i $LOCALES/$POTFILE -l en_GB -o $LOCALES/en_GB.po

### for using tx :
##tx set --execute --auto-local -r GLPI.glpipot 'locales/<lang>.po' --source-lang en_GB --source-file locales/glpi.pot
## tx push -s
## tx pull -a

cd $LOCALES

sed -i "s/SOME DESCRIPTIVE TITLE/$PLUGINNAME Glpi Plugin/" $POTFILE
sed -i "s/FIRST AUTHOR <EMAIL@ADDRESS>, YEAR./TICgal, $(date +%Y)/" $POTFILE
sed -i "s/YEAR/$(date +%Y)/" $POTFILE

#Update all languages with localazy
if command -v localazy &>/dev/null; then
    if [ -f "localazy.keys.json" ] && [ -f "localazy.json" ]; then
        localazy upload
        localazy download
    else
        echo "Missing credentials to update translations"
    fi
fi

#Compile all languages
for a in $(ls *.po); do
    msgmerge -U $a $POTFILE
    msgfmt $a -o "${a%.*}.mo"
done
rm -f *.po~

cd $INIT_PWD