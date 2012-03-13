#!/usr/bin/python -tt
##
# Copyright (C) 2012 by Konstantin Ryabitsev and contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
from ConfigParser import ConfigParser, NoSectionError
import sys

sys.path.insert(0, '../')

import crudminer

TESTDIR  = '.'
CRUDFILE = '../crud.ini'

def compare_results(want, results):
    assert want in results, \
        '"%s ver %s" not found in results' % (want[0], want[3])

def check_sections(crudsec, testsecs):
    assert crudsec in testsecs, 'section "%s" not found in test.ini' % crudsec

def test_crud():
    report = crudminer.analyze_dir(TESTDIR, CRUDFILE, True)

    results = []
    for (path, crudp, state, foundver) in report:
        results.append((crudp.name, crudp.secure, state, foundver))

    crudcfg = ConfigParser()
    crudcfg.read(CRUDFILE)

    testcfg = ConfigParser()
    testcfg.read(TESTDIR + '/test.ini')

    for section in crudcfg.sections():
        yield check_sections, section, testcfg.sections()

        if section not in testcfg.sections():
            continue

        secure  = crudcfg.get(section, 'secure')
        failver = testcfg.get(section, 'failver')

        testlist = (section, secure, 'vulnerable', failver)

        yield compare_results, testlist, results

        # pop it from the result, so matches are faster
        results.remove(testlist)

