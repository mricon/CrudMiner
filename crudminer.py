#!/usr/bin/python -tt
##
# Copyright (C) 2011 by McGill University
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# $Id$
#
# @Author Konstantin Ryabitsev <konstantin.ryabitsev@mcgill.ca>
# @version $Date$
#

import os, sys
import re

from ConfigParser import ConfigParser
from fnmatch      import fnmatch


CRUDFILE = './crud.ini'

class CrudProduct:

    def __init__(self, name, config):
        self.name    = name
        self.expand  = config.get(name, 'expand')
        self.secure  = config.get(name, 'secure')
        self.comment = config.get(name, 'comment')

        regex = config.get(name, 'regex')

        self.regex = re.compile(regex, re.MULTILINE | re.DOTALL)

        self.isalnum = re.compile('[^a-zA-Z0-9]')

    # Adapted from
    # http://concisionandconcinnity.blogspot.com/2008/12/rpm-style-version-comparison-in-python.html
    def _gen_segments(self, val):
        """
        Generator that splits a string into segments.
        e.g., '2xFg33.+f.5' => ('2', 'xFg', '33', 'f', '5')
        """
        val = self.isalnum.split(val)
        for dot in val:
            res = ''
            for s in dot:
                if not res:
                    res += s
                elif (res.isdigit() and s.isdigit()) or \
                   (res.isalpha() and s.isalpha()):
                    res += s
                else:
                    if res:
                        yield res
                    res = s
            if res:
                yield res

    def version_compare(self, ver1, ver2):
        """
        returns:
            ver1  < ver2  return -1
            ver1 == ver2: return  0
            ver1  > ver2: return  1
        """

        # If they're the same, we're done
        if ver1 == ver2: return 0

        l1, l2 = map(self._gen_segments, (ver1, ver2))
        while l1 and l2:
            # Get the next segment; if none exists, done
            try: s1 = l1.next()
            except StopIteration: s1 = None
            try: s2 = l2.next()
            except StopIteration: s2 = None

            if s1 is None and s2 is None: break
            if (s1 and not s2): return 1
            if (s2 and not s1): return -1

            # Check for type mismatch
            if s1.isdigit() and not s2.isdigit(): return 1
            if s2.isdigit() and not s1.isdigit(): return -1

            # Cast as ints if possible
            if s1.isdigit(): s1 = int(s1)
            if s2.isdigit(): s2 = int(s2)

            rc = cmp(s1, s2)
            if rc: return rc

        return 0

    def analyze(self, contents):
        match = self.regex.search(contents)
        if match is None:
            return None

        got_version = match.expand(self.expand)
        is_secure = False

        if self.secure != 'none' and \
                self.version_compare(got_version, self.secure) >= 0:
            is_secure = True

        return (is_secure, got_version, self.secure, self.comment)

def analyze_dir(rootpath, crudfile, quiet, wantenv=[]):

    config = ConfigParser()
    if crudfile.find('://') > -1:
        import urllib2
        req = urllib2.Request(crudfile)
        crudfp = urllib2.urlopen(req)
    else:
        crudfp = open(crudfile, 'r')

    config.readfp(crudfp)
    
    # walk through sections and build path:[section,]
    # keep the list of filenames in the separate dict for quick matching
    seekpaths = {}
    seekfiles = []
    for section in config.sections():
        if len(wantenv) > 0:
            seekenv  = config.get(section, 'env')
            # do we care about this env?
            if seekenv not in wantenv:
                continue
        seekpath = config.get(section, 'path')
        if seekpath not in seekpaths.keys():
            seekpaths[seekpath] = []

        product = CrudProduct(section, config)

        seekpaths[seekpath].append(product)

        seekfile = os.path.basename(seekpath)
        if seekfile not in seekfiles:
            seekfiles.append(seekfile)
    
    report = []

    for root, dirs, files in os.walk(rootpath):
        if not files:
            continue
        for filename in files:
            if filename not in seekfiles:
                # quick match and discard
                continue
            # slow match against full paths
            for seekpath in seekpaths.keys():
                havepath = os.path.join(root, filename)
                if fnmatch(havepath, '*' + seekpath):
                    installdir = havepath.replace(seekpath, '')
                    fh = open(havepath, 'r')
                    contents = fh.read()
                    fh.close()
                    for product in seekpaths[seekpath]:
                        result = product.analyze(contents) 
                        if result is None:
                            continue
                        status = 'vulnerable'
                        if result[0]:
                            status = 'secure'
                        else:
                            if not quiet:
                                print "[%s] %s found, %s wanted, in %s" % (
                                        product.name, result[1], result[2], 
                                        installdir)
                            
                        report.append((installdir, product.name, 
                                       result[1], result[2], status, result[3]))
                        break

    return report


def main():
    '''
    Main invocation.

    @rtype: void
    '''

    from optparse     import OptionParser

    usage = '''usage: %prog [options] path
    This tool helps find unmaintained web software.
    '''

    parser = OptionParser(usage=usage, version='0.1')
    parser.add_option('--crudfile', dest='crudfile',
        default=CRUDFILE,
        help='Location of the crud.ini file (%default).')
    parser.add_option('-q', '--quiet', dest='quiet', action='store_true',
        default=False,
        help='Do not output anything (usually used with --csv).')
    parser.add_option('-r', '--csv-report', dest='csv', default=None,
        help='Produce a CSV report and save it in a file.')
    parser.add_option('-s', '--report-secure', dest='repsec', 
        action='store_true', default=False,
        help='Include secure versions in the report, as well as vulnerable.')
    parser.add_option('-e', '--environment', dest='env', action='append',
        default=[],
        help='Only analyze for these environments (php, perl, etc). \
              Default: all')

    (opts, args) = parser.parse_args()
    
    if not args:
        parser.error('You must specify a path where to look for crud.')

    rootpath = os.path.abspath(args[0])

    report = analyze_dir(rootpath, opts.crudfile, opts.quiet, opts.env)

    if opts.csv is not None:
        import csv
        out = open(opts.csv, 'w')
        writer = csv.writer(out, quoting=csv.QUOTE_ALL)
        writer.writerow(('path', 'product', 'found', 'secure', 'status',
                         'comment'))
        
        for entry in report:
            if  entry[4] == 'secure' and not opts.repsec:
                continue

            writer.writerow(entry)

        out.close()

        if not opts.quiet:
            print 'CSV report saved in %s' % opts.csv
    
    
if __name__ == '__main__':
    main()
