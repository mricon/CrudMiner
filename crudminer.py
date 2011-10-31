#!/usr/bin/python -tt
#
# Copyright (C) 2011 by McGill University and contributors
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
# @Author Konstantin Ryabitsev <konstantin.ryabitsev@mcgill.ca>
# @version 0.4
#

import os, sys
import re

from ConfigParser import ConfigParser, RawConfigParser, NoOptionError
from fnmatch      import fnmatch

import smtplib

try:
    import sqlite3 as sqlite
except ImportError:
    import sqlite

try:
    from email.mime.text import MIMEText
    from email.utils import COMMASPACE
except ImportError:
    # for older python versions
    from email.MIMEText import MIMEText
    from email.Utils import COMMASPACE

import time, datetime


VERSION   = '0.4'
DBVERSION = 2
CRUDFILE  = 'crud.ini'
MAILOPTS  = 'mailopts.ini'

dotremove = re.compile('^\.$', re.MULTILINE)

class CrudProduct:
    """
    Class to hold information about every product we're checking for.
    Basically, it takes information from crud.ini and provides a couple
    of methods to make comparions more convenient.
    """

    def __init__(self, name, config):
        """
        @param   name: the name of the product
        @param config: the ConfigParser object of crud.ini
        """
        #: The product name
        self.name    = name 
        #: How to combine the groups in the regex into the version number
        self.expand  = config.get(name, 'expand')
        #: The secure version of the product
        self.secure  = config.get(name, 'secure')
        #: Some comments about the product, if any
        self.comment = config.get(name, 'comment')
        #: The language environment of the product (e.g. "php")
        self.env     = config.get(name, 'env')
        #: URL for the vulnerability
        self.infourl = config.get(name, 'infourl')
        #: additional paths to check to help differentiate products
        self.andpath = []
        
        try:
            andpath = config.get(name, 'andpath')
            if andpath != '':
                self.andpath = comma2array(andpath)
        except NoOptionError:
            # assume we have an older crud.ini without andpath=
            pass

        regex = config.get(name, 'regex')
        #: Compiled regex to get the version out of a file
        self.regex   = re.compile(regex, re.MULTILINE | re.DOTALL)

        #: Used internally to identify alpha-numeric strings
        self.isalnum = re.compile('[^a-zA-Z0-9]')

    def _gen_segments(self, val):
        """
        Generator that splits a string into segments.
        e.g., '2xFg33.+f.5' => ('2', 'xFg', '33', 'f', '5')

        Adapted from a function found on
        http://concisionandconcinnity.blogspot.com/
        Snippet Copyright 2008 Ian McCracken, licensed under GPLv3.
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

        Adapted from a function found on
        http://concisionandconcinnity.blogspot.com/
        Snippet Copyright 2008 Ian McCracken, licensed under GPLv3.
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

    def analyze(self, installdir, contents):
        """
        Try to find the product version in the file contents.

        @param installdir: the directory that matched (for andpath checking)
        @type  installdir: str
        @param contents: the contents of a file
        @type  contents: str

        @return: (is_secure, got_version)
                    is_secure:   boolean True if the version is secure
                    got_version: str the version we found
        @rtype: tuple
        """

        if self.andpath:
            # look for other files relative to this dir to verify
            # that it's not some other product with similar files
            for checkpath in self.andpath:
                fullpath = os.path.normpath(installdir + checkpath)
                if not os.access(fullpath, os.R_OK):
                    return None

        match = self.regex.search(contents)
        if match is None:
            return None

        got_version = match.expand(self.expand)
        is_secure = False

        if self.secure != 'none' and \
                self.version_compare(got_version, self.secure) >= 0:
            is_secure = True

        return (is_secure, got_version)

def analyze_dir(rootpath, crudfile, quiet, wantenv=[]):
    """
    Look at all the files in the path provided and attempt to find 
    the products we recognize.

    Returns a report with the findings in the format:

    @param rootpath: the root path of where to look for crud
    @type  rootpath: str
    @param crudfile: the location of crud.ini
    @type  crudfile: str
    @param quiet: whether to be quiet
    @type  quiet: boolean
    @param wantenv: list of environments  (e.g.: ['php', 'perl'], [] means all)

    @return: List of tuples in the following format:
                [(installdir, product, status, got_version), ...]
                installdir:  string, path with the location of the product
                product:     CrudProduct, the product found
                status:      string, 'secure' or 'vulnerable'
                got_version: string, version of the product found
    @rtype: list
    """
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
                        result = product.analyze(installdir, contents) 
                        if result is None:
                            continue
                        (is_secure, got_version) = result
                        status = 'vulnerable'
                        if is_secure:
                            status = 'secure'
                        else:
                            if not quiet:
                                print "[%s] %s found, %s wanted, in %s" % (
                                        product.name, got_version, 
                                        product.secure, installdir)
                            
                        report.append((installdir, product, status, 
                                       got_version))
                        break

    return report

def loadmailmap(mailmapini):
    """
    Load mailmap.ini file and return the dict with contents.
    
    @param mailmapini: path with mailmap.ini
    @type  mailmapini: string

    @return: dict in the following format:
             {
                 '/some/path': {
                    'fqdn':   'foobar.baz', 
                    'admins': ['eml1', 'eml2']
                 },
                 ...
             }
    @rtype dict
    """

    conf = ConfigParser()
    conf.read(mailmapini)

    mailmap = {}

    for fqdn in conf.sections():
        path = conf.get(fqdn, 'path')
        path = os.path.normpath(path) + '/'

        admins = comma2array(conf.get(fqdn, 'email'))

        mailmap[path] = {'fqdn': fqdn, 'admins': admins}

    return mailmap

def nagowners(naglist, smtp, quiet):
    """
    Nags the owners of sites with insecure software.

    @param naglist: dict with various bits related to nagging
    @type  naglist: dict
    @param smtp: smtp object
    @type  smtp: smtplib.SMTP
    @param quiet: whether to output anything to the console
    @type  quiet: boolean
    
    @rtype: void
    """
    for sitename, nagdata in naglist.items():
        body = nagdata['greeting']
        body += '\n'
        body += nagdata['daysleft']
        body += '\n'

        body += '\n'.join(nagdata['products'])
        
        body += nagdata['closing']

        # A hack to preserve linebreaks is to keep
        # lonely "." on each line. 
        body = dotremove.sub('', body)

        # send mail
        msg = MIMEText(body)

        msg['From'] = nagdata['mailfrom']
        msg['Subject'] = nagdata['subject']
        msg['To'] = COMMASPACE.join(nagdata['admins'])

        recipients = nagdata['admins']

        if nagdata['mailcc']:
            msg['Cc'] = COMMASPACE.join(nagdata['mailcc'])
            recipients.extend(nagdata['mailcc'])

        if not quiet:
            print 'Nagging: %s' % msg['To']

        try:
            smtp.sendmail(nagdata['mailfrom'], recipients, msg.as_string())
        except smtplib.SMTPRecipientsRefused, ex:
            print 'Nagging failed: %s' % ex

def comma2array(commastr):
    """
    Helper function to convert "foo, bar, baz" into ['foo', 'bar', 'baz']

    @param commastr: comma-separated string
    @type  commastr: str

    @rtype: list
    """

    entries = []
    for entry in commastr.split(','):
        entries.append(entry.strip())
    return entries

def nagstate_connect(statedb):
    """
    Helper function to establish a connection to the nagstate database,
    initialize it if necessary, and perform the required conversions.

    @param statedb: the location of the nagstate database
    @type  statedb: str

    @rtype: sqlite.Connection
    """
    if not os.path.exists(statedb):
        # create the database
        sconn   = sqlite.connect(statedb)
        scursor = sconn.cursor()

        query = """CREATE TABLE nagstate (
                          installed_dir    TEXT,
                          product_name     TEXT,
                          found_version    TEXT,
                          found_date       DATE DEFAULT CURRENT_DATE,
                          nag_date         DATE DEFAULT CURRENT_DATE,
                          do_not_nag_until DATE DEFAULT NULL)"""
        scursor.execute(query)

        query = """CREATE TABLE meta (
                          dbversion INTEGER
                          )"""
        scursor.execute(query)
        query = "INSERT INTO meta (dbversion) VALUES (%d)" % DBVERSION
        scursor.execute(query)
        sconn.commit()

    else:
        sconn   = sqlite.connect(statedb)
        scursor = sconn.cursor()

        # Do we need to upgrade the table?
        query = "SELECT dbversion FROM meta"
        try:
            scursor.execute(query)
            (dbversion,)  = scursor.fetchone()
        except sqlite.OperationalError:
            # Assume this is because it's db version 1, which didn't
            # have a meta table
            dbversion = 1

        if dbversion == 1:
            # Add do_not_nag_until column
            query = """ALTER TABLE nagstate 
                         ADD COLUMN do_not_nag_until DATE DEFAULT NULL"""
            scursor.execute(query)
            # change all do_not_nag == 1 to do_not_nag_until = today + 1 year
            query = """
                UPDATE nagstate
                   SET do_not_nag_until = date('now', '+1 year')
                 WHERE do_not_nag = 1"""
            scursor.execute(query)
            # Add the meta table
            query = """CREATE TABLE meta (
                              dbversion INTEGER
                              )"""
            scursor.execute(query)
            query = "INSERT INTO meta (dbversion) VALUES (2)"
            scursor.execute(query)

            sconn.commit()

            dbversion = 2

    return sconn

def sqlite2datetime(sqlitedate):
    """
    Convert sqlite's date into a python datetime.
    This is dirtier, and yet easier than trying to set connection options 
    to sqlite and then making it work with both sqlite and sqlite3.

    @param sqlitedate: Sqlite's date string
    @type  sqlitedate: str

    @rtype datetime
    """
    # sqlite3 and sqlite behave differently, so we cast to 
    # strings. Depending on the version, it may or may not 
    # contain 00:00:00.00 at the end

    sqlitedate = str(sqlitedate)
    if sqlitedate.find('00:00:00.00') > 0:
        datefmt = '%Y-%m-%d 00:00:00.00'
    else:
        datefmt = '%Y-%m-%d'

    pdate = time.strptime(sqlitedate, datefmt)
    rdate = datetime.date(pdate[0], pdate[1], pdate[2])

    return rdate

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
        help='Do not output anything (usually with -r or -m).')
    parser.add_option('-r', '--csv-report', dest='csv', default=None,
        help='Produce a CSV report and save it in a file.')
    parser.add_option('-s', '--report-secure', dest='repsec', 
        action='store_true', default=False,
        help='Include secure versions in the report, as well as vulnerable.')
    parser.add_option('-e', '--environment', dest='env', action='append',
        default=[],
        help='Only analyze for these environments (php, perl, etc). \
              Default: all')
    parser.add_option('--mailopts', dest='mailopts',
        default=MAILOPTS,
        help='Mail options to use when sending notifications.')
    parser.add_option('--do-not-nag-until', dest='do_not_nag_until',
        default=None,
        help='''Do not nag about anything found during this run until 
                this date (YYYY-MM-DD).''')

    (opts, args) = parser.parse_args()
    
    if not args:
        parser.error('You must specify a path where to mine for crud.')

    rootpath = os.path.abspath(args[0])

    report = analyze_dir(rootpath, opts.crudfile, opts.quiet, opts.env)

    if opts.csv is not None:
        import csv
        out = open(opts.csv, 'w')
        writer = csv.writer(out, quoting=csv.QUOTE_ALL)
        writer.writerow(('path', 'product', 'found', 'secure', 'status',
                         'comment', 'more info'))
        
        for (installdir, product, status, got_version) in report:
            if  status == 'secure' and not opts.repsec:
                continue

            writer.writerow((installdir, product.name, got_version,
                             product.secure, status, product.comment,
                             product.infourl))

        out.close()

        if not opts.quiet:
            print 'CSV report saved in %s' % opts.csv
    
    if opts.mailopts is not None:
        # load mail options
        mailini = RawConfigParser()
        mailini.read(opts.mailopts)

        mailmap = loadmailmap(mailini.get('main', 'mailmap'))

        nagdays     = mailini.getint('main', 'nagdays')
        nagfreq     = mailini.getint('main', 'nagfreq')
        mailhost    = mailini.get('main', 'mailhost')
        statedb     = mailini.get('main', 'statedb')
        subject     = mailini.get('nagmail', 'subject')
        mailfrom    = mailini.get('nagmail', 'from')
        mailcc      = comma2array(mailini.get('nagmail', 'cc'))
        greeting    = mailini.get('nagmail', 'greeting')
        daysleft    = mailini.get('nagmail', 'daysleft')
        productline = mailini.get('nagmail', 'productline')
        hasupdate   = mailini.get('nagmail', 'hasupdate')
        noupdate    = mailini.get('nagmail', 'noupdate')
        hascomment  = mailini.get('nagmail', 'hascomment')
        hasinfourl  = mailini.get('nagmail', 'hasinfourl')
        closing     = mailini.get('nagmail', 'closing')
        
        naglist = {}
        offenders = {}

        now  = time.localtime()
        now_date = datetime.date(now[0], now[1], now[2])

        sconn = None

        for (installdir, product, status, got_version) in report:
            if status == 'secure':
                continue

            installdir = os.path.normpath(installdir) + '/'

            # is this path in our mailmap?
            for path in mailmap.keys():
                if not fnmatch(installdir, path + '*'):
                    continue

                # Do we have it in statedb?
                if sconn is None:
                    sconn = nagstate_connect(statedb)

                installed_dir_sql = installdir.replace("'", "''")
                product_name_sql  = product.name.replace("'", "''")
                found_version_sql = got_version.replace("'", "''")

                equery = """
                    SELECT found_date, nag_date, do_not_nag_until
                      FROM nagstate
                     WHERE installed_dir = '""" + installed_dir_sql + """'
                       AND product_name  = '""" + product_name_sql  + """'
                       AND found_version = '""" + found_version_sql + "'"
                scursor = sconn.cursor()
                scursor.execute(equery)

                row = scursor.fetchone()

                isnew = 0

                if not row:
                    # this is a new discovery
                    isnew = 1
                    nquery = """
                        INSERT INTO nagstate
                                    (installed_dir, product_name, 
                                     found_version)
                             VALUES ('""" + installed_dir_sql + """',
                                     '""" + product_name_sql  + """',
                                     '""" + found_version_sql + "')"
                    out = scursor.execute(nquery)
                    # rerun the equery, to get the dates
                    scursor.execute(equery)
                    row = scursor.fetchone()
                    
                (found_date, nag_date, do_not_nag_until) = row
                # do they need to be nagged?

                if do_not_nag_until is not None:
                    # we were asked not to nag them
                    until_date = sqlite2datetime(do_not_nag_until)
                    if now_date < until_date:
                        if not opts.quiet:
                            print "Not nagging about %s v.%s in %s until %s" % (
                                    product.name, got_version, installdir,
                                    until_date.isoformat())
                        continue

                if opts.do_not_nag_until:
                    # we were asked to stop nagging about this issue
                    # Sanity check on date format
                    try:
                        sqlite2datetime(opts.do_not_nag_until)
                    except ValueError:
                        print "%s is not in YYYY-MM-DD format" \
                                % opts.do_not_nag_until
                        sys.exit(1)

                    until_sql = opts.do_not_nag_until.replace("'", "''")
                    dnquery = """
                        UPDATE nagstate
                           SET do_not_nag_until = '""" + until_sql + """'
                         WHERE installed_dir = '""" + installed_dir_sql + """'
                           AND product_name  = '""" + product_name_sql  + """'
                           AND found_version = '""" + found_version_sql + "'"
                    scursor.execute(dnquery)
                    if not opts.quiet:
                        print "Will no longer nag about %s v.%s in %s" % (
                                product.name, got_version, installdir)
                    continue

                nag_date   = sqlite2datetime(nag_date)
                found_date = sqlite2datetime(found_date)

                nagdiff = now_date - found_date

                if not isnew and nagdiff.days < nagfreq:
                    # they don't get nagged
                    continue

                # update nag date
                uquery = """
                    UPDATE nagstate
                       SET nag_date = CURRENT_DATE
                     WHERE installed_dir = '""" + installed_dir_sql + """'
                       AND product_name  = '""" + product_name_sql  + """'
                       AND found_version = '""" + found_version_sql + "'"
                scursor.execute(uquery)

                founddiff = now_date - found_date

                sitename = mailmap[path]['fqdn']

                values = {
                        'nagdays'         : nagdays,
                        'daysleft'        : nagdays - founddiff.days,
                        'sitename'        : sitename,
                        'productname'     : product.name,
                        'foundversion'    : got_version,
                        'installdir'      : installdir,
                        'secureversion'   : product.secure,
                        'comment'         : product.comment,
                        'infourl'         : product.infourl,
                        'crudminerversion': VERSION
                        }

                if founddiff.days > nagdays:
                    # past nagging deadline, don't nag them any more,
                    # but keep nagging the hosting admins
                    if sitename not in offenders.keys():
                        offenders[sitename] = {
                                'admins':    mailmap[path]['admins'],
                                'knowndays': founddiff.days,
                                'products':  [],
                                }
                    
                else:
                    if sitename not in naglist.keys():
                        if not isnew:
                            mysubject = 'Re: %s' % subject
                        else:
                            mysubject = subject

                        naglist[sitename] = {
                                'admins'  : mailmap[path]['admins'],
                                'mailfrom': mailfrom,
                                'mailcc'  : mailcc,
                                'subject' : mysubject % values,
                                'greeting': greeting % values,
                                'daysleft': daysleft % values,
                                'products': [],
                                'closing' : closing % values
                                }
                           

                # formulate product lines

                entry = productline % values
                entry += '\n'

                if product.secure != 'none':
                    entry += hasupdate % values
                else:
                    entry += noupdate % values

                entry += '\n'

                if product.comment:
                    entry += hascomment % values
                    entry += '\n'

                if product.infourl:
                    entry += hasinfourl % values
                    entry += '\n'

                if founddiff.days > nagdays:
                    offenders[sitename]['products'].append(entry)
                else:
                    naglist[sitename]['products'].append(entry)

                break

        if sconn is not None:
            sconn.commit()

        smtp = None
        
        if naglist:
            # send the mail now
            smtp = smtplib.SMTP(mailhost)
            nagowners(naglist, smtp, opts.quiet)

        if offenders:
            # I know that I need to refactor this, considering
            # nagowners is its own method.
            if smtp is None:
                smtp = smtplib.SMTP(mailhost)

            subject   = mailini.get('nagreport', 'subject')
            mailfrom  = mailini.get('nagreport', 'from')
            greeting  = mailini.get('nagreport', 'greeting')
            hostentry = mailini.get('nagreport', 'hostentry')
            closing   = mailini.get('nagreport', 'closing')

            mailto = comma2array(mailini.get('nagreport', 'to'))
            mailcc = comma2array(mailini.get('nagreport', 'cc'))

            values = {
                    'nagdays': nagdays,
                    'crudminerversion': VERSION
                    }

            body = greeting % values
            body += '\n'

            for sitename, offdata in offenders.items():
                values['admins'] = COMMASPACE.join(offdata['admins'])
                values['sitename'] = sitename
                values['knowndays'] = offdata['knowndays']

                body += hostentry % values
                body += '\n'
                body += '\n'.join(offdata['products'])
        
            body += closing % values
            body = dotremove.sub('', body)

            # send mail
            msg = MIMEText(body)

            msg['From'] = mailfrom
            msg['Subject'] = subject
            msg['To'] = COMMASPACE.join(mailto)

            recipients = mailto

            if mailcc:
                msg['Cc'] = COMMASPACE.join(mailcc)
                recipients.extend(mailcc)

            if not opts.quiet:
                print 'Sending an offender report to: %s' % msg['To']

            try:
                smtp.sendmail(mailfrom, recipients, msg.as_string())
            except smtplib.SMTPRecipientsRefused, ex:
                print 'Sending offender report failed: %s' % ex


if __name__ == '__main__':
    main()
