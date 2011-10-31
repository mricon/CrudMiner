CrudMiner
=========
-------------------------------------------
Find known-vulnerable software in a webroot
-------------------------------------------

:Author:    konstantin.ryabitsev@mcgill.ca
:Date:      2011-10-19
:Copyright: McGill University and contributors
:License:   GPLv3
:Version:   0.4.0

SYNOPSIS
--------
    crudminer.py /path/to/www

DESCRIPTION
-----------
The idea of CrudMiner came from having inherited a large webserver full
of user-installed software. As it is nearly always the case, when
clients are allowed to install their own software, they never actually
bother to keep it patched and updated. I wrote CrudMiner with the sole
task of looking for known-outdated web software and reporting it to me
in a format that was easy to grok and process.

OPTIONS
-------
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  --crudfile=CRUDFILE   Location of the crud.ini file (crud.ini).
  -q, --quiet           Do not output anything (usually with -r or -m).
  -r CSV, --csv-report=CSV
                        Produce a CSV report and save it in a file.
  -s, --report-secure   Include secure versions in the report, as well as
                        vulnerable.
  -e ENV, --environment=ENV
                        Only analyze for these environments (php, perl, etc).
                        Default: all
  --mailopts=MAILOPTS   Mail options to use when sending notifications.
  --do-not-nag-until=DO_NOT_NAG_UNTIL
                        Do not nag about anything found during this run until
                        this date (YYYY-MM-DD).



EXAMPLES
--------
To run CrudMiner, simply do::

    crudminer.py /path/to/www

You can start by running it against tests. You probably want to run it
on a periodic basis and notify you of the findings, for which you
probably want to put the following command in your cron scripts::

    crudminer.py -q -r /path/to/report.csv /path/to/www

This will generate a CSV file with the findings, which you can later
mail to yourself.

If you want to always test against the latest definitions, you can pass
a `--crudfile` parameter to point to the github location of the
`crud.ini` file::

    crudminer.py \
        --crudfile=https://raw.github.com/mricon/CrudMiner/master/crud.ini \
        /path/to/www

Nagging
~~~~~~~
Additionally, you can generate a simple `mailmap.ini` file with a
mapping of paths to hostnames and admin email addresses. This will allow
you to automatically nag owners of sites to update their software. Not
that this is very effective, but it helps shift the blame::

    crudminer.py -q \
        --mailopts=/path/to/mailopts.ini \
        /path/to/www

See the provided example of the `mailopts.ini` for more info. No nagging
will be done as long as ``mailmap.ini`` is empty.

If you want to disable nagging for a specific path, (e.g. if there are
legitimate reasons for a specific version of the software to be
installed, or if there is a global .htaccess that prevents any
exploitation of said software), you may run the following::

    crudminer.py --do-not-nag-until 2012-12-31 /path/to/ignore

This will stop nagging until specified date, as long as the version of
the installed software remains the same. If new vulnerable software is
found or if the installed version of the software changes, the nagging
will recommence regardless of the date specified.

FURTHER WORK
------------
As you can tell, this is fairly early in the development. You should
check out the TODO file to see what is planned for the future.
