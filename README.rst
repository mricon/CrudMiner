CrudMiner
=========

The idea of CrudMiner came from having inherited a large webserver full
of user-installed software. As it is nearly always the case, when
clients are allowed to install their own software, they never actually
bother to keep it patched and updated. I wrote CrudMiner with the sole
task of looking for known-outdated web software and reporting it to me
in a format that was easy to grok and process.

Running
-------
To run CrudMiner, simply do::

    ./crudminer.py /path/to/www

You can start by running it against tests. You probably want to run it
on a periodic basis and notify you of the findings, for which you
probably want to put the following command in your cron scripts::

    ./crudminer.py -q -r /path/to/report.csv /path/to/www

This will generate a CSV file with the findings, which you can later
mail to yourself.

If you want to always test against the latest definitions, you can pass
a `--crudfile` parameter to point to the github location of the
`crud.ini` file::

    ./crudminer.py \
        --crudfile=https://raw.github.com/mricon/CrudMiner/master/crud.ini
        /path/to/www

Nagging
-------
Additionally, you can generate a simple `mailmap.ini` file with a
mapping of paths to hostnames and admin email addresses. This will allow
you to automatically nag owners of sites to update their software. Not
that this is very effective, but it helps shift the blame::

    ./crudminer.py -q \
        --mailmap=/path/to/mailmap.ini \
        --template=/path/to/template.ini \
        --mailhost=mailhost.example.com \
        /path/to/www

See the provided examples of the `mailmap.ini` and `template.ini` files.

Further work
------------
As you can tell, this is fairly early in the development. You should
check out the TODO file to see what is planned for the future.
