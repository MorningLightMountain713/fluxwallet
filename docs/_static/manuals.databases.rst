Using MySQL or PostgreSQL databases
===================================

fluxwallet uses the SQLite database by default, because it easy to use and requires no installation.

But you can also use other databases. At this moment fluxwallet is tested with MySQL and PostgreSQL.


Using MySQL database
--------------------

We assume you have a MySQL server at localhost. Unlike with the SQLite database MySQL databases are not created
automatically, so create one from the mysql command prompt:

.. code-block:: mysql

    mysql> create database fluxwallet;

Now create a user for your application and grant this user access. And off course replace the password 'secret' with
a better password.

.. code-block:: mysql

    mysql> create user fluxwallet@localhost identified by 'secret';
    mysql> grant all on fluxwallet.* to fluxwallet@localhost with grant option;

In your application you can create a database link. The database tables are created when you first run the application

.. code-block:: python

    db_uri = 'mysql://fluxwallet:secret@localhost:3306/fluxwallet'
    w = wallet_create_or_open('wallet_mysql', db_uri=db_uri)
    w.info()


Using PostgreSQL database
-------------------------

First create a user and the database from a shell. We assume you have a PostgreSQL server running at your Linux machine.

.. code-block:: bash

    $ su - postgres
    postgres@localhost:~$ createuser --interactive --pwprompt
    Enter name of role to add: fluxwallet
    Enter password for new role:
    Enter it again:
    Shall the new role be a superuser? (y/n) n
    Shall the new role be allowed to create databases? (y/n) n
    Shall the new role be allowed to create more new roles? (y/n) n
    $ createdb fluxwallet

And assume you unwisely have chosen the password 'secret' you can use the database as follows:

.. code-block:: python

    db_uri = 'postgresql://fluxwallet:secret@localhost:5432/'
    w = wallet_create_or_open('wallet_mysql', db_uri=db_uri)
    w.info()
