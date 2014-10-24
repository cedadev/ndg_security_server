#!/usr/bin/env python
import getpass
from sqlalchemy import create_engine

from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey

class CreateResourceConstraintsDb(object):

    def createResourceConstraintsTable(self):
        metadata = MetaData()
        users_table = Table('resource_constraints', metadata,
            Column('id', Integer, primary_key=True),
            Column('uri_regex', String))
        
    def createActionTypeTable(self):
        metadata = MetaData()
        users_table = Table('action_type', metadata,
            Column('id', Integer, primary_key=True),
            Column('uri_regex', String),
            Column('action', String))
        
    def createAttributesTable(self):
        metadata = MetaData()
        users_table = Table('attributes', metadata,
            Column('id', Integer, primary_key=True),
            Column('uri_regex', String),
            Column('attribute', String))
            
if __name__ == "__main__":
    import sys
    import pdb;pdb.set_trace()
    username, hostname, dbName = sys.argv[1:]
    
    # postgres
    pwd = getpass.getpass()
    pg_db = create_engine('postgres://%s:%s@%s/%s' % 
                          (username, pwd, hostname, dbName))
    connection = pg_db.connect()
    result = connection.execute("select * from users")
    for row in result:
        print ', '.join(["%s=%s" % (k,v) for k,v in row.items()])
    connection.close()


