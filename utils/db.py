#!/usr/bin/python

from Maat.utils.graphics import *
from Maat.utils.misc import *
from Maat.conf.config import *

import glob, sqlite3, datetime, os
from datetime import datetime

class DB():
    """
    A class to handle access to the SQLite database
    """
    def __init__(self):
        """
        Initializes an object with metadata about the current run
        """
        try:
            # Check for the existence of the database
            dbPath = Maat_DB
            if not os.path.exists(dbPath):
                prettyPrint("Unable to locate the database \"%s\". A new database will be created" % dbPath, "warning")
                dbScriptPath = DB_RECOVERY
                if not os.path.exists(dbScriptPath):
                    prettyPrint("Unable to locate the database script file under \"%s\". Exiting" % dbScriptPath, "error")
                    exit(1)
                # Connect to database
                self.conn = sqlite3.connect(dbPath) # Creates a DB if it does NOT exist
                self.conn.executescript(open(dbScriptPath).read())
            else:
                self.conn = sqlite3.connect(dbPath)

        except Exception as e:
            prettyPrintError(e)

    def close(self):
        """
        Saves and closes the database
        :return: A bool depicting the success/failure of the operation
        """
        try:
            if not self.save():
                prettyPrint("Unable to save the current state of the database", "warning")
                return False
        except Exception as e:
            prettyPrintError(e)
            return False

        return True
       
    def delete(self, table, filters, cOperator="=", lOperator="AND"):
        """
        Deletes records from a table
        :param table: The name of the table to be updated
        :type table: str
        :param filters: A list of conditions to use in the WHERE clause of the query
        :type filters: list of tuples
        :param cOperator: The comparison operator used in the WHERE clause (i.e. '=', '>', '<', 'LIKE', etc.)
        :type cOperator: str
        :param lOperator: The logic operator used to join the filters in the WHERE clause (i.e. 'AND' or 'OR')
        :type lOperator: str
        :return: A bool depicting the success/failure of the operation
        """
        try:
            # Build query
            query = "DELETE FROM %s" % table
            # Add WHERE clause, if applicable
            if len(filters) > 0:
                query += " WHERE "
                temp = ""
                for i in range(len(filters)):
                    query = query + "%s %s '%s'" % (filters[i][0], cOperator, filters[i][1])
                    if i != len(filters) - 1:
                        query += " %s " % lOperator
            # Execute query
            if VERBOSE:
                prettyPrint("Executing query: %s" % query, "debug")
            self.conn.execute(query)
    
        except Exception as e:
            prettyPrintError(e)
            return False

        return True
    
    def execute(self, query):
        """
        Executes a SQL query passed as a string
        :param query: The SQL query to execute
        :type query: str
        :return: A cursor of the results set or None
        """
        try:
            if VERBOSE():
                prettyPrint("Executing query: %s" % query, "debug")
            results = self.conn.execute(query)
        except Exception as e:
            prettyPrintError(e)
            return None

        return results

    def insert(self, table, columns, values):
        """
        Inserts a new record into the database
        :param table: The table to insert the new values in
        :type table: str
        :param values: The new values to be inserted
        :type values: list
        :return: A bool depicting the success/failure of the INSERT operation
        """
        try:
            # Prepare values
            values = ["'%s'" % str(v) for v in values]
            #print values
            # Build query
            if len(columns) > 0:
                query = "INSERT INTO %s (%s) VALUES (%s)" % (table, ",".join(columns), ",".join(values))
            else:
                query = "INSERT INTO %s VALUES(%s)" % (table, ",".join(values))
            # Execute query
            if VERBOSE:
                prettyPrint("Executing query: %s" % query, "debug")
            self.conn.execute(query)
            
        except Exception as e:
            prettyPrintError(e)
            return False

        return True

    def save(self):
        """
        Saves the current state of the database by committing the changes
        :return: A bool depicting the success/failure of the operation
        """
        try:
            self.conn.commit()
        except Exception as e:
            prettyPrintError(e)
            return False

        return True

    def select(self, columns, table, filters, cOperator="=", lOperator="AND"):
        """
        Retrieves records from the the database
        :param columns: The columns to select from the table
        :type columns: list (Default: [] = *)
        :param table: The table whence the data is selected
        :type table: str
        :param filters: A list of conditions to use in the WHERE clause of the query
        :type filters: list of tuples
        :param cOperator: The comparison operator used in the WHERE clause (i.e. '=', '>', '<', 'LIKE', etc.)
        :type cOperator: str
        :param lOperator: The logic operator used to join the filters in the WHERE clause (i.e. 'AND' or 'OR')
        :type lOperator: str
        :return: sqlite3.Cursor of the returned rows
        """
        try:
            # Build query
            query = "SELECT "
            if len(columns) < 1:
                query += "*"
            else:
                query += ",".join(columns)
            # FROM [table]
            query += " FROM %s" % table
            # Add WHERE clause, if applicable
            if len(filters) > 0:
                query += " WHERE "
                temp = ""
                for i in range(len(filters)):
                    query = query + "%s %s '%s'" % (filters[i][0], cOperator, filters[i][1])
                    if i != len(filters) - 1:
                        query += " %s " % lOperator
            # Execute query
            if VERBOSE:
                prettyPrint("Executing query: %s" % query, "debug")
            cursor = self.conn.execute(query)
                        
        except Exception as e:
            prettyPrintError(e)
            return None

        return cursor

    def update(self, table, values, filters, cOperator="=", lOperator="AND"):
        """
        Updates records in the database
        :param table: The name of the table to be updated
        :type table: str
        :param values: The list of columns to be updated along with their new values
        :type values: list of tuples
        :param filters: A list of conditions to use in the WHERE clause of the query
        :type filters: list of tuples
        :param cOperator: The comparison operator used in the WHERE clause (i.e. '=', '>', '<', 'LIKE', etc.)
        :type cOperator: str
        :param lOperator: The logic operator used to join the filters in the WHERE clause (i.e. 'AND' or 'OR')
        :type lOperator: str
        :return: A bool depicting the success/failure of the operation
        """
        try:
            # Build query
            query = "UPDATE %s SET " % table
            # Add the columns to be updated and their values
            for v in values:
                query = query + "%s='%s'," % (v[0], v[1])
            query = query[:-1] # Remove the trailing comma
            # Add WHERE clause, if applicable
            if len(filters) > 0:
                query += " WHERE "
                temp = ""
                for i in range(len(filters)):
                    query = query + "%s %s '%s'" % (filters[i][0], cOperator, filters[i][1])
                    if i != len(filters) - 1:
                        query += " %s " % lOperator
            # Execute query
            if VERBOSE:
                prettyPrint("Executing query: %s" % query, "debug")
            self.conn.execute(query)
            
        except Exception as e:
            prettyPrintError(e)
            return False

        return True

