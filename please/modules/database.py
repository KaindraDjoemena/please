import sqlite3


class Database:
    def __init__(self, db_name: str, pass_table: str, mp_table: str):
        self.db_name = db_name
        self.pass_table = pass_table
        self.mp_table = mp_table
        self.connection = sqlite3.connect(db_name)
        self.c = self.connection.cursor()


    def init_tables(self) -> None:
        self.create_table(self.mp_table, ["id INTEGER PRIMARY KEY AUTOINCREMENT",
                                                    "hash TEXT NOT NULL"])

        self.create_table(self.pass_table, ["id INTEGER PRIMARY KEY AUTOINCREMENT",
                                             "username TEXT NOT NULL",
                                             "password TEXT NOT NULL",
                                             "platform TEXT NOT NULL",
                                             "username_salt TEXT",
                                             "password_salt TEXT",
                                             "platform_salt TEXT"])


    def create_table(self, table_name: str, cols: list[str]) -> None:
        cols_str = ", ".join(cols)
        query = f"""
            CREATE TABLE {table_name} ({cols_str})
        """
        self.c.execute(query)
        self.connection.commit()


    def insert_entry(self, table_name: str, data: tuple[str]) -> None:
        data_placeholder = ", ".join(["?" for _ in data])
        if table_name == self.mp_table:
            fields = "(hash)"
        elif table_name == self.pass_table:
            fields = "(username, password, platform, username_salt, password_salt, platform_salt)"

        query = f"""
            INSERT INTO {table_name} {fields}
            VALUES ({data_placeholder})
        """
        self.c.execute(query, data)
        self.connection.commit()


    def get_entry(self, table_name: str, field: str = None, condition: str = None,
                  limit: int = None, offset: int = None):
        # base query
        query = f"""
            SELECT *
            FROM {table_name}
        """
        
        if limit or offset != None:
            query += (f"""
                        LIMIT {limit}
                        OFFSET {offset}
                    """)

        if field:
            query += (f"""
                        WHERE {field} = {condition}
                    """)

        self.c.execute(query)
        for row in self.c:
            yield row
        self.connection.commit()


    def delete_entry(self, table_name: str, field_name: str, params: tuple) -> None:
        query = f"""
            DELETE FROM {table_name}
            WHERE {field_name} = ?
        """
        self.c.execute(query, (params,))
        self.connection.commit()


    def close_connection(self):
        self.connection.close()
