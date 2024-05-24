import os
import json
import math

import pyperclip
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.prompt import Confirm
from rich.prompt import IntPrompt
from readchar import readkey, key
from pyfiglet import Figlet
import pwinput
import pandas

from please.utils.generate_pass import gen_pass
from please.utils.options import format_options
from please.modules.database import Database
from please.modules.cryptography import AESCipher, Argon2Hasher


class App:
    def __init__(self, db_name: str, pass_table: str, mp_table: str):
        # db initialization
        self.db_name = db_name
        self.pass_table = pass_table
        self.mp_table = mp_table
        self.db = Database(
            db_name=self.db_name,
            pass_table=self.pass_table,
            mp_table=self.mp_table
        )

        # app initialization
        with open("please/theme.json") as f:
            theme_data = json.load(f)
        theme = Theme(theme_data)
        self.console = Console(theme=theme)
        self.title_card = Figlet(font="small", width=200)
        self.title_card_text = "Please?"

        # operation initialization
        self.aes = AESCipher()
        self.password_min_len = 20
        self.entry_table = {}


    def render_hit_key(self, msg="(hit any key to exit)"):
        self.console.show_cursor(False)
        self.console.print(f"\n{msg}", style="info")
        readkey()


    def render_title_card(self):
        self.console.print(self.title_card.renderText(self.title_card_text))


    def render_page_header(self, msg):
        self.render_title_card()
        self.console.print(f"[{msg}]", style="reverse")


    def user_signup(self) -> None:
        '''SIGN UP'''

        self.render_page_header("SIGN UP")

        # get user input
        try:
            mp_input = pwinput.pwinput("make master password: ").strip()
            mp_confirmation = pwinput.pwinput("password confirmation: ").strip()
        except KeyboardInterrupt:
            os.remove(self.db_name)
            readkey()
            exit()

        # removes the .db file
        if (mp_input != mp_confirmation):
            self.console.print("passwords don't match", style="warning")
            self.db.close_connection()
            os.remove(self.db_name)
        else:
            # hash mp input
            with self.console.status("[notif]hashing password...[/]"):
                hashed_mp = Argon2Hasher().hash_password(mp_input)

            # insert hashsed mp input
            with self.console.status("[notif]inserting data...[/]"):
                self.db.init_tables()
                self.db.insert_entry(self.mp_table, [hashed_mp])
                self.console.print("sign up successful!", style="notif")

        self.render_hit_key()
        return


    def derivate_enc_keys(self, limit, offset):
        db2 = Database(
            db_name = self.db_name,
            pass_table=self.pass_table,
            mp_table=self.mp_table
        )
        for entry in db2.get_entry(self.pass_table, limit=limit, offset=offset):
            for i in range(4):
                if i == 0:
                    continue
                self.aes.derive_key(self.mp, entry[i+3]).decode("utf-8")
        db2.close_connection()

    def user_signin(self) -> bool:
        '''SIGN IN'''

        self.render_page_header("SIGN IN")

        # get user password
        mp_input = pwinput.pwinput("master password: ", mask="").strip()

        try:
            # compare the hashes
            with self.console.status("[notif]verifying user...[/]"):
                fetched_hash_gen = self.db.get_entry(self.mp_table)
                hash = next(fetched_hash_gen)[1]

                Argon2Hasher.verify_password(hash, mp_input)
                self.mp = mp_input

                # key_derivation_thread = threading.Thread(target=self.derivate_enc_keys)
                # key_derivation_thread.start()

            # load entries for quick operations
            with self.console.status("[notif]fetching entries...[/]"):
                self.entry_table = self.fetch_entries()

            return 1
        except Exception as e:
            self.console.print("wrong password", style="warning")
            return 0


    def menu(self) -> None:
        '''MENU'''

        # options with their corresponding functions
        OPTIONS = [
            ("list entries", lambda: self.list_entries(hidden=True)),
            ("add entry", self.add_entry),
            ("delete entry", self.delete_entry),
            ("search entry", self.search_entry),
            ("generate password", self.generate_password)
        ]

        cur_loc = 0 # cursor location (index of the options list)
        with self.console.screen():
            while True:
                self.console.show_cursor(False)

                # rendering
                self.render_title_card()                                                    # render title card
                self.console.print(format_options(OPTIONS, cur_loc))                        # render options
                self.console.print("[c]onfigurations [q]uit", markup=False, style="info")   # render help

                user_input = readkey()

                # exit program
                if user_input.lower() == "q":
                    exit()

                # TODO: make configuration page
                if user_input.lower() == "c":
                    pass
                
                # cursor navigation
                if (user_input == key.DOWN or user_input.lower() == "j") and cur_loc < len(OPTIONS) - 1:
                    cur_loc += 1
                if (user_input == key.UP or user_input.lower() == "k") and cur_loc > 0:
                    cur_loc -= 1
                
                # option input
                if (user_input == key.ENTER) or (user_input in [str(i) for i in range(1, len(OPTIONS) + 1)]):
                    if user_input != key.ENTER:
                        cur_loc = int(user_input) - 1
                    
                    self.console.clear()
                    OPTIONS[cur_loc][1]()

                self.console.clear()


    def render_table(self, input_table: pandas.DataFrame, cur_loc: int,
                     page_size: int, page_idx: int, max_pages: int, hidden: bool) -> Table:
        # table formatting
        right_arrow = " " if page_idx == max_pages or page_idx == max_pages - 1 else ">"
        left_arrow = " " if page_idx == max_pages or page_idx == 0 else "<"
        caption = f"{left_arrow} {page_idx + 1}/{max_pages} {right_arrow}"
        table = Table(caption=caption)
        table.add_column("ID")
        table.add_column("USERNAME")
        table.add_column("PASSWORD")
        table.add_column("PLATFORM")

        # add rows
        row_count = 0
        for idx, row in input_table.iterrows():
            if hidden:
                password_cell = "*" * 10
            else:
                password_cell = row["PASSWORD"]

            # show a limited table
            if idx >= page_size * page_idx:
                # selected row
                style = None
                if idx == cur_loc:
                    style = "reverse"

                table.add_row(
                    str(row["ID"]),
                    row["USERNAME"],
                    password_cell,
                    row["PLATFORM"],
                    style=style
                )

                # track rows that have been printed
                row_count += 1
                if row_count == page_size:
                    break

        self.console.print(table)


    def list_entries(self, hidden: bool) -> None:
        cur_loc = 0     # cursor location (index of the options list)
        page_idx = 0    # current page index
        while True:
            self.render_page_header("ENTRY LIST")
            self.console.print(f"[b]ack [c]opy [d]elete [t]oggle-view", 
                               markup=False, style="info")
            if self.is_empty(self.entry_table, extra_msg="cannot list entries due to an empty table"):
                return
            page_size = self.console.height - 14
            max_pages = math.ceil(len(self.entry_table) / page_size)
            self.render_table(self.entry_table, 
                              cur_loc, page_size,
                              page_idx,
                              max_pages,
                              hidden=hidden)
            user_input = readkey()

            # exit program
            if user_input.lower() == "b":
                return
            
            # show and hide tables
            if user_input.lower() == "t":
                if hidden:
                    hidden = False
                else:
                    hidden = True

            # copy password to clipboard
            if user_input.lower() == "c":
                pyperclip.copy(self.entry_table.iloc[cur_loc]["PASSWORD"])
                self.console.print("\npassword copied to clipboard", style="notif")
                readkey()

            # cursor navigation
            # row scroll
            if ((user_input == key.DOWN or user_input.lower() == "j") and   # if user hits a key
                (cur_loc < len(self.entry_table) - 1) and                   # if the cursor is less than the len of the table
                 cur_loc < page_size * (page_idx + 1) - 1):                 # if the cursor is less than a page's rows
                cur_loc += 1
            if (user_input == key.UP or user_input.lower() == "k") and (cur_loc > page_size * page_idx):
                cur_loc -= 1
            
            # page scroll
            if (user_input == key.RIGHT or user_input.lower() == "l") and page_idx < max_pages - 1:
                page_idx += 1
                cur_loc = page_idx * page_size
            if (user_input == key.LEFT or user_input.lower() == "h") and page_idx > 0:
                page_idx -= 1
                cur_loc = (page_idx + 1) * page_size - 1

            # delete row
            if user_input.lower() == "d":
                # check master password confirmation
                self.console.show_cursor(True)
                mp_input = pwinput.pwinput("password confirmation: ", mask="")
                self.console.show_cursor(False)
                if mp_input != self.mp:
                    self.console.print("nconnect master password", style="warning")
                    return

                with self.console.status("[notif]deleting...[/]"):
                    # get the value of the ID column that corresponds with pandas.DataFrame index
                    row_id = self.entry_table.iloc[cur_loc]["ID"]

                    # delete row by referencing its ID column value
                    self.db.delete_entry(self.pass_table, "ID", int(row_id))
                    
                    # # update loaded data
                    self.entry_table = self.entry_table.drop(cur_loc)
                    self.entry_table.reset_index(drop=True, inplace=True)

                    # update cur_loc
                    if cur_loc == len(self.entry_table):
                        cur_loc = len(self.entry_table) - 1
                self.console.show_cursor(False)

            self.console.clear()


    def add_entry(self) -> None:
        self.render_page_header("ADD ENTRY")
        # get user input
        # TODO: user needs to hit esc to go back to menu
        self.console.show_cursor(True)
        username_input = Prompt.ask("username", default="username", show_default=True)
        password_input = Prompt.ask("password", default=gen_pass(), show_default=True)
        platform_input = Prompt.ask("platform", default="", show_default=False)
        self.console.show_cursor(False)

        input_fields = [
            username_input,
            password_input,
            platform_input
        ]

        encrypted_fields = []
        encrypted_salts = []

        # encrypt fields
        with self.console.status("[notif]encrypting data...[/]"):
            for input_field in input_fields:
                field_salt, encrypted_field = self.aes.encrypt(self.mp, input_field)
                encrypted_fields.append(encrypted_field)
                encrypted_salts.append(field_salt)

        # update table
        with self.console.status("[notif]updating table...[/]"):
            self.db.insert_entry(self.pass_table,encrypted_fields + encrypted_salts)
            self.entry_table = self.fetch_entries()

        return


    def is_empty(self, table: pandas.DataFrame, extra_msg: str = None) -> bool:
        if table.empty:
            self.console.show_cursor(False)
            self.console.print("\nempty row", style="notif")
            if extra_msg:
                self.console.print(extra_msg, style="warning")
            self.render_hit_key()
            return True
        return False


    def delete_entry(self) -> None:
        OPTIONS = [
            ("id", lambda: IntPrompt.ask(">> id")),
            ("username", lambda: Prompt.ask(">> username")),
            ("platform", lambda: Prompt.ask(">> platform"))
        ]

        cur_loc = 0 # cursor location (index of the options list)
        while True:
            self.render_page_header("DELETE ENTRY BY:")
            if self.is_empty(self.entry_table, extra_msg="cannot perform deletion due to an empty table"):
                return
            self.console.print(format_options(OPTIONS, cur_loc))
            self.console.print("[b]ack", markup=False, style="info")

            user_input = readkey()

            # exit program
            if user_input.lower() == "b":
                return
            
            # cursor navigation
            if (user_input == key.DOWN or user_input.lower() == "j") and cur_loc < len(OPTIONS) - 1:
                cur_loc += 1
            if (user_input == key.UP or user_input.lower() == "k") and cur_loc > 0:
                cur_loc -= 1

            # option input
            if (user_input == key.ENTER) or (user_input in [str(i) for i in range(1, len(OPTIONS) + 1)]):
                # update screen and cursor location
                if user_input != key.ENTER:
                    cur_loc = int(user_input) - 1
                self.console.clear()
                self.render_page_header("DELETE ENTRY BY:")
                self.console.print(format_options(OPTIONS, cur_loc))

                # get field
                self.console.show_cursor(True)
                field_input = OPTIONS[cur_loc][1]()
                filtered_table = self.entry_table[self.entry_table[OPTIONS[cur_loc][0].upper()] == field_input]
                
                # if the table is empty
                if self.is_empty(filtered_table, extra_msg=f"{OPTIONS[cur_loc][0]} of [underline]{field_input}[/] does not exist"):
                    return

                page_idx = 0
                page_size = self.console.height - 20
                max_pages = max_pages = math.ceil(len(self.entry_table) / page_size)
                hidden = False
                while True:
                    self.console.clear()
                    self.render_page_header("DELETION PREVIEW")
                    self.console.print("[ESC] - back | [ENTER] - proceed", style="info")
                    self.render_table(filtered_table,
                                    cur_loc=-1,
                                    page_size=page_size,
                                    page_idx=page_idx,
                                    max_pages=max_pages,
                                    hidden=hidden)

                    self.console.show_cursor(False)
                    user_input = readkey()

                    # cancel action
                    if (user_input == key.ESC):
                        return

                    # page navigation
                    if (user_input == key.LEFT or user_input.lower() == "h") and (page_idx > 0):
                        page_idx -= 1
                    if (user_input == key.RIGHT or user_input.lower() == "l") and (page_idx < max_pages - 1):
                        page_idx += 1

                    if (user_input == key.ENTER):
                        # get user confirmation
                        self.console.show_cursor(True)
                        user_confirmation = Confirm.ask("delete?")
                        if not user_confirmation:
                            self.console.show_cursor(False)
                            return
                        mp_input = pwinput.pwinput("master password confirmation: ", mask="")    # get user input
                        self.console.show_cursor(False)

                        # check user confirmation
                        if (mp_input != self.mp):
                            self.console.print("wrong password", style="warning")
                            self.console.print("deletion cancelled", style="warning")
                            self.render_hit_key()
                            continue

                        with self.console.status("[notif]deleting data...[/]"):
                            for row_id in filtered_table["ID"]:
                                # delete from database
                                self.db.delete_entry(self.pass_table, "ID", row_id)

                                # update loaded table
                                self.entry_table = self.entry_table[self.entry_table["ID"] != row_id]

                        self.render_hit_key()
                        self.console.show_cursor(False)
                        return

            self.console.clear()


    def search_entry(self) -> None:
        OPTIONS = [
            ("id", lambda: IntPrompt.ask(">> id")),
            ("username", lambda: Prompt.ask(">> username")),
            ("platform", lambda: Prompt.ask(">> platform"))
        ]

        cur_loc = 0 # cursor location (index of the options list)
        while True:
            self.render_page_header("SEARCH ENTRY BY:")
            if self.is_empty(self.entry_table, extra_msg="cannot perform a search due to an empty table"):
                return
            self.console.print(format_options(OPTIONS, cur_loc))
            self.console.print("[b]ack", markup=False, style="info")

            user_input = readkey()

            # exit program
            if user_input == "b":
                return
            
            # cursor navigation
            if (user_input == key.DOWN or user_input.lower() == "j") and cur_loc < len(OPTIONS) - 1:
                cur_loc += 1
            if (user_input == key.UP or user_input.lower() == "k") and cur_loc > 0:
                cur_loc -= 1

            # option input
            if (user_input == key.ENTER) or (user_input in [str(i) for i in range(1, len(OPTIONS) + 1)]):
                # update screen and cursor location
                if user_input != key.ENTER:
                    cur_loc = int(user_input) - 1
                self.console.clear()
                self.render_page_header("DELETE ENTRY BY:")
                self.console.print(format_options(OPTIONS, cur_loc))

                # get field
                self.console.show_cursor(True)
                field_input = OPTIONS[cur_loc][1]()
                filtered_table = self.entry_table[self.entry_table[OPTIONS[cur_loc][0].upper()] == field_input]
                
                # if the table is empty
                if self.is_empty(filtered_table, extra_msg=f"{OPTIONS[cur_loc][0]} of [underline]{field_input}[/] does not exist"):
                    return

                page_idx = 0
                page_size = self.console.height - 20
                max_pages = max_pages = math.ceil(len(self.entry_table) / page_size)
                hidden = False
                while True:
                    self.console.clear()
                    self.render_page_header("SEARCHED ENTRIES")
                    self.console.print("[ESC] - back", style="info")
                    self.render_table(filtered_table,
                                    cur_loc=-1,
                                    page_size=page_size,
                                    page_idx=page_idx,
                                    max_pages=max_pages,
                                    hidden=hidden)

                    self.console.show_cursor(False)
                    user_input = readkey()

                    # cancel action
                    if (user_input == key.ESC):
                        return

                    # page navigation
                    if (user_input == key.LEFT or user_input.lower() == "h") and (page_idx > 0):
                        page_idx -= 1
                    if (user_input == key.RIGHT or user_input.lower() == "l") and (page_idx < max_pages - 1):
                        page_idx += 1

            self.console.clear()


    def fetch_entries(self, page: int = None, page_size: int = None) -> pandas.DataFrame:
        # fetch encrypted rows
        fetched_rows = self.db.get_entry(self.pass_table)

        decrypted_rows = {}

        # iterate over fetched rows
        for row in fetched_rows:
            decrypted_fields = []
            
            # decrypt each data point in the row
            for i in range(4):
                if i == 0:
                    decrypted_fields.append(row[i])
                    continue
                decrypted_fields.append(self.aes.decrypt(self.mp, row[i], row[i+3]).decode("utf-8"))
            
            # assign decrypted fields to corresponding column names
            for column, value in zip(["ID", "USERNAME", "PASSWORD", "PLATFORM"], decrypted_fields):
                decrypted_rows.setdefault(column, []).append(value)

        return pandas.DataFrame(decrypted_rows)


    def generate_password(self) -> None:
        '''GENERATES A RANDOM PASSWORD'''

        self.render_page_header("GENERATE PASSWORD")

        # get user input
        self.console.show_cursor(True)
        while True:
            pass_len = IntPrompt.ask("password length", show_default=True, default=self.password_min_len)
            if pass_len < 500:
                break
            self.console.print("[warning]password length too big (< 500)[/]")
        self.console.show_cursor(False)
        
        # generate random password
        with self.console.status("[notif]generating password...[/]"):
            generated_pass = gen_pass(pass_len)

        self.console.print()

        # show generated password in a rich panel
        self.console.print(Panel.fit(generated_pass,
                                     padding=1,
                                     title="generated password",
                                     title_align="left",
                                     subtitle="'c' to copy",
                                     subtitle_align="left"))

        self.console.print("\nhit any key to exit", style="info")
        while True:
            self.console.show_cursor(False)
            key = readkey()        
            if key != "c":
                break
            pyperclip.copy(generated_pass)