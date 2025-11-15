"""
University Database Management System (Tkinter + MySQL)

- Requires: mysql-connector-python, cryptography
- Run: python university_db_gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import mysql.connector
from mysql.connector import Error

from cryptography.fernet import Fernet, InvalidToken
import os

# --------------------- CONFIG (edit or enter at runtime) ---------------------
DEFAULT_DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "abc",
    "database": "uni_academic_db"
}

# --------------------- ENCRYPTION CONFIG ---------------------
# File to store symmetric key (auto-generated first run)
KEYFILE = "secret.key"

# Map of table -> list of column names that should be encrypted before storing
# Edit this to add/remove which columns you want encrypted for each table.
SENSITIVE_COLUMNS = {
    "Student": ["Email", "Phone"],
    "Teacher": ["Email", "Phone"],
    "Department": ["Email", "Phone"]
}

def load_or_create_key():
    """Load Fernet key from KEYFILE or generate and save a new one."""
    if os.path.exists(KEYFILE):
        with open(KEYFILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEYFILE, "wb") as f:
            f.write(key)
        return key

FERNET_KEY = load_or_create_key()
FERNET = Fernet(FERNET_KEY)

def encrypt_value(value):
    """Encrypt a string (returns str) - value should be str or None."""
    if value is None:
        return None
    # Ensure bytes input
    if not isinstance(value, bytes):
        value = str(value).encode("utf-8")
    token = FERNET.encrypt(value)
    return token.decode("utf-8")

def decrypt_value(token):
    """Decrypt a token produced by encrypt_value. Returns str. If invalid, return token as-is."""
    if token is None:
        return None
    try:
        # token might already be bytes or str
        if isinstance(token, str):
            token_bytes = token.encode("utf-8")
        else:
            token_bytes = token
        plain = FERNET.decrypt(token_bytes)
        return plain.decode("utf-8")
    except (InvalidToken, ValueError):
        # If token isn't valid or wasn't encrypted (e.g., plain text), return original
        try:
            # if bytes, decode; otherwise return as-is
            return token.decode("utf-8") if isinstance(token, bytes) else token
        except Exception:
            return token

# --------------------- DB HELPERS ---------------------
def connect_db(cfg):
    try:
        conn = mysql.connector.connect(
            host=cfg["host"],
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"]
        )
        return conn
    except Error as e:
        raise

def fetch_tables(conn):
    cur = conn.cursor()
    cur.execute("SHOW TABLES;")
    tables = [r[0] for r in cur.fetchall()]
    cur.close()
    return tables

def fetch_columns(conn, dbname, table):
    cur = conn.cursor(dictionary=True)
    sql = """
      SELECT COLUMN_NAME, DATA_TYPE, COLUMN_KEY, EXTRA
      FROM information_schema.columns
      WHERE table_schema=%s AND table_name=%s
      ORDER BY ORDINAL_POSITION;
    """
    cur.execute(sql, (dbname, table))
    cols = cur.fetchall()
    cur.close()
    return cols

def fetch_all_rows(conn, table):
    cur = conn.cursor()
    # simple validation: table name should not contain semicolons or spaces
    if not table.isidentifier():
        raise ValueError("Invalid table name")
    cur.execute(f"SELECT * FROM `{table}`;")
    rows = cur.fetchall()
    colnames = [d[0] for d in cur.description]
    cur.close()

    # Decrypt sensitive columns before returning (if configured)
    sensitive = SENSITIVE_COLUMNS.get(table, [])
    if sensitive and rows:
        decrypted_rows = []
        # build index map for columns to decrypt
        col_index = {name: idx for idx, name in enumerate(colnames)}
        decrypt_indices = [col_index[c] for c in sensitive if c in col_index]
        for r in rows:
            r = list(r)
            for idx in decrypt_indices:
                try:
                    r[idx] = decrypt_value(r[idx])
                except Exception:
                    # if decryption fails, leave as original
                    pass
            decrypted_rows.append(tuple(r))
        rows = decrypted_rows

    return colnames, rows

def insert_row(conn, table, data):
    # Encrypt sensitive columns in data before insert
    sensitive = SENSITIVE_COLUMNS.get(table, [])
    data_enc = data.copy()
    for col in sensitive:
        if col in data_enc and data_enc[col] is not None:
            # only encrypt non-None values
            data_enc[col] = encrypt_value(data_enc[col])
    cols = ", ".join(f"`{c}`" for c in data_enc.keys())
    vals_place = ", ".join(["%s"] * len(data_enc))
    sql = f"INSERT INTO `{table}` ({cols}) VALUES ({vals_place})"
    cur = conn.cursor()
    cur.execute(sql, tuple(data_enc.values()))
    conn.commit()
    lid = cur.lastrowid
    cur.close()
    return lid

def update_row(conn, table, data, pk_where):
    # Encrypt sensitive columns in data before update
    sensitive = SENSITIVE_COLUMNS.get(table, [])
    data_enc = data.copy()
    for col in sensitive:
        if col in data_enc and data_enc[col] is not None:
            data_enc[col] = encrypt_value(data_enc[col])
    set_clause = ", ".join(f"`{c}`=%s" for c in data_enc.keys())
    where_clause = " AND ".join(f"`{c}`=%s" for c in pk_where.keys())
    sql = f"UPDATE `{table}` SET {set_clause} WHERE {where_clause}"
    cur = conn.cursor()
    cur.execute(sql, tuple(data_enc.values()) + tuple(pk_where.values()))
    conn.commit()
    cur.close()

def delete_row(conn, table, pk_where):
    where_clause = " AND ".join(f"`{c}`=%s" for c in pk_where.keys())
    sql = f"DELETE FROM `{table}` WHERE {where_clause}"
    cur = conn.cursor()
    cur.execute(sql, tuple(pk_where.values()))
    conn.commit()
    cur.close()

# --------------------- UI ---------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("University Database Management System")
        self.geometry("1100x700")
        self.minsize(900, 600)
        # theme colors
        self.bg_blue = "#183f63"
        self.panel_blue = "#214e78"
        self.header_gray = "#2b2b2b"
        self.text_fg = "#e8eef6"
        self.row_alt = "#123a58"
        self.btn_gray = "#2f3a44"

        self.configure(bg=self.bg_blue)
        self.conn = None
        self.dbname = None

        self.create_topbar()
        self.create_main_layout()
        self.prompt_db_credentials()

    def create_topbar(self):
        top = tk.Frame(self, bg=self.header_gray, height=60)
        top.pack(side="top", fill="x")
        lbl = tk.Label(top, text="University Academic Database System",
                       bg=self.header_gray, fg=self.text_fg,
                       font=("Helvetica", 18, "bold"), pady=12)
        lbl.pack()

    def create_main_layout(self):
        main = tk.Frame(self, bg=self.bg_blue)
        main.pack(fill="both", expand=True, padx=12, pady=12)

        left = tk.Frame(main, width=220, bg=self.panel_blue)
        left.pack(side="left", fill="y", padx=(0,10), pady=4)
        left.pack_propagate(False)
        tk.Label(left, text="Tables", bg=self.panel_blue, fg=self.text_fg,
                 font=("Helvetica", 14, "bold")).pack(anchor="nw", padx=10, pady=8)

        self.table_listbox = tk.Listbox(left, bg=self.panel_blue, fg=self.text_fg,
                                        bd=0, highlightthickness=0, activestyle="none",
                                        font=("Helvetica", 12), selectbackground="#1a6a9a")
        self.table_listbox.pack(fill="both", expand=True, padx=8, pady=6)
        self.table_listbox.bind("<<ListboxSelect>>", self.on_table_select)

        center = tk.Frame(main, bg=self.bg_blue)
        center.pack(side="left", fill="both", expand=True, padx=(0,10))

        self.table_label = tk.Label(center, text="Select a table", bg=self.bg_blue, fg=self.text_fg,
                                    font=("Helvetica", 16, "bold"))
        self.table_label.pack(anchor="n", pady=(4,6))

        tv_frame = tk.Frame(center, bg=self.panel_blue, padx=8, pady=8)
        tv_frame.pack(fill="both", expand=True, padx=6, pady=6)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=self.panel_blue,
                        fieldbackground=self.panel_blue,
                        foreground=self.text_fg,
                        rowheight=30,
                        font=("Helvetica", 11))
        style.map('Treeview', background=[('selected', '#1a6a9a')])
        style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"),
                        background=self.panel_blue, foreground=self.text_fg)

        self.tree = ttk.Treeview(tv_frame, show="headings")
        self.tree.pack(fill="both", expand=True, side="left")
        self.tree_scroll = ttk.Scrollbar(tv_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.pack(side="right", fill="y")

        btn_frame = tk.Frame(center, bg=self.bg_blue)
        btn_frame.pack(fill="x", pady=10)

        self.btn_add = tk.Button(btn_frame, text="Add Record", command=self.add_record,
                                 font=("Helvetica", 12), bd=0, relief="raised",
                                 bg=self.btn_gray, fg=self.text_fg, padx=18, pady=10)
        self.btn_add.pack(side="left", padx=12, expand=True)

        self.btn_edit = tk.Button(btn_frame, text="Edit Record", command=self.edit_record,
                                 font=("Helvetica", 12), bd=0, relief="raised",
                                 bg=self.btn_gray, fg=self.text_fg, padx=18, pady=10)
        self.btn_edit.pack(side="left", padx=12, expand=True)

        self.btn_del = tk.Button(btn_frame, text="Delete Record", command=self.delete_record,
                                 font=("Helvetica", 12), bd=0, relief="raised",
                                 bg=self.btn_gray, fg=self.text_fg, padx=18, pady=10)
        self.btn_del.pack(side="left", padx=12, expand=True)

        self.btn_refresh = tk.Button(btn_frame, text="Refresh Data", command=self.refresh_data,
                                 font=("Helvetica", 12), bd=0, relief="raised",
                                 bg=self.btn_gray, fg=self.text_fg, padx=18, pady=10)
        self.btn_refresh.pack(side="left", padx=12, expand=True)

    # --------------------- DB CONNECT FLOW ---------------------
    def prompt_db_credentials(self):
        cfg = DEFAULT_DB_CONFIG.copy()
        try:
            host = simpledialog.askstring("DB Host", "MySQL Host:", initialvalue=cfg["host"], parent=self)
            if host is None:
                self.destroy(); return
            user = simpledialog.askstring("DB User", "MySQL User:", initialvalue=cfg["user"], parent=self)
            if user is None:
                self.destroy(); return
            password = simpledialog.askstring("DB Password", "MySQL Password:", show="*", parent=self)
            if password is None:
                password = ""
            database = simpledialog.askstring("Database", "Database Name:", initialvalue=cfg["database"], parent=self)
            if database is None:
                self.destroy(); return
            cfg.update({"host": host.strip(), "user": user.strip(), "password": password, "database": database.strip()})
            self.dbname = database.strip()
            self.conn = connect_db(cfg)
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            self.destroy()
            return

        # load tables
        self.load_tables_into_listbox()

    def load_tables_into_listbox(self):
        try:
            tables = fetch_tables(self.conn)
            self.table_listbox.delete(0, tk.END)
            for t in tables:
                self.table_listbox.insert(tk.END, t)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list tables: {e}")

    # --------------------- TABLE OPERATIONS ---------------------
    def on_table_select(self, event=None):
        sel = self.table_listbox.curselection()
        if not sel:
            return
        table = self.table_listbox.get(sel[0])
        self.current_table = table
        self.table_label.config(text=table)
        self.load_table_data(table)

    def load_table_data(self, table):
        try:
            colnames, rows = fetch_all_rows(self.conn, table)
            self.tree.delete(*self.tree.get_children())
            self.tree["columns"] = colnames
            for c in colnames:
                self.tree.heading(c, text=c)
                self.tree.column(c, width=150, anchor="center")
            for r in rows:
                self.tree.insert("", tk.END, values=r)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load table data: {e}")

    def refresh_data(self):
        if hasattr(self, "current_table"):
            self.load_table_data(self.current_table)

    def get_table_metadata(self, table):
        return fetch_columns(self.conn, self.dbname, table)

    def detect_primary_keys(self, metadata):
        pks = [col["COLUMN_NAME"] for col in metadata if col["COLUMN_KEY"] == "PRI"]
        return pks

    # --------------------- CRUD POPUPS ---------------------
    def add_record(self):
        if not hasattr(self, "current_table"):
            messagebox.showwarning("No table", "Select a table first.")
            return
        table = self.current_table
        meta = self.get_table_metadata(table)
        fields = [c for c in meta if "auto_increment" not in (c.get("EXTRA") or "").lower()]
        PopupForm(self, title=f"Add to {table}", table=table, conn=self.conn,
                  meta=fields, on_success=self.refresh_data, is_update=False)

    def edit_record(self):
        if not hasattr(self, "current_table"):
            messagebox.showwarning("No table", "Select a table first.")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No row", "Select a row to edit.")
            return
        rowvals = self.tree.item(sel[0])["values"]
        colnames = self.tree["columns"]
        rowdict = dict(zip(colnames, rowvals))
        table = self.current_table
        meta = self.get_table_metadata(table)
        PopupForm(self, title=f"Edit {table}", table=table, conn=self.conn,
                  meta=meta, on_success=self.refresh_data, is_update=True,
                  row=rowdict)

    def delete_record(self):
        if not hasattr(self, "current_table"):
            messagebox.showwarning("No table", "Select a table first.")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No row", "Select a row to delete.")
            return
        table = self.current_table
        meta = self.get_table_metadata(table)
        pks = self.detect_primary_keys(meta)
        for iid in sel:
            rowvals = self.tree.item(iid)["values"]
            colnames = self.tree["columns"]
            rowdict = dict(zip(colnames, rowvals))
            if pks:
                pk_where = {k: rowdict[k] for k in pks}
            else:
                pk_where = rowdict
            if messagebox.askyesno("Confirm Delete", f"Delete selected row from {table}?"):
                try:
                    delete_row(self.conn, table, pk_where)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete row: {e}")
        self.refresh_data()

# --------------------- POPUP FORM CLASS ---------------------
class PopupForm(tk.Toplevel):
    def __init__(self, parent, title, table, conn, meta, on_success, is_update=False, row=None):
        super().__init__(parent)
        self.parent = parent
        self.table = table
        self.conn = conn
        self.meta = meta
        self.on_success = on_success
        self.is_update = is_update
        self.row = row or {}
        self.title(title)
        self.configure(bg=parent.bg_blue)
        self.build_form()

    def build_form(self):
        frm = tk.Frame(self, bg=self.parent.bg_blue, padx=12, pady=12)
        frm.pack(fill="both", expand=True)
        self.entries = {}
        rowi = 0
        for col in self.meta:
            cname = col["COLUMN_NAME"]
            if not self.is_update and "auto_increment" in (col.get("EXTRA") or "").lower():
                continue
            lbl = tk.Label(frm, text=cname, bg=self.parent.bg_blue, fg=self.parent.text_fg,
                           font=("Helvetica", 11))
            lbl.grid(row=rowi, column=0, sticky="w", pady=6)
            ent = tk.Entry(frm, width=40, font=("Helvetica", 11))
            ent.grid(row=rowi, column=1, pady=6, padx=(10,0))
            if self.is_update and cname in self.row:
                ent.insert(0, str(self.row[cname] if self.row[cname] is not None else ""))
            self.entries[cname] = ent
            rowi += 1

        btn_frame = tk.Frame(frm, bg=self.parent.bg_blue)
        btn_frame.grid(row=rowi, column=0, columnspan=2, pady=(12,4))
        save_text = "Update" if self.is_update else "Save"
        btn_save = tk.Button(btn_frame, text=save_text, command=self.on_save,
                             bg=self.parent.btn_gray, fg=self.parent.text_fg, padx=14, pady=8)
        btn_save.pack(side="left", padx=8)
        btn_cancel = tk.Button(btn_frame, text="Cancel", command=self.destroy,
                             bg=self.parent.btn_gray, fg=self.parent.text_fg, padx=14, pady=8)
        btn_cancel.pack(side="left", padx=8)

    def on_save(self):
        data = {}
        for c, ent in self.entries.items():
            data[c] = ent.get() or None
        try:
            if self.is_update:
                all_meta = fetch_columns(self.conn, self.conn.database, self.table)
                pks = [m["COLUMN_NAME"] for m in all_meta if m["COLUMN_KEY"] == "PRI"]
                if not pks:
                    if not messagebox.askyesno("No PK", "Table has no primary key. Proceed with update using all columns in WHERE?"):
                        return
                    pk_where = self.row.copy()
                else:
                    pk_where = {pk: self.row.get(pk) for pk in pks}
                set_data = {k: v for k, v in data.items() if k not in pk_where}
                if not set_data:
                    messagebox.showwarning("Nothing to update", "No editable columns were changed.")
                    return
                update_row(self.conn, self.table, set_data, pk_where)
                messagebox.showinfo("Success", "Row updated.")
            else:
                insert_row(self.conn, self.table, data)
                messagebox.showinfo("Success", "Row added.")
            self.on_success()
            self.destroy()
        except Exception as e:
            messagebox.showerror("DB Error", f"{e}")

# --------------------- MAIN ---------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
