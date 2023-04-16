import os
import getpass as gt
import pandas as pd
import sqlite3
import re
import sys
import gzip
import codecs
import blackboxprotobuf
import json
import hashlib
import struct
from datetime import datetime
from Crypto.Cipher import AES


class MDFile:
    def __init__(self, title, directory):
        self.file = ""
        self.filename = os.path.join(directory, f"{title.replace('/', '&')}_notes.md")
        self.headers = []
        self.title = get_title(title)

    def add_header(self, level, title, header_id=""):
        header, header_id = get_header(level, title, header_id)
        self.file += header
        self.headers.append({"level": level, "header": f"[{title}](#{header_id})"})

    def add_paragraph(self, text):
        self.file += f"\n\n{text}"

    def add_table_of_content(self, title, depth):
        toc = []
        title = get_title(title)
        for header in self.headers:
            level = header["level"]
            if level <= depth:
                toc.append("\t"*(level-1) + f"* {header['header']}")
        toc = '\n'.join(toc) + '\n'
        self.file = title + toc + self.file

    def add_line(self, text):
        self.file += " \n" + text

    def add_status(self, title, level):
        header, _ = get_header(level, title)
        self.file = header + self.file

    def write_annotations(self, annotations, chapter):
        self.add_header(level=2, title=chapter)
        index = 1
        for annotation in annotations:
            note = annotation["notes"]
            self.add_header(level=3, title=str(index).rjust(3, '0'))
            self.add_paragraph(annotation["highlights"])
            if note:
                note = note.split('\n')
                if len(note) > 1:
                    for n in note:
                        self.add_line(f"> {n}")
                else:
                    self.add_paragraph(f"> {note[0]}")
            index += 1

    def write_file(self):
        with open(self.filename, 'w') as file:
            file.write(self.title + self.file)


def get_title(title):
    return "\n" + title + "\n" + "".join(["=" for _ in title]) + "\n"


def get_header(level, title, header_id=""):
    header_id = header_id if header_id else re.sub("[^a-z0-9_\-]", "", title.lower().replace(" ", "-"))
    header = f"\n\n{'#' * level} {title} \n"
    return header, header_id


def get_argument():
    if len(sys.argv) == 1:
        directory = 'notes/'
    elif sys.argv[1] == '--directory':
        directory = sys.argv[2]
    else:
        raise ValueError("only argument --directory is supported")

    password = input("Enter your password for notes if there are locked notes.")
    return directory, password


def create_directory(directory, path):
    full_path = os.path.join(directory, path)
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    return full_path


def aes_unwrap_key(kek, wrapped):
    quad = struct.Struct('>Q')
    n = len(wrapped) // 8 - 1
    R = [b'None'] + [wrapped[i * 8:i * 8 + 8] for i in range(1, n + 1)]
    A = quad.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek, AES.MODE_ECB).decrypt
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            ciphertext = quad.pack(A ^ (n * j + i)) + R[i]
            B = decrypt(ciphertext)
            A = quad.unpack(B[:8])[0]
            R[i] = B[8:]
    return b"".join(R[1:])


def derive_password_key(data, password):
    password_key = hashlib.pbkdf2_hmac("sha256",
                                       bytes(password, 'utf-8'),
                                       data["crypto_salt"],
                                       data["crypto_iteration"],
                                       dklen=16)
    return password_key


def unwrap_encryption_key(data, password_key):
    unwrapped_key = aes_unwrap_key(password_key,
                                   data["crypto_wrapped_key"])
    return unwrapped_key


def decrypt_data(data, password):
    if not password:
        raise ValueError("Please put in your password to process the locked notes.")
    password_key = derive_password_key(data, password)
    key = unwrap_encryption_key(data, password_key)
    cipher = AES.new(key, AES.MODE_GCM, data["crypto_initialization_vector"])
    unwrapped_data = cipher.decrypt(data["data"])
    return unwrapped_data


def get_database_connection(db_dir):
    try:
        database = sqlite3.connect(db_dir)
    except sqlite3.Error as error:
        raise ValueError(error)
    database.text_factory = lambda x: str(x, "utf8")
    return database


def get_text(data, password):
    message = None
    unwrapped_data = decrypt_data(data, password) if data["is_password_protected"] else data["data"]
    try:
        unwrapped_data = gzip.decompress(unwrapped_data)
        unwrapped_data = codecs.decode(unwrapped_data.hex(), encoding='hex', errors='strict')
        message, typedef = blackboxprotobuf.protobuf_to_json(unwrapped_data)
        message = json.loads(message)['2']['3']['2']
    except Exception as error:
        print(f"note decryption failed for <{data['title']}>")
        print(f"Error: {error}")
    return message


def get_metadata(db_dir, password):
    database = get_database_connection(db_dir)
    query = """
    SELECT 
        Z.Z_PK as key, Z.ZTITLE1 as title, _FOLDER.ZTITLE2 as folder, NOTEDATA.ZDATA as data, 
        Z.ZCREATIONDATE3 as creation_date, Z.ZMODIFICATIONDATE1 as modification_date,
        Z.ZISPASSWORDPROTECTED as is_password_protected,
        Z.ZCRYPTOITERATIONCOUNT as crypto_iteration, Z.ZCRYPTOSALT as crypto_salt, Z.ZCRYPTOTAG as crypto_tag,
        Z.ZCRYPTOINITIALIZATIONVECTOR as crypto_initialization_vector, Z.ZCRYPTOWRAPPEDKEY as crypto_wrapped_key
    FROM ZICCLOUDSYNCINGOBJECT as Z 
    INNER JOIN ZICCLOUDSYNCINGOBJECT AS _FOLDER ON Z.ZFOLDER = _FOLDER.Z_PK 
    INNER JOIN ZICNOTEDATA as NOTEDATA ON Z.ZNOTEDATA = NOTEDATA.Z_PK 
    WHERE _FOLDER.ZTITLE2 != 'Recently Deleted'
    """
    metadata = pd.read_sql_query(query, database)
    metadata["data"] = [get_text(metadata.loc[i], password) for i in metadata.index]
    for col in ["creation_date", "modification_date"]:
        metadata[col] = [datetime.fromtimestamp(date + 978307200).strftime('%Y-%m-%d %H:%M:%S')
                         for date in metadata[col]]
    return metadata


def save_raw_data(data, path):
    raw_data = data[["key", "title", "folder", "data", "creation_date", "modification_date", "is_password_protected"]]
    raw_data.to_csv(path, index=False)


def create_md_file(note, directory):
    title = note["title"]
    folder_path = create_directory(directory, note["folder"])
    md_file = MDFile(title=title, directory=folder_path)
    md_file.add_header(level=1, title='Note Overview')
    for key in ["folder", "creation_date", "modification_date"]:
        md_file.add_paragraph(f"**{key.capitalize()}**: {note[key]}")
    md_file.add_header(level=1, title='Note Content')
    md_file.add_paragraph(note["data"])
    md_file.write_file()


def export_notes(user, password="", directory="notes/"):
    data_path = create_directory(directory, "raw_data/")
    lib_dir = f"/Users/{user}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"
    notes = get_metadata(lib_dir, password)
    save_raw_data(notes, os.path.join(data_path, "notes_data.csv"))
    for index in notes.index:
        create_md_file(notes.loc[index], directory)
    print(f"Exported {len(notes)} notes successfully from Apple Notes.")


if __name__ == "__main__":
    dir_name, note_password = get_argument()
    username = gt.getuser()
    export_notes(username, note_password, dir_name)

