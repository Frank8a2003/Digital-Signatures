## README

# PDF Document Signing Application

This is a Python application that allows users to sign PDF documents using GPG keys. The application uses a SQLite database to store user credentials and details of initiatives. It features a Tkinter-based GUI for user interaction.

## Features

- **User Authentication**: Secure login with username and password.
- **Admin Functionality**: Admin user can generate reports and update initiatives.
- **Initiative Management**: Add and manage initiatives, including downloading and signing PDF documents.
- **GPG Signing**: Uses GPG keys to sign documents and verify their integrity.
- **CSV Logging**: Logs signed documents and changes in a CSV file.

## Installation

### Prerequisites

- Python 3.x
- Required Python packages: `tkinter`, `sqlite3`, `hashlib`, `gnupg`, `requests`, `csv`, `pypdf`, `pycryptodome`

### Install Required Packages

You can install the required packages using pip:

```bash
pip install tkinter gnupg requests pypdf pycryptodome
```

### GPG Configuration

Ensure you have GPG installed on your system. You can download it from [GnuPG's official website](https://gnupg.org/download/index.html).

Configure your GPG home and binary paths as needed. Update the following lines in the script to match your environment:

```python
gpg = gnupg.GPG(gnupghome='path_to_gpg_home', gpgbinary='path_to_gpg_binary')
```

## Usage

1. **Run the Script**:
   ```bash
   python your_script_name.py
   ```

2. **Login**:
   - Use one of the predefined usernames and passwords to log in. 
   - Admin credentials: `username: admin`, `password: admin1234`

3. **Admin Functions**:
   - Generate reports and update initiatives.

4. **User Functions**:
   - Add and manage initiatives.
   - Sign initiative documents.

## Database Schema

### Users Table

| Column     | Type    | Description                   |
|------------|---------|-------------------------------|
| username   | TEXT    | Primary key, unique username  |
| password   | TEXT    | User password                 |
| keyid      | TEXT    | GPG key ID                    |
| last_login | TIMESTAMP | Last login timestamp          |

### Initiatives Table

| Column        | Type      | Description                             |
|---------------|-----------|-----------------------------------------|
| initiative_id | INTEGER   | Primary key, unique initiative ID       |
| url           | TEXT      | URL of the initiative                   |
| hashant       | TEXT      | Previous hash of the document           |
| hashnew       | TEXT      | Current hash of the document            |
| sign          | TEXT      | GPG signed content                      |
| first_mod     | TIMESTAMP | Timestamp of the first modification     |
| last_mod      | TIMESTAMP | Timestamp of the last modification      |
| user          | TEXT      | Username of the user who last modified  |

