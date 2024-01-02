## DJSM - Django JSON Secrets Manager

Light weight Python module that allows you to easily store and access your Django project's secrets like secret key, database password, etc., encrypted in a JSON file.

[View package on PyPI](https://pypi.org/project/djsm/)

## Installation and Quick Setup

* Install the package using pip

```bash
pip install djsm
```

* Initial setup:

Copy this into a .env file just outside your project (adjust as needed)

```.env
DJSM_SECRETS_FILE_PATH = "./.secretfolder/path/secrets.json" 
# Assign path to file you want secrets to be stored in. Even if it does not exist yet

# NOT MANDATORY
DJSM_SECRET_KEY_NAME = "secretkey"
```

Your project structure should look like this:

```bash

|-- my_project
|   |-- my_project
|   |   |-- __init__.py
|   |   |-- settings.py
|   |   |-- urls.py
|   |   |-- wsgi.py
|   |
|   |-- my_app
|   |   |-- __init__.py
|   |   |-- admin.py
|   |   |-- apps.py
|   |   |-- models.py
|   |   |-- tests.py
|   |   |-- views.py
|   |
|   |-- db.sqlite3
|   |-- manage.py
|
|-- venv
|-- .env
|-- .gitignore
|-- requirements.txt

```

* Import the package in your Django project

In settings.py

```python
from djsm import get_djsm

manager = get_djsm()
```

* Run server

```bash
python manage.py runserver
```

If everything was setup successfully, you should see "Setup OK!" on the terminal.

## Usage

Before starting, a '.env' file as to be created just outside the django project directory.
In the file, the following should be added;

* **`DJSM_SECRETS_FILE_PATH`** -> Path(preferably absolute) to file where all secrets will be stored.
Example:

```.env
SECRETS_FILE_PATH = "/.secrets/pathtofile/secrets.json"
```

* **`DJSM_SECRET_KEY_NAME`** -> Name with which the Django secret key should be stored.
Example:

```.env
DJSM_SECRET_KEY_NAME = 'django_secret_key'
```

### Creating and using a secrets manager

`get_djsm` returns a DJSM object instantiated using values defined in .env file after performing necessary checks.

```python
from djsm import get_djsm

manager = get_djsm(quiet=False)
```

You can set `quiet=True` if you do not want to see messages on the terminal. Although, important messages are always displayed.

To generate a new secret key or use and existing one. In settings.py:

```python
# generate secret key if it does not exist
SECRET_KEY = manager.get_or_create_secret_key()

```

To update or add a new secret:

```python
new_secret = {"DB_PASSWORD": "db_password"}
manager.update_secrets(new_secret)

```

Once the update has been performed you can delete these lines.

To get a secret:

```python
# Get a secret, say DB_PASSWORD
db_password = manager.get_secret("DB_PASSWORD")
```

### `DjangoJSONSecretManager`

This class is the main class of the module. It provides the following methods:

* `get_secret(secret_name)` -> Returns the secret with the name `secret_name` if it exists, otherwise returns `None`

* `update_secrets(new_secrets)` -> Updates the secrets file with the new secrets provided in the `new_secrets` dictionary.
If a secret already exists, it is updated, otherwise, it is added.

* `get_or_create_secret_key()` -> Returns the Django secret key if it exists, otherwise generates a new one and returns it

* `write_secrets(secrets, path_to_secret_file, **kwargs)` -> Writes secrets to the secrets file whose path is provided.

* `load_secrets(path_to_secret_file, **kwargs)` -> Loads secrets from the secrets file whose path is provided.

* `change_crypt_keys()` -> Changes the encryption keys used to encrypt and decrypt secrets. This is useful if you want to change the encryption keys used to encrypt and decrypt existing secrets.

* `clean_up()` -> Deletes the secret key file and the secrets file and clears all environment variables set by the module.

* `reload_env()` -> Reloads the environment variables from the .env file.

* `clean_up_and_reload()` -> Calls the `clean_up()` and `reload_env()` methods.

How to use the `DJSM` class:

```python
from djsm import DJSM  # DJSM is an alias for DjangoJSONSecretManager

# Instantiation
manager = DJSM('./.secretfolder/secrets.json')

# get a secret, say DB_PASSWORD
db_password = manager.get_secret("DB_PASSWORD")

# generate a new secret key
new_secret_key = manager.get_or_create_secret_key()

# update secrets or add new secrets
new_secret = {"DB_PASSWORD": "new_db_password"}
manager.update_secrets(new_secret)

# change encryption and decryption keys
manager.change_crypt_keys()
```

**DO NOT DELETE `cryptkeys.json`. IF YOU DO, ALL ENCRYPTED SECRET WILL BE LOST**

> NOTE: DJSM just provides an added layer of security in managing secrets in your application. It is not tested to be completely attack proof.

Contributions are welcome. Please fork the repository and submit a pull request.
