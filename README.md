## DJSM - Django JSON Secrets Manager

Light weight Python module that allows you to easily store and access your Django project's secrets like secret key, database password, etc., encrypted in a JSON file.

[View package on PyPI](https://pypi.org/project/djsm/)

## Installation and Quick Setup

* Install the package using pip.

```bash
pip install djsm
```

* Setup or update a '.env' file for your project.

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
|   |-- .gitignore
|   |-- requirements.txt
|
|-- venv
|-- .env
```

* Import the package in your Django project

In settings.py:

```python
import djsm

djsm.check_setup()
```

* Run server

```bash
python manage.py runserver
```

If everything was setup successfully, you should see "Setup OK!" on the terminal. Remember to remove the `djsm.check_setup()` line from your settings.py file.

## Usage

Before starting, a '.env' file has to be created just outside the django project directory.
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

### Using DJSM in the CLI

An easy way to start using DJSM in your project is by letting DJSM handle your django project's secret key. To do this:

* Add djsm to the project's list of installed apps.

In settings.py:

```python

INSTALLED_APPS = [
    ...,
    'djsm',
    ....
]
```

* In the command line/terminal run the management command;

```bash
python manage.py use_djsm
```

You're ready to go. The secrets manager will automatically be created (based on the configurations defined in the .env file) in `your_project.settings.py` and the project's secret key will now be stored and served by the secrets manager. You can use this manager to also handle something like your database key like so.

```python

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'NAME': 'myproject_database'.
            'USER': djsm_manager.get_secret('DB_USER'),
            'PASSWORD': djsm_manager.get_secret('DB_PASSWORD'),
            'HOST': 'localhost',
            'PORT': '3306',
        }
    }
}
```

You could also define optional flags when running the above command. For example;

```bash
python manage.py use_djsm --as "secrets_manager"
```

Lets you define the name of the djsm in settings.py. Also, you could the `--quiet` flag to prevent manager created from printing setup/process logs to the console.

```bash
python manage.py use_djsm --as "secrets_manager" --quiet
```

### Other CLI/Management commands

Apart from the `use_djsm` command, there are two other useful commands that can be run in your project. 

* Add to or update existing secrets

```bash
python manage.py update_secrets "<secret_name>" "<secret_value>"
```

For example:

```bash
python manage.py update_secrets 'api_key' '32456789456sdtfg'
```

However, you should note that the value passed must be a JSON formatted string. See an example of me saving a mapping of my django projects detail below.

```bash
python manage.py update_secrets 'project_emails' '{\"project_email\": \"support@myproject.com\", \"admin_email\": \"admin@myproject.com\"}'
```

* Change the encryption key used by the secrets manager.

```bash
python manage.py change_cryptkeys
```

* Clean up secrets and environment variables set by the secrets manager.

```bash
python manage.py djsm_cleanup
```

* Reload environment variables from .env file

```bash
python manage.py djsm_reload_env
```

### Manually creating and using a secrets manager

```python
import djsm

secrets_manager = djsm.get_djsm(quiet=False)
```

`get_djsm` returns a DJSM object instantiated using values defined in .env file after performing necessary checks.

You can set `quiet=True` if you do not want to see messages on the terminal. Although, important messages are always displayed.

To generate a new secret key or use and existing one. In settings.py:

```python
SECRET_KEY = secrets_manager.get_or_create_secret_key()
```

To update or add a new secret:

```python
new_secret = {"DB_PASSWORD": "db_password"}
secrets_manager.update_secrets(new_secret)
```

Once the update has been performed you can delete these lines.

To get a secret:

```python
# Get a secret, say DB_PASSWORD
db_password = secrets_manager.get_secret("DB_PASSWORD")
```

You can also create a djsm object independent of the configuration in the .env file. Read the next section for more info.

### `DjangoJSONSecretManager`

This class is the main class of the module. It provides the following methods:

* `get_secret(secret_name)` -> Returns the secret with the name `secret_name` if it exists, otherwise returns `None`

* `update_secrets(new_secrets)` -> Updates the secrets file with the new secrets provided in the `new_secrets` dictionary.

* `get_or_create_secret_key()` -> Returns the Django secret key if it exists, otherwise generates a new one and returns it.

* `change_cryptkeys()` -> Replaces the encryption keys used to encrypt and decrypt secrets with a new one.

* `clean_up()` -> Deletes the secrets file and clears all environment variables set by the module.

* `reload_env()` -> Reloads the environment variables from the .env file.

* `clean_up_and_reload()` -> Calls the `clean_up()` and `reload_env()` methods.

```python
from djsm import DJSM  # DJSM is an alias for DjangoJSONSecretManager

# Create a DJSM object
secrets_manager = DJSM('./.secretfolder/secrets.json')
```

**DO NOT DELETE `cryptkeys.json` or any of the encryption keys. IF YOU DO, ALL ENCRYPTED SECRET WILL BE LOST**

> NOTE: DJSM just provides an added layer of security in managing secrets in your application. It is not proven to be completely attack proof.

Contributions are welcome. Please fork the repository and submit a pull request.
