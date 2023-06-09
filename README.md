# DJSM - Django JSON Secrets Manager

## What is DJSM?
DJSM is a light weight python module that allows you to store secrets encrypted in a JSON file and access them easily in your Django project. It provides a simple interface to access the secrets in a JSON file. DJSM uses Fernet encryption combine with RSA encryption to keep secrets secure.

[View Project on PyPI](https://pypi.org/project/djsm/) - NOT LIVE YET


## Installation
**YET TO BE PUBLISHED**
* Install the package using pip
```bash
pip install djsm
```

* Import the package in your Django project
```python
import djsm
```

## Usage
Before starting, a '.env' file as to be created somewhere in the django project directory(preferably the root directory).
In the file, the following should be added;

- **`SECRETS_FILE_PATH`** -> Path(preferably absolute) to file where all secrets will be stored.
Example:

```
SECRETS_FILE_PATH = ".secrets/pathtofile/secrets.json"
```
It is advisable to save secrets in an hidden folder(by prefixing the path with a period - '.'


- **`DJANGO_SECRET_KEY_NAME`** -> Name with which the Django secret key should be stored.
Example:

```
DJANGO_SECRET_KEY_NAME = 'secret_key'
```

- **`DJANGO_SECRET_KEY_FILE_PATH`** -> DJSM stores the Django secret key in a separate file, whose file path is provided by this variable, otherwise, the Django secret key is stored in the secrets file.
Example:

```
DJANGO_SECRET_KEY_FILE_PATH = ".secrets/pathtofile/secret_key.json"
```


### Import djsm
`djsm` is a pre-instanciated object of the class DJSM. You can import it using the following code.
For most use cases, this is the only import you will need.

```python
from djsm import djsm
```

### Generating a secret key or getting an existing key
To generate a secret key:

```python
new_secret_key = djsm.generate_django_secret_key()
```

Or in settings.py implement:

```python

# SECURITY WARNING: keep the secret key used in production secret!
# generate secret key if it does not exist
SECRET_KEY = djsm.get_or_create_secret_key()

```

### Updating or adding new secrets
To add a new secret:

```python
new_secret = {"DB_PASSWORD": "db_password"}
djsm.update_secrets(new_secret)

```
Once the update has been performed you can delete these lines.

Alternatively, You can add a new secret by directly editing the secrets file.


### Getting Secrets
To get a secret:

```python
# get a secret, say DB_PASSWORD
db_password = djsm.get_secret("DB_PASSWORD")

# get secret key
secret_key = djsm.get_secret_key()

```

**DO NOT DELETE `cryptkeys.json`. IF YOU DO, ALL ENCRYPTED SECRET WILL BE LOST**

**NOTE: DJSM just provides an added layer of security in managing secrets in your application. It has not been tested to be completely attack proof**

#### Contributors and feedbacks are welcome. For feedbacks, please open an issue or contact me at tioluwa.dev@gmail.com or on twitter [@ti_oluwa_](https://twitter.com/ti_oluwa_)

#### To contribute, please fork the repo and submit a pull request

#### If you find this module useful, please consider giving it a star. Thanks!
