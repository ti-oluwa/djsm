# DJSM - Django JSON Secrets Manager

## What is DJSM?
DJSM is a light weight python module that allows you to store secrets encrypted in a JSON file and access them easily in your Django project. It provides a simple interface to access the secrets in a JSON file.

[View Project on PyPI](https://pypi.org/project/djsm/)

## Installation
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

-[x] `SECRETS_FILE_PATH` -> Absolute path to file where all secrets will be stored.
Example:

```
SECRETS_FILE_PATH = ".secrets/pathtofile/secrets.json"
```
It is advisable to save secrets in an hidden folder(by prefixing the path with a period - '.')

-[x] `SECRETS_FILE_FALLBACKS_PATHS` -> Absolute paths to existing secrets file(s), stringed together and separated by a delimiter(usually comma), in the project if any. They would be used if any error is encountered while using the preferred secrets file.
Example:

```
SECRETS_FILE_FALLBACKS_PATHS = ".secrets/pathtofile/secrets.json,.secrets/pathtofile/secrets2.json,.secrets/pathtofile/secrets3.json "
```

-[x] `DJANGO_SECRET_KEY_NAME` -> Name with which the Django secret key should be stored.
Example:

```
DJANGO_SECRET_KEY_NAME = 'secret_key'
```

-[x] `DJANGO_SECRET_KEY_FILE_PATH` -> DJSM stores the Django secret key in a separate file, whose file path is provided by this variable, otherwise, the Django secret key is stored in the secrets file.
Example:

```
DJANGO_SECRET_KEY_FILE_PATH = ".secrets/pathtofile/secret_key.json"
```

-[x] `DJANGO_SECRET_KEY_FALLBACKS_PATHS` -> Absolute paths to existing secret_key file(s), stringed together and separated by a delimiter(usually comma), in the project if any. They would be used if any error is encountered while using the preferred secret_key file.
Example:

```
DJANGO_SECRET_KEY_FALLBACKS_PATHS = ".secrets/pathtofile/secret_key.json,.secrets/pathtofile/secret_key2.json,.secrets/pathtofile/secret_key3.json "
```



### Import djsm
`djsm` is a pre-instanciated object of the class DJSM. You can import it using the following code.
For most use cases, this is the only import you will need.

```python
from djsm import djsm
```

For other use cases, you can import the DJSM class and create your own instance of it.

```python
import os
from djsm import DJSM


djsm = DJSM(os.environ.get('SECRETS_FILE_PATH'))
djsm.django_secret_key_name = os.environ.get('DJANGO_SECRET_KEY_NAME')
djsm.django_secret_key_file_path = os.environ.get('DJANGO_SECRET_KEY_FILE_PATH')
djsm.secret_key_fallbacks = os.environ.get('DJANGO_SECRET_KEY_FALLBACKS_PATHS', '').split(',')

```

### Generating a secret key or getting an existing key
To generate a secret key, in settings.py implement:

```python

# SECURITY WARNING: keep the secret key used in production secret!
# generate secret key if it does not exist
SECRET_KEY = djsm.generate_secret_key()

```

### Updating or Adding new secrets
To add a new secret:

```python
new_secret = {"DB_PASSWORD": "db_password"}
djsm.update_secrets(new_secret)

```
Once the update as been performed you can delete these lines.

### Get all secrets
To get all secrets:

```python
all_secrets = djsm.secrets 

```


#### Contributors and feedbacks are welcome. For feedbacks, please open an issue or contact me at tioluwa.dev@gmail.com or on twitter [@ti_oluwa_](https://twitter.com/ti_oluwa_)

#### To contribute, please fork the repo and submit a pull request

#### If you find this module useful, please consider giving it a star. Thanks!
