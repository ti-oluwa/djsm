# DJSM - Django JSON Secrets Manager

## What is DJSM?

DJSM is a light weight Python module that allows you to store secrets encrypted in a JSON file and access them easily in your Django project. DJSM uses Fernet encryption combined with RSA encryption to keep secrets secure.

[View Project on PyPI](https://pypi.org/project/djsm/)


## Installation and Quick Setup

* Install the package using pip

```bash
pip install djsm
```

* Initial setup:

Copy this into a .env file just outside your project (adjust as needed)

```.env
DJSM_SECRETS_FILE_PATH = "/.hidden_folder/pathtofile/secrets_file.json"

# NOT MANDATORY
DJSM_SECRET_KEY_NAME = "__secret_key_name__"
DJSM_SECRET_KEY_FILE_PATH = "/.hidden_folder/pathtofile/secret_key_file.json"
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
|-- requirements.py

```

* Import the package in your Django project

In settings.py

```python
import djsm
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

It is advisable to save secrets in an hidden folder(by prefixing the path with a period - '.'

* **`DJSM_SECRET_KEY_NAME`** -> Name with which the Django secret key should be stored.
Example:

```.env
DJSM_SECRET_KEY_NAME = 'secret_key'
```

* **`DJSM_SECRET_KEY_FILE_PATH`** -> DJSM stores the Django secret key in a separate file, whose file path is provided by this variable, otherwise, the Django secret key is stored in the secrets file.
Example:

```.env

DJSM_SECRET_KEY_FILE_PATH = "/.secrets/pathtofile/secret_key.json"
```

### Import djsm

`djsm` is a pre-instanciated object of the class DJSM. You can import it using the following code.
For most use cases, this is the only import you will need.

```python
from djsm import djsm
```

### Generating a secret key or getting an existing key

To generate a new secret key:

```python
new_secret_key = djsm.generate_django_secret_key()
```

Or in settings.py implement (Best Implementation):

```python

# SECURITY WARNING: keep the secret key used in production secret!
# generate secret key if it does not exist
SECRET_KEY = djsm.get_or_create_secret_key()

```

### Updating or adding new secrets

To update or add a new secret:

```python
new_secret = {"DB_PASSWORD": "db_password"}
djsm.update_secrets(new_secret)

```

Once the update has been performed you can delete these lines.

### Getting Secrets

To get a secret:

```python
# get a secret, say DB_PASSWORD
db_password = djsm.get_secret("DB_PASSWORD")
```

## Classes and Functions

### `DjangoJSONSecretManager`

This class is the main class of the module. It provides the following methods:

* `get_secret(secret_name)` -> Returns the secret with the name `secret_name` if it exists, otherwise returns `None`

* `update_secrets(new_secrets)` -> Updates the secrets file with the new secrets provided in the `new_secrets` dictionary.
If a secret already exists, it is updated, otherwise, it is added.

* `generate_django_secret_key()` -> Generates a new Django secret key and returns it

* `get_or_create_secret_key()` -> Returns the Django secret key if it exists, otherwise generates a new one and returns it

* `change_secret_key()` -> Replaces the Django secret key with a new one. This is useful if you want to change the Django secret key.

* `validate_secret_key(secret_key)` -> Validates the Django secret key. Returns `True` if the key is valid, otherwise returns `False`

* `write_secrets(secrets, path_to_secret_file, **kwargs)` -> Writes secrets to the secrets file whose path is provided.

* `load_secrets(path_to_secret_file, **kwargs)` -> Loads secrets from the secrets file whose path is provided.

* `encrypt(secret)` -> Encrypts the secret provided and returns the encrypted secret.

* `decrypt(encrypted_secret)` -> Decrypts the encrypted secret provided and returns the decrypted secret.

* `change_crypt_keys()` -> Changes the encryption keys used to encrypt and decrypt secrets. This is useful if you want to change the encryption keys used to encrypt and decrypt existing secrets.

* `clean_up()` -> Deletes the secret key file and the secrets file and clears all environment variables set by the module.

* `reload_env()` -> Reloads the environment variables from the .env file.

* `clean_up_and_reload()` -> Calls the `clean_up()` and `reload_env()` methods.

How to use the `DjangoJSONSecretManager` class:

```python
import os
from djsm import DJSM  # DJSM is an alias for DjangoJSONSecretManager

# Instantiation
djsm = DJSM(os.getenv('DJSM_SECRETS_FILE_PATH'))

# get a secret, say DB_PASSWORD
db_password = djsm.get_secret("DB_PASSWORD")

# generate a new secret key
new_secret_key = djsm.generate_django_secret_key()

# update secrets
new_secret = {"DB_PASSWORD": "new_db_password"}
djsm.update_secrets(new_secret)

# write secrets to a file
path_to_secret_file = ".secrets/pathtofile/secrets.json"
new_secret = {"API_KEY": "api_key"}
djsm.write_secrets(new_secret, path_to_secret_file, overwrite=True, encrypt=True)

# load secrets from a file
path_to_secret_file = ".secrets/pathtofile/secrets.json"
secrets = djsm.load_secrets(path_to_secret_file, decrypt=True)

# encrypt a secret
secret = {"API_KEY": "api_key"}
encrypted_secret = djsm.encrypt(secret)

# decrypt a secret
decrypted_secret = djsm.decrypt(encrypted_secret)

# change encryption and decryption keys
djsm.change_crypt_keys()

```

### `Crypt`

This class provides methods for encrypting and decrypting strings. Its subclass is used by the `DjangoJSONSecretManager` class to encrypt and decrypt secrets. It can also be used independently. It uses RSA + Fernet encryption to encrypt and decrypt strings.

It provides the following methods:
* `generate_key()` -> Generates a new encrypted fernet key and returns a tuple of the encrypted key and the keys used to encrypt and decrypt the fernet key. This is a class method and can be called without instantiating the class.

* `generate_key_as_str(encoding="utf-8")` -> Generates a new encrypted fernet key and returns a tuple of the encrypted key and the keys used to encrypt and decrypt the fernet key as strings. The key is encoded using the specified encoding. This is a class method and can be called without instantiating the class.

* `from_str(enc_fernet_key: str, rsa_public_key: str, rsa_private_key: str, encoding: str = 'utf-8')` -> Returns an instance of the class with the encrypted fernet key and the keys used to encrypt and decrypt the fernet key provided as strings. The key is decoded using the specified encoding. This is also a class method and can be called without instantiating the class.

* `encrypt(string: str, encoding: str = 'utf-8')` -> Encrypts the string provided and returns the encrypted string. The string is decoded and the cipher string is encoded using the specified encoding.

* `decrypt(cipher_string: str, encoding: str = 'utf-8')` -> Decrypts the cipher string provided and returns the decrypted string. The cipher string is decoded and the decrypted string is encoded using the specified encoding (This is usually the same encoding used during encryption of the string).

The class has the following attributes/properties:

* `rsa_key_strength` -> The strength of the RSA keys used to encrypt and decrypt the fernet key. The default is 1 (1024 bits). This can be 1, 2  or 3 (1024, 2048 or 4096 bits respectively).

* `sign_and_verify_key` -> Whether to sign and verify the encrypted fernet key.

* `hash_algorithm` -> The hash algorithm to use for signing and verifying the encrypted fernet key. The default is SHA512. This can be 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384' or 'SHA-512'.

Usage:

```python
from djsm.crypt import Crypt

# Get keys
fernet_key, rsa_pub_key, rsa_priv_key = Crypt.generate_key()

# Get key strings
fernet_key_str, rsa_pub_key_str, rsa_priv_key_str = Crypt.generate_key_as_str()

# Instantiating a Crypt object from keys
crypt = Crypt(fernet_key, rsa_pub_key, rsa_priv_key, hash_algorithm="SHA-256")

# Instantiating a Crypt object from key strings
crypt = Crypt.from_str(fernet_key_str, rsa_pub_key_str, rsa_priv_key_str, encoding: str = 'utf-8')
crypt.hash_algorithm = "SHA-256"
text = 'Text I want to keep secret.'

# Encrypt text
cipher_text = crypt.encrypt(text)
print(cipher_text)

# decrypt text
decrypted_text = crypt.decrypt(cipher_text)
assert text == decrypted_text

```

### `JSONCrypt`

This class provides methods for encrypting and decrypting JSON parsable objects . It uses the `Crypt` class to encrypt and decrypt JSON. It is a subclass of the `Crypt` class. It inherits all the methods and attributes of the `Crypt` class. It also provides the following methods:

* `j_encrypt(json_object)` -> Encrypts JSON parsable object and returns the encrypted object.

* `j_decrypt(encrypted_object)` -> Decrypts the encrypted JSON parsable object and returns the decrypted object.

Usage:

```python
from djsm.jcrypt import JSONCrypt

# Changing class variables by creating a subclass and modifying the variables in the subclass
class CustomJSONCrypt(JSONCrypt):
    rsa_key_strength = 2
    hash_algorithm = "SHA-1"

fernet_key, rsa_pub_key, rsa_priv_key = CustomJSONCrypt.generate_key()

jcrypt = CustomJSONCrypt(fernet_key, rsa_pub_key, rsa_priv_key)

dictionary = {
    'foo': 'bar',
    'integer': 12345,
    'dict': {
        'foo': 'bar',
        'integer': 12345,
    },
    'array': [
        {'key': 'value'},
        [1, 2, 3, 4, 5],
    ]
}

# Encrypting the dictionary
encrypted_dict = jcrypt.j_encrypt(dictionary)
print(encrypted_dict)

# Decrypting the encrypted dictionary
decrypted_dict = jcrypt.j_decrypt(encrypted_dict)

assert dictionary == decrypted_dict
```

### Other functions and constants

* `find_and_load_env_var()` -> Finds and loads environment variables from the `.env` file in the root directory(or any other directory) of the project. This is useful if you want to load newly added environment variables from the `.env` file without restarting the server. This function is called automatically when the `DjangoJSONSecretManager` class is imported.

```python
from djsm import find_and_load_env_var

find_and_load_env_var()
```

* `env_variables` -> a list of all variables that must/can be set in the .env file before using the djsm object.

```python
from djsm import env_variables

print(env_variables)
```

**DO NOT DELETE `cryptkeys.json`. IF YOU DO, ALL ENCRYPTED SECRET WILL BE LOST**

#### NOTE: DJSM just provides an added layer of security in managing secrets in your application. It has not been tested to be completely attack proof

### CREDITS

* [python-dotenv](https://pypi.org/project/python-dotenv/)
* [cryptography](https://pypi.org/project/cryptography/)
* [rsa](https://pypi.org/project/rsa/)

#### Contributors and feedbacks are welcome. For feedbacks, please open an issue or contact me at tioluwa.dev@gmail.com or on twitter [@ti_oluwa_](https://twitter.com/ti_oluwa_)

#### To contribute, please fork the repo and submit a pull request

#### If you find this module useful, please consider giving it a star. Thanks!
