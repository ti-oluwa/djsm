from django.core.management.base import BaseCommand

import djsm


class Command(BaseCommand):
    """
    Changes the encryption and decryption keys used by secrets manager.

    Example:
    ```bash
    python manage.py change_cryptkeys
    ```
    """
    help = '''
    Changes the encryption and decryption keys used by secrets manager.
    '''

    def handle(self, *args, **options) -> None:
        manager = djsm.get_djsm(quiet=True)
        manager.change_cryptkeys()
        self.stdout.write(
            self.style.SUCCESS('DJSM: Encryption keys change was successfully!')
        )
        return None
