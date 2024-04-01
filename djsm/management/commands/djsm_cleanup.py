from django.core.management.base import BaseCommand

import djsm


class Command(BaseCommand):
    """
    Delete the secrets  and remove environment variables set by secrets manager.

    Example:
    ```bash
    python manage.py djsm_cleanup
    ```
    """
    help = '''
    Delete the secrets (project secret key inclusive) and removes environment variables set by secrets manager.
    '''

    def handle(self, *args, **options) -> None:
        manager = djsm.get_djsm(quiet=True)
        manager.clean_up()
        self.stdout.write(
            self.style.SUCCESS('DJSM: Clean up completed!')
        )
        return None
