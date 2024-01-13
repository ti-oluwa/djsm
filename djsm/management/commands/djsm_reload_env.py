from django.core.management.base import BaseCommand

import djsm


class Command(BaseCommand):
    """
    Reloads configurations defined in the .env file into the environment variables.

    Example:
    ```bash
    python manage.py djsm_reload_env
    ```
    """
    help = '''
    Reloads configurations defined in the .env file into the environment variables.
    '''

    def handle(self, *args, **options) -> None:
        manager = djsm.get_djsm(quiet=True)
        manager.reload_env()
        self.stdout.write(
            self.style.SUCCESS(f'DJSM: Reload complete!')
        )
        return None
