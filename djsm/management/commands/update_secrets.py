import json
from django.core.management.base import BaseCommand, CommandParser

import djsm


def parse_value(value: str) -> str:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value
    

class Command(BaseCommand):
    """
    Update secrets file with new secrets. The secrets file updated is the one defined in the .env file.

    Example:
    ```bash
    python manage.py update_secrets API_KEY 1234567890
    ```
    """
    help = '''
    Update secrets file with new secrets. The secrets file updated is the one defined in the .env file.
    '''

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            'name',
            type=str,
            help='The name of the secret to be updated.',
        )

        parser.add_argument(
            'value',
            type=parse_value,
            help='The value of the secret to be updated.',
        )


    def handle(self, *args, **options) -> None:
        name = options['name']
        value = options['value']

        manager = djsm.get_djsm(quiet=True)
        manager.update_secrets({name: value})
        self.stdout.write(
            self.style.SUCCESS('DJSM: Secrets updated successfully!')
        )
        return None
