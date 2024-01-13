from django.core.management.base import BaseCommand
from django.conf import settings
import simple_file_handler as sfh
from typing import List
import re
from django.utils.module_loading import import_string

from ...manager import DJSM


def get_settings_filepath():
    """Return the path to the project's settings file."""
    try:
        settings.configure()
    except RuntimeError:
        pass

    settings_module = settings.SETTINGS_MODULE
    if settings_module is None:
        return None
    return settings.SETTINGS_MODULE.split('.')[0] + '/settings.py'


def check_if_djsm_is_imported_in_settings(settings_lines: List[str]) -> bool:
    """
    Return True if djsm is already imported in the project's settings file.

    :param settings_lines: list containing the lines of the project's settings file.
    """
    possible_imports = ('djsm', 'DJSM', 'DjangoJSONSecretsManager')
    for line in settings_lines:
        # Ignore comments and blank lines and docstrings.
        if line.startswith(("#", "'''", '"""')) or line.strip() == '':
            continue
        # Ignore lines that are not imports.
        if not line.startswith(('import', 'from')):
            continue
        # If any of the possible imports are in the line, return True.
        if any(map(lambda x: x in line, possible_imports)):
            return True
    return False


def get_djsm_obj_name_in_settings() -> DJSM | None:
    """
    Return the name of the DJSM object in the project's settings file, If there is one.

    If there is no DJSM object in the project's settings file, return None.
    """
    settings_module = import_string(settings.SETTINGS_MODULE)
    for name, obj in settings_module.__dict__.items():
        if isinstance(obj, DJSM):
            return name
    return None


def get_secret_key_line_index(settings_lines: List[str]) -> int:
    """
    Return the index of the line in the project's settings file that contains the secret key.

    :param settings_lines: list containing the lines of the project's settings file.
    :return: The index of the line in the project's settings file that contains the secret key.
    Returns -1 if there is no such line.
    """
    pattern = re.compile(r'^SECRET_KEY\s*=\s*[\'"]+.*[\'"]+\s*$')
    for index, line in enumerate(settings_lines):
        if pattern.match(line):
            return index
    return -1


def get_index_of_line_after_top_imports(settings_lines: List[str]) -> int:
    """
    Return the index of the line after the imports in the project's settings file.

    :param settings_lines: list containing the lines of the project's settings file.
    :return: The index of the line after the imports in the project's settings file.
    Returns 0 if there are no lines or imports in the project's settings file.
    """
    for index, line in enumerate(settings_lines):
        if line.strip() == '':
            continue
        if line.startswith(('import', 'from')):
            continue
        return index
    return 0


def manage_secret_key_with_djsm(manager_name: str, quiet: bool, command: BaseCommand) -> None:
    """
    Edits project settings to use djsm to manage secret key. To be used by a `BaseCommand`.

    :param manager_name: The name of the DJSM object in the project's settings file.
    :param quiet: If set to True, DJSM will not print any messages.
    :param command: The BaseCommand object that called this function.
    """
    settings_filepath = get_settings_filepath()
    if settings_filepath is None:
        raise Exception('settings.SETTINGS_MODULE is not set.')
    
    with sfh.FileHandler(settings_filepath, not_found_ok=False, allow_any=True) as hdl:
        content = hdl.file_content
        lines = content.split('\n')
        project_name = settings.SETTINGS_MODULE.split('.')[0]
        has_been_imported = check_if_djsm_is_imported_in_settings(lines)
        djsm_obj_name = get_djsm_obj_name_in_settings()
        secret_key_line_index = get_secret_key_line_index(lines)
        index_after_top_imports = get_index_of_line_after_top_imports(lines)
        secret_key_line = f'''SECRET_KEY = {manager_name}.get_or_create_secret_key()'''

        if has_been_imported and djsm_obj_name:
            pattern = re.compile(
                f'''^SECRET_KEY\\s*=\\s*{djsm_obj_name}\\.[a-zA-Z_]*\\(([\\'"]+[\\w]*[\\'"]+)?\\)\\s*$'''
            )
            # If the secret key line is already managed by DJSM, do nothing.
            if pattern.match(lines[secret_key_line_index]):
                command.stdout.write(
                    command.style.SUCCESS(f'DJSM: Looks like DJSM already manages the secret key for {project_name}!')
                )
                return None
            lines[secret_key_line_index] = f'''SECRET_KEY = {djsm_obj_name}.get_or_create_secret_key()'''

        elif has_been_imported and not djsm_obj_name:
            setup_line = f"""{manager_name} = djsm.get_djsm(quiet={quiet})"""
            lines.insert(index_after_top_imports, setup_line)
            lines[secret_key_line_index] = secret_key_line

        elif not has_been_imported and not djsm_obj_name:
            setup_line = f"""import djsm\n\n{manager_name} = djsm.get_djsm(quiet={quiet})"""
            lines.insert(index_after_top_imports, setup_line)
            lines[secret_key_line_index] = secret_key_line

        new_content = '\n'.join(lines)
        # Overwrite the project's settings file with the new content.
        hdl.write_to_file(new_content, write_mode='w')

    command.stdout.write(
        command.style.SUCCESS(f'DJSM: DJSM now manages the secret key for {project_name}!')
    )
    return None



class Command(BaseCommand):
    """
    Use DJSM to manage the secret key in the project's settings file.

    This command will add the DJSM object to the project's settings file if it is not already there.

    Example usage:
    ```bash
    python manage.py use_djsm --as djsm_manager --quiet
    ```

    The following code will be added to the project's settings file:
    ```python
    ...
    import djsm

    djsm_manager = djsm.get_djsm(quiet=True)
    ...
    SECRET_KEY = djsm_manager.get_or_create_secret_key()
    ...
    """
    help = 'Use DJSM to manage the secret key in the project\'s settings file.'

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            '--as',
            type=str,
            default='djsm_manager',
            help='The name to be used for the DJSM object in the project\'s settings file.',
        )

        parser.add_argument(
            '--quiet',
            action='store_true',
            help='If set to True, DJSM will not print any messages.',
        )
        

    def handle(self, *args, **options) -> None:
        manager_name = options['as']
        quiet = options['quiet']
        manage_secret_key_with_djsm(manager_name, quiet=quiet, command=self)
        return None
