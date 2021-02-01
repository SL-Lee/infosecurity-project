# infosecurity-project

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

IT2566 Infosecurity Project

## How to Install sqlite3 Tools

1. Visit [this page](https://www.sqlite.org/download.html) and download `sqlite-tools-win32-x86-3330000.zip` (or use this [direct link](https://www.sqlite.org/2020/sqlite-tools-win32-x86-3330000.zip)).
2. In the zip file, extract the 3 EXE files to the `C:\sqlite3` directory.
3. Use the keyboard shortcut `Windows key + R`, type in `systempropertiesadvanced` and press `Enter`. A new window titled **System Properties** should open.
4. Click on the button labeled `Environment Variables` near the bottom.
5. In the `System Variables` section, scroll down and double-click on the `Path` variable. A new window titled **Edit environment variable** should open.
6. Click on `New`, type in `C:\sqlite3`, and press `Enter`.
7. Press `OK` on all the previous dialogs to close them.

## How to Set up a Virtual Environment (venv)

1. Open an administrator command prompt.
2. Change directory to the project folder (e.g. `C:\Users\<username>\infosecurity-project\`).
3. Run `python -m venv venv` and wait for it to finish.
4. Run `venv\scripts\activate`.
5. Run `pip install -r requirements.txt`.

> **NOTE:** If you installed a new package, update `requirements.txt` by following the steps below (since the `venv` directory will not be pushed to the remote repository):
>
> 1. Open an administrator command prompt.
> 2. Change directory to the project folder (e.g. `C:\Users\<username>\infosecurity-project\`).
> 3. Run `venv\scripts\activate`.
> 4. Run `pip freeze > requirements.txt`.
> 5. Commit the changes to `requirements.txt` and push it to the remote repository.

## Code Style

This project is formatted using [Black](https://github.com/psf/black). Instructions for how to install black can be found [here](https://github.com/psf/black#installation-and-usage).

Please remember to run `black .` **before** committing your changes to any Python file(s) to ensure consistent formatting across all Python files in this project.

## Case Styles

- `camelCase`: first word is all lowercase, then subsequent words are capitalized. Has no delimiters.
- `PascalCase`: like `camelCase`, but the first word is also capitalized.
- `snake_case`: all words are in lowercase, delimited by a single underscore.
- `SCREAMING_SNAKE_CASE` like `snake_case`, but all words are in uppercase.
- `kebab-case` all words are in lowercase, delimited by a single hyphen.

### What Case Style to Use

#### Python

Use `snake_case` for most names, except:

- Class names: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`

You **DO NOT** use `camelCase` in Python.

#### JavaScript

Use `camelCase` for most names, except:

- Class names: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`

You **DO NOT** use `snake_case` in JavaScript.

#### CSS (e.g. `background-color`), HTML attribute names and values (e.g. `<button data-target="#generate-new-api-key-prompt">Generate New API Key</button>`), and URLs (e.g. `/api/key-management`)

Use `kebab-case` for all names.

#### Jinja

Use `snake_case` for Jinja variables, since they are essentially Python variables under the hood.
