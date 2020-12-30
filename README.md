# infosecurity-project

IT2566 Infosecurity Project

## How to install SQLite3 tools

1. Visit [this page](https://www.sqlite.org/download.html) and download `sqlite-tools-win32-x86-3330000.zip` (or use this [direct link](https://www.sqlite.org/2020/sqlite-tools-win32-x86-3330000.zip)).
2. In the zip file, extract the 3 EXE files to the `C:\sqlite3` directory.
3. Use the keyboard shortcut `Windows key + R`, type in `systempropertiesadvanced` and press `Enter`. A new window titled **System Properties** should open.
4. Click on the button labeled `Environment Variables` near the bottom.
5. In the `System Variables` section, scroll down and double-click on the `Path` variable. A new window titled **Edit environment variable** should open.
6. Click on `New`, type in `C:\sqlite3`, and press `Enter`.
7. Press `OK` on all the previous dialogs to close them.

## How to set up a virtual environment (venv)

1. Open an administrator command prompt.
2. Change directory to the project folder (e.g. `C:\Users\{username}\infosecurity-project\`).
3. Run `python -m venv venv` and wait for it to finish.
4. Run `venv\scripts\activate`.
5. Run `pip install -r requirements.txt`.

> **NOTE:** If you installed a new package, update `requirements.txt` by following the steps below (since the `venv` directory will not be pushed to the remote repository):
>
> 1. Open an administrator command prompt.
> 2. Change directory to the project folder (e.g. `C:\Users\{username}\infosecurity-project\`).
> 3. Run `venv\scripts\activate`.
> 4. Run `pip freeze > requirements.txt`.
> 5. Commit the changes to `requirements.txt` and push it to the remote repository.

## Code Style

This project is formatted using [Black](https://github.com/psf/black). Instructions for how to install black can be found [here](https://github.com/psf/black#installation-and-usage).

Please remember to run `black --line-length=80 .` **before** committing your changes to any Python file(s) to ensure consistent formatting across all Python files in this project.


## Case Styles

- `camelCase` is the first word is all lowercase, then subsequent words are capitalized and appended directly to the previous word(s)
- `PascalCase` is like `camelCase` but the first word is also capitalized
- `snake_case` is where all words are in lowercase, delimited by a single underscore
- `SCREAMING_SNAKE_CASE` is like `snake_case` but all words are in uppercase
- `kebab-case` is where all words are in lowercase, delimited by a single hyphen

## What Case Style to use

### Python

- Variables: `snake_case` for most variables
- Class Names: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Filename: `snake_case`

You **DO NOT** use `camelCase` in Python

### JavaScript

- Variables: `camelCase` for most variables
- Class Names: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`

You **DO NOT** use `snake_case` in JavaScript

### CSS (e.g. `background-color`), HTML (e.g. `.col-md-6`), and URLs (e.g. `/api/key-management`)

- All (including HTML files): `kebab-case`

### Jinja

- Variables: `snake_case`
