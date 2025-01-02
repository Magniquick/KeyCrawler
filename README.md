# KeyCrawler 🔑

## Overview
**KeyCrawler** is a Python project designed to fetch, validate, and manage `keybox.xml` files from GitHub. This project is specifically intended to work with [TrickyStore](https://github.com/5ec1cff/TrickyStore), a tool for modifying certificate chains in Android Key Attestation to pass integrity checks.

The scraper uses the GitHub API to locate `keybox.xml` files, validating their content with the google pubkey.

Hacked together really quick - making it public as now I use a stock rom.

## Features
- Scrapes `keybox.xml` files from GitHub repositories using the GitHub API.
- Validates `keybox.xml` files using a custom validation function (`keybox_check` from `check.py`).
- Stores validated files in a hashed format to prevent duplicates.
- Provides an interactive interface to manage invalid files.

## Requirements
- Python 3.8+
- Poetry
- A GitHub personal access token with permissions to search code repositories.

## Setup

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone KeyCrawler
   cd KeyCrawler
   ```

2. Install the required Python libraries using Poetry:
   ```bash
   poetry install
   ```

3. Create a `.env` file in the project directory and add your GitHub personal access token:
   ```env
   GITHUB_TOKEN=your_personal_access_token
   ```

4. Ensure the `check.py` file exists in the project directory with a valid implementation of the `keybox_check` function.

5. Create a directory named `keys` in the project root to store the downloaded XML files:
   ```bash
   mkdir keys
   ```

## Usage

1. Run the main script to scrape `keybox.xml` files from GitHub, validate them, and save them:
   ```zsh
   poetry run python main.py
   ```

2. Follow the interactive prompts to manage invalid files in the `keys` directory.

3. Use the keys with [TrickyStore](https://github.com/5ec1cff/TrickyStore) to achive strong intergrity.

## Notes
- The project uses the GitHub API and requires a valid token in the `.env` file. Make sure the token has the necessary permissions to search code repositories.
- This project is intended to be used with TrickyStore.

## Limitations
- The script only processes fully valid xml files.

## License
This project is licensed under the GPLv3 License.

## Contributing
Contributions are welcome! Feel free to fork the repository and submit pull requests.

## Acknowledgments
- [KimmyXYC's KeyboxChecker](https://github.com/KimmyXYC/KeyboxChecker)
- [TrickyStore](https://github.com/5ec1cff/TrickyStore)