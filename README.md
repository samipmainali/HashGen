```markdown
# Hash Gen - Advanced Hash Generation Tool

## Overview

Hash Gen is a Python-based tool that provides advanced hash generation capabilities with customizable options for salting, encoding, and double hashing. It supports several popular hashing algorithms, salt methods, and encodings for generating secure hash values. This tool is designed for both command-line users and developers who require flexible hash generation features.

## Features

- **Multiple Hash Algorithms**: Supports MD5, SHA1, SHA256, SHA512, BLAKE2b, and SHA3-256.
- **Salt Methods**: Includes options for salt prepending, appending, wrapping, HMAC-based salting, and dual salt application.
- **Encoding Options**: Automatically detects the appropriate encoding or allows manual selection between UTF-8, Latin-1, and auto-encoding.
- **Double Hashing**: Option to perform a second round of hashing using a different algorithm.
- **Interactive Mode**: Command-line interface for step-by-step hash generation and result display.
- **Result Export**: Saves generated hash and related data to a file.

## Requirements

- Python 3.x
- `colorama` package (for colored terminal output)

You can install the required dependencies by running:

```bash
pip install colorama
```

## Usage

To run the tool, execute the following command in your terminal:

```bash
python hashgen.py
```

The tool will prompt you for the following inputs:

1. **Text to Hash**: Enter the text you want to hash.
2. **Salt**: Optionally provide a salt string. You can use `||` to create a dual salt effect.
3. **Salt Method**: Choose from:
   - Prepend
   - Append
   - Wrap
   - HMAC
   - Dual (uses `||` separator)
4. **Encoding**: Select the encoding method:
   - Auto
   - UTF-8
   - Latin-1
5. **Hash Algorithm**: Choose from a variety of hash algorithms:
   - MD5
   - SHA1
   - SHA256
   - SHA512
   - BLAKE2b
   - SHA3-256
6. **Double Hashing**: Optionally enable double hashing and select the second algorithm.

The results will be displayed in a readable format and you will have the option to save them to a file.

## Example

```plaintext
Enter text to hash ➜ Hello, world!
Enter salt ➜ my_salt
Select Salt Method:
  [1] Prepend
  [2] Append
  [3] Wrap
  [4] HMAC
  [5] Dual
Your choice ➜ 1
Select Encoding Method:
  [1] Auto
  [2] UTF-8
  [3] Latin-1
Your choice ➜ 2
Choose Hash Algorithm:
  [1] MD5
  [2] SHA1
  [3] SHA256
  [4] SHA512
  [5] BLAKE2b
  [6] SHA3-256
Your choice ➜ 3
Enable double hashing? (y/n) ➜ n
Generate another hash? (y/n) ➜ n
```

## File Output

The results will be saved in a text file with the following structure:

```plaintext
text:Hello, world!
salt:my_salt
hash:sha256hashvaluehere
```

The filename will be automatically sanitized and structured as:  
`SHA256_Prepended_Hello_world_my_salt.txt`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

Special thanks to the `hashlib` and `colorama` libraries for their functionality.

## Contributing

Feel free to fork this repository and open pull requests for improvements or bug fixes.

---

Thank you for using Hash Gen! 🔒
