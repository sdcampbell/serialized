# serialized
serialized is a Python script that detects serialized data in HTTP requests.

The script takes input form stdin and expects a complete HTTP request. Some uses include cat'ing a file from the terminal, using the Burp Suite 'Piper' extension, or in a Caido workflow cmd.

It detects the following serialized data types:

- PHP
- Python Pickle versions 1 through 4
- NET Binary Formatter serialization
- Ruby Marshal
- Java
- JSON Web Token
- MessagePack
- Protobuf

Currently it has only been tested with PHP and Python. Submit an issue if it has a false negative with the other formats.

Example:

<img width="869" alt="image" src="https://github.com/user-attachments/assets/d338e070-fa88-4658-9229-2b056bc7c266" />
