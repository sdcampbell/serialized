# serialized
serialized is a Python script that detects serialized data in HTTP requests.

## Purpose

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

## Setup

None required. All imports are part of the standard library.

## Examples

In this example, the script is used with the Burp Suite Pro "Piper" extension by right-clicking on the request and choosing the script in the context menu.

<img width="593" alt="image" src="https://github.com/user-attachments/assets/fe38ef0f-95ff-40df-9ca1-75c53c6320cd" />

In the following examples, the request was saved to file from Burp and piped to the script.

<img width="869" alt="image" src="https://github.com/user-attachments/assets/d338e070-fa88-4658-9229-2b056bc7c266" />

<img width="849" alt="image" src="https://github.com/user-attachments/assets/ae89efb5-49d1-4040-aa63-7bf6e7fbd646" />
