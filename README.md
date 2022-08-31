# Crypt Security

Helper for string encryption and decryption.

## Installation

To install, just run the C# compiler to generate the .dll file and once the file has been generated, just add the reference to the project or use [Nuget](https://www.nuget.org/packages/PublicUtility.CryptSecurity) or in nuget console, use the following command:


```bash
install-Package PublicUtility.CryptSecurity
```

## Usage

```csharp
using PublicUtility.CryptSecurity;

string nameToCrypt = "My name is Lucas!"; // example string to crypt and decrypt
string key = "12345678"; // example key to encrypt and decrypt

var responseEncrypt = Security.Encrypt(nameToCrypt, key); // Encrypts the string using an 8-number encryption key.

var responseDecrypt = Security.Decrypt(responseEncrypt, key); // Reverses encryption using the 8-number key and the previously encrypted string.

var password = "1235IsMyPass";

var randomHash = Security.GetHash(); // get a random hash
var pbkdf2Hash = Security.GetHashPbkdf2(password); // get the hash in the Pbkdf2 format provided with a string
var md5Hash = Security.GetHashMD5(password); // get the hash in the MD5 format provided with a string


```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
