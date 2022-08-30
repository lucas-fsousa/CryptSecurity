using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

namespace PublicUtility.CryptSecurity {
  public static class Security {

    #region PRIVATE METHODS
    private static bool IsNumber(this string input) {
      foreach(var c in input) {
        if(!char.IsNumber(c))
          return false;
      }
      return true;
    }

    private static string CheckCryptInput(string input, string privateKeyNumber) {
      string result;

      if(string.IsNullOrEmpty(input))
        result = string.Concat(nameof(input), " is null or empty.");

      else if(string.IsNullOrEmpty(privateKeyNumber))
        result = string.Concat(nameof(privateKeyNumber), " is null or empty.");

      else if(!privateKeyNumber.IsNumber())
        result = string.Concat(nameof(privateKeyNumber), " not a valid number");

      else if(privateKeyNumber.Length > 8)
        result = string.Concat(nameof(privateKeyNumber), " above the allowed (max 8 numbers)");

      else if(privateKeyNumber.Length < 8)
        result = string.Concat(nameof(privateKeyNumber), " below of the necessary (min 8 numbers)");

      else
        result = null;

      return result;
    }

    #endregion

    public static string GetHashMD5(string str) {
      MD5 md5Hash = MD5.Create();
      byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(str));

      var sBuilder = new StringBuilder();

      for(int i = 0; i < data.Length; i++) {
        sBuilder.Append(data[i].ToString("x2"));
      }

      return sBuilder.ToString();
    }

    public static string GetHashPbkdf2(string str) {
      byte[] salt = new byte[128 / 8];
      byte[] codify = KeyDerivation.Pbkdf2(str, salt, KeyDerivationPrf.HMACSHA1, 10000, 256 / 8);
      return Convert.ToBase64String(codify);
    }

    public static string GetHash() {
      Guid guid = Guid.NewGuid();
      return Convert.ToBase64String(Encoding.UTF8.GetBytes(guid.ToString().Replace("-", "")));
    }

    public static string Decrypt(string str, string privateKeyNumber) {
      string response = string.Empty;
      string publicKey = string.Empty;

      var result = CheckCryptInput(str, privateKeyNumber);

      /* a null value is expected for CheckCryptInput with no adverse situation.
        If the value is filled in, it is understood that it was filled in incorrectly.*/
      if(result != null)
        throw new Exception(result);

      privateKeyNumber.Reverse().ToList().ForEach(x => publicKey += x);

      try {
        byte[] privatekeyByte = Encoding.UTF8.GetBytes(privateKeyNumber);
        byte[] publickeybyte = Encoding.UTF8.GetBytes(publicKey);
        byte[] byteArray = new byte[str.Replace(" ", "+").Length];

        byteArray = Convert.FromBase64String(str.Replace(" ", "+"));
        using var des = DES.Create();
        using var ms = new MemoryStream();
        var cs = new CryptoStream(ms, des.CreateDecryptor(publickeybyte, privatekeyByte), CryptoStreamMode.Write);
        cs.Write(byteArray, 0, byteArray.Length);
        cs.FlushFinalBlock();
        response = Encoding.UTF8.GetString(ms.ToArray());

      } catch(Exception) { throw; }
      return response;
    }

    public static string Encrypt(string str, string privateKeyNumber) {
      string response = string.Empty;
      string publicKey = string.Empty;

      var result = CheckCryptInput(str, privateKeyNumber);

      /* a null value is expected for CheckCryptInput with no adverse situation.
        If the value is filled in, it is understood that it was filled in incorrectly.*/
      if(result != null)
        throw new Exception(result);

      privateKeyNumber.Reverse().ToList().ForEach(x => publicKey += x);

      try {
        byte[] privatekeyByte = Encoding.UTF8.GetBytes(privateKeyNumber);
        byte[] publickeybyte = Encoding.UTF8.GetBytes(publicKey);
        byte[] byteArray = Encoding.UTF8.GetBytes(str);

        using var des = DES.Create();
        using var ms = new MemoryStream();
        var cs = new CryptoStream(ms, des.CreateEncryptor(publickeybyte, privatekeyByte), CryptoStreamMode.Write);
        cs.Write(byteArray, 0, byteArray.Length);
        cs.FlushFinalBlock();
        response = Convert.ToBase64String(ms.ToArray());

      } catch(Exception) { throw; }

      return response;
    }

  }
}