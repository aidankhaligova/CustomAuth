namespace CustomAuth.Helpers;
public static class DecodeRS256
{
    public static string Decode(string token, string key, bool verify = true)
    {
        string[] parts = token.Split('.');
        string header = parts[0];
        string payload = parts[1];
        byte[] crypto = Base64UrlDecode(parts[2]);

        string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
        JObject headerData = JObject.Parse(headerJson);

        string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
        JObject payloadData = JObject.Parse(payloadJson);

        if (verify)
        {
            //var keyBytes = Convert.FromBase64String(key); // your key here

            //AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            //RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            //RSAParameters rsaParameters = new()
            //{
            //    Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
            //    Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            //};
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //rsa.ImportParameters(rsaParameters);

            //SHA256 sha256 = SHA256.Create();
            //byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

            //RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            //rsaDeformatter.SetHashAlgorithm("SHA256");
            //if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
            //    throw new ApplicationException(string.Format("Invalid signature"));

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
              new RSAParameters()
              {
                  Modulus = FromBase64Url(key),
                  Exponent = FromBase64Url("AQAB")
              });

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
                throw new ApplicationException(string.Format("Invalid signature"));
        }

        return payloadData.ToString();
    }
    static byte[] Base64UrlDecode(string input)
    {
        var output = input;
        output = output.Replace('-', '+'); // 62nd char of encoding
        output = output.Replace('_', '/'); // 63rd char of encoding
        switch (output.Length % 4) // Pad with trailing '='s
        {
            case 0: break; // No pad chars in this case
            case 1: output += "==="; break; // Three pad chars
            case 2: output += "=="; break; // Two pad chars
            case 3: output += "="; break; // One pad char
            default: throw new System.Exception("Illegal base64url string!");
        }
        var converted = Convert.FromBase64String(output); // Standard base64 decoder
        return converted;
    }
    static byte[] FromBase64Url(string base64Url)
    {
        string padded = base64Url.Length % 4 == 0
            ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
        string base64 = padded.Replace("_", "/")
                              .Replace("-", "+");
        return Convert.FromBase64String(base64);
    }
}