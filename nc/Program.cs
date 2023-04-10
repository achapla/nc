using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 3 || args[2].Length < 8)
        {
            Console.WriteLine("Usage: NC.exe [encrypt|decrypt|e|d|verify|v] [input-file|input-directory] [password] {output-directory}");
            return;
        }

        bool encrypt = args[0].StartsWith("e");
        bool decrypt = args[0].StartsWith("d");
        string password = args[2];

        string[] inputFiles;
        if (File.Exists(args[1]))
        {
            inputFiles = new string[] { args[1] };
        }
        else
        {
            inputFiles = Directory.GetFiles(args[1], "*.*");
        }

        string outputPath;
        if (args.Length > 3)
        {
            outputPath = args[3];
        }
        else
        {
            outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output");
        }

        if (!Directory.Exists(outputPath))
        {
            Directory.CreateDirectory(outputPath);
        }

        foreach (string inputFile in inputFiles)
        {
            if (encrypt)
            {
                Encrypt(inputFile, outputPath, password);
            }
            else if (decrypt)
            {
                Decrypt(inputFile, outputPath, password);
            }
            else
            {
                Verify(inputFile, password);
            }
        }
    }

    private static void Encrypt(string inputFile, string outputPath, string password)
    {
        using (Aes aesAlg = Aes.Create())
        {
            byte[] salt = GenerateSalt(aesAlg);
            aesAlg.Key = GenerateKey(password, salt);
            aesAlg.IV = GenerateIV(aesAlg);

            using (FileStream inputFileStream = new FileStream(inputFile, FileMode.Open))
            {
                string outputFile = Path.Combine(outputPath, Guid.NewGuid().ToString());
                using (FileStream outputFileStream = new FileStream(outputFile, FileMode.Create))
                {
                    byte[] base64FileName = Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(Path.GetFileName(inputFile))));

                    WriteBytes(salt, outputFileStream);
                    WriteBytes(aesAlg.IV, outputFileStream);
                    WriteBytes(base64FileName, outputFileStream);

                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                    }
                }
            }
        }
    }

    static void Decrypt(string inputFile, string outputPath, string password)
    {
        try
        {
            using (Aes aesAlg = Aes.Create())
            {
                using (FileStream inputFileStream = new FileStream(inputFile, FileMode.Open))
                {
                    byte[] salt = ReadBytes(inputFileStream);
                    aesAlg.Key = GenerateKey(password, salt);
                    aesAlg.IV = ReadBytes(inputFileStream);

                    byte[] base64FileName = ReadBytes(inputFileStream);
                    string fileName = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(base64FileName)));
                    string outputFile = Path.Combine(outputPath, fileName);

                    try
                    {
                        using (FileStream outputFileStream = new FileStream(outputFile, FileMode.Create))
                        {
                            using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                            {
                                cryptoStream.CopyTo(outputFileStream);
                            }
                        }
                    }
                    catch
                    {
                        if (File.Exists(outputFile))
                        {
                            File.Delete(outputFile);
                        }

                        throw;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Cannot decrypt file '{inputFile}'.");
            Console.WriteLine($"Reason: {ex.Message}");
        }
    }

    static void Verify(string inputFile, string password)
    {
        try
        {
            using (Aes aesAlg = Aes.Create())
            {
                using (FileStream inputFileStream = new FileStream(inputFile, FileMode.Open))
                {
                    byte[] salt = ReadBytes(inputFileStream);
                    aesAlg.Key = GenerateKey(password, salt);
                    aesAlg.IV = ReadBytes(inputFileStream);

                    byte[] base64FileName = ReadBytes(inputFileStream);
                    string fileName = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(base64FileName)));

                    try
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            cryptoStream.CopyTo(Stream.Null);
                        }
                    }
                    catch
                    {
                        throw;
                    }
                }
            }

            Console.WriteLine($"[SUCCESS] '{inputFile}'");
        }
        catch
        {
            Console.WriteLine($"[FAIL]    '{inputFile}'");
        }
    }

    private static byte[] ReadBytes(FileStream inputFileStream)
    {
        byte[] lengthBytes = new byte[4];
        inputFileStream.Read(lengthBytes, 0, lengthBytes.Length);

        int length = BitConverter.ToInt32(lengthBytes, 0);
        byte[] data = new byte[length];
        inputFileStream.Read(data, 0, data.Length);

        return data;
    }

    private static void WriteBytes(byte[] bytes, FileStream outputFileStream)
    {
        outputFileStream.Write(BitConverter.GetBytes(bytes.Length));
        outputFileStream.Write(bytes, 0, bytes.Length);
    }

    static byte[] GenerateKey(string password, byte[] salt)
    {
        const int keySize = 256;
        const int iterations = 1000;

        Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
        return pbkdf2.GetBytes(keySize / 8);
    }

    static byte[] GenerateSalt(SymmetricAlgorithm symmetricAlgorithm)
    {
        return RandomNumberGenerator.GetBytes(symmetricAlgorithm.BlockSize / 8);
    }

    static byte[] GenerateIV(SymmetricAlgorithm symmetricAlgorithm)
    {
        symmetricAlgorithm.GenerateIV();
        return symmetricAlgorithm.IV;
    }
}
