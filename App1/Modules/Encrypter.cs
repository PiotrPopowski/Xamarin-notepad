using System;
using System.Security.Cryptography;

namespace App1.Modules
{
    public class Encrypter
    {
        private static readonly int DeriveBytesIterationsCount = 10000;
        private static readonly int SaltSize = 40;
        private static readonly Random random = new Random();

        public static string GenerateSalt()
        {
            var saltBytes = new byte[SaltSize];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(saltBytes);

            return Convert.ToBase64String(saltBytes);
        }

        public static string GetHash(string value, string salt)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Can not generate hash from an empty value.", nameof(value));
            }
            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentException("Can not use an empty salt from hashing value.", nameof(value));
            }

            var pbkdf2 = new Rfc2898DeriveBytes(value, GetBytes(salt), DeriveBytesIterationsCount);

            return Convert.ToBase64String(pbkdf2.GetBytes(SaltSize));
        }

        private static byte[] GetBytes(string value)
        {
            var bytes = new byte[value.Length * sizeof(char)];
            Buffer.BlockCopy(value.ToCharArray(), 0, bytes, 0, bytes.Length);

            return bytes;
        }
    }
}