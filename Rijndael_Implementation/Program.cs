using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace Rijndael_Implementation
{
    class Program
    {
        static void Main(string[] args)
        {
            var input = new byte[] { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
            var key = new byte[] { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };
            var iv = new byte[] { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, };

            var aes = new AES(key, iv);
            aes.aesMode = AES.AESMode.CBC;

            var encrypted = new byte[input.Length + (aes.key.Length - input.Length % aes.key.Length)];
            Array.Copy(input, 0, encrypted, 0, input.Length);
            var original = new byte[encrypted.Length];
            aes.Decrypt(encrypted, 0, encrypted.Length, original, 0);

            var unencrypted = Encoding.ASCII.GetString(original);

            if (input.SequenceEqual(original))
                ;   //successful
            else
                ;   //not successful
        }
    }
}
