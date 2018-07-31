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
            
            ;

            /*var input = new byte[] { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
            var key = new byte[] { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };
            var iv = new byte[] { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, };*/

            /*var aes = new AES(key, iv, 128);
            aes.aesMode = AES.AESMode.CBC;

            var encrypted = new byte[input.Length];
            aes.Encrypt(input, 0, input.Length, encrypted, 0);
            var original = new byte[encrypted.Length];
            aes.Decrypt(encrypted, 0, encrypted.Length, original, 0);

            if (input.SequenceEqual(original))
                ;   //successful
            else
                ;   //not successful

            /*var plainText = File.ReadAllBytes("C:\\Users\\Kirito\\Desktop\\plain.bin");
            var key = File.ReadAllBytes("C:\\Users\\Kirito\\Desktop\\key.bin");
            byte[] output = new byte[plainText.Length];

            var aes = new AES(key, 128);
            aes.Encrypt(plainText, 0, plainText.Length, output, 0);

            File.WriteAllBytes("C:\\Users\\Kirito\\Desktop\\encrypt.bin", output);*/
        }
    }
}
