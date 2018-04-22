using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Rijndael_Implementation
{
    class Program
    {
        static void Main(string[] args)
        {
            var plainText = File.ReadAllBytes("C:\\Users\\Kirito\\Desktop\\plain.bin");
            var key = File.ReadAllBytes("C:\\Users\\Kirito\\Desktop\\key.bin");
            byte[] output = new byte[plainText.Length];

            var aes = new AES(key, 128);
            aes.Encrypt(plainText, 0, plainText.Length, output, 0);

            File.WriteAllBytes("C:\\Users\\Kirito\\Desktop\\encrypt.bin", output);
        }
    }
}
