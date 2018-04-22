﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rijndael_Implementation
{
    public class AES
    {
        public enum AESMode
        {
            ECB
        }

        public enum Padding
        {
            None,
            Null,
            PKCS7
        }

        private byte[] _key = null;
        private int _blockLength = 128;
        private int _blockLengthInBytes { get { return _blockLength / 8; } }

        public AESMode aesMode = AESMode.ECB;
        public Padding _padding = Padding.PKCS7;

        public byte[] key { get { return _key; } set { if (value.Length % 8 != 0 || value.Length < 16 || value.Length > 32) throw new Exception("Key has to be 16, 24, or 32 byte."); else _key = value; } }
        public int blockLength { get { return _blockLength; } set { if (value % 64 != 0 || value < 128 || value > 256) throw new Exception("Blocksize has to be 128, 192, or 256 bits."); else _blockLength = value; } }

        public Rijndael _baseRijndael { get; private set; }

        public AES()
        {
            _baseRijndael = new Rijndael(_key, _blockLengthInBytes);
        }
        /// <summary>
        /// Initializes an instance of AES
        /// </summary>
        /// <param name="key">the key to use for en-/decryption</param>
        /// <param name="blockLength">Blocklength in bits</param>
        public AES(byte[] key, int blockLength)
        {
            this.key = key;
            this.blockLength = blockLength;

            _baseRijndael = new Rijndael(_key, _blockLengthInBytes);
        }

        public void Encrypt(byte[] input, int offset, int length, byte[] output, int outOffset)
        {
            if (_key == null)
                throw new Exception("No key set.");

            switch (aesMode)
            {
                case AESMode.ECB:
                    var blockCount = 0;
                    while (blockCount * _blockLengthInBytes < length)
                    {
                        byte[] part;
                        if ((blockCount + 1) * _blockLengthInBytes > length)
                            part = ApplyPadding(input.GetElements(offset + blockCount * _blockLengthInBytes, blockCount * _blockLengthInBytes - length));
                        else
                            part = input.GetElements(offset + blockCount * _blockLengthInBytes, _blockLengthInBytes);

                        _baseRijndael.EncryptBlock(part).CopyTo(output, outOffset + blockCount * _blockLengthInBytes);

                        blockCount++;
                    }
                    break;
            }
        }

        private byte[] ApplyPadding(byte[] input)
        {
            var bytesToPad = _blockLengthInBytes - input.Length % _blockLengthInBytes;
            var output = new byte[input.Length + bytesToPad];
            input.CopyTo(output, 0);

            switch (_padding)
            {
                case Padding.None:
                    return input;
                case Padding.Null:
                    return output;
                case Padding.PKCS7:
                    for (int i = 0; i < bytesToPad; i++)
                        output[output.Length - bytesToPad + i] = (byte)bytesToPad;
                    return output;
                default:
                    return null;
            }
        }
    }
}