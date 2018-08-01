using System;
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
            ECB,
            CBC
        }

        public enum Padding
        {
            None,
            Null,
            PKCS7
        }

        private byte[] _key = null;
        private byte[] _iv = null;
        private int _blockLengthInBit = 128;
        private int _blockLengthInBytes { get { return _blockLengthInBit / 8; } }

        public AESMode aesMode = AESMode.ECB;
        public Padding _padding = Padding.PKCS7;

        public byte[] key { get { return _key; } set { if (value.Length % 8 != 0 || value.Length < 16 || value.Length > 32) throw new Exception("Key has to be 16, 24, or 32 byte."); else _key = value; } }
        public byte[] iv { get { return _iv; } set { if (value.Length % 8 != 0 || value.Length < 16 || value.Length > 32) throw new Exception("IV has to be 16, 24, or 32 byte."); else _iv = value; } }
        public int blockLengthInBit { get { return _blockLengthInBit; } set { if (value % 64 != 0 || value < 128 || value > 256) throw new Exception("Blocksize has to be 128, 192, or 256 bits."); else _blockLengthInBit = value; } }

        public Rijndael _baseRijndael { get; private set; }

        public AES()
        {
            _baseRijndael = new Rijndael(_key, _blockLengthInBytes);
        }
        /// <summary>
        /// Initializes an instance of AES
        /// </summary>
        /// <param name="key">the key to use for en-/decryption</param>
        /// <param name="blockLengthInBit">Blocklength in bits</param>
        public AES(byte[] key, byte[] iv, int blockLengthInBit = -1)
        {
            if (key.Length != iv.Length)
                throw new Exception("Key and IV need to be the same size.");
            if (blockLengthInBit >= 0 && blockLengthInBit != key.Length * 8)
                throw new Exception("BlockLength needs to be the right amount of bits.");

            this.key = key;
            this.iv = iv;
            this.blockLengthInBit = (blockLengthInBit < 0) ? key.Length * 8 : blockLengthInBit;

            _baseRijndael = new Rijndael(_key, _blockLengthInBytes);
        }

        public void Encrypt(byte[] input, int offset, int length, byte[] output, int outOffset)
        {
            if (offset < 0 || outOffset < 0)
                throw new Exception("No negative offsets allowed.");
            if (offset >= input.Length || outOffset >= output.Length)
                throw new Exception("Offset can't be larger than the array.");
            if (offset + length > input.Length)
                throw new Exception("Length+Offset reaches out of range.");

            if (_key == null)
                throw new Exception("No key set.");
            if (aesMode == AESMode.CBC && iv == null)
                throw new Exception("No IV set.");

            var blockCount = 0;
            var localIV = iv;
            while (blockCount * _blockLengthInBytes < length)
            {
                byte[] part;
                if ((blockCount + 1) * _blockLengthInBytes > length)
                    part = ApplyPadding(input.GetElements(offset + blockCount * _blockLengthInBytes, length % _blockLengthInBytes));
                else
                    part = input.GetElements(offset + blockCount * _blockLengthInBytes, _blockLengthInBytes);

                switch (aesMode)
                {
                    case AESMode.ECB:
                        _baseRijndael.EncryptBlock(part).CopyTo(output, outOffset + blockCount * _blockLengthInBytes);
                        break;
                    case AESMode.CBC:
                        for (int i = 0; i < part.Length; i++)
                            part[i] ^= localIV[i];
                        _baseRijndael.EncryptBlock(part).CopyTo(output, outOffset + blockCount * _blockLengthInBytes);
                        localIV = output.GetElements(outOffset + blockCount * _blockLengthInBytes, part.Length);
                        break;
                }

                blockCount++;
            }
        }

        public void Decrypt(byte[] input, int offset, int length, byte[] output, int outOffset)
        {
            if (offset < 0 || outOffset < 0)
                throw new Exception("No negative offsets allowed.");
            if (offset >= input.Length || outOffset >= output.Length)
                throw new Exception("Offset can't be larger than the array.");
            if (offset + length > input.Length)
                throw new Exception("Length+Offset reaches out of range.");
            if (input.Length % _blockLengthInBytes > 0)
                throw new Exception("input array length needs to be a multiple of keysize.");
            if (length % _blockLengthInBytes > 0)
                throw new Exception("length needs to be a multiple of keysize.");

            if (_key == null)
                throw new Exception("No key set.");
            if (aesMode == AESMode.CBC && iv == null)
                throw new Exception("No IV set.");

            var blockCount = 0;
            var localIV = iv;
            while (blockCount * _blockLengthInBytes < length)
            {
                byte[] part;
                if ((blockCount + 1) * _blockLengthInBytes > length)
                {
                    part = input.GetElements(offset + blockCount * _blockLengthInBytes, length % _blockLengthInBytes);
                }
                else
                {
                    part = input.GetElements(offset + blockCount * _blockLengthInBytes, _blockLengthInBytes);
                }

                switch (aesMode)
                {
                    case AESMode.ECB:
                        _baseRijndael.DecryptBlock(part).CopyTo(output, outOffset + blockCount * _blockLengthInBytes);
                        break;
                    case AESMode.CBC:
                        _baseRijndael.DecryptBlock(part).CopyTo(output, outOffset + blockCount * _blockLengthInBytes);
                        var index = 0;
                        for (int i = outOffset + blockCount * _blockLengthInBytes; i < outOffset + blockCount * _blockLengthInBytes + part.Length; i++)
                            output[i] ^= localIV[index++];
                        localIV = part;
                        break;
                }

                blockCount++;
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
