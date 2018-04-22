using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/* Specification: https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
 * Another write-up: http://jda.noekeon.org/JDA_VRI_Rijndael_2002.pdf
 * High-Level description by https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * ExpansionKey algorithm used from the specification, since the explanation on wikipedia seems a bit off
 * ShiftRows matrix taken from the write-up, since the official specification doesn't name shiftings for blocks of 20 and 28 Bytes
 */
namespace Rijndael_Implementation
{
    public class Rijndael
    {
        public class Tables
        {
            #region Public members
            public byte[] SBox { get { return _sbox; } set { _sbox = value; _invsbox = CalculateSBoxInverse(value); } }
            public byte[] InverseSBox { get { return _invsbox; } set { _invsbox = value; _sbox = CalculateSBoxInverse(value); } }

            public byte[] RCon { get { return _rcon; } set { _rcon = value; } }

            public byte[] MixColumnMatrix { get { return _mixColumnMatrix; } set { _mixColumnMatrix = value; /*_mixColumnMatrixInv = CalculateMixColumnsInverse(value);*/ } }
            public byte[] InverseMixColumnMatrix { get { return _mixColumnMatrixInv; } set { _mixColumnMatrixInv = value; /*_mixColumnMatrix = CalculateMixColumnsInverse(value);*/ } }

            public Dictionary<int, int[]> ShiftRowMatrix { get { return _shiftRowMatrix; } set { _shiftRowMatrix = value; _shiftRowMatrixInv = CalculateShiftRowsInverse(value); } }
            public Dictionary<int, int[]> InverseShiftRowMatrix { get { return _shiftRowMatrixInv; } set { _shiftRowMatrixInv = value; _shiftRowMatrix = CalculateShiftRowsInverse(value); } }
            #endregion

            #region Private members
            private byte[] _sbox = new byte[]
            {
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            };
            private byte[] _invsbox;

            private byte[] _rcon = new byte[]
            {
                0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
                0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
                0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
                0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
                0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
                0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
                0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
                0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
                0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
                0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
                0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
                0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
                0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
                0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
                0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
            };

            private byte[] _mixColumnMatrix = new byte[]
            {
                0x02, 0x03, 0x01, 0x01,
                0x01, 0x02, 0x03, 0x01,
                0x01, 0x01, 0x02, 0x03,
                0x03, 0x01, 0x01, 0x02
            };
            private byte[] _mixColumnMatrixInv = new byte[] {
                0xe,0x9,0xd,0xb,
                0xb,0xe,0x9,0xd,
                0xd,0xb,0xe,0x9,
                0x9,0xd,0xb,0xe
            };

            private Dictionary<int, int[]> _shiftRowMatrix = new Dictionary<int, int[]>
            {
                [4] = new[] { 0, 1, 2, 3 },
                [5] = new[] { 0, 1, 2, 3 },
                [6] = new[] { 0, 1, 2, 3 },
                [7] = new[] { 0, 1, 2, 4 },
                [8] = new[] { 0, 1, 3, 4 },
            };
            private Dictionary<int, int[]> _shiftRowMatrixInv;

            private int blockLength;
            #endregion

            public Tables(int blockLength)
            {
                //Create inverse SBox
                _invsbox = CalculateSBoxInverse(_sbox);

                //Create inverse mixColumn matrix
                //_mixColumnInverse=CalculateMixColumnsInverse(_mixColumnMatrix);

                //Create inverse shiftRow matrix
                _shiftRowMatrixInv = CalculateShiftRowsInverse(_shiftRowMatrix);
            }

            private byte[] CalculateSBoxInverse(byte[] input)
            {
                byte[] invbox = new byte[input.Length];
                for (int i = 0; i < 256; i++)
                    invbox[input[i]] = (byte)i;
                return invbox;
            }

            private byte[] CalculateMixColumnsInverse(byte[] input)
            {
                return null;
            }

            private Dictionary<int, int[]> CalculateShiftRowsInverse(Dictionary<int, int[]> input)
            {
                Dictionary<int, int[]> output = new Dictionary<int, int[]>();
                foreach (var e in input)
                    output.Add(e.Key, input[e.Key].Select(t => e.Key - t).ToArray());
                return output;
            }
        }

        public byte[] _key { get; private set; }

        public int _keyLength { get => _key.Length; }
        public int _blockLength { get; private set; }

        private int _rounds { get => Math.Max(_keyLength / 4, _blockLength / 4) + 6; }

        private byte[][] _keyExp;
        private int _keyExpLength { get => (_rounds + 1) * _blockLength; }

        public Tables _tables;

        /// <summary>
        /// Creates a Rijndael instance
        /// </summary>
        /// <param name="key">Byte[] of key material</param>
        /// <param name="blockLength">Blocksize in bytes</param>
        public Rijndael(byte[] key, int blockLength)
        {
            if (key.Length < 16 || key.Length > 32 || key.Length % 4 != 0)
                throw new ArgumentException("Invalid key length.");
            if (blockLength < 16 || blockLength > 32 || blockLength % 4 != 0)
                throw new ArgumentException("Invalid block size.");

            _tables = new Tables();

            _key = key;
            _blockLength = blockLength;

            //Key expansion
            ExpandKey();
        }

        //Done, according to specifications
        private void ExpandKey()
        {
            _keyExp = new byte[_blockLength / 4 * (_rounds + 1)][];

            //set user key
            for (int i = 0; i < _keyLength / 4; i++)
                _keyExp[i] = _key.GetElements(i * 4, 4);

            var rconIter = 1;
            for (int i = _keyLength / 4; i < _blockLength / 4 * (_rounds + 1); i++)
            {
                var temp = _keyExp[i - 1];
                if (i % (_keyLength / 4) == 0)
                    temp = ApplyKeyScheduleCore(temp, rconIter++);
                else if (_keyLength / 4 > 6 && i % (_keyLength / 4) == 4)
                    temp = ApplySBox(temp);
                _keyExp[i] = Support.XOR(_keyExp[i - (_keyLength / 4)], temp);
            }
        }

        //Done
        #region Key Schedule Functions
        //Done, according to wikipedia and specification
        private byte[] ApplyKeyScheduleCore(byte[] input, int rconIndex) => Rcon(ApplySBox(Rotate(input)), rconIndex);

        //Done, according to specification
        private byte[] Rotate(byte[] input, int count = 1)
        {
            if (count > input.Length) count = count % input.Length;
            if (count <= 0) return input;

            var output = new byte[input.Length];
            var help = input.GetElements(0, count);
            for (int i = count; i < input.Length; i++)
                output[i - count] = input[i];
            for (int i = 0; i < help.Length; i++)
                output[output.Length - count + i] = help[i];
            return output;
        }

        //Done, according to specification
        private byte[] ApplySBox(byte[] input)
        {
            var output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                output[i] = _tables.sbox[input[i]];
            return output;
        }

        //Done, according to wikipedia and specification
        private byte[] Rcon(byte[] input, int rconIndex)
        {
            var output = new byte[input.Length];
            output[0] = (byte)(_tables.rcon[rconIndex] ^ input[0]);
            for (int i = 1; i < input.Length; i++)
                output[i] = input[i];
            return output;
        }
        #endregion

        public byte[] EncryptBlock(byte[] block)
        {
            //Initial round
            block = AddRoundKey(block, _keyExp.GetElements(0, _blockLength / 4).ToByteArray());

            //Rounds
            for (int i = 1; i < _rounds; i++)
            {
                block = ApplyRound(block, _keyExp.GetElements(i * (_blockLength / 4), _blockLength / 4).ToByteArray());
            }

            //Final round
            block = ApplyFinalRound(block, _keyExp.GetElements((_keyExpLength / 4) - (_blockLength / 4), (_blockLength / 4)).ToByteArray());

            return block;
        }

        #region Round Functions
        //Done, following the write-up
        private byte[] ApplyRound(byte[] block, byte[] key) => AddRoundKey(MixColumns(ShiftRows(ApplySBox(block))), key);

        //Done, following the write-up
        private byte[] ApplyFinalRound(byte[] block, byte[] key) => AddRoundKey(ShiftRows(ApplySBox(block)), key);

        private byte[] AddRoundKey(byte[] block, byte[] key) => block.Select((b, i) => (byte)(b ^ key[i])).ToArray();

        //Done, following the write-up
        private byte[] ShiftRows(byte[] block)
        {
            for (int i = 1; i < 4; i++)
            {
                byte[] toShift = new byte[_blockLength / 4];
                for (int j = 0; j < _blockLength / 4; j++)
                    toShift[j] = block[j * 4 + i];
                var rotated = Rotate(toShift, _tables.shiftRowMatrix[_blockLength / 4][i]);
                for (int j = 0; j < _blockLength / 4; j++)
                    block[j * 4 + i] = rotated[j];
            }

            return block;
        }

        //Done, according to wikipedia pseudo-code and specification
        private byte[] MixColumns(byte[] block)
        {
            for (int i = 0; i < _blockLength; i += 4)
            {
                var tempColumn = block.GetElements(i, 4);

                tempColumn[0] = (byte)(GMul(_tables.mixColumnMatrix[0], block[i]) ^ GMul(_tables.mixColumnMatrix[1], block[i + 1]) ^ GMul(_tables.mixColumnMatrix[2], block[i + 2]) ^ GMul(_tables.mixColumnMatrix[3], block[i + 3]));
                tempColumn[1] = (byte)(GMul(_tables.mixColumnMatrix[4], block[i]) ^ GMul(_tables.mixColumnMatrix[5], block[i + 1]) ^ GMul(_tables.mixColumnMatrix[6], block[i + 2]) ^ GMul(_tables.mixColumnMatrix[7], block[i + 3]));
                tempColumn[2] = (byte)(GMul(_tables.mixColumnMatrix[8], block[i]) ^ GMul(_tables.mixColumnMatrix[9], block[i + 1]) ^ GMul(_tables.mixColumnMatrix[10], block[i + 2]) ^ GMul(_tables.mixColumnMatrix[11], block[i + 3]));
                tempColumn[3] = (byte)(GMul(_tables.mixColumnMatrix[12], block[i]) ^ GMul(_tables.mixColumnMatrix[13], block[i + 1]) ^ GMul(_tables.mixColumnMatrix[14], block[i + 2]) ^ GMul(_tables.mixColumnMatrix[15], block[i + 3]));

                for (var j = 0; j < 4; j++)
                    block[i + j] = tempColumn[j];
            }

            return block;
        }
        #endregion

        //wikipedia pseudo-code for Galois multiplication
        private byte GMul(byte a, byte b)
        { // Galois Field (256) Multiplication of two Bytes
            byte p = 0;

            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hi_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if (hi_bit_set)
                {
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }

            return p;
        }
    }

    public static class Support
    {
        public static byte[] ToByteArray(this byte[][] input) => input.SelectMany(ba => ba).ToArray();
        public static T[] GetElements<T>(this T[] input, int offset, int length)
        {
            T[] output = new T[length];
            for (int i = 0; i < length; i++)
                output[i] = input[i + offset];
            return output;
        }
        public static T[] GetElements<T>(this List<T> input, int offset, int length)
        {
            T[] output = new T[length];
            for (int i = 0; i < length; i++)
                output[i] = input[i + offset];
            return output;
        }

        public static byte[] XOR(byte[] in1, byte[] in2)
        {
            var output = new byte[in2.Length];
            for (int i = 0; i < in1.Length; i++)
                output[i] = (byte)(in1[i] ^ in2[i]);
            return output;
        }
    }
}
