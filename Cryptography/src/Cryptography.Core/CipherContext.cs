using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Cryptography.Core.Enums;
using Cryptography.Core.Interfaces;
using Cryptography.Core.Padding;
using PaddingMode = Cryptography.Core.Enums.PaddingMode;

namespace Cryptography.Core
{
    public class CipherContext : IDisposable
    {
        private readonly ISymmetricCipher _cipher;
        private readonly EncryptionMode _encryptionMode;
        private readonly IPaddingProvider _paddingProvider;
        private readonly byte[]? _iv;
        private bool _disposed = false;
        private readonly byte[] _randomData;

        public CipherContext(
            ISymmetricCipher cipher,
            byte[] key,
            EncryptionMode encryptionMode,
            PaddingMode paddingMode,
            byte[]? iv = null)
        {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
            _encryptionMode = encryptionMode;
            _paddingProvider = PaddingFactory.Create(paddingMode);
            if (iv != null)
            {
                _iv = new byte[iv.Length];
                Array.Copy(iv, _iv, iv.Length);
            }
            else
            {
                _iv = null;
            }
            _randomData = new byte[_cipher.BlockSize];
            RandomNumberGenerator.Fill(_randomData);

            ValidateParameters(key);
            _cipher.Initialize(key);
        }

        public async Task<byte[]> Encrypt(byte[] data)
        {
            return await EncryptPrivate(data);
        }

        public async Task<byte[]> Decrypt(byte[] data)
        {
            return await DecryptPrivate(data);
        }

        private async Task<byte[]> EncryptPrivate(byte[] data, InitialData? initialData = null)
        {
            CheckDisposed();

            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data));
            if (data.Length != 1024)
            {
                //
            }

            return await Task.Run(() =>
            {
                byte[] paddedData = _paddingProvider.AddPadding(data, _cipher.BlockSize);
                byte[] encryptedData = _encryptionMode switch
                {
                    EncryptionMode.ECB => EncryptECB(paddedData),
                    EncryptionMode.CBC => EncryptCBC(paddedData, initialData),
                    EncryptionMode.PCBC => EncryptPCBC(paddedData, initialData),
                    EncryptionMode.CFB => EncryptCFB(paddedData, initialData),
                    EncryptionMode.OFB => EncryptOFB(paddedData, initialData),
                    EncryptionMode.CTR => EncryptCTR(paddedData, initialData),
                    EncryptionMode.RandomDelta => EncryptRandomDelta(paddedData, initialData),
                    _ => throw new NotSupportedException($"Режим {_encryptionMode} не поддерживается")
                };
                return encryptedData;
            });
        }

        private async Task<byte[]> DecryptPrivate(byte[] data, InitialData? initialData = null)
        {
            CheckDisposed();

            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data));
            
            if (data.Length != 1024)
            {
                //
            }

            return await Task.Run(() =>
            {
                byte[] decryptedData = _encryptionMode switch
                {
                    EncryptionMode.ECB => DecryptECB(data),
                    EncryptionMode.CBC => DecryptCBC(data, initialData),
                    EncryptionMode.PCBC => DecryptPCBC(data, initialData),
                    EncryptionMode.CFB => DecryptCFB(data, initialData),
                    EncryptionMode.OFB => DecryptOFB(data, initialData),
                    EncryptionMode.CTR => DecryptCTR(data, initialData),
                    EncryptionMode.RandomDelta => DecryptRandomDelta(data, initialData),
                    _ => throw new NotSupportedException($"Режим {_encryptionMode} не поддерживается")
                };
                byte[] result;
                if (initialData != null && !initialData.IsEnd)
                {
                    result = new byte[decryptedData.Length];
                    Array.Copy(decryptedData, 0, result, 0, result.Length);
                }
                else
                {
                    result = _paddingProvider.RemovePadding(decryptedData, _cipher.BlockSize);
                }
                return result;
                
            });
        }

        public async Task<int> Encrypt(byte[] data, byte[] outputBuffer)
        {
            CheckDisposed();

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] result = await EncryptPrivate(data);

            if (outputBuffer is null || outputBuffer.Length < result.Length)
            {
                return -1;
            }

            Array.Copy(result, 0, outputBuffer, 0, result.Length);
            return result.Length;
        }


        public async Task<int> Decrypt(byte[] data, byte[] outputBuffer)
        {
            CheckDisposed();

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] result = await DecryptPrivate(data);

            if (outputBuffer is null || outputBuffer.Length < result.Length)
            {
                return -1;
            }

            Array.Copy(result, 0, outputBuffer, 0, result.Length);

            return result.Length;
        }

        public async Task Encrypt(string inputFilePath, string outputFilePath, int bufferSize = 4096)
        {
            CheckDisposed();

            ValidateFilePaths(inputFilePath, outputFilePath);

            await using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            await using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[bufferSize];
                await ProcessStreamAsync(inputStream, outputStream, buffer, true);
            }
        }

        public async Task Decrypt(string inputFilePath, string outputFilePath, int bufferSize = 4096)
        {
            CheckDisposed();

            ValidateFilePaths(inputFilePath, outputFilePath);

            await using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            await using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[bufferSize];

                await ProcessStreamAsync(inputStream, outputStream, buffer, false);
            }
        }


        private byte[] EncryptECB(byte[] data)
        {
            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount, i =>
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);
                byte[] encryptedBlock = _cipher.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);
            });

            return result;
        }

        private byte[] DecryptECB(byte[] data)
        {
            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount, i =>
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);
                byte[] decryptedBlock = _cipher.DecryptBlock(block);
                Array.Copy(decryptedBlock, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);
            });

            return result;
        }

        private byte[] EncryptCBC(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = new byte[_cipher.BlockSize];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, previousBlock, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, previousBlock, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    block[j] ^= previousBlock[j];
                }

                byte[] encryptedBlock = _cipher.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);
                Array.Copy(encryptedBlock, previousBlock, _cipher.BlockSize);
            }

            if (initialData != null)
            {
                Array.Copy(previousBlock, initialData.Initial, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] DecryptCBC(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = new byte[_cipher.BlockSize];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, previousBlock, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, previousBlock, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);

                byte[] decryptedBlock = _cipher.DecryptBlock(block);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    decryptedBlock[j] ^= previousBlock[j];
                }

                Array.Copy(decryptedBlock, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);
                Array.Copy(block, previousBlock, _cipher.BlockSize);
            }

            if (initialData != null)
            {
                Array.Copy(previousBlock, 0, initialData.Initial, 0, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] EncryptPCBC(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] previous = new byte[_cipher.BlockSize];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, previous, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, previous, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    block[j] ^= previous[j];
                }

                byte[] encryptedBlock = _cipher.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    previous[j] = (byte)(data[i * _cipher.BlockSize + j] ^ encryptedBlock[j]);
                }
            }

            if (initialData != null)
            {
                Array.Copy(previous, initialData.Initial, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] DecryptPCBC(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] previous = new byte[_cipher.BlockSize];

            if (initialData != null)
            {
                Array.Copy(initialData.Initial, previous, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, previous, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);

                byte[] decryptedBlock = _cipher.DecryptBlock(block);
                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    decryptedBlock[j] ^= previous[j];
                }

                Array.Copy(decryptedBlock, 0, result, i * _cipher.BlockSize, _cipher.BlockSize);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    previous[j] = (byte)(block[j] ^ decryptedBlock[j]);
                }
            }

            if (initialData != null)
            {
                Array.Copy(previous, initialData.Initial, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] EncryptCFB(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] shiftRegister = new byte[_cipher.BlockSize];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, shiftRegister, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, shiftRegister, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                byte[] encryptedShift = _cipher.EncryptBlock(shiftRegister);

                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    result[i * _cipher.BlockSize + j] = (byte)(block[j] ^ encryptedShift[j]);
                    shiftRegister[j] = result[i * _cipher.BlockSize + j];
                }
            }

            if (initialData != null)
            {
                Array.Copy(shiftRegister, initialData.Initial, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] DecryptCFB(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] shiftRegister = new byte[_cipher.BlockSize];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, shiftRegister, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, shiftRegister, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                byte[] encryptedShift = _cipher.EncryptBlock(shiftRegister);

                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);

                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    result[i * _cipher.BlockSize + j] = (byte)(block[j] ^ encryptedShift[j]);
                    shiftRegister[j] = data[i * _cipher.BlockSize + j];
                }
            }

            if (initialData != null)
            {
                Array.Copy(shiftRegister, initialData.Initial, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] EncryptOFB(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = new byte[_cipher.BlockSize];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, feedback, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_iv, feedback, _cipher.BlockSize);
            }

            for (int i = 0; i < blockCount; i++)
            {
                feedback = _cipher.EncryptBlock(feedback);


                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    result[i * _cipher.BlockSize + j] = (byte)(data[i * _cipher.BlockSize + j] ^ feedback[j]);
                }
            }

            if (initialData != null)
            {
                Array.Copy(feedback, initialData.Initial, _cipher.BlockSize);
            }

            return result;
        }

        private byte[] DecryptOFB(byte[] data, InitialData? initialData = null)
        {
            return EncryptOFB(data, initialData);
        }

        private byte[] EncryptCTR(byte[] data, InitialData? initialData = null)
        {
            ValidateIV();

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] nonceCounter = new byte[_cipher.BlockSize];
            byte[] result = new byte[data.Length];
            if (initialData != null)
            {
                Array.Copy(initialData.Initial, nonceCounter, _cipher.BlockSize);
            }
            else
            {
                Array.Copy(_randomData, 0, nonceCounter, 0, _cipher.BlockSize);
                Array.Clear(nonceCounter, nonceCounter.Length * 3 / 4, nonceCounter.Length / 4);
            }

            Parallel.For(0, blockCount, i =>
            {
                byte[] blockCounter = new byte[_cipher.BlockSize];
                Array.Copy(nonceCounter, blockCounter, _cipher.BlockSize);

                IncrementCounter(blockCounter, i);

                byte[] block = new byte[_cipher.BlockSize];
                Array.Copy(data, i * _cipher.BlockSize, block, 0, _cipher.BlockSize);
                byte[] encryptedCounter = _cipher.EncryptBlock(blockCounter);
                for (int j = 0; j < _cipher.BlockSize; j++)
                {
                    result[i * _cipher.BlockSize + j] = (byte)(data[i * _cipher.BlockSize + j] ^ encryptedCounter[j]);
                }
            });
            if (initialData != null)
            {
                IncrementCounter(initialData.Initial, blockCount);
                return result;
            }

            return _cipher.EncryptBlock(nonceCounter).Concat(result).ToArray();
        }

        private byte[] DecryptCTR(byte[] data, InitialData? initialData = null)
        {
            if (initialData != null)
            {
                return EncryptCTR(data, initialData);
            }

            byte[] nonceCounter = new byte[_cipher.BlockSize];
            Array.Copy(data, 0, nonceCounter, 0, _cipher.BlockSize);
            InitialData inDa = new InitialData(_encryptionMode, _cipher.DecryptBlock(nonceCounter));
            return EncryptCTR(data.Skip(_cipher.BlockSize).ToArray(), inDa);
        }

        private byte[] EncryptRandomDelta(byte[] data, InitialData? initialData = null)
        {
            int n = _cipher.BlockSize;
            byte[] initial = new byte[n];
            byte[] delta = new byte[n / 2];
            if (initialData is null)
            {
                Array.Copy(_randomData, initial, n);
                Array.Copy(initial, n / 2, delta, 0, n / 2);
            }
            else
            {
                Array.Copy(initialData.Initial, 0, initial, 0, n);
                Array.Copy(initialData.Delta, 0, delta, 0, n / 2);
            }

            int blockCount = data.Length / _cipher.BlockSize;
            byte[] result = new byte[data.Length];

            for (int i = 0; i < blockCount; i++)
            {
                ProcessBlockWithDelta(data, result, i, initial, true);
                IncrementCounter(initial, delta);
            }

            if (initialData is not null)
            {
                Array.Copy(initial, initialData.Initial, n);
                return result;
            }
            byte[] res = new byte[result.Length + _randomData.Length];
            Array.Copy(_cipher.EncryptBlock(_randomData), res, _cipher.BlockSize);
            Array.Copy(result, 0, res, _cipher.BlockSize, result.Length);

            return res;
        }

        private byte[] DecryptRandomDelta(byte[] data, InitialData? initialData = null)
        {
            int n = _cipher.BlockSize;
            byte[] initial = new byte[n];
            byte[] delta = new byte[n / 2];
            if (initialData == null)
            {
                Array.Copy(data, 0, initial, 0, n);
                initial = _cipher.DecryptBlock(initial);
                Array.Copy(initial, n / 2, delta, 0, n / 2);
            }
            else
            {
                Array.Copy(initialData.Initial, 0, initial, 0, n);
                Array.Copy(initialData.Delta, 0, delta, 0, n / 2);
            }

            int blockCount = data.Length / n;

            byte[] result = new byte[data.Length];


            for (int i = (initialData is null ? 1 : 0); i < blockCount; i++)
            {
                ProcessBlockWithDelta(data, result, i, initial, false);
                IncrementCounter(initial, delta);
            }

            if (initialData is not null)
            {
                Array.Copy(initial, initialData.Initial, n);
                return result;
            }
            byte[] res = new byte[result.Length - initial.Length];
            Array.Copy(result, _cipher.BlockSize, res, 0, res.Length);
            return res;
        }

        private void ProcessBlockWithDelta(
            byte[] input, byte[] output, int blockIndex, byte[] initial, bool encrypt)
        {
            int offset = blockIndex * _cipher.BlockSize;
            byte[] block = new byte[_cipher.BlockSize];
            Array.Copy(input, offset, block, 0, _cipher.BlockSize);

            byte[] processedBlock;

            if (encrypt)
            {
                byte[] deltaApplied = ApplyDelta(block, initial);
                processedBlock = _cipher.EncryptBlock(deltaApplied);
            }
            else
            {
                byte[] decrypted = _cipher.DecryptBlock(block);
                processedBlock = ApplyDelta(decrypted, initial);
            }

            Array.Copy(processedBlock, 0, output, offset, _cipher.BlockSize);
        }

        private byte[] ApplyDelta(byte[] data, byte[] delta)
        {
            byte[] result = new byte[data.Length];
            Array.Copy(data, result, data.Length);
            int i;
            for (i = 0; i < delta.Length; i++)
            {
                result[i] ^= delta[i];
            }

            return result;
        }
        

        private async Task ProcessStreamAsync(FileStream inputStream, FileStream outputStream, byte[] buffer,
            bool encrypt)
        {
            int bytesRead;
            InitialData? initialData = _encryptionMode switch
            {
                EncryptionMode.CBC => new InitialData(_encryptionMode, _iv),
                EncryptionMode.PCBC => new InitialData(_encryptionMode, _iv),
                EncryptionMode.CFB => new InitialData(_encryptionMode, _iv),
                EncryptionMode.OFB => new InitialData(_encryptionMode, _iv),
                EncryptionMode.CTR => new InitialData(_encryptionMode, _randomData),
                EncryptionMode.RandomDelta => new InitialData(_encryptionMode, _randomData),
                EncryptionMode.ECB => new InitialData(_encryptionMode, _randomData),
                _ => null
            };
            if ((_encryptionMode == EncryptionMode.RandomDelta || _encryptionMode == EncryptionMode.CTR))
            {
                if (!encrypt)
                {
                    byte[] temp = new byte[_cipher.BlockSize];
                    bytesRead = await inputStream.ReadAsync(temp, 0, temp.Length);
                    if (bytesRead < _cipher.BlockSize)
                    {
                        throw new IOException("Input stream is too small.");
                    }

                    byte[] tempDecrypt = _cipher.DecryptBlock(temp);
                    initialData = new InitialData(_encryptionMode, tempDecrypt);
                }
                else
                {
                    byte[] initialEncrypt = _cipher.EncryptBlock(initialData.Initial);
                    await outputStream.WriteAsync(initialEncrypt, 0, initialEncrypt.Length);
                }
                
            }


            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                byte[] processedData;
                if (bytesRead < buffer.Length)
                {
                    initialData.IsEnd = true;
                }

                if (encrypt)
                {
                    processedData = await EncryptPrivate(buffer.Take(bytesRead).ToArray(), initialData);
                }
                else
                {
                    processedData = await DecryptPrivate(buffer.Take(bytesRead).ToArray(), initialData);
                }

                await outputStream.WriteAsync(processedData, 0, processedData.Length);
            }
        }

        private void ValidateParameters(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            // Проверяем, нужен ли IV для выбранного режима
            if (_encryptionMode != EncryptionMode.ECB && _iv == null)
            {
                throw new ArgumentException(
                    $"Для режима {_encryptionMode} требуется вектор инициализации (IV)");
            }

            if (_iv != null && _iv.Length != _cipher.BlockSize)
            {
                throw new ArgumentException(
                    $"Вектор инициализации должен иметь длину {_cipher.BlockSize} байт. " +
                    $"Фактическая длина: {_iv.Length} байт");
            }
        }

        private void ValidateIV()
        {
            if (_iv == null)
                throw new InvalidOperationException("Вектор инициализации не установлен");

            if (_iv.Length != _cipher.BlockSize)
                throw new InvalidOperationException(
                    $"Некорректная длина вектора инициализации: {_iv.Length} байт. " +
                    $"Требуется: {_cipher.BlockSize} байт");
        }

        private void ValidateFilePaths(string inputPath, string outputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
                throw new ArgumentException("Путь к входному файлу не может быть пустым", nameof(inputPath));

            if (string.IsNullOrWhiteSpace(outputPath))
                throw new ArgumentException("Путь к выходному файлу не может быть пустым", nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException($"Входной файл не найден: {inputPath}");

            // Проверяем возможность записи в выходной файл
            string outputDirectory = Path.GetDirectoryName(outputPath);
            if (!Directory.Exists(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }
        }

        private void IncrementCounter(byte[] counter, int increment)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                int sum = counter[i] + increment;
                counter[i] = (byte)(sum % 256);
                increment = sum / 256;
                if (increment == 0) break;
            }
        }

        private void IncrementCounter(byte[] counter, byte[] increment)
        {
            byte carry = 0;
            int i;
            for (i = 0; i <  increment.Length; i++)
            {
                int sum = counter[counter.Length - i - 1] + increment[increment.Length - i - 1] + carry;
                counter[counter.Length - i - 1] = (byte)(sum % 256);
                carry = (byte)(sum / 256);
            }

            for (; i < counter.Length; i++)
            {
                int sum = counter[counter.Length - i - 1] + carry;
                counter[counter.Length - i - 1] = (byte)(sum % 256);
                carry = (byte)(sum / 256);
                if (carry == 0) break;
            }
        }

        private void CheckDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CipherContext));
        }
        

        #region IDisposable Implementation

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Очищаем управляемые ресурсы
                    if (_iv != null) Array.Clear(_iv, 0, _iv.Length);
                    if (_randomData != null) Array.Clear(_randomData, 0, _randomData.Length);

                    if (_cipher is IDisposable disposableCipher)
                    {
                        disposableCipher.Dispose();
                    }
                }

                // Очищаем неуправляемые ресурсы
                _disposed = true;
            }
        }

        ~CipherContext()
        {
            Dispose(false);
        }

        #endregion

        private class InitialData
        {
            public byte[] Initial { get; set; }
            public byte[] Delta { get; set; }

            public bool IsEnd = false;

            public InitialData(EncryptionMode mode, byte[] iv)
            {
                int n = iv.Length;
                Initial = new byte[n];
                Delta = new byte[n / 2];
                if (mode == EncryptionMode.RandomDelta)
                {
                    Array.Copy(iv, Initial, n);
                    Array.Copy(Initial, n / 2, Delta, 0, n / 2);
                }
                else if (mode == EncryptionMode.CTR)
                {
                    Array.Copy(iv, Initial, n);
                }
                else if (mode != EncryptionMode.ECB)
                {
                    Array.Copy(iv, Initial, n);
                }
            }
        }
    }
}