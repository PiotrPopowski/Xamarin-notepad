using System;
using Android.Security.Keystore;
using Android.Support.V4.Hardware.Fingerprint;
using Android.Util;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Xamarin.Essentials;

namespace App1.Modules
{
    /// <summary>
    ///     This class encapsulates the creation of a CryptoObject based on a javax.crypto.Cipher.
    /// </summary>
    /// <remarks>Each invocation of BuildCryptoObject will instantiate a new CryptoObjet. 
    /// If necessary a key for the cipher will be created.</remarks>
    public class CryptoObjectHelper
    {
        // ReSharper disable InconsistentNaming
        static readonly string TAG = "X:" + typeof(CryptoObjectHelper).Name;

        // This can be key name you want. Should be unique for the app.
        static readonly string KEY_NAME = "SampleFingerprintKey1";

        // We always use this keystore on Android.
        static readonly string KEYSTORE_NAME = "AndroidKeyStore";

        // Should be no need to change these values.
        static readonly string KEY_ALGORITHM = KeyProperties.KeyAlgorithmAes;
        static readonly string BLOCK_MODE = KeyProperties.BlockModeCbc;
        static readonly string ENCRYPTION_PADDING = KeyProperties.EncryptionPaddingPkcs7;

        static readonly string TRANSFORMATION = KEY_ALGORITHM + "/" +
                                                BLOCK_MODE + "/" +
                                                ENCRYPTION_PADDING;
        // ReSharper restore InconsistentNaming

        readonly KeyStore _keystore;

        public CryptoObjectHelper()
        {
            _keystore = KeyStore.GetInstance(KEYSTORE_NAME);
            _keystore.Load(null);
        }

        public FingerprintManagerCompat.CryptoObject BuildCryptoObject(CipherMode mode = CipherMode.EncryptMode)
        {
            Log.Debug("crypto object", "Creating crypto object");
            Cipher cipher = CreateCipher(true, mode);
            Log.Debug("crypto object", "Cipher created");
            return new FingerprintManagerCompat.CryptoObject(cipher);
        }

        /// <summary>
        ///     Creates the cipher.
        /// </summary>
        /// <returns>The cipher.</returns>
        /// <param name="retry">If set to <c>true</c>, recreate the key and try again.</param>
        Cipher CreateCipher(bool retry = true, CipherMode mode = CipherMode.EncryptMode)
        {
            IKey key = GetKey();
            Log.Debug("crypto object", "Got key");
            Cipher cipher = Cipher.GetInstance(TRANSFORMATION);
            Log.Debug("crypto object", "Got cipher instance");
            try
            {
                if (mode == CipherMode.EncryptMode)
                {
                    cipher.Init(mode, key);
                    SecureStorage.SetAsync("cipherIvKey", Convert.ToBase64String(cipher.GetIV()));
                }
                else
                    cipher.Init(mode, key, new IvParameterSpec(Convert.FromBase64String(SecureStorage.GetAsync("cipherIvKey").Result)));
            }
            catch (KeyPermanentlyInvalidatedException e)
            {
                Log.Debug(TAG, "The key was invalidated, creating a new key.");
                _keystore.DeleteEntry(KEY_NAME);
                if (retry)
                {
                    CreateCipher(false);
                }
                else
                {
                    throw new Exception("Could not create the cipher for fingerprint authentication.", e);
                }
            }
            return cipher;
        }

        /// <summary>
        ///     Will get the key from the Android keystore, creating it if necessary.
        /// </summary>
        /// <returns></returns>
        public IKey GetKey()
        {
            if (!_keystore.IsKeyEntry(KEY_NAME))
            {
                CreateKey();
            }

            IKey secretKey = _keystore.GetKey(KEY_NAME, null);
            return secretKey;
        }

        /// <summary>
        ///     Creates the Key for fingerprint authentication.
        /// </summary>
        void CreateKey()
        {
            KeyGenerator keyGen = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, KEYSTORE_NAME);
            KeyGenParameterSpec keyGenSpec =
                new KeyGenParameterSpec.Builder(KEY_NAME, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                    .SetBlockModes(BLOCK_MODE)
                    .SetEncryptionPaddings(ENCRYPTION_PADDING)
                    .SetUserAuthenticationRequired(true)
                    .Build();
            keyGen.Init(keyGenSpec);
            keyGen.GenerateKey();
            Log.Debug(TAG, "New key created for fingerprint authentication.");
        }
    }
}