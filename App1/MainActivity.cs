using Android.App;
using Android.OS;
using Android.Widget;
using App1.Modules;
using Xamarin.Essentials;
using System.Security;
using Android.Views;
using System;
using Android.Support.V4.Hardware.Fingerprint;
using Android.Support.V4.Content;
using Android;
using Android.Hardware.Fingerprints;
using Android.Util;

namespace App1
{
    [Activity(Label = "App1", MainLauncher = true)]
    public class MainActivity : Activity
    {
        private SecureString secretInMemory = new SecureString();
        private FingerprintManagerCompat _fingerprintManager;
        private CryptoObjectHelper cryptObjectHelper = new CryptoObjectHelper();
        private SimpleCallbacks myCallback;

        private Android.Support.V4.OS.CancellationSignal _cancellationSignal;

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            _fingerprintManager = FingerprintManagerCompat.From(this);

            if (String.IsNullOrWhiteSpace(SecureStorage.GetAsync("secretFingerprint").Result))
            {
                SetContentView(Resource.Layout.initial_fingerprint);
            }
            else
                SetContentView(Resource.Layout.encryptedLayout);
        }

        void OnAuthSucceededDecryption(FingerprintManagerCompat.AuthenticationResult result)
        {
            Log.Debug("Auth deryption", "First dec");
            var cipher = result.CryptoObject.Cipher;
            var secretFingerprint = Convert.FromBase64String(SecureStorage.GetAsync("secretFingerprint").Result);
            var decryptedSecret = cipher.DoFinal(secretFingerprint);

            foreach (char c in System.Text.Encoding.Unicode.GetString(decryptedSecret))
            {
                secretInMemory.AppendChar(c);
            }

            SetContentView(Resource.Layout.decryptedLayout);
            if (!String.IsNullOrWhiteSpace(SecureStorage.GetAsync("notepad").Result))
            {
                var notepad = FindViewById<EditText>(Resource.Id.notepad);
                notepad.Text = StringCipher.Decrypt(SecureStorage.GetAsync("notepad").Result,
                                                    new System.Net.NetworkCredential("", secretInMemory).Password);
            }
        }

        void OnAuthSucceededEncryption(FingerprintManagerCompat.AuthenticationResult result)
        {
            Log.Debug("Authenticated", "First");
            var cipher = result.CryptoObject.Cipher;
            var encryptedSecret = cipher.DoFinal(System.Text.Encoding.Unicode.GetBytes(Guid.NewGuid().ToString("n")));
            SecureStorage.SetAsync("secretFingerprint", Convert.ToBase64String(encryptedSecret));
            SetContentView(Resource.Layout.encryptedLayout);
            /*
            if (first)
            {
                var initialText = "hihihih";
                // cipher.Init(Javax.Crypto.CipherMode.EncryptMode, cryptObjectHelper.GetKey());
                Log.Debug("Auth", $"Try encrypt do final {cipher.BlockSize}");
                var encryptedText = cipher.DoFinal(System.Text.Encoding.Unicode.GetBytes(initialText));
                SecureStorage.SetAsync("secret", Convert.ToBase64String(encryptedText)).Wait();
                notepad.Text = Convert.ToBase64String(encryptedText);
                first = !first;
                Log.Debug("Authenticated", "Done");
            }
            else
            {
                Log.Debug("Auth", "Decrypting");
                String cipherText = SecureStorage.GetAsync("secret").Result;
                Log.Debug("decrt", "try dofinal");
                var enbytes = Convert.FromBase64String(SecureStorage.GetAsync("secret").Result);
                String finalText = System.Text.Encoding.Unicode.GetString(cipher.DoFinal(enbytes, 0, enbytes.Length));
                notepad.Text = finalText;
            }*/

        }

        void OnAuthFailed()
        {
            setAlert("Your fingerprint is bad :(");
        }

        [Java.Interop.Export("Scan_Fingerprint")]
        public void StartFingerprintScan(View v)
        {
            Log.Debug("scan_fingerprint", "scanning");
            Android.Content.PM.Permission permissionResult = ContextCompat.CheckSelfPermission(this, Manifest.Permission.UseFingerprint);
            if (permissionResult == Android.Content.PM.Permission.Granted && _fingerprintManager.HasEnrolledFingerprints)
            {
                Log.Debug("scan_fingerprint", "permission granted");

                myCallback = new SimpleCallbacks();
                myCallback.AuthenticationSucceeded += OnAuthSucceededEncryption;
                myCallback.AuthenticationFailed += OnAuthFailed;

                _cancellationSignal = new Android.Support.V4.OS.CancellationSignal();
                _fingerprintManager.Authenticate(cryptObjectHelper.BuildCryptoObject(),
                                             (int)FingerprintAuthenticationFlags.None,
                                             _cancellationSignal,
                                             myCallback,
                                             null);

            }
            else
            {
                throw new Exception();
            }
        }

        [Java.Interop.Export("Decrypt_Fingerprint")]
        public void DecryptFingerprint(View v)
        {
            Log.Debug("decrypt_fingerprint", "scanning");
            Android.Content.PM.Permission permissionResult = ContextCompat.CheckSelfPermission(this, Manifest.Permission.UseFingerprint);
            if (permissionResult == Android.Content.PM.Permission.Granted && _fingerprintManager.HasEnrolledFingerprints)
            {
                Log.Debug("decrypt_fingerprint", "permission granted");

                myCallback = new SimpleCallbacks();
                myCallback.AuthenticationSucceeded += OnAuthSucceededDecryption;
                myCallback.AuthenticationFailed += OnAuthFailed;

                _cancellationSignal = new Android.Support.V4.OS.CancellationSignal();
                _fingerprintManager.Authenticate(cryptObjectHelper.BuildCryptoObject(Javax.Crypto.CipherMode.DecryptMode),
                                             (int)FingerprintAuthenticationFlags.None,
                                             _cancellationSignal,
                                             myCallback,
                                             null);
            }
        }

        [Java.Interop.Export("EncryptText")]
        public void EncryptText(View v)
        {
            var notepad = FindViewById<EditText>(Resource.Id.notepad);
            encryptNotepad(new System.Net.NetworkCredential("", secretInMemory).Password, notepad.Text);

            secretInMemory.Clear();
            SetContentView(Resource.Layout.encryptedLayout);
        }

        [Java.Interop.Export("SignOut")]
        public void SignOut(View v)
        {
            secretInMemory.Clear();
            SetContentView(Resource.Layout.encryptedLayout);
        }

        private void encryptNotepad(string password, string text)
        {
            var encryptedText = StringCipher.Encrypt(text, password);
            SecureStorage.SetAsync("notepad", encryptedText).Wait();
        }

        private void savePassword(string password)
        {
            if (password.Length < 9)
            {
                throw new Exception("Password must have at least 8 characters.");
            }

            var salt = Encrypter.GenerateSalt();
            var hash = Encrypter.GetHash(password, salt);

            SecureStorage.SetAsync("user_salt", salt).Wait();
            SecureStorage.SetAsync("user_password", hash).Wait();
        }

        private void setAlert(string text, string color = "red")
        {
            var alert = FindViewById<TextView>(Resource.Id.alertText);
            alert.SetTextColor(Android.Graphics.Color.ParseColor(color));
            alert.Text = text;
        }
    }
}