using Android.App;
using Android.OS;
using Android.Widget;
using App1.Modules;
using Xamarin.Essentials;
using System.Security;
using Android.Views;
using System;
using System.Linq;
using System.Text.RegularExpressions;
using Android.Content;
using Android.Runtime;
using System.Threading.Tasks;

namespace App1
{
    [Activity(Label = "App1", MainLauncher = true)]
    public class MainActivity : Activity
    {
        private SecureString passwordInMemory = new SecureString();

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            if (string.IsNullOrWhiteSpace(SecureStorage.GetAsync("user_password").Result))
                SetContentView(Resource.Layout.activity_main);
            else
                SetContentView(Resource.Layout.encryptedLayout);
        }

        protected override void OnPause()
        {
            if (string.IsNullOrWhiteSpace(SecureStorage.GetAsync("user_password").Result))
                SetContentView(Resource.Layout.activity_main);
            else
                SetContentView(Resource.Layout.encryptedLayout);
            base.OnPause();
        }

        [Java.Interop.Export("Create")]
        public void Create(View v)
        {
            var notepad = FindViewById<EditText>(Resource.Id.notepad);
            var notepadPassword = FindViewById<EditText>(Resource.Id.password);
            var notepadRepeatPassword = FindViewById<EditText>(Resource.Id.repeatPassword);

            if (notepadPassword.Text != notepadRepeatPassword.Text)
            {
                setAlert("Given passwords are different.");
                return;
            }

            try
            {
                savePassword(notepadPassword.Text);
            }
            catch (Exception e)
            {
                setAlert(e.Message);
                return;
            }
            encryptNotepad(notepadPassword.Text, notepad.Text);

            SetContentView(Resource.Layout.encryptedLayout);
        }

        [Java.Interop.Export("EncryptText")]
        public void EncryptText(View v)
        {
            var notepad = FindViewById<EditText>(Resource.Id.notepad);
            encryptNotepad(new System.Net.NetworkCredential("", passwordInMemory).Password, notepad.Text);

            passwordInMemory.Clear();
            SetContentView(Resource.Layout.encryptedLayout);
        }

        [Java.Interop.Export("DecryptText")]
        public void DecryptText(View v)
        {
            var password = FindViewById<EditText>(Resource.Id.password);
            var pswd = password.Text;
            if (String.IsNullOrWhiteSpace(pswd))
            {
                return;
            }
            var hash = Encrypter.GetHash(pswd, SecureStorage.GetAsync("user_salt").Result);
            if (hash != SecureStorage.GetAsync("user_password").Result)
            {
                setAlert("Incorrect password.");
            }
            else
            {
                password.Text.ToCharArray().ToList()
                    .ForEach(c => passwordInMemory.AppendChar(c));
                SetContentView(Resource.Layout.decryptedLayout);
                var notepad = FindViewById<EditText>(Resource.Id.notepad);
                notepad.Text = StringCipher.Decrypt(SecureStorage.GetAsync("notepad").Result, pswd);
            }
        }

        [Java.Interop.Export("ChangePassword")]
        public void ChangePassword(View v)
        {
            var password = FindViewById<EditText>(Resource.Id.password);
            var repeatPassword = FindViewById<EditText>(Resource.Id.repeatPassword);

            if (password.Text != repeatPassword.Text)
            {
                setAlert("Given passwords are different.");
                return;
            }

            try
            {
                savePassword(password.Text);
            }
            catch (Exception e)
            {
                setAlert(e.Message);
                return;
            }

            var notepadText = StringCipher.Decrypt(SecureStorage.GetAsync("notepad").Result,
                                new System.Net.NetworkCredential("", passwordInMemory).Password);
            encryptNotepad(password.Text, notepadText);

            passwordInMemory.Clear();
            password.Text.ToCharArray().ToList()
                .ForEach(c => passwordInMemory.AppendChar(c));

            setAlert("Password successfully changed.", "green");
            password.Text = "";
            repeatPassword.Text = "";
        }

        [Java.Interop.Export("SingOut")]
        public void SingOut(View v)
        {
            var password = FindViewById<EditText>(Resource.Id.password);
            var repeatPassword = FindViewById<EditText>(Resource.Id.repeatPassword);
            var notepad = FindViewById<EditText>(Resource.Id.notepad);

            passwordInMemory.Clear();

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
            if (!password.Any(c => char.IsUpper(c)) || !password.Any(c => "!@#$%^&*()-+<>|~?".Any(s => s == c)))
            {
                throw new Exception("Password must consists of at least 1 upper case letter and one special character.");
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