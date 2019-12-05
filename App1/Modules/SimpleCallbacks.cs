using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Support.V4.Hardware.Fingerprint;
using Android.Util;
using Android.Views;
using Android.Widget;
using Javax.Crypto;

namespace App1.Modules
{
    class SimpleCallbacks : FingerprintManagerCompat.AuthenticationCallback
    {
        // ReSharper disable once MemberHidesStaticFromOuterClass
        static readonly string TAG = "X:" + typeof(SimpleCallbacks).Name;
        static readonly byte[] SECRET_BYTES = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

        public delegate void authenticated(FingerprintManagerCompat.AuthenticationResult result);
        public delegate void authenticationFailed();

        public event authenticated AuthenticationSucceeded;
        public event authenticationFailed AuthenticationFailed;

        public override void OnAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result)
        {
            Log.Debug("SimpleCallback", "Authentication succeeded");
            AuthenticationSucceeded.Invoke(result);
        }

        public override void OnAuthenticationFailed()
        {
            Log.Debug("SimpleCallback", "Auth failed");
            AuthenticationFailed.Invoke();
        }
    }
}