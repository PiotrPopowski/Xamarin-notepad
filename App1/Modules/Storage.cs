using Android.App;
using Android.Content;

namespace App1.Modules
{
    public static class Storage
    {
        public static void Save(string key, string value)
        {
            var prefs = Application.Context.GetSharedPreferences("App1", FileCreationMode.Private);
            var prefEditor = prefs.Edit();
            prefEditor.PutString(key, value);
            prefEditor.Commit();
        }

        public static string Get(string key)
        {
            //retreive 
            var prefs = Application.Context.GetSharedPreferences("App1", FileCreationMode.Private);
            return prefs.GetString(key, null);
        }
    }
}