using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace CheckCng
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(Environment.MachineName);

            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            var isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (!isAdmin)
            {
                Console.WriteLine("Please run as Administrator");
                return;
            }

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide at least first 5 characters of thumbprint");
                return;
            }

            X509Store store = new X509Store("MY",StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            bool found = false;
            foreach (var cert in store.Certificates)
            {
                if (cert.Thumbprint.ToUpper().StartsWith(args[0].ToUpper()))
                {
                    found = true;
                    Console.WriteLine(cert.Thumbprint);

                    try
                    {
                        var rsa = cert.GetRSAPrivateKey();
                        Console.WriteLine(rsa.ExportParameters(true));
                        Console.WriteLine("Private key is setup correctly.");
                    }
                    catch (Exception exception)
                    {
                        Console.WriteLine(exception);
                        Console.WriteLine("Private key is NOT setup correctly!");
                    }
                }
            }

            if (!found)
            {
                Console.WriteLine("Certificate was NOT found!");
            }
        }
    }
}
