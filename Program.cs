using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultSignandVerify
{
    class Program
    {
        private static KeyVaultClient _keyVaultClient = null;
        private static AuthenticationResult _authenticationResult = null;
        //Azure Active Directory App Registration Id and Secret Id
        private const string _clientId = "00000000-0000-0000-0000-000000000000";
        private const string _clientSecretId = "SecretId";
        private const string _keyVaultURL = "https://[yourkeyvault].vault.azure.net";
        //Key Vault Imported RSA private Keys
        private const string _privateKeyVersioninKeyVault = "/keys/keyname/74b5d90494cb4c4cdeb1587af26cb03a";
        private const string _publicKeyVersioninKeyVault = "/keys/keyname/e01913b55026cde2b08f21a1e82d10f5";
        static void Main(string[] args)
        {
            MainAsync().Wait();
        }

        private static async Task MainAsync()
        {
            string plainText = "Hello. This is an example for sign and verify using keyvault";
            byte[] dataBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] signatureData = await SignAsync(_privateKeyVersioninKeyVault, dataBytes);
            string signedDataString = BitConverter.ToString(signatureData).Replace("-", "");

            Console.WriteLine("Signed text: {0}", signedDataString);

            var result = await VerifyAsync(_publicKeyVersioninKeyVault, dataBytes, signatureData);
            Console.WriteLine("Verified: {0}", result);

        }

        //Sign input with SHA256
        public static async Task<byte[]> SignAsync(string keyId, Byte[] value)
        {
            KeyVaultClient keyVaultClient = GetClient();
            var appId = $"{_keyVaultURL}{keyId}";
            //Hash the data and send the digest to SignAsync
            byte[] digestBytes = SHA256.Create().ComputeHash(value);
            var keyOperationResult = await keyVaultClient.SignAsync(appId, JsonWebKeySignatureAlgorithm.RS256, digestBytes);
            
            return keyOperationResult.Result;
        }

        public static async Task<bool> VerifyAsync(string keyId, Byte[] plainText, byte[] signature)
        {
            bool result = false;
            KeyVaultClient keyVaultClient = GetClient();
            var appId = $"{_keyVaultURL}{keyId}";
            
            //Hash the data and send the digest to SignAsync
            byte[] digestBytes = SHA256.Create().ComputeHash(plainText);

            try
            {
                 result = await keyVaultClient.VerifyAsync(appId, JsonWebKeySignatureAlgorithm.RS256, digestBytes, signature);
            }
            catch(Exception ex)
            {
                Console.WriteLine("Errors: {0}", ex.Message);
            }
            return result;
        }
        private static KeyVaultClient GetClient()
        {
            if (_keyVaultClient != null)
            {
                return _keyVaultClient;
            }
            //The AzureServiceTokenProvider class caches the token in memory and retrieves it from Azure AD just before expiration.
            AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
            //If _clientId is empty, system assumes it is using app managed identity 
            if (string.IsNullOrEmpty(_clientId))
            {
                _keyVaultClient = new KeyVaultClient(
            new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            }
            else
            {
                _keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));
            }
            return _keyVaultClient;
        }

        private static async Task<string> GetToken(string authority, string resource, string scope)
        {
            //Reuse existing token if it is not expired
            if (_authenticationResult != null && DateTime.Compare(_authenticationResult.ExpiresOn.AddMinutes(-5).ToUniversalTime().DateTime, DateTime.Now.ToUniversalTime()) > 0)
            {
                return _authenticationResult.AccessToken;
            }
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(_clientId, _clientSecretId);
            _authenticationResult = await authContext.AcquireTokenAsync(resource, clientCred);

            if (_authenticationResult == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return _authenticationResult.AccessToken;
        }
    }
}
