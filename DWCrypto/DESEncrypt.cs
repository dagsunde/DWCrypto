using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DWCrypto {
    public class DESEncrypt {
        private const string EncryptionAppSettingKey = "EnableEncryption";

        public bool IsEncryptionEnabled {
            get {
                return true;
            }
        }

        private System.Security.Cryptography.TripleDES CreateDes( string key ) {
            var md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            var des = new System.Security.Cryptography.TripleDESCryptoServiceProvider { Key = md5.ComputeHash( System.Text.Encoding.Unicode.GetBytes( key ) ) };
            des.IV = new byte[ des.BlockSize / 8 ];

            return des;
        }

        public string Encrypt( string key, string plainText ) {
            if ( !IsEncryptionEnabled ) {
                return plainText;
            }

            if ( plainText == null ) {
                return plainText;
            }

            var des = CreateDes( key );
            var ct = des.CreateEncryptor();
            var input = System.Text.Encoding.Unicode.GetBytes( plainText );
            return Convert.ToBase64String( ct.TransformFinalBlock( input, 0, input.Length ) );
        }
        public string Decrypt( string key, string cypherText ) {
            if ( !IsEncryptionEnabled ) {
                return cypherText;
            }

            if ( cypherText == null ) {
                return cypherText;
            }

            var b = Convert.FromBase64String( cypherText );
            var des = CreateDes( key );
            var ct = des.CreateDecryptor();
            var output = ct.TransformFinalBlock( b, 0, b.Length );
            return System.Text.Encoding.Unicode.GetString( output );
        }
    }
}
