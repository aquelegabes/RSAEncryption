using System;
using System.Collections.Generic;
using System.Text;

namespace RSAEncryption.Extensions
{
    /// <summary>
    /// Extensions methods for <see cref="String" />.
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Returns a <see cref="byte[]" /> string encoded with default encoding <see cref="Encoding.UTF8" />.
        /// </summary>
        /// <param name="str"></param>
        /// <example>
        /// <code>foo.ToByteArray();</code>
        /// </example>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="EncoderFallbackException"></exception>
        public static byte[] ToByteArray(this string str)
        {
            return ToByteArray(str, Encoding.UTF8);
        }

        /// <summary>
        /// Returns a <see cref="byte[]" /> string encoded with a chosen charset
        /// </summary>
        /// <param name="str"></param>
        /// <param name="encoding" cref="Encoding">Check <see cref="Encoding" /> properties members.</param>
        /// <example>
        /// <code>foo.ToByteArray(Encoding.UTF8);</code>
        /// </example>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="EncoderFallbackException"></exception>
        public static byte[] ToByteArray(this string str, Encoding encoding)
        {
            if (string.IsNullOrWhiteSpace(str))
                throw new ArgumentNullException(nameof(str), "In order to encode value can not be null");
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding), "Encoding can not be null");
            try
            {
                return encoding.GetBytes(str);
            }
            catch (EncoderFallbackException ex)
            {
                throw new Exception("Wasn't possible to encode specified value, see inner exception for details", ex);
            }
            catch (Exception ex)
            {
                ex.Data["params"] = new List<object> { str, encoding };
                throw;
            }
        }
    }
}