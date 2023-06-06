namespace RSAEncryption.Core.Extensions
{
    /// <summary>
    /// Extensions methods for <see cref="Byte" />.
    /// </summary>
    public static class ByteExtensions
    {
        /// <summary>
        /// Return a <see cref="String" /> from a <see cref="byte[]" /> with default <see cref="Encoding.UTF8" />.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        /// <example>
        /// <code>value.AsEncodedString()</code>
        /// </example>
        /// <exception cref="ArugmentNullException"></exception>
        /// <exception cref="EncoderFallbackException"></exception>
        public static string AsEncodedString(this byte[] value)
        {
            return AsEncodedString(value, Encoding.UTF8);
        }

        /// <summary>
        /// Return a <see cref="String" /> from a <see cref="byte[]" /> with specified <see cref="Encoding" />.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        /// <example>
        /// <code>value.AsEncodedString(Encoding.UTF8)</code>
        /// </example>
        /// <exception cref="ArugmentNullException"></exception>
        /// <exception cref="EncoderFallbackException"></exception>
        public static string AsEncodedString(this byte[] value, Encoding encoding)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value), "In order to encode value can not be null");
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding), "Encoding can not be null");
            try
            {
                return encoding.GetString(value);
            }
            catch (EncoderFallbackException ex)
            {
                throw new Exception("Wasn't possible to encode specified value, see inner exception for details", ex);
            }
            catch (Exception ex)
            {
                ex.Data["params"] = new List<object> { value, encoding };
                throw;
            }
        }
    }
}