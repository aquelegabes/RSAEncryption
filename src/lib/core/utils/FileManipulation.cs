namespace RSAEncryption.Core.Utils
{
    public static class FileManipulation
    {
        /// <summary>
        /// Open a file and outputs it's content.
        /// </summary>
        /// <param name="path">Full path with filename</param>
        /// <param name="file">Outputs <see cref="FileStream"/> bytes.</param>
        /// <exception cref="NullReferenceException">Path is null.</exception>
        /// <exception cref="FileLoadException">Could not open file, check inner exception.</exception>
        public static void OpenFile(string path, out byte[] file)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new NullReferenceException("Path is required");

            try
            {
                using (FileStream fs = File.OpenRead(path))
                {
                    byte[] bytes = new byte[fs.Length];
                    fs.Read(bytes, 0, Convert.ToInt32(fs.Length));
                    fs.Close();
                    file = bytes;
                }
            }
            catch (Exception ex)
            {
                throw new FileLoadException("Couldn't open file see inner exception for details", ex);
            }
        }

        /// <summary>
        /// Save <see cref="byte[]"/> content into a file.
        /// </summary>
        /// <param name="fileContent">File content.</param>
        /// <param name="targetPath">Path to save.</param>
        /// <param name="nameWithExtension">File name with it's extension</param>
        /// <param name="overwriteFile">Overwrite existent file, otherwise false.</param>
        /// <param name="attributes">Attributes to add to file, otherwise <see cref="FileAttributes.Normal"/></param>
        /// <returns><see cref="true"/> if file saved successfully, otherwise <see cref="false"/>.</returns>
        /// <exception cref="NullReferenceException">Any of the required parameters are null.</exception>
        /// <exception cref="IOException">Could not save file, check inner exception</exception>
        public static bool SaveFile(byte[] fileContent, string targetPath, string nameWithExtension,
            bool overwriteFile = false, FileAttributes attributes = FileAttributes.Normal)
        {
            if (string.IsNullOrWhiteSpace(nameWithExtension))
                throw new NullReferenceException("File name is required.");
            if (string.IsNullOrWhiteSpace(targetPath))
                throw new NullReferenceException("Target path is required.");
            if (!Directory.Exists(targetPath))
                throw new ArgumentException(
                    message: "Invalid directory path.",
                    paramName: nameof(targetPath));
            if (fileContent == null || fileContent.Length == 0)
                throw new NullReferenceException("File is required");

            string fullPath = $@"{targetPath}\{nameWithExtension}";

            try
            {
                if (!Directory.Exists(targetPath))
                    Directory.CreateDirectory(targetPath);
                if (!File.Exists(fullPath))
                    File.WriteAllBytes(fullPath, fileContent);
                else if (overwriteFile)
                    File.WriteAllBytes(fullPath, fileContent);
                else
                    return false;

                if (attributes != FileAttributes.Normal)
                {
                    File.SetAttributes(fullPath, attributes);
                }
                return true;
            }
            catch (Exception ex)
            {
                if (File.Exists(fullPath))
                    DeleteFile(fullPath);
                throw new IOException("Couldn't save the file check inner exception for details", ex);
            }
        }

        /// <summary>
        /// Delete a specified file.
        /// </summary>
        /// <param name="filePath">Full path file.</param>
        /// <returns><see cref="true"/> if deleted file, otherwise <see cref="false"/>.</returns>
        /// <exception cref="NullReferenceException">File path is null.</exception>
        /// <exception cref="ArgumentException">Path is not a valid file.</exception>
        /// <exception cref="IOException">Could not delete the file, check inner exception.</exception>
        public static bool DeleteFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new NullReferenceException("File path is required");

            if (!File.Exists(filePath))
                throw new ArgumentException(
                    message: "File do not exist.",
                    paramName: nameof(filePath));

            try
            {
                File.Delete(filePath);
                return true;
            }
            catch (Exception exe)
            {
                throw new IOException("Couldn't delete the file check inner exception for details", exe);
            }
        }
    }
}