using System;
using System.IO;

namespace RSAEncryption
{
    public static class FileManipulation
    {
        public static bool OpenFile(string path, out byte[] file)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new NullReferenceException("Path is required");

            try
            {
                FileStream fs = File.OpenRead(path);
                byte[] bytes = new byte[fs.Length];
                fs.Read(bytes, 0, Convert.ToInt32(fs.Length));
                fs.Close();
                file = bytes;
                return true;
            }
            catch (Exception ex)
            {
                throw new FileLoadException("Couldn't open file see inner exception for details", ex);
            }
        }

        public static bool SaveFile(byte[] file, string targetPath, string name, bool overwriteFile = false)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new NullReferenceException("File name is required");
            if (string.IsNullOrWhiteSpace(targetPath))
                throw new NullReferenceException("Target path is required");
            if (file == null || file.Length == 0)
                throw new NullReferenceException("File is required");

            try
            {
                string fullPath = $@"{targetPath}\{name}";
                if (!Directory.Exists(targetPath))
                    Directory.CreateDirectory(targetPath);
                if (!File.Exists(fullPath))
                    File.WriteAllBytes(fullPath, file);
                else if (overwriteFile)
                    File.WriteAllBytes(fullPath, file);
                else
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                throw new IOException("Couldn't save the file check inner exception for details", ex);
            }
        }

        public static bool DeleteFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new NullReferenceException("File path is required");

            var attr = File.GetAttributes(filePath);
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                throw new ArgumentException("Must be a file not a directory", nameof(filePath));

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