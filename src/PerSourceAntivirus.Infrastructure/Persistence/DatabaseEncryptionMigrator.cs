using Microsoft.Data.Sqlite;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public static class DatabaseEncryptionMigrator
{
    private static readonly byte[] PlaintextSqliteMagic = "SQLite format 3\0"u8.ToArray();

    public static void EnsureEncrypted(string dbFilePath, string passphrase)
    {
        if (!File.Exists(dbFilePath)) return;
        if (!IsPlaintextSqlite(dbFilePath)) return;

        var tempEncryptedPath = dbFilePath + ".encrypting.tmp";
        if (File.Exists(tempEncryptedPath)) File.Delete(tempEncryptedPath);

        try
        {
            using (var connection = new SqliteConnection($"Data Source={dbFilePath}"))
            {
                connection.Open();
                using (var attach = connection.CreateCommand())
                {
                    attach.CommandText = "ATTACH DATABASE $path AS encrypted KEY $key;";
                    attach.Parameters.AddWithValue("$path", tempEncryptedPath);
                    attach.Parameters.AddWithValue("$key", passphrase);
                    attach.ExecuteNonQuery();
                }

                using (var export = connection.CreateCommand())
                {
                    export.CommandText = "SELECT sqlcipher_export('encrypted');";
                    export.ExecuteNonQuery();
                }

                using (var detach = connection.CreateCommand())
                {
                    detach.CommandText = "DETACH DATABASE encrypted;";
                    detach.ExecuteNonQuery();
                }
            }

            SqliteConnection.ClearAllPools();

            var backupPath = dbFilePath + ".plaintext.bak";
            File.Move(dbFilePath, backupPath, overwrite: true);
            File.Move(tempEncryptedPath, dbFilePath, overwrite: true);
        }
        catch
        {
            try { if (File.Exists(tempEncryptedPath)) File.Delete(tempEncryptedPath); } catch { }
        }
    }

    private static bool IsPlaintextSqlite(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            if (stream.Length < PlaintextSqliteMagic.Length) return false;

            var header = new byte[PlaintextSqliteMagic.Length];
            var read = stream.Read(header, 0, header.Length);
            return read == header.Length && header.AsSpan().SequenceEqual(PlaintextSqliteMagic);
        }
        catch
        {
            return false;
        }
    }
}
