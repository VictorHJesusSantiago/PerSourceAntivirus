using Microsoft.Data.Sqlite;

namespace PerSourceAntivirus.Infrastructure.Persistence;

// One-time, in-place conversion of a pre-existing plaintext persourceav.db into a SQLCipher
// encrypted database, using sqlcipher_export() (attach a new encrypted DB, copy everything,
// swap the file). New installs never hit this path — AddDbContext already opens fresh
// databases with Password= set, so they're encrypted from creation.
public static class DatabaseEncryptionMigrator
{
    private static readonly byte[] PlaintextSqliteMagic = "SQLite format 3\0"u8.ToArray();

    public static void EnsureEncrypted(string dbFilePath, string passphrase)
    {
        if (!File.Exists(dbFilePath)) return;
        if (!IsPlaintextSqlite(dbFilePath)) return; // already encrypted (or not a recognizable sqlite file)

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
            // Leave the original plaintext database untouched if anything goes wrong —
            // the app keeps working unencrypted rather than risking data loss.
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
