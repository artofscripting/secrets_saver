namespace SecretsSaver;

public sealed class InvalidKeyOrCorruptedDataException : Exception
{
    public InvalidKeyOrCorruptedDataException() : base("Invalid key or corrupted data.")
    {
    }
}
