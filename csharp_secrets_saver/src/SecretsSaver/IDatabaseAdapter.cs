namespace SecretsSaver;

public interface IDatabaseAdapter
{
    RawContent? ReadEncryptedRow();
    void UpsertEncryptedRow(RawContent content);
}
