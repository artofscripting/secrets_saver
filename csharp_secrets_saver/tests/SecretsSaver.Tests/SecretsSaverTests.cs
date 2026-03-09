using SecretsSaver;
using Xunit;

namespace SecretsSaver.Tests;

public class SecretsSaverTests
{
    [Fact]
    public void SetGetListClear_FileBackend_Works()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "secrets-saver-cs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var file = Path.Combine(tempDir, "secrets.ep");
        var goodPass = "test-" + Guid.NewGuid().ToString("N");

        var saver = SecretsSaverClient.NewFile(file, _ => goodPass);

        saver.SetSecret("a", "1");
        saver.SetSecret("b", "2");

        Assert.Equal("1", saver.GetSecret("a"));
        Assert.Equal(new[] { "a", "b" }, saver.ListSecrets());

        saver.ClearDatabase();
        Assert.Empty(saver.ListSecrets());
    }

    [Fact]
    public void InvalidKey_ThrowsExpectedError()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "secrets-saver-cs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var file = Path.Combine(tempDir, "secrets.ep");
        var goodPass = "test-" + Guid.NewGuid().ToString("N");
        var badPass = goodPass + "-wrong";

        var writer = SecretsSaverClient.NewFile(file, _ => goodPass);
        writer.SetSecret("x", "y");

        var reader = SecretsSaverClient.NewFile(file, _ => badPass);
        Assert.Throws<InvalidKeyOrCorruptedDataException>(() => reader.GetSecret("x"));
    }
}
