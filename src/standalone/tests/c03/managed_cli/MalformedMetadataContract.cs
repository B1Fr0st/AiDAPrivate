namespace Aida.C03.ManagedCliFixtures;

public static class MalformedMetadataContract
{
    public const string ExpectedFailureCode = "malformed_metadata";
    public const string ExpectedFailureKey = "managed_cli.malformed_metadata";
    public const string MetadataSignature = "BSJB";
    public const string CorruptSignatureMutation = "corrupt_metadata_signature";
    public const string TruncateRootMutation = "truncate_metadata_root";
    public const int NonMethodToken = 33554433;
}
