using System.Text.Json.Serialization;

namespace Qopanza.Sdk;

public sealed record KeyResponse(
    string Id,
    string Purpose,
    string Algorithm,
    string Backend,
    string PublicKey,
    DateTimeOffset CreatedAt,
    string? Label,
    DateTimeOffset? ExpiresAt);

public sealed record EncryptResult(
    string KeyId,
    string CiphertextKem,
    string CiphertextPayload,
    string Nonce,
    string Backend);

public sealed record SignResult(string KeyId, string Signature, string Backend);

public sealed record AnalysisFinding(
    string Severity,
    string RuleId,
    string Title,
    string Detail,
    string Recommendation);

public sealed record AnalyzeResult(
    IReadOnlyList<AnalysisFinding> Findings,
    string Summary,
    string GeneratedBy);

// -- Wire-format (snake_case) DTOs, internal to this library — the public
// records above are what SDK consumers see. Keeping the two separate means
// a wire-format change only touches the mapping code, not every call site.

internal sealed record KeyResponseWire(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("purpose")] string Purpose,
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("backend")] string Backend,
    [property: JsonPropertyName("public_key")] string PublicKey,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("expires_at")] DateTimeOffset? ExpiresAt)
{
    public KeyResponse ToPublic() => new(Id, Purpose, Algorithm, Backend, PublicKey, CreatedAt, Label, ExpiresAt);
}

internal sealed record EncryptResponseWire(
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("ciphertext_kem")] string CiphertextKem,
    [property: JsonPropertyName("ciphertext_payload")] string CiphertextPayload,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("backend")] string Backend)
{
    public EncryptResult ToPublic() => new(KeyId, CiphertextKem, CiphertextPayload, Nonce, Backend);
}

internal sealed record DecryptResponseWire([property: JsonPropertyName("plaintext")] string Plaintext);

internal sealed record SignResponseWire(
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("backend")] string Backend)
{
    public SignResult ToPublic() => new(KeyId, Signature, Backend);
}

internal sealed record VerifyResponseWire([property: JsonPropertyName("valid")] bool Valid);

internal sealed record AnalysisFindingWire(
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("rule_id")] string RuleId,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("recommendation")] string Recommendation)
{
    public AnalysisFinding ToPublic() => new(Severity, RuleId, Title, Detail, Recommendation);
}

internal sealed record AnalyzeResponseWire(
    [property: JsonPropertyName("findings")] List<AnalysisFindingWire> Findings,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("generated_by")] string GeneratedBy)
{
    public AnalyzeResult ToPublic() => new(Findings.Select(f => f.ToPublic()).ToList(), Summary, GeneratedBy);
}
