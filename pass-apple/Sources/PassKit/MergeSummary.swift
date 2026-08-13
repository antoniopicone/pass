/// Summary of a cross-device merge, mirroring the `*_out` parameters of
/// `vault_merge_from_file` in passlib_ffi.h.
public struct MergeSummary: Equatable, Sendable {
    public let created: Int
    public let updated: Int
    public let unchanged: Int
    public let deleted: Int

    public var changed: Bool {
        created > 0 || updated > 0 || deleted > 0
    }
}
