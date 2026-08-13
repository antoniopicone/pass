import Foundation

/// Calls `body` with a C string pointer for each Swift string in `strings`,
/// keeping every one of them alive for the duration of the call (`nil`
/// entries produce a `nil` pointer, for FFI parameters that accept NULL —
/// e.g. `vault_update_entry`'s password).
///
/// This exists so every FFI call site builds its pointer array through one
/// reviewed helper instead of a hand-nested pyramid of `withCString` per
/// call, which is where a transcription mistake would be easy to make and
/// hard to notice.
func withCStrings<R>(_ strings: [String?], _ body: ([UnsafePointer<CChar>?]) -> R) -> R {
    func recurse(_ index: Int, _ pointers: [UnsafePointer<CChar>?]) -> R {
        guard index < strings.count else {
            return body(pointers)
        }
        guard let s = strings[index] else {
            return recurse(index + 1, pointers + [nil])
        }
        return s.withCString { ptr in
            recurse(index + 1, pointers + [ptr])
        }
    }
    return recurse(0, [])
}
