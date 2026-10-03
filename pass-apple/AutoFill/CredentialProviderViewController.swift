import AuthenticationServices
import SwiftUI

/// Entry point of the AutoFill credential provider extension, the piece
/// that lets Pass replace Apple Passwords: the system calls one of the
/// `prepare…`/`provide…` methods below, the extension unlocks the vault
/// (Face ID/Touch ID through the keychain item the app shares, or the
/// master password) and hands back a login or a verification code.
///
/// The vault is read from the App Group container (`SharedConfig`), never
/// from wherever else it might live — the extension is sandboxed.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var model = AutoFillModel(
        vaultPath: SharedConfig.vaultPath ?? SharedConfig.defaultVaultPath,
        complete: { [weak self] result in self?.complete(with: result) },
        cancel: { [weak self] in self?.cancel() }
    )

    #if os(macOS)
    override func loadView() {
        view = NSHostingView(rootView: AutoFillView(model: model))
        preferredContentSize = NSSize(width: 420, height: 520)
    }
    #else
    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: AutoFillView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }
    #endif

    // MARK: - Requests from the system

    /// The user asked for the full list ("Passwords…" / the key icon).
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.start(.chooseLogin(serviceIdentifiers))
    }

    /// The user tapped a one-time-code field and asked for the list.
    @available(iOS 18.0, macOS 15.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.start(.chooseOneTimeCode(serviceIdentifiers))
    }

    /// The user picked one of our suggestions. Reading the password needs
    /// the master password, which is only reachable through Face ID/Touch ID
    /// — so always ask the system to show our UI instead.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: Self.error(.userInteractionRequired))
    }

    /// Shown after `provideCredentialWithoutUserInteraction` asked for UI:
    /// unlock, then fill the suggestion the user already picked.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        var wantsOneTimeCode = false
        if #available(iOS 18.0, macOS 15.0, *) {
            wantsOneTimeCode = credentialRequest.type == .oneTimeCode
        }
        model.start(.provide(entryID: credentialRequest.credentialIdentity.recordIdentifier, oneTimeCode: wantsOneTimeCode))
    }

    // MARK: - Answering

    private func complete(with result: AutoFillModel.Result) {
        switch result {
        case let .login(user, password):
            extensionContext.completeRequest(
                withSelectedCredential: ASPasswordCredential(user: user, password: password),
                completionHandler: nil
            )
        case let .oneTimeCode(code):
            if #available(iOS 18.0, macOS 15.0, *) {
                extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
            } else {
                cancel()
            }
        }
    }

    private func cancel() {
        extensionContext.cancelRequest(withError: Self.error(.userCanceled))
    }

    private static func error(_ code: ASExtensionError.Code) -> NSError {
        NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
    }
}
