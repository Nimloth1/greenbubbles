// Derived from wcdb-key-tool (https://github.com/TANGandXUE/wcdb-key-tool), MIT license.

import Foundation

public enum LLDBTargetArchitecture: String, Sendable {
  case arm64
  // swift-format-ignore: AlwaysUseLowerCamelCase
  case x86_64

  public static var current: LLDBTargetArchitecture {
    #if arch(arm64)
      return .arm64
    #else
      return .x86_64
    #endif
  }

  /// Register holding `CCKeyDerivationPBKDF`'s `password` argument.
  public var passwordRegister: String {
    switch self {
    case .arm64: return "x1"
    case .x86_64: return "rsi"
    }
  }

  /// Register holding `CCKeyDerivationPBKDF`'s `passwordLen` argument.
  public var lengthRegister: String {
    switch self {
    case .arm64: return "x2"
    case .x86_64: return "rdx"
    }
  }

  /// Breakpoint condition matching only SQLCipher 4's account-key derivation:
  /// `kCCPBKDF2` (2), a 32-byte password, a 16-byte salt and
  /// `kCCPRFHmacAlgSHA512` (5), plus 256,000 rounds where the argument is in a
  /// register. A length-only condition also stops on unrelated 32-byte
  /// derivations that WeChat 4.1.15 performs first (issue #20).
  public var breakpointCondition: String {
    switch self {
    case .arm64: return "$x0 == 2 && $x2 == 32 && $x4 == 16 && $x5 == 5 && $x6 == 256000"
    // `rounds` is the seventh argument and is passed on the stack.
    case .x86_64: return "$rdi == 2 && $rdx == 32 && $r8 == 16 && $r9 == 5"
    }
  }
}

/// Generates the lldb command script whose ordering was validated live against
/// the pinned WeChat build: attach, break on the system `CCKeyDerivationPBKDF`
/// symbol only for SQLCipher's PBKDF2-HMAC-SHA512 parameters, read the 32-byte
/// passphrase from the password register when the breakpoint hits, then detach
/// and quit.
public enum LLDBCaptureScript {
  public static func script(
    processID: pid_t,
    architecture: LLDBTargetArchitecture = .current
  ) -> String {
    """
    settings set target.preload-symbols false
    process attach -p \(processID)
    breakpoint set -n CCKeyDerivationPBKDF -c '\(architecture.breakpointCondition)'
    breakpoint command add 1
    memory read --size 1 --count 32 --format x $\(architecture.passwordRegister)
    detach
    quit
    DONE
    process continue

    """
  }
}
