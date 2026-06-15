import Foundation

extension Data {
    var fenHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

extension String {
    var fenUTF8HexString: String {
        Data(utf8).fenHexString
    }
}
