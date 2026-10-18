import XCTest

/// Chats with a person on another device through the development mailbox. Skipped unless
/// `JANUS_PEER` names a directory (pass `TEST_RUNNER_JANUS_PEER` to `xcodebuild test`): this
/// phone invites and writes the 6 words to `words` there, waits for the 3 safety words the other
/// device shows in `safety`, sends a message, and writes the answer it gets to `reply`.
final class PeerChatUITests: XCTestCase {
    private let mine = "hola desde el iPhone"

    func testChatWithAnotherDevice() throws {
        guard let peer = ProcessInfo.processInfo.environment["JANUS_PEER"] else {
            throw XCTSkip("set TEST_RUNNER_JANUS_PEER to chat with another device")
        }
        let dir = URL(fileURLWithPath: peer)
        let app = XCUIApplication()
        app.launch()
        unlock(app)

        app.buttons["New"].tap()
        app.buttons["Create an invitation"].tap()
        app.buttons["Create the invitation"].tap()
        let words = app.staticTexts.matching(NSPredicate(format: "label MATCHES %@", "[a-z]+( [a-z]+){5}"))
            .firstMatch
        XCTAssert(words.waitForExistence(timeout: 30), "no invitation words")
        try words.label.write(to: dir.appendingPathComponent("words"), atomically: true, encoding: .utf8)

        let typed = app.textFields["3 safety words"]
        XCTAssert(typed.waitForExistence(timeout: 600), "nobody answered the invitation")
        let safety = try wait(for: dir.appendingPathComponent("safety"), timeout: 600)
        typed.tap()
        typed.typeText(safety)
        let name = app.textFields["Name for this contact"]
        name.tap()
        name.typeText("android")
        app.buttons["Check the words"].tap()

        let contact = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'android'")).firstMatch
        XCTAssert(contact.waitForExistence(timeout: 15), "the safety words were rejected")
        contact.tap()
        XCTAssert(app.buttons["Send"].waitForExistence(timeout: 15), "no chat")
        let field = app.textViews["Message"].exists ? app.textViews["Message"] : app.textFields["Message"]
        field.tap()
        field.typeText(mine)
        app.buttons["Send"].tap()
        XCTAssert(app.staticTexts[mine].waitForExistence(timeout: 15), "the message was not sent")

        let before = Set(app.staticTexts.allElementsBoundByIndex.map(\.label))
        let deadline = Date().addingTimeInterval(600)
        while Date() < deadline {
            if let reply = app.staticTexts.allElementsBoundByIndex.map(\.label).first(where: { !before.contains($0) }) {
                try reply.write(to: dir.appendingPathComponent("reply"), atomically: true, encoding: .utf8)
                return
            }
            sleep(2)
        }
        XCTFail("no reply arrived")
    }

    /// Taps Unlock until the app lock lets go; the device's Face ID prompt is matched from outside.
    private func unlock(_ app: XCUIApplication) {
        let deadline = Date().addingTimeInterval(90)
        while Date() < deadline {
            if app.buttons["New"].exists && !app.buttons["Unlock"].exists { return }
            if app.buttons["Unlock"].exists { app.buttons["Unlock"].tap() }
            sleep(3)
        }
        XCTFail("the app stayed locked")
    }

    private func wait(for file: URL, timeout: TimeInterval) throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOf: file, encoding: .utf8),
               !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return text.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            sleep(2)
        }
        throw XCTSkip("no safety words in \(file.path)")
    }
}
