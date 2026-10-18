#if os(iOS)
import BackgroundTasks

/// Wakes the app now and then to fetch, answer handshakes and send cover. There is no push by
/// default, so this is how messages arrive while the app is closed.
enum Background {
    static let identifier = "org.janusknot.janus.refresh"

    /// Must run before the app finishes launching.
    static func register(_ model: AppModel) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            schedule()
            let work = Task { @MainActor in await model.wake() }
            task.expirationHandler = { work.cancel() }
            Task {
                await work.value
                task.setTaskCompleted(success: true)
            }
        }
    }

    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }
}
#endif
