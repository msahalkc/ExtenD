import SwiftUI

@main
struct ExtenDPadApp: App {
    var body: some Scene {
        WindowGroup {
            DisplayView()
                .ignoresSafeArea()
                .statusBarHidden()
                .persistentSystemOverlays(.hidden)
        }
    }
}

struct DisplayView: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> DisplayViewController { DisplayViewController() }
    func updateUIViewController(_ vc: DisplayViewController, context: Context) {}
}
