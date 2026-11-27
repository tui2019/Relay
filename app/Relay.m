#import <Cocoa/Cocoa.h>
#import <FileProvider/FileProvider.h>
#import <UserNotifications/UserNotifications.h>
#import <WebKit/WebKit.h>

static NSString *const kFileProviderDomainId = @"relay-android";
static NSString *const kNotifCategoryDefault = @"RELAY_NOTIF";
static NSString *const kNotifCategoryReply   = @"RELAY_NOTIF_REPLY";
static NSString *const kActionDismiss        = @"ACTION_DISMISS";
static NSString *const kActionReply          = @"ACTION_REPLY";

static NSString *fallbackMountPointPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Android Phone"];
}

@interface RelayApp : NSObject <NSApplicationDelegate, UNUserNotificationCenterDelegate, WKNavigationDelegate, NSWindowDelegate>
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSMenu *menu;
@property (nonatomic, strong) NSTask *daemonTask;
@property (nonatomic, strong) NSFileHandle *daemonStdin;
@property (nonatomic, strong) NSMutableData *stdoutBuffer;

// Native Google Sign-In WKWebView window (non-persistent store, native macOS Safari UA)
@property (nonatomic, strong) NSWindow *loginWindow;
@property (nonatomic, strong) WKWebView *loginWebView;
@property (nonatomic, strong) NSTimer *loginCookieTimer;
@property (nonatomic, assign) BOOL loginFinished;

// FileProvider & fallback mount state (NEVER queried synchronously on main thread!)
@property (nonatomic, strong) NSFileProviderDomain *fpDomain;
@property (nonatomic, assign) BOOL fileProviderActive;
@property (nonatomic, assign) BOOL fallbackMounted;
@property (nonatomic, assign) BOOL fallbackMountInProgress;

// Live status state
@property (nonatomic, copy) NSString *deviceName;
@property (nonatomic, assign) BOOL bleNearby;
@property (nonatomic, assign) BOOL deviceLinkConnected;
@property (nonatomic, strong) NSNumber *rssi;
@property (nonatomic, strong) NSNumber *batteryPercent;
@property (nonatomic, copy) NSString *cellProvider;
@property (nonatomic, assign) BOOL hotspotAvailable;
@property (nonatomic, assign) BOOL hotspotActive;
@property (nonatomic, copy) NSString *hotspotSsid;
@property (nonatomic, assign) BOOL wifiShareAvailable;
@property (nonatomic, copy) NSString *wifiShareSsid;
@property (nonatomic, copy) NSString *webdavUrl;
@property (nonatomic, copy) NSString *busyAction;
@property (nonatomic, assign) BOOL signedIn;
@property (nonatomic, copy) NSString *accountEmail;
@property (nonatomic, assign) NSInteger credentialCount;
@property (nonatomic, strong) NSNumber *lastSyncUnix;
@property (nonatomic, strong) NSMutableSet<NSString *> *seenNotificationKeys;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *notifIdToKey;
@end

@implementation RelayApp

- (instancetype)init {
    self = [super init];
    if (self) {
        _deviceName = @"Android Phone";
        _webdavUrl = @"http://127.0.0.1:48921/";
        _stdoutBuffer = [NSMutableData data];
        _seenNotificationKeys = [NSMutableSet set];
        _notifIdToKey = [NSMutableDictionary dictionary];
        _fpDomain = [[NSFileProviderDomain alloc] initWithIdentifier:kFileProviderDomainId
                                                         displayName:_deviceName];
        if (@available(macOS 13.0, *)) {
            _fpDomain.supportsSyncingTrash = NO;
        }
    }
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    [self setupNotificationCenter];
    [self setupStatusItem];
    [self registerFileProviderDomain];
    [self startDaemon];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    (void)notification;
    if (self.fallbackMounted) {
        [self unmountFallbackVolumeSync];
    }
    if (self.daemonTask && self.daemonTask.isRunning) {
        [self.daemonTask terminate];
    }
}

#pragma mark - Native macOS FileProvider (Finder Locations Sidebar, same as Google Drive)

- (void)registerFileProviderDomain {
    __weak typeof(self) weakSelf = self;
    BOOL resetDomain = [[[NSProcessInfo processInfo] arguments] containsObject:@"--reset-domain"];
    void (^doAdd)(void) = ^{
        [NSFileProviderManager addDomain:self.fpDomain
                       completionHandler:^(NSError * _Nullable error) {
                           dispatch_async(dispatch_get_main_queue(), ^{
                               __strong typeof(weakSelf) strongSelf = weakSelf;
                               if (!strongSelf) return;
                               if (error == nil) {
                                   strongSelf.fileProviderActive = YES;
                                   NSLog(@"Relay FileProvider domain registered successfully!");
                               } else {
                                   strongSelf.fileProviderActive = NO;
                                   NSLog(@"Relay FileProvider addDomain error (falling back to WebDAV): %@", error);
                                   if (strongSelf.deviceLinkConnected) {
                                       [strongSelf autoMountFallbackIfNeeded];
                                   }
                               }
                               [strongSelf rebuildMenu];
                           });
                       }];
    };
    if (resetDomain) {
        [NSFileProviderManager removeDomain:self.fpDomain
                          completionHandler:^(NSError * _Nullable err) {
                              (void)err;
                              dispatch_async(dispatch_get_main_queue(), doAdd);
                          }];
    } else {
        doAdd();
    }
}

- (void)signalFileProviderRoot {
    if (!self.fileProviderActive) return;
    NSFileProviderManager *mgr = [NSFileProviderManager managerForDomain:self.fpDomain];
    [mgr signalEnumeratorForContainerItemIdentifier:NSFileProviderRootContainerItemIdentifier
                                  completionHandler:^(NSError * _Nullable error) {
                                      if (error) {
                                          NSLog(@"Relay FileProvider signalEnumerator error: %@", error);
                                      }
                                  }];
}

- (void)autoMountFallbackIfNeeded {
    if (self.fileProviderActive || self.fallbackMounted || self.fallbackMountInProgress || !self.deviceLinkConnected) {
        return;
    }
    self.fallbackMountInProgress = YES;
    NSString *mp = fallbackMountPointPath();
    NSString *urlStr = self.webdavUrl ?: @"http://127.0.0.1:48921/";
    NSString *volName = self.deviceName.length > 0 ? self.deviceName : @"Android Phone";
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:mp withIntermediateDirectories:YES attributes:nil error:nil];

        NSTask *mountTask = [[NSTask alloc] init];
        mountTask.executableURL = [NSURL fileURLWithPath:@"/sbin/mount_webdav"];
        mountTask.arguments = @[@"-S", @"-v", volName, urlStr, mp];
        [mountTask launchAndReturnError:nil];
        [mountTask waitUntilExit];
        BOOL ok = (mountTask.terminationStatus == 0);
        if (!ok) {
            [fm removeItemAtPath:mp error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            strongSelf.fallbackMountInProgress = NO;
            strongSelf.fallbackMounted = ok;
            [strongSelf rebuildMenu];
        });
    });
}

- (void)unmountFallbackVolumeSync {
    NSString *mp = fallbackMountPointPath();
    NSTask *umount = [[NSTask alloc] init];
    umount.executableURL = [NSURL fileURLWithPath:@"/sbin/umount"];
    umount.arguments = @[@"-f", mp];
    [umount launchAndReturnError:nil];
    [umount waitUntilExit];
    [[NSFileManager defaultManager] removeItemAtPath:mp error:nil];
    self.fallbackMounted = NO;
}

#pragma mark - Native macOS Notification Center (always on, delivered straight to system panel)

- (void)setupNotificationCenter {
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    center.delegate = self;

    UNNotificationAction *dismissAction =
        [UNNotificationAction actionWithIdentifier:kActionDismiss
                                             title:@"Dismiss on Phone"
                                           options:UNNotificationActionOptionNone];

    UNTextInputNotificationAction *replyAction =
        [UNTextInputNotificationAction actionWithIdentifier:kActionReply
                                                      title:@"Reply"
                                                    options:UNNotificationActionOptionNone
                                       textInputButtonTitle:@"Send"
                                       textInputPlaceholder:@"Reply..."];

    UNNotificationCategory *defaultCat =
        [UNNotificationCategory categoryWithIdentifier:kNotifCategoryDefault
                                               actions:@[dismissAction]
                                     intentIdentifiers:@[]
                                               options:UNNotificationCategoryOptionCustomDismissAction];

    UNNotificationCategory *replyCat =
        [UNNotificationCategory categoryWithIdentifier:kNotifCategoryReply
                                               actions:@[replyAction, dismissAction]
                                     intentIdentifiers:@[]
                                               options:UNNotificationCategoryOptionCustomDismissAction];

    [center setNotificationCategories:[NSSet setWithObjects:defaultCat, replyCat, nil]];
    [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound | UNAuthorizationOptionBadge)
                          completionHandler:^(BOOL granted, NSError * _Nullable error) {
                              (void)granted;
                              if (error) {
                                  NSLog(@"Relay UNUserNotificationCenter auth error: %@", error);
                              }
                          }];
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
    (void)center;
    BOOL isInitial = [notification.request.content.userInfo[@"is_initial"] boolValue];
    if (isInitial) {
        // Place existing unread phone notifications quietly in macOS Notification Center panel
        completionHandler(UNNotificationPresentationOptionList);
    } else {
        completionHandler(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionSound | UNNotificationPresentationOptionList);
    }
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
didReceiveNotificationResponse:(UNNotificationResponse *)response
         withCompletionHandler:(void (^)(void))completionHandler {
    (void)center;
    NSDictionary *userInfo = response.notification.request.content.userInfo;
    NSString *key = userInfo[@"android_key"];
    NSNumber *replyIdx = userInfo[@"reply_action_index"] ?: @(0);
    if (key.length > 0) {
        if ([response.actionIdentifier isEqualToString:kActionReply] &&
            [response isKindOfClass:[UNTextInputNotificationResponse class]]) {
            NSString *replyText = ((UNTextInputNotificationResponse *)response).userText;
            if (replyText.length > 0) {
                [self sendDaemonCommand:@{
                    @"cmd": @"reply_notification",
                    @"key": key,
                    @"action_index": replyIdx,
                    @"text": replyText
                }];
            }
        } else if ([response.actionIdentifier isEqualToString:kActionDismiss] ||
                   [response.actionIdentifier isEqualToString:UNNotificationDismissActionIdentifier]) {
            [self sendDaemonCommand:@{
                @"cmd": @"dismiss_notification",
                @"key": key
            }];
        }
    }
    completionHandler();
}

- (void)postNativeNotification:(NSDictionary *)ev {
    NSString *key = ev[@"key"] ?: @"";
    NSString *appName = ev[@"app_name"] ?: self.deviceName;
    NSString *title = ev[@"title"] ?: @"";
    NSString *text = ev[@"text"] ?: @"";
    BOOL canReply = [ev[@"can_reply"] boolValue];
    NSNumber *replyIdx = ev[@"reply_action_index"] ?: @(0);
    BOOL isInitial = [ev[@"is_initial"] boolValue];

    // Deduplicate initial unread notifications across reconnects
    if (isInitial && key.length > 0 && [self.seenNotificationKeys containsObject:key]) {
        return;
    }
    if (key.length > 0) {
        [self.seenNotificationKeys addObject:key];
    }

    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = title.length > 0 ? title : appName;
    if (appName.length > 0 && title.length > 0 && ![appName isEqualToString:title]) {
        content.subtitle = appName;
    }
    content.body = text;
    if (!isInitial) {
        content.sound = [UNNotificationSound defaultSound];
    }
    content.categoryIdentifier = canReply ? kNotifCategoryReply : kNotifCategoryDefault;
    content.userInfo = @{
        @"android_key": key,
        @"reply_action_index": replyIdx,
        @"is_initial": @(isInitial)
    };

    NSString *reqId = key.length > 0 ? [NSString stringWithFormat:@"relay-%lu", (unsigned long)key.hash] : [[NSUUID UUID] UUIDString];
    if (key.length > 0) {
        self.notifIdToKey[key] = reqId;
    }
    UNNotificationRequest *req = [UNNotificationRequest requestWithIdentifier:reqId content:content trigger:nil];
    [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:req withCompletionHandler:nil];
}

- (void)postLocalBanner:(NSString *)title body:(NSString *)body {
    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = title;
    content.body = body;
    content.sound = [UNNotificationSound defaultSound];
    UNNotificationRequest *req = [UNNotificationRequest requestWithIdentifier:[[NSUUID UUID] UUIDString]
                                                                      content:content
                                                                      trigger:nil];
    [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:req withCompletionHandler:nil];
}

#pragma mark - Status Bar Item & Dynamic Menu

- (void)setupStatusItem {
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    self.menu = [[NSMenu alloc] initWithTitle:@"Relay"];
    self.statusItem.menu = self.menu;
    [self updateStatusIcon];
    [self rebuildMenu];
}

- (void)updateStatusIcon {
    NSStatusBarButton *btn = self.statusItem.button;
    if (!btn) return;

    NSString *symName = (self.deviceLinkConnected || self.hotspotActive || self.bleNearby) ? @"iphone" : @"iphone.slash";
    NSImage *img = [NSImage imageWithSystemSymbolName:symName accessibilityDescription:self.deviceName];
    [img setTemplate:YES];
    btn.image = img;
    btn.imagePosition = NSImageLeft;

    if (self.batteryPercent != nil) {
        btn.title = [NSString stringWithFormat:@" %d%%", self.batteryPercent.intValue];
    } else {
        btn.title = @"";
    }
}

- (void)rebuildMenu {
    [self.menu removeAllItems];

    // Header (no battery % inside menu — shown only in the status bar directly)
    NSString *headerTitle = nil;
    if (!self.signedIn && self.credentialCount == 0) {
        NSString *sub = self.busyAction.length > 0 ? self.busyAction : @"Sign in with Google to connect";
        headerTitle = [NSString stringWithFormat:@"Relay — %@", sub];
    } else {
        NSString *connText = @"Searching for phone...";
        if (self.busyAction.length > 0) {
            connText = self.busyAction;
        } else if (self.hotspotActive) {
            connText = @"Connected (Instant Hotspot)";
        } else if (self.deviceLinkConnected) {
            connText = @"Connected (Wi-Fi LAN)";
        } else if (self.bleNearby) {
            connText = @"Nearby (Bluetooth LE)";
        }
        headerTitle = [NSString stringWithFormat:@"%@ — %@", self.deviceName, connText];
    }
    NSMenuItem *titleItem = [[NSMenuItem alloc] initWithTitle:headerTitle
                                                       action:nil
                                                keyEquivalent:@""];
    titleItem.enabled = NO;
    [self.menu addItem:titleItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    if (!self.signedIn && self.credentialCount == 0) {
        NSMenuItem *signInItem = [[NSMenuItem alloc] initWithTitle:@"Sign in with Google..."
                                                            action:@selector(onGoogleSignIn:)
                                                     keyEquivalent:@""];
        signInItem.target = self;
        signInItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:signInItem];

        [self.menu addItem:[NSMenuItem separatorItem]];

        NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit"
                                                          action:@selector(onQuit:)
                                                   keyEquivalent:@"q"];
        quitItem.target = self;
        [self.menu addItem:quitItem];
        return;
    }

    // Dynamic Hotspot & Phone Wi-Fi Buttons
    BOOL addedNetworkBtn = NO;
    if (self.hotspotActive) {
        NSMenuItem *hsItem = [[NSMenuItem alloc] initWithTitle:@"Stop Instant Hotspot"
                                                        action:@selector(onStopHotspot:)
                                                 keyEquivalent:@""];
        hsItem.target = self;
        hsItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:hsItem];
        addedNetworkBtn = YES;
    } else if (self.hotspotAvailable) {
        NSMenuItem *hsItem = [[NSMenuItem alloc] initWithTitle:@"Start Instant Hotspot"
                                                        action:@selector(onStartHotspot:)
                                                 keyEquivalent:@""];
        hsItem.target = self;
        hsItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:hsItem];
        addedNetworkBtn = YES;
    }
    if (self.wifiShareAvailable && self.wifiShareSsid.length > 0) {
        NSString *label = [NSString stringWithFormat:@"Connect to Phone's Wi-Fi (%@)", self.wifiShareSsid];
        NSMenuItem *wfItem = [[NSMenuItem alloc] initWithTitle:label
                                                        action:@selector(onConnectPhoneWifi:)
                                                 keyEquivalent:@""];
        wfItem.target = self;
        wfItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:wfItem];
        addedNetworkBtn = YES;
    }
    if (addedNetworkBtn) {
        [self.menu addItem:[NSMenuItem separatorItem]];
    }

    // Finder Files Section
    NSString *finderTitle = [NSString stringWithFormat:@"Open %@ in Finder", self.deviceName];
    NSMenuItem *filesItem = [[NSMenuItem alloc] initWithTitle:finderTitle
                                                       action:@selector(onOpenFinderFiles:)
                                                keyEquivalent:@"f"];
    filesItem.target = self;
    filesItem.enabled = self.fileProviderActive || self.fallbackMounted || self.deviceLinkConnected;
    [self.menu addItem:filesItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    // Google Account Section
    if (self.signedIn) {
        NSString *acctTitle = self.accountEmail.length > 0
            ? [NSString stringWithFormat:@"Google Account: %@", self.accountEmail]
            : @"Google Account: Signed in";
        NSMenuItem *acctItem = [[NSMenuItem alloc] initWithTitle:acctTitle
                                                          action:nil
                                                   keyEquivalent:@""];
        acctItem.enabled = NO;
        [self.menu addItem:acctItem];

        NSMenuItem *syncItem = [[NSMenuItem alloc] initWithTitle:@"Sync Credentials Now"
                                                          action:@selector(onSyncCredentials:)
                                                   keyEquivalent:@""];
        syncItem.target = self;
        syncItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:syncItem];

        NSMenuItem *signOutItem = [[NSMenuItem alloc] initWithTitle:@"Sign Out"
                                                             action:@selector(onGoogleSignOut:)
                                                      keyEquivalent:@""];
        signOutItem.target = self;
        signOutItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:signOutItem];
    } else {
        NSMenuItem *signInItem = [[NSMenuItem alloc] initWithTitle:@"Sign in with Google..."
                                                            action:@selector(onGoogleSignIn:)
                                                     keyEquivalent:@""];
        signInItem.target = self;
        signInItem.enabled = (self.busyAction.length == 0);
        [self.menu addItem:signInItem];
    }

    [self.menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *refreshItem = [[NSMenuItem alloc] initWithTitle:@"Refresh Status"
                                                         action:@selector(onRefreshStatus:)
                                                  keyEquivalent:@"r"];
    refreshItem.target = self;
    refreshItem.enabled = (self.busyAction.length == 0);
    [self.menu addItem:refreshItem];

    NSMenuItem *reconnectItem = [[NSMenuItem alloc] initWithTitle:@"Reconnect"
                                                           action:@selector(onReconnect:)
                                                    keyEquivalent:@""];
    reconnectItem.target = self;
    [self.menu addItem:reconnectItem];

    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit"
                                                      action:@selector(onQuit:)
                                               keyEquivalent:@"q"];
    quitItem.target = self;
    [self.menu addItem:quitItem];
}

#pragma mark - Native Google Sign-In Window (WKWebView)

- (void)showGoogleSignInWindow {
    if (self.loginWindow) {
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        [self.loginWindow makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        return;
    }

    self.loginFinished = NO;
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    NSRect frame = NSMakeRect(0, 0, 480, 680);
    NSWindow *win = [[NSWindow alloc]
        initWithContentRect:frame
                  styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable)
                    backing:NSBackingStoreBuffered
                      defer:NO];
    win.title = @"Sign in with Google — Relay";
    win.delegate = self;
    win.releasedWhenClosed = NO;
    [win center];

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    cfg.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];

    WKWebView *wv = [[WKWebView alloc] initWithFrame:frame configuration:cfg];
    wv.navigationDelegate = self;
    wv.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    // Match native macOS WebKit/Safari UA so Google's JS integrity check passes cleanly
    // and registers this login session as a Mac instead of spoofing an Android phone.
    wv.customUserAgent =
        @"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15";

    win.contentView = wv;
    self.loginWindow = win;
    self.loginWebView = wv;

    [win makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];

    NSURL *url = [NSURL URLWithString:@"https://accounts.google.com/EmbeddedSetup"];
    [wv loadRequest:[NSURLRequest requestWithURL:url]];

    self.loginCookieTimer = [NSTimer scheduledTimerWithTimeInterval:0.5
                                                             target:self
                                                           selector:@selector(checkLoginCookies)
                                                           userInfo:nil
                                                            repeats:YES];
}

- (void)closeGoogleSignInWindow {
    [self.loginCookieTimer invalidate];
    self.loginCookieTimer = nil;
    self.loginWebView.navigationDelegate = nil;
    self.loginWebView = nil;
    if (self.loginWindow) {
        self.loginWindow.delegate = nil;
        [self.loginWindow orderOut:nil];
        self.loginWindow = nil;
    }
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    (void)webView;
    (void)navigation;
    [self checkLoginCookies];
}

- (void)checkLoginCookies {
    if (self.loginFinished || !self.loginWebView) return;
    WKHTTPCookieStore *store = self.loginWebView.configuration.websiteDataStore.httpCookieStore;
    __weak typeof(self) weakSelf = self;
    [store getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf || strongSelf.loginFinished) return;
            for (NSHTTPCookie *c in cookies) {
                if ([c.name isEqualToString:@"oauth_token"] && c.value.length > 10) {
                    strongSelf.loginFinished = YES;
                    NSString *token = [c.value copy];
                    [strongSelf closeGoogleSignInWindow];
                    [strongSelf sendDaemonCommand:@{
                        @"cmd": @"google_login",
                        @"oauth_token": token
                    }];
                    return;
                }
            }
        });
    }];
}

- (void)windowWillClose:(NSNotification *)notification {
    if (notification.object == self.loginWindow) {
        [self closeGoogleSignInWindow];
    }
}

#pragma mark - Menu Actions

- (void)onGoogleSignIn:(id)sender {
    (void)sender;
    [self showGoogleSignInWindow];
}

- (void)onSyncCredentials:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"sync_credentials"}];
}

- (void)onGoogleSignOut:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"google_sign_out"}];
}

- (void)onStartHotspot:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"start_hotspot"}];
}

- (void)onStopHotspot:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"stop_hotspot"}];
}

- (void)onConnectPhoneWifi:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"connect_phone_wifi"}];
}

- (void)onRefreshStatus:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"probe_tether"}];
}

- (void)onReconnect:(id)sender {
    (void)sender;
    [self sendDaemonCommand:@{@"cmd": @"reconnect"}];
}

- (void)onOpenFinderFiles:(id)sender {
    (void)sender;
    if (self.fileProviderActive) {
        NSFileProviderManager *mgr = [NSFileProviderManager managerForDomain:self.fpDomain];
        [mgr getUserVisibleURLForItemIdentifier:NSFileProviderRootContainerItemIdentifier
                              completionHandler:^(NSURL * _Nullable userVisibleFile, NSError * _Nullable error) {
                                  dispatch_async(dispatch_get_main_queue(), ^{
                                      if (userVisibleFile && !error) {
                                          [[NSWorkspace sharedWorkspace] openURL:userVisibleFile];
                                      } else {
                                          NSLog(@"Relay getUserVisibleURL error: %@", error);
                                      }
                                  });
                              }];
        return;
    }
    if (self.fallbackMounted) {
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:fallbackMountPointPath()]];
    } else if (self.deviceLinkConnected) {
        [self autoMountFallbackIfNeeded];
    }
}

- (void)onQuit:(id)sender {
    (void)sender;
    [NSApp terminate:nil];
}

#pragma mark - Rust Daemon Bridge

- (void)startDaemon {
    NSString *resDir = [[NSBundle mainBundle] resourcePath];
    NSString *daemonPath = [resDir stringByAppendingPathComponent:@"relay-daemon"];
    NSString *macBridgePath = [resDir stringByAppendingPathComponent:@"RelayBridge"];

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm isExecutableFileAtPath:daemonPath]) {
        daemonPath = @"./core/target/release/relay-daemon";
    }
    if (![fm isExecutableFileAtPath:macBridgePath]) {
        macBridgePath = @"./bridge/RelayBridge";
    }

    NSString *appSupport = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dataDir = [appSupport stringByAppendingPathComponent:@"Relay"];

    NSArray<NSString *> *daemonArgs = @[
        @"--data-dir", dataDir,
        @"--mac-bridge", macBridgePath,
        @"--webdav-port", @"48921"
    ];

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:daemonPath];
    task.arguments = daemonArgs;
    NSPipe *inPipe = [NSPipe pipe];
    NSPipe *outPipe = [NSPipe pipe];
    task.standardInput = inPipe;
    task.standardOutput = outPipe;
    task.standardError = [NSFileHandle fileHandleWithStandardError];

    self.daemonTask = task;
    self.daemonStdin = inPipe.fileHandleForWriting;

    __weak typeof(self) weakSelf = self;
    outPipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *chunk = [handle availableData];
        if (chunk.length == 0) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf handleDaemonStdoutData:chunk];
        });
    };

    NSError *err = nil;
    if (![task launchAndReturnError:&err]) {
        NSLog(@"Relay failed to launch daemon %@: %@", daemonPath, err);
    }
}

- (void)sendDaemonCommand:(NSDictionary *)cmd {
    if (!self.daemonStdin) return;
    NSData *json = [NSJSONSerialization dataWithJSONObject:cmd options:0 error:nil];
    if (!json) return;
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @try {
            [self.daemonStdin writeData:line];
        } @catch (NSException *ex) {
            NSLog(@"Relay writeData error: %@", ex);
        }
    });
}

- (void)handleDaemonStdoutData:(NSData *)chunk {
    [self.stdoutBuffer appendData:chunk];
    while (YES) {
        NSRange nl = [self.stdoutBuffer rangeOfData:[NSData dataWithBytes:"\n" length:1]
                                            options:0
                                              range:NSMakeRange(0, self.stdoutBuffer.length)];
        if (nl.location == NSNotFound) break;
        NSData *lineData = [self.stdoutBuffer subdataWithRange:NSMakeRange(0, nl.location)];
        [self.stdoutBuffer replaceBytesInRange:NSMakeRange(0, nl.location + 1) withBytes:NULL length:0];
        if (lineData.length == 0) continue;

        NSDictionary *ev = [NSJSONSerialization JSONObjectWithData:lineData options:0 error:nil];
        if (![ev isKindOfClass:[NSDictionary class]]) continue;
        NSString *etype = ev[@"event"];
        if ([etype isEqualToString:@"status"]) {
            BOOL wasConnected = self.deviceLinkConnected;
            if ([ev[@"device_name"] isKindOfClass:[NSString class]]) {
                self.deviceName = ev[@"device_name"];
            }
            self.bleNearby = [ev[@"ble_nearby"] boolValue];
            self.deviceLinkConnected = [ev[@"devicelink_connected"] boolValue];
            self.rssi = [ev[@"rssi"] isKindOfClass:[NSNumber class]] ? ev[@"rssi"] : nil;
            self.batteryPercent = [ev[@"battery_percent"] isKindOfClass:[NSNumber class]] ? ev[@"battery_percent"] : nil;
            self.cellProvider = [ev[@"cell_provider"] isKindOfClass:[NSString class]] ? ev[@"cell_provider"] : nil;
            self.hotspotAvailable = [ev[@"hotspot_available"] boolValue];
            self.hotspotActive = [ev[@"hotspot_active"] boolValue];
            self.hotspotSsid = [ev[@"hotspot_ssid"] isKindOfClass:[NSString class]] ? ev[@"hotspot_ssid"] : nil;
            self.wifiShareAvailable = [ev[@"wifi_share_available"] boolValue];
            self.wifiShareSsid = [ev[@"wifi_share_ssid"] isKindOfClass:[NSString class]] ? ev[@"wifi_share_ssid"] : nil;
            if ([ev[@"webdav_url"] isKindOfClass:[NSString class]]) {
                self.webdavUrl = ev[@"webdav_url"];
            }
            self.busyAction = [ev[@"busy_action"] isKindOfClass:[NSString class]] ? ev[@"busy_action"] : nil;
            self.signedIn = [ev[@"signed_in"] boolValue];
            self.accountEmail = [ev[@"account_email"] isKindOfClass:[NSString class]] ? ev[@"account_email"] : nil;
            self.credentialCount = [ev[@"credential_count"] isKindOfClass:[NSNumber class]] ? [ev[@"credential_count"] integerValue] : 0;
            self.lastSyncUnix = [ev[@"last_sync_unix"] isKindOfClass:[NSNumber class]] ? ev[@"last_sync_unix"] : nil;
            [self updateStatusIcon];
            [self rebuildMenu];

            // Auto-refresh FileProvider or auto-mount WebDAV fallback when DeviceLink connects!
            if (self.deviceLinkConnected && !wasConnected) {
                if (self.fileProviderActive) {
                    [self signalFileProviderRoot];
                } else {
                    [self autoMountFallbackIfNeeded];
                }
            }
        } else if ([etype isEqualToString:@"notification_posted"]) {
            [self postNativeNotification:ev];
        } else if ([etype isEqualToString:@"notification_removed"]) {
            NSArray<NSString *> *keys = ev[@"keys"];
            if ([keys isKindOfClass:[NSArray class]]) {
                NSMutableArray<NSString *> *idsToRemove = [NSMutableArray array];
                for (NSString *k in keys) {
                    [self.seenNotificationKeys removeObject:k];
                    NSString *reqId = self.notifIdToKey[k];
                    if (reqId) {
                        [idsToRemove addObject:reqId];
                        [self.notifIdToKey removeObjectForKey:k];
                    }
                }
                if (idsToRemove.count > 0) {
                    [[UNUserNotificationCenter currentNotificationCenter] removeDeliveredNotificationsWithIdentifiers:idsToRemove];
                }
            }
        } else if ([etype isEqualToString:@"action_result"]) {
            BOOL ok = [ev[@"ok"] boolValue];
            NSString *msg = ev[@"message"] ?: @"";
            [self postLocalBanner:(ok ? self.deviceName : @"Relay Error") body:msg];
        } else if ([etype isEqualToString:@"log"]) {
            NSLog(@"[relay-daemon] %@", ev[@"message"]);
        }
    }
}

@end

int main(void) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        RelayApp *delegate = [[RelayApp alloc] init];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
