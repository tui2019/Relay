#import <AppKit/AppKit.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#import <Network/Network.h>

// Native macOS CoreBluetooth + Bonjour mDNS + CoreWLAN + Pasteboard bridge for `relay-daemon`.
//
// Verified macOS API capabilities:
// - CBCentralManager: CAN scan 0xFCF1 (Nearby Presence) & 0xFEF3 (Nearby Connections),
//   read CBAdvertisementDataServiceDataKey, connect to GATT, and open BLE L2CAP CoC channels.
// - CBPeripheralManager: CANNOT advertise raw BLE 0x16 Service Data (only LocalName + ServiceUUIDs).
// - Network.framework (nw_browser): Bidirectional Bonjour mDNS discovery on Wi-Fi LAN.
// - CoreWLAN (CWWiFiClient): Joins Instant Hotspot SSID + passphrase programmatically.

static void emitJSON(NSDictionary *dict) {
    NSError *err = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&err];
    if (!data || err) return;
    NSMutableData *line = [data mutableCopy];
    [line appendBytes:"\n" length:1];
    [[NSFileHandle fileHandleWithStandardOutput] writeData:line];
}

static NSString *hexStringFromData(NSData *data) {
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSMutableString *out = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [out appendFormat:@"%02x", bytes[i]];
    }
    return out;
}

@interface NearbyMacBridge : NSObject <CBCentralManagerDelegate, CBPeripheralDelegate>
@property (nonatomic, strong) CBCentralManager *central;
@property (nonatomic, strong) CBUUID *presenceUUID;
@property (nonatomic, strong) CBUUID *connectionsUUID;
@property (nonatomic, strong) CBUUID *weaveTxUUID;
@property (nonatomic, strong) CBUUID *weaveRxUUID;
@property (nonatomic, strong) NSMutableDictionary<NSUUID *, CBPeripheral *> *peripherals;
@property (nonatomic, strong) CBPeripheral *connectedPeripheral;
@property (nonatomic, strong) CBCharacteristic *weaveTxChar;
@property (nonatomic, strong) CBCharacteristic *weaveRxChar;
@property (nonatomic, strong) nw_browser_t mdnsBrowser;
@property (nonatomic, assign) BOOL scanAllServices;
@property (nonatomic, copy) NSString *autoConnectPeripheralUUID;
@property (nonatomic, assign) BOOL enableWeaveSession;
@property (nonatomic, assign) BOOL didStartConnect;
@end

static NSData *dataFromHexString(NSString *hex) {
    NSString *clean = [[hex stringByReplacingOccurrencesOfString:@" " withString:@""]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableData *data = [NSMutableData dataWithCapacity:clean.length / 2];
    char buf[3] = {0, 0, 0};
    for (NSUInteger i = 0; i + 1 < clean.length; i += 2) {
        buf[0] = (char)[clean characterAtIndex:i];
        buf[1] = (char)[clean characterAtIndex:i + 1];
        uint8_t b = (uint8_t)strtoul(buf, NULL, 16);
        [data appendBytes:&b length:1];
    }
    return data;
}

@implementation NearbyMacBridge

- (instancetype)init {
    self = [super init];
    if (self) {
        _presenceUUID = [CBUUID UUIDWithString:@"FCF1"];
        _connectionsUUID = [CBUUID UUIDWithString:@"FEF3"];
        _weaveTxUUID = [CBUUID UUIDWithString:@"00000100-0004-1000-8000-001A11000101"];
        _weaveRxUUID = [CBUUID UUIDWithString:@"00000100-0004-1000-8000-001A11000102"];
        _peripherals = [NSMutableDictionary dictionary];
    }
    return self;
}

- (void)start {
    dispatch_queue_t bleQueue = dispatch_queue_create("relay.ble", DISPATCH_QUEUE_SERIAL);
    self.central = [[CBCentralManager alloc] initWithDelegate:self queue:bleQueue];
    [self startMdnsBrowser];
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"bluetooth_state",
        @"state": @(central.state)
    });
    if (central.state != CBManagerStatePoweredOn) return;

    NSArray<CBUUID *> *filter = self.scanAllServices ? nil : @[self.presenceUUID, self.connectionsUUID];
    [central scanForPeripheralsWithServices:filter
                                    options:@{CBCentralManagerScanOptionAllowDuplicatesKey: @YES}];
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"ble_scanning_started",
        @"services": self.scanAllServices ? @[@"ALL"] : @[@"FCF1", @"FEF3"]
    });
}

- (void)centralManager:(CBCentralManager *)central
 didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary<NSString *, id> *)advertisementData
                  RSSI:(NSNumber *)RSSI {
    self.peripherals[peripheral.identifier] = peripheral;
    NSString *pid = peripheral.identifier.UUIDString;

    if (self.autoConnectPeripheralUUID && !self.didStartConnect &&
        [pid caseInsensitiveCompare:self.autoConnectPeripheralUUID] == NSOrderedSame) {
        self.didStartConnect = YES;
        emitJSON(@{
            @"source": @"macos_ble",
            @"event": @"ble_connecting",
            @"peripheral_id": pid
        });
        [central connectPeripheral:peripheral options:nil];
    }

    NSDictionary<CBUUID *, NSData *> *serviceData =
        advertisementData[CBAdvertisementDataServiceDataKey];
    if (!serviceData) return;

    NSData *presenceData = serviceData[self.presenceUUID];
    if (presenceData) {
        // Matches `relay-cli` stdin JSON command schema directly.
        emitJSON(@{
            @"cmd": @"ble_presence_adv",
            @"peripheral_id": pid,
            @"rssi": RSSI,
            @"service_data_hex": hexStringFromData(presenceData)
        });
    }

    NSData *connData = serviceData[self.connectionsUUID];
    if (connData) {
        emitJSON(@{
            @"source": @"macos_ble",
            @"event": @"nearby_connections_ble_adv",
            @"peripheral_id": pid,
            @"rssi": RSSI,
            @"service_data_hex": hexStringFromData(connData)
        });
    }
}

- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral {
    self.connectedPeripheral = peripheral;
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"ble_connected",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"max_write_with_response": @([peripheral maximumWriteValueLengthForType:CBCharacteristicWriteWithResponse])
    });
    peripheral.delegate = self;
    [peripheral discoverServices:self.enableWeaveSession ? @[self.connectionsUUID] : nil];
}

- (void)centralManager:(CBCentralManager *)central
didFailToConnectPeripheral:(CBPeripheral *)peripheral
                 error:(NSError *)error {
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"ble_connect_failed",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"error": error ? error.localizedDescription : @"unknown"
    });
}

- (void)centralManager:(CBCentralManager *)central
didDisconnectPeripheral:(CBPeripheral *)peripheral
                  error:(NSError *)error {
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"ble_disconnected",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"error": error ? error.localizedDescription : @""
    });
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
    if (error) {
        emitJSON(@{@"source": @"macos_ble", @"event": @"gatt_services_error", @"error": error.localizedDescription});
        return;
    }
    NSMutableArray<NSString *> *svcs = [NSMutableArray array];
    for (CBService *svc in peripheral.services) {
        [svcs addObject:svc.UUID.UUIDString];
        [peripheral discoverCharacteristics:nil forService:svc];
    }
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"gatt_services_discovered",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"services": svcs
    });
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverCharacteristicsForService:(CBService *)service
             error:(NSError *)error {
    if (error) return;
    NSMutableArray<NSDictionary *> *chars = [NSMutableArray array];
    for (CBCharacteristic *ch in service.characteristics) {
        [chars addObject:@{
            @"uuid": ch.UUID.UUIDString,
            @"properties": @(ch.properties)
        }];
        if ([ch.UUID isEqual:self.weaveTxUUID]) {
            self.weaveTxChar = ch;
        } else if ([ch.UUID isEqual:self.weaveRxUUID]) {
            self.weaveRxChar = ch;
        }
        if (!self.enableWeaveSession && (ch.properties & CBCharacteristicPropertyRead)) {
            [peripheral readValueForCharacteristic:ch];
        }
    }
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"gatt_characteristics_discovered",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"service": service.UUID.UUIDString,
        @"characteristics": chars
    });

    if (self.enableWeaveSession && self.weaveTxChar && self.weaveRxChar) {
        [peripheral setNotifyValue:YES forCharacteristic:self.weaveRxChar];
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didUpdateNotificationStateForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
    if (error) {
        emitJSON(@{
            @"source": @"macos_ble",
            @"event": @"weave_subscribe_error",
            @"error": error.localizedDescription
        });
        return;
    }
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"weave_ready",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"max_write_len": @([peripheral maximumWriteValueLengthForType:CBCharacteristicWriteWithResponse])
    });
    if (self.enableWeaveSession) {
        [self startStdinWriteLoop];
    }
}

- (void)startStdinWriteLoop {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        char line[8192];
        while (fgets(line, sizeof(line), stdin) != NULL) {
            NSString *s = [[NSString stringWithUTF8String:line]
                           stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if ([s hasPrefix:@"write "]) {
                NSString *hex = [s substringFromIndex:6];
                NSData *payload = dataFromHexString(hex);
                if (self.connectedPeripheral && self.weaveTxChar && payload.length > 0) {
                    [self.connectedPeripheral writeValue:payload
                                       forCharacteristic:self.weaveTxChar
                                                    type:CBCharacteristicWriteWithResponse];
                }
            }
        }
    });
}

- (void)peripheral:(CBPeripheral *)peripheral
didWriteValueForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"weave_tx_ack",
        @"characteristic": characteristic.UUID.UUIDString,
        @"error": error ? error.localizedDescription : @""
    });
}

- (void)peripheral:(CBPeripheral *)peripheral
didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
    NSString *eventName = [characteristic.UUID isEqual:self.weaveRxUUID]
        ? @"weave_rx"
        : @"gatt_characteristic_value";
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": eventName,
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"service": characteristic.service.UUID.UUIDString,
        @"characteristic": characteristic.UUID.UUIDString,
        @"value_hex": characteristic.value ? hexStringFromData(characteristic.value) : @"",
        @"error": error ? error.localizedDescription : @""
    });
}

- (void)peripheral:(CBPeripheral *)peripheral
 didOpenL2CAPChannel:(CBL2CAPChannel *)channel
               error:(NSError *)error {
    if (error || !channel) {
        emitJSON(@{
            @"source": @"macos_ble",
            @"event": @"l2cap_error",
            @"error": error ? error.localizedDescription : @"unknown"
        });
        return;
    }
    [channel.inputStream open];
    [channel.outputStream open];
    emitJSON(@{
        @"source": @"macos_ble",
        @"event": @"l2cap_opened",
        @"peripheral_id": peripheral.identifier.UUIDString,
        @"psm": @(channel.PSM)
    });
}

- (void)startMdnsBrowser {
    nw_browse_descriptor_t desc =
        nw_browse_descriptor_create_bonjour_service("_FC9F5ED42C8A._tcp", "local.");
    nw_parameters_t params = nw_parameters_create();
    self.mdnsBrowser = nw_browser_create(desc, params);
    nw_browser_set_queue(self.mdnsBrowser, dispatch_queue_create("relay.mdns", DISPATCH_QUEUE_SERIAL));
    nw_browser_set_browse_results_changed_handler(
        self.mdnsBrowser,
        ^(nw_browse_result_t old_result, nw_browse_result_t new_result, bool batch_complete) {
            (void)old_result;
            (void)batch_complete;
            if (!new_result) return;
            nw_endpoint_t ep = nw_browse_result_copy_endpoint(new_result);
            if (!ep) return;
            const char *name = nw_endpoint_get_bonjour_service_name(ep);
            const char *type = nw_endpoint_get_bonjour_service_type(ep);
            const char *domain = nw_endpoint_get_bonjour_service_domain(ep);
            emitJSON(@{
                @"source": @"macos_mdns",
                @"event": @"mdns_service_found",
                @"name": name ? @(name) : @"",
                @"type": type ? @(type) : @"",
                @"domain": domain ? @(domain) : @""
            });
        });
    nw_browser_start(self.mdnsBrowser);
}

+ (int)joinHotspotSSID:(NSString *)ssid password:(NSString *)password {
    CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
    if (!iface) {
        emitJSON(@{@"event": @"wifi_join_error", @"error": @"No active Wi-Fi interface"});
        return 1;
    }
    NSError *err = nil;
    NSSet<CWNetwork *> *nets = [iface scanForNetworksWithName:ssid error:&err];
    if (err || nets.count == 0) {
        emitJSON(@{
            @"event": @"wifi_join_error",
            @"error": err ? err.localizedDescription : @"SSID not found in scan"
        });
        return 1;
    }
    CWNetwork *target = [nets anyObject];
    BOOL ok = [iface associateToNetwork:target password:password error:&err];
    if (!ok || err) {
        emitJSON(@{
            @"event": @"wifi_join_error",
            @"error": err ? err.localizedDescription : @"associateToNetwork failed"
        });
        return 1;
    }
    emitJSON(@{@"event": @"wifi_joined", @"ssid": ssid});
    return 0;
}

@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc >= 4 && strcmp(argv[1], "join-wifi") == 0) {
            return [NearbyMacBridge joinHotspotSSID:@(argv[2]) password:@(argv[3])];
        }
        if (argc >= 2 && strcmp(argv[1], "get-clipboard") == 0) {
            NSString *s = [[NSPasteboard generalPasteboard] stringForType:NSPasteboardTypeString];
            printf("%s\n", s ? s.UTF8String : "");
            return 0;
        }
        if (argc >= 3 && strcmp(argv[1], "set-clipboard") == 0) {
            NSPasteboard *pb = [NSPasteboard generalPasteboard];
            [pb clearContents];
            [pb setString:@(argv[2]) forType:NSPasteboardTypeString];
            emitJSON(@{@"event": @"clipboard_updated"});
            return 0;
        }

        NearbyMacBridge *bridge = [[NearbyMacBridge alloc] init];
        if (argc >= 2 && strcmp(argv[1], "scan-all") == 0) {
            bridge.scanAllServices = YES;
        } else if (argc >= 3 && strcmp(argv[1], "connect") == 0) {
            bridge.scanAllServices = YES;
            bridge.autoConnectPeripheralUUID = @(argv[2]);
        } else if (argc >= 3 && strcmp(argv[1], "weave") == 0) {
            bridge.scanAllServices = YES;
            bridge.autoConnectPeripheralUUID = @(argv[2]);
            bridge.enableWeaveSession = YES;
        }
        [bridge start];
        [[NSRunLoop mainRunLoop] run];
    }
    return 0;
}
