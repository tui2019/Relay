#import <Foundation/Foundation.h>
#import <FileProvider/FileProvider.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

static NSString *const kDaemonBaseURL = @"http://127.0.0.1:48921";

static NSString *pathFromIdentifier(NSFileProviderItemIdentifier ident) {
    if ([ident isEqualToString:NSFileProviderRootContainerItemIdentifier] || ident.length == 0) {
        return @"/";
    }
    return ident;
}

static NSString *urlEncodeQueryValue(NSString *s) {
    NSMutableCharacterSet *allowed = [[NSCharacterSet URLQueryAllowedCharacterSet] mutableCopy];
    [allowed removeCharactersInString:@"&=+?#"];
    return [s stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: s;
}

static NSError *fpErrorForHTTP(NSInteger statusCode, NSError *netErr) {
    if (netErr != nil || statusCode == 503 || statusCode == 0) {
        return [NSError errorWithDomain:NSFileProviderErrorDomain
                                   code:NSFileProviderErrorServerUnreachable
                               userInfo:nil];
    }
    if (statusCode == 404) {
        return [NSError errorWithDomain:NSFileProviderErrorDomain
                                   code:NSFileProviderErrorNoSuchItem
                               userInfo:nil];
    }
    return [NSError errorWithDomain:NSFileProviderErrorDomain
                               code:NSFileProviderErrorServerUnreachable
                           userInfo:nil];
}

#pragma mark - RelayItem

@interface RelayItem : NSObject <NSFileProviderItem>
@property (nonatomic, copy) NSFileProviderItemIdentifier itemIdentifier;
@property (nonatomic, copy) NSFileProviderItemIdentifier parentItemIdentifier;
@property (nonatomic, copy) NSString *filename;
@property (nonatomic, copy) UTType *contentType;
@property (nonatomic, copy) NSNumber *documentSize;
@property (nonatomic, copy) NSDate *contentModificationDate;
@property (nonatomic, strong) NSFileProviderItemVersion *itemVersion;
@property (nonatomic, assign) NSFileProviderItemCapabilities capabilities;
@end

@implementation RelayItem

+ (instancetype)rootItemWithName:(NSString *)name {
    RelayItem *it = [[RelayItem alloc] init];
    it.itemIdentifier = NSFileProviderRootContainerItemIdentifier;
    it.parentItemIdentifier = NSFileProviderRootContainerItemIdentifier;
    it.filename = name.length > 0 ? name : @"Android Phone";
    it.contentType = UTTypeFolder;
    it.capabilities = NSFileProviderItemCapabilitiesAllowsReading |
                      NSFileProviderItemCapabilitiesAllowsContentEnumerating |
                      NSFileProviderItemCapabilitiesAllowsAddingSubItems;
    it.itemVersion = [[NSFileProviderItemVersion alloc]
        initWithContentVersion:[@"root-1" dataUsingEncoding:NSUTF8StringEncoding]
               metadataVersion:[@"root-1" dataUsingEncoding:NSUTF8StringEncoding]];
    return it;
}

+ (nullable instancetype)itemFromJSON:(NSDictionary *)dict rootName:(NSString *)rootName {
    if (![dict isKindOfClass:[NSDictionary class]]) return nil;
    NSString *docId = [dict[@"document_id"] isKindOfClass:[NSString class]] ? dict[@"document_id"] : nil;
    if (docId.length == 0 || [docId isEqualToString:@"/"]) {
        return [self rootItemWithName:rootName];
    }
    if (![docId hasPrefix:@"/"]) {
        docId = [@"/" stringByAppendingString:docId];
    }

    NSString *mime = [dict[@"mime_type"] isKindOfClass:[NSString class]] ? dict[@"mime_type"] : @"";
    BOOL isDir = [mime isEqualToString:@"vnd.android.document/directory"];

    NSString *name = [dict[@"display_name"] isKindOfClass:[NSString class]] ? dict[@"display_name"] : nil;
    if (name.length == 0) {
        name = [docId lastPathComponent];
    }

    NSString *parentPath = [docId stringByDeletingLastPathComponent];
    NSFileProviderItemIdentifier parentId =
        (parentPath.length == 0 || [parentPath isEqualToString:@"/"])
            ? NSFileProviderRootContainerItemIdentifier
            : parentPath;

    NSNumber *sizeNum = [dict[@"size"] isKindOfClass:[NSNumber class]] ? dict[@"size"] : @(0);
    NSNumber *modMs = [dict[@"last_modified_ms"] isKindOfClass:[NSNumber class]] ? dict[@"last_modified_ms"] : @(0);
    NSTimeInterval modSec = modMs.doubleValue / 1000.0;
    NSDate *modDate = (modSec > 0) ? [NSDate dateWithTimeIntervalSince1970:modSec] : [NSDate date];

    UTType *ut = nil;
    if (isDir) {
        ut = UTTypeFolder;
    } else {
        NSString *ext = [name pathExtension];
        if (ext.length > 0) {
            ut = [UTType typeWithFilenameExtension:ext];
        }
        if (!ut && mime.length > 0) {
            ut = [UTType typeWithMIMEType:mime];
        }
        if (!ut) {
            ut = UTTypeData;
        }
    }

    NSString *verStr = [NSString stringWithFormat:@"%@-%@", modMs, sizeNum];
    NSData *verData = [verStr dataUsingEncoding:NSUTF8StringEncoding];

    RelayItem *it = [[RelayItem alloc] init];
    it.itemIdentifier = docId;
    it.parentItemIdentifier = parentId;
    it.filename = name;
    it.contentType = ut;
    it.documentSize = isDir ? nil : sizeNum;
    it.contentModificationDate = modDate;
    it.itemVersion = [[NSFileProviderItemVersion alloc] initWithContentVersion:verData
                                                               metadataVersion:verData];
    // Full read/write capabilities backed by QuickAccessService RPCs — removes read-only padlocks in Finder!
    if (isDir) {
        it.capabilities = NSFileProviderItemCapabilitiesAllowsReading |
                          NSFileProviderItemCapabilitiesAllowsContentEnumerating |
                          NSFileProviderItemCapabilitiesAllowsAddingSubItems |
                          NSFileProviderItemCapabilitiesAllowsRenaming |
                          NSFileProviderItemCapabilitiesAllowsDeleting |
                          NSFileProviderItemCapabilitiesAllowsReparenting;
    } else {
        it.capabilities = NSFileProviderItemCapabilitiesAllowsReading |
                          NSFileProviderItemCapabilitiesAllowsWriting |
                          NSFileProviderItemCapabilitiesAllowsRenaming |
                          NSFileProviderItemCapabilitiesAllowsDeleting |
                          NSFileProviderItemCapabilitiesAllowsReparenting;
    }
    return it;
}

@end

#pragma mark - RelayEnumerator

@interface RelayEnumerator : NSObject <NSFileProviderEnumerator>
@property (nonatomic, copy) NSFileProviderItemIdentifier containerId;
@property (nonatomic, copy) NSString *rootName;
@property (nonatomic, strong) NSURLSession *session;
@end

@implementation RelayEnumerator

- (instancetype)initWithContainerId:(NSFileProviderItemIdentifier)cid
                           rootName:(NSString *)rootName
                            session:(NSURLSession *)session {
    self = [super init];
    if (self) {
        _containerId = [cid copy];
        _rootName = [rootName copy];
        _session = session;
    }
    return self;
}

- (void)invalidate {
}

- (void)enumerateItemsForObserver:(id<NSFileProviderEnumerationObserver>)observer
                     startingAtPage:(NSFileProviderPage)page {
    (void)page;
    if ([self.containerId isEqualToString:NSFileProviderWorkingSetContainerItemIdentifier] ||
        [self.containerId isEqualToString:NSFileProviderTrashContainerItemIdentifier]) {
        [observer finishEnumeratingUpToPage:nil];
        return;
    }

    NSString *qaPath = pathFromIdentifier(self.containerId);
    NSString *urlStr = [NSString stringWithFormat:@"%@/_api/list?path=%@",
                        kDaemonBaseURL, urlEncodeQueryValue(qaPath)];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSURLSessionDataTask *task =
        [self.session dataTaskWithURL:url
                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                        NSInteger status = [response isKindOfClass:[NSHTTPURLResponse class]]
                                               ? ((NSHTTPURLResponse *)response).statusCode
                                               : 0;
                        if (error || status != 200 || !data) {
                            [observer finishEnumeratingWithError:fpErrorForHTTP(status, error)];
                            return;
                        }
                        NSArray *arr = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                        if (![arr isKindOfClass:[NSArray class]]) {
                            [observer finishEnumeratingUpToPage:nil];
                            return;
                        }
                        NSMutableArray<id<NSFileProviderItem>> *items = [NSMutableArray arrayWithCapacity:arr.count];
                        for (NSDictionary *entry in arr) {
                            RelayItem *it = [RelayItem itemFromJSON:entry rootName:self.rootName];
                            if (it && ![it.itemIdentifier isEqualToString:NSFileProviderRootContainerItemIdentifier]) {
                                [items addObject:it];
                            }
                        }
                        if (items.count > 0) {
                            [observer didEnumerateItems:items];
                        }
                        [observer finishEnumeratingUpToPage:nil];
                    }];
    [task resume];
}

- (void)enumerateChangesForObserver:(id<NSFileProviderChangeObserver>)observer
                     fromSyncAnchor:(NSFileProviderSyncAnchor)syncAnchor {
    [observer finishEnumeratingChangesUpToSyncAnchor:syncAnchor moreComing:NO];
}

- (void)currentSyncAnchorWithCompletionHandler:(void (^)(NSFileProviderSyncAnchor _Nullable))completionHandler {
    NSData *anchor = [@"v2" dataUsingEncoding:NSUTF8StringEncoding];
    completionHandler(anchor);
}

@end

#pragma mark - RelayFileProvider (NSFileProviderReplicatedExtension)

@interface RelayFileProvider : NSObject <NSFileProviderReplicatedExtension>
@property (nonatomic, strong) NSFileProviderDomain *domain;
@property (nonatomic, strong) NSURLSession *session;
@end

@implementation RelayFileProvider

- (instancetype)initWithDomain:(NSFileProviderDomain *)domain {
    self = [super init];
    if (self) {
        _domain = domain;
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 20.0;
        cfg.timeoutIntervalForResource = 120.0;
        _session = [NSURLSession sessionWithConfiguration:cfg];
    }
    return self;
}

- (void)invalidate {
    [self.session invalidateAndCancel];
}

- (NSString *)rootDisplayName {
    return self.domain.displayName.length > 0 ? self.domain.displayName : @"Android Phone";
}

- (nullable id<NSFileProviderEnumerator>)enumeratorForContainerItemIdentifier:(NSFileProviderItemIdentifier)containerItemIdentifier
                                                                      request:(NSFileProviderRequest *)request
                                                                        error:(NSError * _Nullable __autoreleasing *)error {
    (void)request;
    (void)error;
    return [[RelayEnumerator alloc] initWithContainerId:containerItemIdentifier
                                                   rootName:[self rootDisplayName]
                                                    session:self.session];
}

- (void)statPath:(NSString *)qaPath
      completion:(void (^)(RelayItem * _Nullable, NSError * _Nullable))completion {
    NSString *urlStr = [NSString stringWithFormat:@"%@/_api/stat?path=%@",
                        kDaemonBaseURL, urlEncodeQueryValue(qaPath)];
    NSURLSessionDataTask *task =
        [self.session dataTaskWithURL:[NSURL URLWithString:urlStr]
                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                        NSInteger status = [response isKindOfClass:[NSHTTPURLResponse class]]
                                               ? ((NSHTTPURLResponse *)response).statusCode
                                               : 0;
                        if (error || status != 200 || !data) {
                            completion(nil, fpErrorForHTTP(status, error));
                            return;
                        }
                        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                        RelayItem *item = [RelayItem itemFromJSON:dict rootName:[self rootDisplayName]];
                        if (!item) {
                            completion(nil, fpErrorForHTTP(404, nil));
                            return;
                        }
                        completion(item, nil);
                    }];
    [task resume];
}

- (void)uploadFileURL:(NSURL *)fileURL
               toPath:(NSString *)qaPath
           completion:(void (^)(NSError * _Nullable))completion {
    NSError *readErr = nil;
    NSData *body = [NSData dataWithContentsOfURL:fileURL options:0 error:&readErr];
    if (readErr && !body) {
        completion(readErr);
        return;
    }
    NSString *urlStr = [NSString stringWithFormat:@"%@/_api/write?path=%@",
                        kDaemonBaseURL, urlEncodeQueryValue(qaPath)];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    req.HTTPMethod = @"PUT";
    [req setValue:@"application/octet-stream" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = body ?: [NSData data];
    NSURLSessionDataTask *task =
        [self.session dataTaskWithRequest:req
                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                            (void)data;
                            NSInteger status = [response isKindOfClass:[NSHTTPURLResponse class]]
                                                   ? ((NSHTTPURLResponse *)response).statusCode
                                                   : 0;
                            if (error || status != 200) {
                                completion(fpErrorForHTTP(status, error));
                                return;
                            }
                            completion(nil);
                        }];
    [task resume];
}

- (NSProgress *)itemForIdentifier:(NSFileProviderItemIdentifier)identifier
                          request:(NSFileProviderRequest *)request
                completionHandler:(void (^)(NSFileProviderItem _Nullable, NSError * _Nullable))completionHandler {
    (void)request;
    NSProgress *progress = [NSProgress progressWithTotalUnitCount:1];
    if ([identifier isEqualToString:NSFileProviderRootContainerItemIdentifier]) {
        progress.completedUnitCount = 1;
        completionHandler([RelayItem rootItemWithName:[self rootDisplayName]], nil);
        return progress;
    }

    NSString *qaPath = pathFromIdentifier(identifier);
    [self statPath:qaPath completion:^(RelayItem *item, NSError *err) {
        progress.completedUnitCount = 1;
        completionHandler(item, err);
    }];
    return progress;
}

- (NSProgress *)fetchContentsForItemWithIdentifier:(NSFileProviderItemIdentifier)itemIdentifier
                                           version:(nullable NSFileProviderItemVersion *)requestedVersion
                                           request:(NSFileProviderRequest *)request
                                 completionHandler:(void (^)(NSURL * _Nullable, NSFileProviderItem _Nullable, NSError * _Nullable))completionHandler {
    (void)requestedVersion;
    (void)request;
    NSProgress *progress = [NSProgress progressWithTotalUnitCount:2];
    NSString *qaPath = pathFromIdentifier(itemIdentifier);
    NSString *readUrlStr = [NSString stringWithFormat:@"%@/_api/read?path=%@",
                            kDaemonBaseURL, urlEncodeQueryValue(qaPath)];

    [self statPath:qaPath completion:^(RelayItem *item, NSError *serr) {
        if (serr || !item) {
            completionHandler(nil, nil, serr ?: fpErrorForHTTP(404, nil));
            return;
        }
        progress.completedUnitCount = 1;
        NSURLSessionDownloadTask *dlTask =
            [self.session downloadTaskWithURL:[NSURL URLWithString:readUrlStr]
                            completionHandler:^(NSURL *location, NSURLResponse *rresp, NSError *rerr) {
                                progress.completedUnitCount = 2;
                                NSInteger rstatus = [rresp isKindOfClass:[NSHTTPURLResponse class]]
                                                        ? ((NSHTTPURLResponse *)rresp).statusCode
                                                        : 0;
                                if (rerr || rstatus != 200 || !location) {
                                    completionHandler(nil, nil, fpErrorForHTTP(rstatus, rerr));
                                    return;
                                }
                                NSString *tmpName = [NSString stringWithFormat:@"relay-%@-%@",
                                                     [[NSUUID UUID] UUIDString],
                                                     item.filename ?: @"file"];
                                NSURL *dest = [NSURL fileURLWithPath:[NSTemporaryDirectory() stringByAppendingPathComponent:tmpName]];
                                NSError *mvErr = nil;
                                [[NSFileManager defaultManager] moveItemAtURL:location toURL:dest error:&mvErr];
                                if (mvErr) {
                                    completionHandler(nil, nil, mvErr);
                                    return;
                                }
                                completionHandler(dest, item, nil);
                            }];
        [dlTask resume];
    }];
    return progress;
}

- (NSProgress *)createItemBasedOnTemplate:(NSFileProviderItem)itemTemplate
                                   fields:(NSFileProviderItemFields)fields
                                 contents:(nullable NSURL *)url
                                  options:(NSFileProviderCreateItemOptions)options
                                  request:(NSFileProviderRequest *)request
                        completionHandler:(void (^)(NSFileProviderItem _Nullable, NSFileProviderItemFields, BOOL, NSError * _Nullable))completionHandler {
    (void)fields; (void)options; (void)request;
    NSProgress *progress = [NSProgress progressWithTotalUnitCount:2];
    NSString *parentPath = pathFromIdentifier(itemTemplate.parentItemIdentifier);
    NSString *name = itemTemplate.filename ?: @"Untitled";
    BOOL isDir = [itemTemplate.contentType conformsToType:UTTypeFolder];
    NSString *mime = isDir
                         ? @"vnd.android.document/directory"
                         : (itemTemplate.contentType.preferredMIMEType ?: @"application/octet-stream");

    NSString *urlStr = [NSString stringWithFormat:@"%@/_api/create?parent=%@&name=%@&mime=%@",
                        kDaemonBaseURL,
                        urlEncodeQueryValue(parentPath),
                        urlEncodeQueryValue(name),
                        urlEncodeQueryValue(mime)];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    req.HTTPMethod = @"POST";
    NSURLSessionDataTask *task =
        [self.session dataTaskWithRequest:req
                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                            NSInteger status = [response isKindOfClass:[NSHTTPURLResponse class]]
                                                   ? ((NSHTTPURLResponse *)response).statusCode
                                                   : 0;
                            if (error || status != 200 || !data) {
                                completionHandler(nil, 0, NO, fpErrorForHTTP(status, error));
                                return;
                            }
                            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                            RelayItem *created = [RelayItem itemFromJSON:dict rootName:[self rootDisplayName]];
                            if (!created) {
                                completionHandler(nil, 0, NO, fpErrorForHTTP(500, nil));
                                return;
                            }
                            progress.completedUnitCount = 1;
                            if (!isDir && url != nil) {
                                NSString *createdPath = pathFromIdentifier(created.itemIdentifier);
                                [self uploadFileURL:url toPath:createdPath completion:^(NSError *werr) {
                                    progress.completedUnitCount = 2;
                                    if (werr) {
                                        completionHandler(nil, 0, NO, werr);
                                        return;
                                    }
                                    [self statPath:createdPath completion:^(RelayItem *updated, NSError *serr) {
                                        (void)serr;
                                        completionHandler(updated ?: created, 0, NO, nil);
                                    }];
                                }];
                            } else {
                                progress.completedUnitCount = 2;
                                completionHandler(created, 0, NO, nil);
                            }
                        }];
    [task resume];
    return progress;
}

- (NSProgress *)modifyItem:(NSFileProviderItem)item
               baseVersion:(NSFileProviderItemVersion *)version
             changedFields:(NSFileProviderItemFields)changedFields
                  contents:(nullable NSURL *)newContents
                   options:(NSFileProviderModifyItemOptions)options
                   request:(NSFileProviderRequest *)request
         completionHandler:(void (^)(NSFileProviderItem _Nullable, NSFileProviderItemFields, BOOL, NSError * _Nullable))completionHandler {
    (void)version; (void)options; (void)request;
    NSProgress *progress = [NSProgress progressWithTotalUnitCount:3];
    NSString *origPath = pathFromIdentifier(item.itemIdentifier);

    void (^finishWriteAndStat)(NSString *) = ^(NSString *curPath) {
        if ((changedFields & NSFileProviderItemContents) && newContents != nil) {
            [self uploadFileURL:newContents toPath:curPath completion:^(NSError *werr) {
                progress.completedUnitCount = 3;
                if (werr) {
                    completionHandler(nil, 0, NO, werr);
                    return;
                }
                [self statPath:curPath completion:^(RelayItem *updated, NSError *serr) {
                    completionHandler(updated, 0, NO, serr);
                }];
            }];
        } else {
            progress.completedUnitCount = 3;
            [self statPath:curPath completion:^(RelayItem *updated, NSError *serr) {
                completionHandler(updated, 0, NO, serr);
            }];
        }
    };

    void (^doRenameThenWrite)(NSString *) = ^(NSString *curPath) {
        progress.completedUnitCount = 1;
        if ((changedFields & NSFileProviderItemFilename) &&
            item.filename.length > 0 &&
            ![item.filename isEqualToString:[curPath lastPathComponent]]) {
            NSString *urlStr = [NSString stringWithFormat:@"%@/_api/rename?path=%@&name=%@",
                                kDaemonBaseURL,
                                urlEncodeQueryValue(curPath),
                                urlEncodeQueryValue(item.filename)];
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
            req.HTTPMethod = @"POST";
            NSURLSessionDataTask *t =
                [self.session dataTaskWithRequest:req
                                completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
                                    NSInteger st = [resp isKindOfClass:[NSHTTPURLResponse class]]
                                                       ? ((NSHTTPURLResponse *)resp).statusCode
                                                       : 0;
                                    if (err || st != 200 || !data) {
                                        completionHandler(nil, 0, NO, fpErrorForHTTP(st, err));
                                        return;
                                    }
                                    NSDictionary *d = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                                    NSString *newPath = [d[@"document_id"] isKindOfClass:[NSString class]]
                                                            ? d[@"document_id"]
                                                            : [[curPath stringByDeletingLastPathComponent]
                                                                  stringByAppendingPathComponent:item.filename];
                                    progress.completedUnitCount = 2;
                                    finishWriteAndStat(newPath);
                                }];
            [t resume];
        } else {
            progress.completedUnitCount = 2;
            finishWriteAndStat(curPath);
        }
    };

    if (changedFields & NSFileProviderItemParentItemIdentifier) {
        NSString *destParent = pathFromIdentifier(item.parentItemIdentifier);
        NSString *oldParent = [origPath stringByDeletingLastPathComponent];
        if (oldParent.length == 0) oldParent = @"/";
        if (![destParent isEqualToString:oldParent]) {
            NSString *urlStr = [NSString stringWithFormat:@"%@/_api/move?path=%@&dest=%@",
                                kDaemonBaseURL,
                                urlEncodeQueryValue(origPath),
                                urlEncodeQueryValue(destParent)];
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
            req.HTTPMethod = @"POST";
            NSURLSessionDataTask *t =
                [self.session dataTaskWithRequest:req
                                completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
                                    (void)data;
                                    NSInteger st = [resp isKindOfClass:[NSHTTPURLResponse class]]
                                                       ? ((NSHTTPURLResponse *)resp).statusCode
                                                       : 0;
                                    if (err || st != 200) {
                                        completionHandler(nil, 0, NO, fpErrorForHTTP(st, err));
                                        return;
                                    }
                                    NSString *movedPath = [destParent isEqualToString:@"/"]
                                                              ? [@"/" stringByAppendingString:[origPath lastPathComponent]]
                                                              : [destParent stringByAppendingPathComponent:[origPath lastPathComponent]];
                                    doRenameThenWrite(movedPath);
                                }];
            [t resume];
            return progress;
        }
    }

    doRenameThenWrite(origPath);
    return progress;
}

- (NSProgress *)deleteItemWithIdentifier:(NSFileProviderItemIdentifier)identifier
                             baseVersion:(NSFileProviderItemVersion *)version
                                 options:(NSFileProviderDeleteItemOptions)options
                                 request:(NSFileProviderRequest *)request
                       completionHandler:(void (^)(NSError * _Nullable))completionHandler {
    (void)version; (void)options; (void)request;
    NSProgress *progress = [NSProgress progressWithTotalUnitCount:1];
    NSString *qaPath = pathFromIdentifier(identifier);
    NSString *urlStr = [NSString stringWithFormat:@"%@/_api/delete?path=%@",
                        kDaemonBaseURL, urlEncodeQueryValue(qaPath)];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    req.HTTPMethod = @"POST";
    NSURLSessionDataTask *task =
        [self.session dataTaskWithRequest:req
                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                            (void)data;
                            progress.completedUnitCount = 1;
                            NSInteger status = [response isKindOfClass:[NSHTTPURLResponse class]]
                                                   ? ((NSHTTPURLResponse *)response).statusCode
                                                   : 0;
                            if (error || status != 200) {
                                completionHandler(fpErrorForHTTP(status, error));
                                return;
                            }
                            completionHandler(nil);
                        }];
    [task resume];
    return progress;
}

@end
