#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

@interface DASignProcessVC : UIViewController
@end

@interface DASelectAppVC : UIViewController
- (void)signSuccess;
@end

__attribute__((constructor))
static void hook_init() {
    NSLog(@"[Hook] Initializing hook...");

    Class cls = objc_getClass("DASignProcessVC");
    if (!cls) {
        NSLog(@"[Hook] DASignProcessVC class not found");
        return;
    }
    NSLog(@"[Hook] Found DASignProcessVC class");

    Method origMethod = class_getInstanceMethod(cls, @selector(installClick));
    if (!origMethod) {
        NSLog(@"[Hook] installClick method not found");
        return;
    }
    NSLog(@"[Hook] Found installClick method");

    IMP origIMP = method_getImplementation(origMethod);

    IMP newIMP = imp_implementationWithBlock(^(id self) {
        NSLog(@"[Hook] installClick intercepted");

        // Get selectVC using KVC
        id selectVC = nil;
        @try {
            selectVC = [self valueForKey:@"selectVC"];
            NSLog(@"[Hook] selectVC = %@", selectVC);
        } @catch (NSException *e) {
            NSLog(@"[Hook] Failed to get selectVC: %@", e);
        }

        if (!selectVC) {
            NSLog(@"[Hook] selectVC is nil, calling original");
            ((void(*)(id,SEL))origIMP)(self, @selector(installClick));
            return;
        }

        // Call signSuccess
        if ([selectVC respondsToSelector:@selector(signSuccess)]) {
            [selectVC performSelector:@selector(signSuccess)];
            NSLog(@"[Hook] Called signSuccess");
        } else {
            NSLog(@"[Hook] signSuccess not found");
        }
    });

    method_setImplementation(origMethod, newIMP);
    NSLog(@"[Hook] Successfully hooked installClick");
}
