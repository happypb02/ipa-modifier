#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// Minimal hook that swizzles installClick
__attribute__((constructor))
static void hook_init() {
    @autoreleasepool {
        NSLog(@"[Hook] Loading...");

        Class cls = objc_getClass("DASignProcessVC");
        if (!cls) {
            NSLog(@"[Hook] DASignProcessVC not found");
            return;
        }

        SEL origSel = @selector(installClick);
        Method origMethod = class_getInstanceMethod(cls, origSel);
        if (!origMethod) {
            NSLog(@"[Hook] installClick method not found");
            return;
        }

        // Replace with a block that does the redirect
        IMP newIMP = imp_implementationWithBlock(^(UIViewController *self) {
            NSLog(@"[Hook] installClick called");

            // Try to get selectVC via KVC
            id selectVC = nil;
            @try {
                selectVC = [self valueForKey:@"selectVC"];
            } @catch (NSException *e) {
                NSLog(@"[Hook] Failed to get selectVC: %@", e);
            }

            if (selectVC && [selectVC respondsToSelector:@selector(signSuccess)]) {
                NSLog(@"[Hook] Calling signSuccess");
                [selectVC performSelector:@selector(signSuccess)];
            } else {
                NSLog(@"[Hook] selectVC not available or signSuccess not found");
            }
        });

        method_setImplementation(origMethod, newIMP);
        NSLog(@"[Hook] Successfully hooked installClick");
    }
}
