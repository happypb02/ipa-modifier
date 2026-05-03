#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

@interface DASignProcessVC : UIViewController
@property (nonatomic, strong) id selectVC;
@end

@interface DASelectAppVC : UIViewController
@property (nonatomic, strong) UISegmentedControl *segmentedTitleView;
- (void)signSuccess;
@end

__attribute__((constructor))
static void hook_init() {
    Class cls = objc_getClass("DASignProcessVC");
    if (!cls) return;

    Method origMethod = class_getInstanceMethod(cls, @selector(installClick));
    if (!origMethod) return;

    IMP origIMP = method_getImplementation(origMethod);

    IMP newIMP = imp_implementationWithBlock(^(id self) {
        NSLog(@"[Hook] installClick intercepted");

        // Get selectVC
        id selectVC = [self valueForKey:@"selectVC"];
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
    NSLog(@"[Hook] Hooked installClick");
}
