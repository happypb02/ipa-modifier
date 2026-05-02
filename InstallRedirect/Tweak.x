#import <UIKit/UIKit.h>
#import <objc/message.h>

static UIViewController *IRFindViewController(UIViewController *root, NSString *className) {
    if (!root) return nil;
    if ([NSStringFromClass([root class]) isEqualToString:className]) return root;

    if ([root isKindOfClass:[UINavigationController class]]) {
        for (UIViewController *vc in ((UINavigationController *)root).viewControllers) {
            UIViewController *found = IRFindViewController(vc, className);
            if (found) return found;
        }
    }

    if ([root isKindOfClass:[UITabBarController class]]) {
        for (UIViewController *vc in ((UITabBarController *)root).viewControllers) {
            UIViewController *found = IRFindViewController(vc, className);
            if (found) return found;
        }
    }

    for (UIViewController *vc in root.childViewControllers) {
        UIViewController *found = IRFindViewController(vc, className);
        if (found) return found;
    }

    return nil;
}

static UIViewController *IRRootViewController(void) {
    UIWindow *keyWindow = nil;
    for (UIWindow *window in [UIApplication sharedApplication].windows) {
        if (window.isKeyWindow) {
            keyWindow = window;
            break;
        }
    }
    if (!keyWindow) keyWindow = [UIApplication sharedApplication].windows.firstObject;
    return keyWindow.rootViewController;
}

static void IRSwitchSelectAppToSigned(UIViewController *selectVC) {
    if (!selectVC) return;

    if ([selectVC respondsToSelector:@selector(signSuccess)]) {
        ((void (*)(id, SEL))objc_msgSend)(selectVC, @selector(signSuccess));
        NSLog(@"[InstallRedirect] called DASelectAppVC signSuccess");
        return;
    }

    if ([selectVC respondsToSelector:@selector(segmentedTitleView)]) {
        id segmented = ((id (*)(id, SEL))objc_msgSend)(selectVC, @selector(segmentedTitleView));
        if ([segmented respondsToSelector:@selector(setSelectedSegmentIndex:)]) {
            ((void (*)(id, SEL, NSInteger))objc_msgSend)(segmented, @selector(setSelectedSegmentIndex:), 1);
            NSLog(@"[InstallRedirect] set segment index 1");
        }
    }

    if ([selectVC respondsToSelector:@selector(setSelect)]) {
        ((void (*)(id, SEL))objc_msgSend)(selectVC, @selector(setSelect));
        NSLog(@"[InstallRedirect] called setSelect");
    }
}

%hook DASignProcessVC

- (void)installClick {
    NSLog(@"[InstallRedirect] intercept DASignProcessVC installClick");

    UIViewController *root = IRRootViewController();
    UIViewController *selectVC = IRFindViewController(root, @"DASelectAppVC");

    if (!selectVC) {
        NSLog(@"[InstallRedirect] DASelectAppVC not found, fallback original installClick");
        %orig;
        return;
    }

    UITabBarController *tabBar = selectVC.tabBarController;
    if (tabBar) {
        UIViewController *candidate = selectVC;
        while (candidate.parentViewController && candidate.parentViewController != tabBar) {
            candidate = candidate.parentViewController;
        }
        NSUInteger index = [tabBar.viewControllers indexOfObject:candidate];
        if (index != NSNotFound) {
            tabBar.selectedIndex = index;
            NSLog(@"[InstallRedirect] selected tab %lu", (unsigned long)index);
        }
    }

    UINavigationController *nav = selectVC.navigationController;
    if (nav && [nav.viewControllers containsObject:selectVC]) {
        [nav popToViewController:selectVC animated:YES];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            IRSwitchSelectAppToSigned(selectVC);
        });
        NSLog(@"[InstallRedirect] pop to DASelectAppVC then switch signed");
        return;
    }

    IRSwitchSelectAppToSigned(selectVC);
}

%end

%ctor {
    NSLog(@"[InstallRedirect] loaded");
}
