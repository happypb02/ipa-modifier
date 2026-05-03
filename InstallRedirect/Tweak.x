#import <UIKit/UIKit.h>
#import <objc/message.h>

@interface DASelectAppVC : UIViewController
@property (nonatomic, strong) UISegmentedControl *segmentedTitleView;
@property (nonatomic, strong) UIViewController *signedVC;
@property (nonatomic, strong) UIViewController *fileVC;
- (void)signSuccess;
- (void)setSelect;
@end

@interface DASignProcessVC : UIViewController
@property (nonatomic, strong) DASelectAppVC *selectVC;
- (void)installClick;
@end

static UIViewController *IRRootViewController(void) {
    for (UIWindow *w in [UIApplication sharedApplication].windows)
        if (w.isKeyWindow) return w.rootViewController;
    return [UIApplication sharedApplication].windows.firstObject.rootViewController;
}

static DASelectAppVC *IRFindSelectAppVC(UIViewController *root) {
    if (!root) return nil;
    if ([root isKindOfClass:NSClassFromString(@"DASelectAppVC")]) return (DASelectAppVC *)root;
    if ([root isKindOfClass:[UITabBarController class]])
        for (UIViewController *vc in ((UITabBarController *)root).viewControllers) {
            DASelectAppVC *r = IRFindSelectAppVC(vc); if (r) return r;
        }
    if ([root isKindOfClass:[UINavigationController class]])
        for (UIViewController *vc in ((UINavigationController *)root).viewControllers) {
            DASelectAppVC *r = IRFindSelectAppVC(vc); if (r) return r;
        }
    for (UIViewController *vc in root.childViewControllers) {
        DASelectAppVC *r = IRFindSelectAppVC(vc); if (r) return r;
    }
    return nil;
}

%hook DASignProcessVC

- (void)installClick {
    NSLog(@"[IR] installClick intercepted");

    // 优先用 self.selectVC 属性直接拿到 DASelectAppVC
    DASelectAppVC *selectVC = nil;
    if ([self respondsToSelector:@selector(selectVC)]) {
        selectVC = ((DASelectAppVC *(*)(id,SEL))objc_msgSend)(self, @selector(selectVC));
    }
    // 备用：从视图层级查找
    if (!selectVC) {
        selectVC = IRFindSelectAppVC(IRRootViewController());
    }

    if (!selectVC) {
        NSLog(@"[IR] DASelectAppVC not found, fallback");
        %orig;
        return;
    }

    // 1. 先切换 TabBar 到 DASelectAppVC 所在的 tab
    UITabBarController *tabBar = selectVC.tabBarController;
    if (tabBar) {
        UIViewController *candidate = selectVC;
        while (candidate.parentViewController && candidate.parentViewController != tabBar)
            candidate = candidate.parentViewController;
        NSUInteger idx = [tabBar.viewControllers indexOfObject:candidate];
        if (idx != NSNotFound) {
            tabBar.selectedIndex = idx;
            NSLog(@"[IR] switched to tab %lu", (unsigned long)idx);
        }
    }

    // 2. 如果在 nav 栈里，pop 回 DASelectAppVC
    UINavigationController *nav = selectVC.navigationController;
    if (nav && [nav.viewControllers containsObject:selectVC]) {
        [nav popToViewController:selectVC animated:YES];
    }

    // 3. 延迟切换 segmentedTitleView 到"已定制"(index 1)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UISegmentedControl *seg = selectVC.segmentedTitleView;
        if (seg && seg.numberOfSegments > 1) {
            seg.selectedSegmentIndex = 1;
            // 手动触发 segmentedControl 的 valueChanged 事件，让页面真正切换
            [seg sendActionsForControlEvents:UIControlEventValueChanged];
            NSLog(@"[IR] segmentedTitleView switched to index 1 (已定制)");
        } else {
            // 备用：调用 signSuccess
            if ([selectVC respondsToSelector:@selector(signSuccess)]) {
                [selectVC signSuccess];
                NSLog(@"[IR] called signSuccess");
            }
        }
    });
}

%end

%ctor {
    NSLog(@"[IR] InstallRedirect loaded");
}
