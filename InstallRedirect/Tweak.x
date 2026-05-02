#import <UIKit/UIKit.h>
#import <substrate.h>

// Hook 目标: DAInstallConfigView 类的"去安装"按钮点击事件
// 目的: 将跳转改为"文件-已定制"页面

@interface DAInstallConfigView : UIView
- (void)installButtonClicked:(id)sender;
@end

@interface UIViewController (Helper)
- (UIViewController *)topViewController;
@end

@implementation UIViewController (Helper)
- (UIViewController *)topViewController {
    UIViewController *topVC = self;
    while (topVC.presentedViewController) {
        topVC = topVC.presentedViewController;
    }
    return topVC;
}
@end

%hook DAInstallConfigView

// Hook "去安装"按钮的点击方法
- (void)installButtonClicked:(id)sender {
    NSLog(@"[InstallRedirect] 拦截到'去安装'按钮点击");

    // 获取当前的视图控制器
    UIResponder *responder = self;
    UIViewController *currentVC = nil;

    while (responder) {
        if ([responder isKindOfClass:[UIViewController class]]) {
            currentVC = (UIViewController *)responder;
            break;
        }
        responder = [responder nextResponder];
    }

    if (!currentVC) {
        NSLog(@"[InstallRedirect] 错误: 无法获取当前视图控制器");
        %orig; // 执行原始方法
        return;
    }

    // 方案1: 尝试通过 TabBarController 切换到"文件"tab
    UITabBarController *tabBarController = currentVC.tabBarController;
    if (tabBarController) {
        NSLog(@"[InstallRedirect] 找到 TabBarController, 尝试切换到文件tab");

        // 切换到"文件"tab (通常是第1或第2个tab,需要根据实际情况调整)
        // 可以尝试 index 0, 1, 2 来找到正确的tab
        for (NSInteger i = 0; i < tabBarController.viewControllers.count; i++) {
            UIViewController *vc = tabBarController.viewControllers[i];
            NSString *className = NSStringFromClass([vc class]);
            NSLog(@"[InstallRedirect] Tab %ld: %@", (long)i, className);

            // 查找包含 "File" 或 "文件" 的控制器
            if ([className containsString:@"File"] ||
                [className containsString:@"Mine"] ||
                [className containsString:@"List"]) {

                tabBarController.selectedIndex = i;
                NSLog(@"[InstallRedirect] 切换到 tab %ld", (long)i);

                // 获取该tab的导航控制器
                UINavigationController *navController = nil;
                if ([tabBarController.selectedViewController isKindOfClass:[UINavigationController class]]) {
                    navController = (UINavigationController *)tabBarController.selectedViewController;
                }

                // 尝试跳转到"已定制"页面
                if (navController) {
                    // 方法1: 尝试通过类名创建视图控制器
                    NSArray *possibleClassNames = @[
                        @"DACustomizedFilesViewController",
                        @"DACustomizedViewController",
                        @"DAFileListViewController",
                        @"DAMineListViewController"
                    ];

                    for (NSString *className in possibleClassNames) {
                        Class vcClass = NSClassFromString(className);
                        if (vcClass) {
                            UIViewController *customizedVC = [[vcClass alloc] init];
                            customizedVC.title = @"已定制";
                            [navController pushViewController:customizedVC animated:YES];
                            NSLog(@"[InstallRedirect] 成功跳转到: %@", className);
                            return; // 成功,不执行原始方法
                        }
                    }

                    // 方法2: 如果找不到具体的类,至少切换到文件tab
                    NSLog(@"[InstallRedirect] 已切换到文件tab");
                    return;
                }

                break;
            }
        }
    }

    // 方案2: 如果没有 TabBarController,尝试直接 push
    UINavigationController *navController = currentVC.navigationController;
    if (navController) {
        NSLog(@"[InstallRedirect] 找到 NavigationController, 尝试直接跳转");

        NSArray *possibleClassNames = @[
            @"DACustomizedFilesViewController",
            @"DACustomizedViewController",
            @"DAFileListViewController",
            @"DAMineListViewController"
        ];

        for (NSString *className in possibleClassNames) {
            Class vcClass = NSClassFromString(className);
            if (vcClass) {
                UIViewController *customizedVC = [[vcClass alloc] init];
                customizedVC.title = @"已定制";
                [navController pushViewController:customizedVC animated:YES];
                NSLog(@"[InstallRedirect] 成功跳转到: %@", className);
                return;
            }
        }
    }

    // 如果所有方案都失败,显示提示并执行原始方法
    NSLog(@"[InstallRedirect] 无法找到目标页面,执行原始跳转");

    // 可选: 显示一个提示
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示"
                                                                   message:@"请手动前往 文件-已定制 查看"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [currentVC presentViewController:alert animated:YES completion:nil];

    // 不执行原始方法,避免跳转到原来的页面
    // %orig;
}

%end

%ctor {
    NSLog(@"[InstallRedirect] Tweak 已加载");
}
