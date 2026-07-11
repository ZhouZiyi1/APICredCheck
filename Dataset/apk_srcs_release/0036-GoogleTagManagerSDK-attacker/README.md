# Google Tag Manager Android 演示工程

基于 [Android 版 Google 跟踪代码管理器官方文档](https://developers.google.com/tag-platform/tag-manager/android/v5?hl=zh-cn) 的最小可运行 Demo。移动端 GTM **不直接提供“发事件”API**，而是通过 **Firebase Analytics** 记录的事件、参数和用户属性，在 GTM 容器中配置触发器与代码。

## 你需要自行申请 / 配置的信息

| 项目 | 从哪里获取 | 在本工程中的位置 |
|------|------------|------------------|
| **Firebase 项目** | [Firebase Console](https://console.firebase.google.com/) 创建项目 | — |
| **启用 Google Analytics** | Firebase 项目设置 → 集成 → Analytics | 前提条件，无单独文件 |
| **Android 应用注册** | Firebase → 添加应用 → 包名 `com.google.tagmanager.demo` | — |
| **`google-services.json`** | Firebase 应用设置 → 下载配置文件 | 复制为 `app/google-services.json`（见下方示例） |
| **Firebase App ID** (`mobilesdk_app_id`) | 内含于 `google-services.json` 的 `client_info.mobilesdk_app_id` | 形如 `1:123456789:android:abc...`，**无需手写** |
| **API Key** | 内含于 `google-services.json` 的 `api_key.current_key` | **由 Firebase 自动生成**，一般不用改代码 |
| **GTM 帐号与移动容器** | [Tag Manager](https://tagmanager.google.com/) → 创建「移动」容器 | — |
| **GTM 容器 ID** | GTM 界面，形如 `GTM-XXXXXX` | `app/src/main/res/values/strings.xml` → `gtm_container_id` |
| **默认容器 JSON** | GTM → 版本 → 下载 | `app/src/main/assets/containers/GTM-XXXXXX.json` |
| **预览链接 / 包名** | GTM → 版本 → 操作 → 预览，输入包名 `com.google.tagmanager.demo` | `AndroidManifest` 中 `tagmanager.c.com.google.tagmanager.demo` scheme |

> **说明**：移动 GTM 没有单独的 “GTM API Key”。Analytics 数据走 Firebase/Google Analytics；GTM 负责在端上根据容器规则处理这些事件。若修改了 `applicationId`，须同步修改 Firebase 注册包名、预览 Activity 的 `android:scheme`（`tagmanager.c.<包名>`）以及 GTM 预览时填写的包名。

### 配置步骤摘要

1. 在 Firebase 创建项目并添加 Android 应用（包名与 `app/build.gradle.kts` 中 `applicationId` 一致）。
2. 下载 `google-services.json` 放到 `app/` 目录（可参考 `app/google-services.json.example`）。
3. 在 [Tag Manager](https://tagmanager.google.com/) 创建**移动**容器，关联同一 Firebase 项目。
4. 在 GTM 下载容器 JSON 到 `app/src/main/assets/containers/`。
5. 将 `strings.xml` 里的 `gtm_container_id` 改为你的 `GTM-XXXXXX`。
6. 用 Android Studio 打开本目录，Sync 后运行到真机或模拟器（需联网以便拉取/更新容器）。

## 界面按钮说明

| 按钮 | 调用的 SDK |
|------|------------|
| 记录自定义事件 share_image | `FirebaseAnalytics.logEvent` + 参数 `image_name`、`full_text` |
| 设置用户属性 favorite_food | `FirebaseAnalytics.setUserProperty` |
| 记录屏幕浏览 | `FirebaseAnalytics.logEvent(SCREEN_VIEW)` |
| 记录购买事件 | `FirebaseAnalytics.logEvent(PURCHASE)` |
| 设置 User ID | `FirebaseAnalytics.setUserId` |
| 打开 GTM 容器 | `TagManager.getInstance().openContainer(containerId)` |

在 GTM 后台可为 `share_image` 配置「事件参数」变量（键名 `image_name`、`full_text`）和「Firebase 用户属性」变量（键名 `favorite_food`），再配置触发器与代码。

## 预览与调试

- **预览容器**：在 GTM 生成预览链接，用链接或二维码启动已安装的应用（Manifest 已注册 `TagManagerPreviewActivity`）。
- **详细日志**（连接设备后）：

```bash
adb shell setprop log.tag.GoogleTagManager VERBOSE
adb logcat -s GoogleTagManager
```

## 构建

使用 Android Studio 打开项目根目录，或（已安装 Android SDK 时）：

```bash
gradlew assembleDebug
```

首次打开若缺少 Gradle Wrapper JAR，请用 Android Studio 的 **Sync Project with Gradle Files** 自动生成。

## 参考

- [Android 版 Google 跟踪代码管理器](https://developers.google.com/tag-platform/tag-manager/android/v5?hl=zh-cn)
- [Firebase Analytics Android](https://firebase.google.com/docs/analytics/android/start)
