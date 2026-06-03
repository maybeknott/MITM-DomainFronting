# راهنمای برنامه گرافیکی محلی

## Purpose

Local Control Center guide for `scripts/gui.py`: startup workflow, pages, telemetry rail,
security boundaries, and Windows executable build.

<div dir="rtl">

فایل `scripts/gui.py` مرکز کنترل محلی این پروژه است. این برنامه برای راه‌اندازی اولیه، اجرای پروکسی، تست مرورگر، بررسی سلامت، تعمیر فایل‌های تولیدی و ساخت گزارش پشتیبانی طراحی شده است. برنامه فقط روی سیستم شما اجرا می‌شود و از کتابخانه استاندارد Python استفاده می‌کند.

## اجرای برنامه

در ویندوز:

```powershell
py -3 scripts\gui.py
```

در سیستم‌هایی که `python` مستقیم در دسترس است:

```bash
python scripts/gui.py
```

اگر فقط می‌خواهید وجود فایل‌ها و اسکریپت‌های اصلی را بدون باز کردن پنجره بررسی کنید:

```powershell
py -3 scripts\gui.py --self-test
```

## مسیر پیشنهادی برای شروع

برنامه با صفحه **Dashboard** باز می‌شود. برای استفاده معمولی همین ترتیب کافی است:

۱. **Check Setup**: بررسی سبک و محلی برای کانفیگ، فایل‌های لازم، ابزارهای موجود و وضعیت پایه.

۲. **Generate Local CA**: ساخت گواهی و کلید شخصی در مسیر `Xray-config/`. نصب Trust Store دستی می‌ماند و برنامه آن را بی‌اجازه انجام نمی‌دهد.

۳. **Start Core**: اجرای Xray Core داخلی برنامه با کانفیگ انتخاب‌شده، اگر runtime محلی در `xray/` موجود باشد. اگر v2rayN یا Xray دیگری از قبل روی `127.0.0.1:10808` فعال باشد، برنامه آن را به عنوان external core نشان می‌دهد، از آن برای تست استفاده می‌کند و آن فرایند را متوقف نمی‌کند.

۴. **Run Page Check**: تست یک صفحه از مسیر پروکسی محلی `127.0.0.1:10808`.

## چینش برنامه

- نوار چپ برای جابه‌جایی بین صفحه‌ها است.
- فضای وسط برای کار اصلی هر صفحه است.
- نوار راست Telemetry همیشه وضعیت زنده، شبکه و فعالیت محلی را نشان می‌دهد.
- Log Drawer پایین برنامه به صورت پیش‌فرض مخفی است و فقط وقتی لازم باشد باز می‌شود.

صفحه روزمره **Dashboard** با مدل control center طراحی شده است: ردیف اول وضعیت System، Xray Core، Local Proxy، DNS و Uptime را نشان می‌دهد؛ پایین‌تر workflow، وضعیت آماده‌بودن، کنترل core، Proxy Control، Browser Proxy Check و Quick Actions قرار دارند. هدف این است که کاربر اول بفهمد «چه چیزی آماده است؟ چه چیزی listener را در اختیار دارد؟ قدم بعدی چیست؟»

با **Focus Mode** می‌توانید نوار چپ را مخفی کنید. با **Telemetry Rail** می‌توانید نوار راست را هم مخفی یا دوباره نمایش دهید.

## کلیدهای میانبر

- `F5`: تازه‌سازی وضعیت.
- `Ctrl+K`: باز کردن Find Action.
- `Ctrl+F`: رفتن به جست‌وجوی checks.
- `Ctrl+R`: اجرای Best Next Action.
- `Ctrl+L`: نمایش یا مخفی کردن Log Drawer.
- `Ctrl+B`: Focus Mode برای نوار چپ.
- `Ctrl+T`: نمایش یا مخفی کردن Telemetry Rail.
- `Escape`: مخفی کردن Log Drawer.

## Find Action

دکمه **Find Action** یا کلید `Ctrl+K` یک command palette باز می‌کند. در آن می‌توانید صفحه‌ها، عملیات‌های رایج، ابزارهای تعمیر، راهنماها و کنترل‌های نمایشی را جست‌وجو کنید. چند نمونه جست‌وجو:

- `health`
- `proxy`
- `cert`
- `browser`
- `logs`
- `telemetry`
- `repair`

با Enter مورد انتخاب‌شده اجرا می‌شود.

## Telemetry Rail

نوار سمت راست شامل این بخش‌ها است:

- **Live Telemetry**: سرعت دریافت/ارسال، connections، requests، blocked و نمودارهای کوچک زنده.
- **Local & Private**: یادآوری اینکه داده‌ها، logها و تنظیمات روی همین دستگاه می‌مانند.
- **Quick Actions**: میانبرهای سریع برای Logs، Find Action، Reset Statistics و Refresh.

داده‌های شبکه از شمارنده‌های سیستم‌عامل خوانده می‌شود. برنامه محتوای ترافیک، کوکی، بدنه درخواست، تاریخچه مرورگر یا payload رمزگشایی‌شده را بررسی نمی‌کند.

## صفحه‌ها

### Dashboard

صفحه اصلی برنامه است. وضعیت **Bundled Xray Core** نشان می‌دهد `xray.exe`، `geoip.dat` و `geosite.dat` در برنامه موجود هستند یا نه. کارت **Proxy Control** مسیر browser proxy، external core، system proxy و TUN را واضح نشان می‌دهد بدون اینکه تنظیمات سیستم را بی‌اجازه تغییر دهد.

### Tools

مسیر راه‌اندازی مرحله‌ای و ابزارهای اختیاری را نگه می‌دارد. ابزارهای اضافی مثل نصب Playwright، نصب ابزار fingerprint، دانلود Xray Core و PyInstaller در بخش اختیاری مخفی شده‌اند تا صفحه اصلی شلوغ نشود.

### Network Mode

این کارت مشخص می‌کند ترافیک از چه مسیری وارد Xray می‌شود:

- **Local proxy endpoint**: آدرس و پورت inbound محلی پروفایل انتخاب‌شده. اگر alternate-port profile انتخاب شود، GUI همان پورت را برای وضعیت و browser proxy استفاده می‌کند.
- **External core ownership**: اگر v2rayN یا Xray دیگری پورت را در اختیار داشته باشد، GUI آن را external نشان می‌دهد و نمی‌بندد.
- **System proxy**: فقط بررسی و هشدار است. برنامه system proxy را خودکار روشن، خاموش یا تغییر نمی‌دهد.
- **TUN mode**: پروفایل استاندارد TUN ندارد. اگر کانفیگ انتخاب‌شده inbound نوع TUN داشته باشد، GUI آن را advisory نشان می‌دهد؛ استفاده از TUN یعنی routing سطح سیستم و معمولاً نیازمند administrator و بررسی routeها است.

### Routing

محیط بررسی محلی است. Checks اصلی اول نمایش داده می‌شوند و checks عمیق‌تر پشت بخش extra پنهان هستند. با Command Search می‌توانید بین checks جست‌وجو کنید.

### Logs & Health

برای زمانی است که تست مرورگر یا راه‌اندازی مشکل دارد. Health Probe، Platform Capability و Trust Store Check خروجی redacted و محلی تولید می‌کنند. گزارش‌های عمیق‌تر مثل Lab Evidence و Decision Report در بخش advanced قرار دارند.

### Settings

ابزارهای تعمیر local را نگه می‌دارد. Repair Setup فایل‌های تولیدی و metadata را بررسی و بازسازی می‌کند. ابزارهای نصب dependency و دانلود Xray Core در advanced قرار دارند.

### Certificates

برای وضعیت گواهی، بررسی تطابق cert/key، ساخت گواهی محلی و راهنمای trust استفاده می‌شود. برنامه کلید خصوصی را آپلود نمی‌کند و trust را بی‌اجازه نصب نمی‌کند.

### Proxy

ابتدا Page Check با Chromium/Playwright را اجرا کنید. تنظیم مسیر Chrome، headless و تست CloakBrowser/Fingerprint برای استفاده advanced است.

### Profiles & DNS

برای تولید پروفایل‌های استاندارد، ساخت alternate-port profile و اجرای DNS Sweep استفاده می‌شود.

### About

لینک‌های سریع به راهنماهای محلی مخزن را نشان می‌دهد.

## Log Drawer

Log Drawer خروجی را به سه بخش تقسیم می‌کند:

- **System**: پیام‌های عمومی برنامه.
- **Core**: پیام‌های مربوط به Xray Core و اتصال.
- **Checks**: خروجی validate، health، release-check و ابزارهای بررسی.

اگر Log Drawer بسته باشد و خروجی جدید برسد، دکمه آن به شکل `Show Logs *` تغییر می‌کند.

## مرزهای امنیتی

- برنامه هیچ گزارشی را خودکار آپلود نمی‌کند.
- برنامه Trust Store را بی‌اجازه تغییر نمی‌دهد.
- برنامه system proxy را بی‌اجازه تغییر نمی‌دهد.
- برنامه کلید خصوصی، کوکی، توکن، request body یا محتوای مرورگر را ذخیره یا ارسال نمی‌کند.
- برنامه فرایندهای Xray/v2rayN خارجی را نمی‌بندد؛ فقط فرایندی را متوقف می‌کند که خودش اجرا کرده باشد.
- خروجی‌های `.local-state/` محلی هستند و قبل از ارسال برای پشتیبانی باید بازبینی شوند.

## ساخت نسخه اجرایی

برای ساخت فایل اجرایی ویندوز:

```powershell
build_gui_exe.bat
```

یا:

```powershell
py -3 scripts\build_gui_exe.py
```

خروجی:

```text
dist\MITM-DomainFronting-Control-Center\
```

اگر runtime محلی در `xray/` موجود باشد، build فایل‌های `xray.exe`، `geoip.dat` و `geosite.dat` را در خروجی کپی می‌کند تا نسخه ساخته‌شده self-contained باشد. فایل‌های `mycert.crt` و `mycert.key` عمداً کپی نمی‌شوند.

اجرای self-test روی نسخه ساخته‌شده:

```powershell
dist\MITM-DomainFronting-Control-Center\MITM-DomainFronting-Control-Center.exe --self-test
```

## انتشار از طریق GitHub Actions

Workflow ساخت GUI روی Windows اجرا می‌شود. برای push و pull request، خروجی به عنوان artifact ذخیره می‌شود. برای tagهایی مثل `v1.0.0`، فایل ZIP و checksum ساخته و به GitHub Release همان tag اضافه می‌شود.

## Related documents

| Document | Topic |
|---|---|
| [`local-telemetry.md`](local-telemetry.md) | Telemetry rail and redaction |
| [`preflight-and-diagnostics.md`](preflight-and-diagnostics.md) | Checks run from GUI |
| [`release-engineering.md`](release-engineering.md) | Release and ZIP build |
| [`fa/quick-start.md`](fa/quick-start.md) | Persian quick start |

</div>
