# MITM-DomainFronting

<div dir="rtl">

این مخزن یک کانفیگ و مجموعه ابزار محلی برای اجرای روش MITM-DomainFronting با Xray است. هدف پروژه این نیست که «همه اینترنت» یا هر کانفیگی را زنده کند؛ این روش فقط برای بعضی سرویس‌ها و بعضی مسیرهای شبکه جواب می‌دهد و رفتار آن ممکن است با تغییرات مرورگرها، ECH، CDNها، DNS و سیاست‌های شبکه تغییر کند.

اصل ایده این است که مرورگر به یک پروکسی محلی وصل می‌شود، پروکسی محلی با گواهی شخصی شما ترافیک HTTPS همان مرورگری را که خودتان تنظیم کرده‌اید رمزگشایی می‌کند، سپس درخواست را با SNI و مسیر مناسب به مقصد می‌فرستد. به همین دلیل امنیت گواهی شخصی مهم‌ترین بخش راه‌اندازی است.

## نکته بسیار مهم درباره گواهی

هر کاربر باید گواهی و کلید خودش را بسازد.

- فایل `mycert.crt` را از دیگران نگیرید.
- فایل `mycert.key` را به هیچ‌کس ندهید.
- اگر کلید خصوصی لو رفت، آن گواهی را از سیستم و مرورگر حذف کنید و یک گواهی جدید بسازید.
- این پروژه گواهی را بی‌اجازه در Trust Store نصب نمی‌کند.
- گزارش‌ها، لاگ‌ها، کوکی‌ها، کلید خصوصی و محتوای مرورگر به جایی آپلود نمی‌شوند.

## روش پیشنهادی برای کاربران ویندوز

ساده‌ترین مسیر استفاده از برنامه گرافیکی محلی است.

```powershell
py -3 scripts\gui.py
```

اگر `python` به‌درستی روی سیستم شما تنظیم شده باشد، این دستور هم کار می‌کند:

```powershell
python scripts\gui.py
```

برنامه با صفحه **Dashboard** باز می‌شود. مسیر پیشنهادی از همان صفحه در کارت **Setup Workflow** و **Quick Actions** در دسترس است:

۱. **Check Setup**: وضعیت فایل‌ها، کانفیگ، ابزارهای محلی و پیش‌نیازهای پایه را بررسی می‌کند.

۲. **Generate Local CA**: فایل‌های شخصی `Xray-config/mycert.crt` و `Xray-config/mycert.key` را می‌سازد. نصب Trust همچنان دستی است.

۳. **Start Core**: اگر Xray Core در پوشه محلی `xray/` موجود باشد، همان هسته داخلی برنامه را با کانفیگ استاندارد اجرا می‌کند. اگر v2rayN یا Xray دیگری از قبل روی `127.0.0.1:10808` باز باشد، برنامه آن را تشخیص می‌دهد، از همان listener برای تست استفاده می‌کند و آن فرایند خارجی را نمی‌بندد.

۴. **Run Page Check**: یک صفحه ساده را از طریق `127.0.0.1:10808` تست می‌کند تا مشخص شود مرورگر، پروکسی و گواهی با هم درست کار می‌کنند.

صفحه **Dashboard** به شکل یک control center دسکتاپ طراحی شده است: نوار بالایی وضعیت سیستم، Xray Core، پروکسی محلی، DNS و Uptime را نشان می‌دهد؛ سپس workflow، کنترل core، وضعیت browser proxy، telemetry زنده و quick actions نمایش داده می‌شود.

### Network Mode و کلاینت‌های دیگر

- حالت پیشنهادی برنامه **Browser proxy** است: مرورگر یا Page Check صریحاً از `socks5://127.0.0.1:10808` یا پورت پروفایل انتخاب‌شده استفاده می‌کند.
- اگر v2rayN یا Xray دیگری از قبل روی پورت انتخاب‌شده فعال باشد، برنامه آن را external core نشان می‌دهد و آن را متوقف نمی‌کند.
- برنامه وضعیت system proxy را فقط برای هشدار درباره loop یا تداخل نشان می‌دهد و تنظیمات proxy سیستم را بی‌اجازه تغییر نمی‌دهد.
- TUN یک حالت OS-wide است و معمولاً دسترسی administrator و بررسی routeها می‌خواهد. پروفایل استاندارد برنامه TUN را فعال نمی‌کند؛ اگر کانفیگ انتخاب‌شده inbound نوع TUN داشته باشد، GUI آن را فقط به عنوان وضعیت advisory نشان می‌دهد.

پنل سمت راست برنامه، Telemetry محلی را نشان می‌دهد: سرعت دریافت و ارسال، شمارنده‌های connections/requests/blocked، نمودارهای کوچک زنده، وضعیت privacy و quick actions. این داده‌ها از شمارنده‌های سیستم‌عامل و رویدادهای محلی GUI می‌آیند و محتوای ترافیک مرورگر را بررسی نمی‌کنند.

## ساخت فایل اجرایی ویندوز

برای ساخت نسخه قابل اجرا:

```powershell
build_gui_exe.bat
```

یا:

```powershell
py -3 scripts\build_gui_exe.py
```

خروجی در مسیر زیر ساخته می‌شود:

```text
dist\MITM-DomainFronting-Control-Center\
```

فایل اجرایی:

```text
dist\MITM-DomainFronting-Control-Center\MITM-DomainFronting-Control-Center.exe
```

اگر فایل‌های runtime در `xray/` موجود باشند، فرایند build فایل‌های `xray.exe`، `geoip.dat` و `geosite.dat` را هم در خروجی قرار می‌دهد تا برنامه بدون نیاز به کلاینت جداگانه اجرا شود. فایل‌های شخصی `mycert.crt` و `mycert.key` همچنان وارد خروجی نمی‌شوند و باید توسط هر کاربر ساخته شوند.

پوشه‌های `build/` و `dist/` خروجی محلی هستند و نباید commit شوند.

## انتشار Release

Workflow مربوط به ساخت GUI در `.github/workflows/build-gui.yml` تنظیم شده است. روی push معمولی و pull request، برنامه ساخته و به عنوان artifact ذخیره می‌شود. وقتی یک tag با الگوی `v*` push شود، workflow نسخه ویندوز را ZIP می‌کند، checksum با SHA256 می‌سازد و هر دو فایل را به GitHub Release همان tag وصل می‌کند.

نمونه:

```powershell
git tag v1.0.0
git push origin v1.0.0
```

بعد از اجرای workflow، فایل‌هایی شبیه این در Release قرار می‌گیرند:

```text
MITM-DomainFronting-Control-Center-v1.0.0-windows-x64.zip
MITM-DomainFronting-Control-Center-v1.0.0-windows-x64.zip.sha256
```

## راه‌اندازی دستی با v2rayN در ویندوز

اگر نمی‌خواهید از GUI استفاده کنید، می‌توانید مسیر دستی را انجام دهید.

۱. آخرین نسخه v2rayN را از صفحه رسمی دانلود و استخراج کنید:

```text
https://github.com/2dust/v2rayN/releases
```

۲. یک گواهی شخصی بسازید تا دو فایل زیر ایجاد شود:

```text
mycert.crt
mycert.key
```

۳. فایل `mycert.crt` را به Trust Store سیستم یا مرورگری که می‌خواهید با آن تست کنید اضافه کنید. برای Windows:

```text
Install Certificate -> Local Machine -> Place all certificates in the following store -> Trusted Root Certification Authorities
```

برای Chrome در ویندوز:

```text
Settings -> Privacy and security -> Security -> Manage certificates -> Trusted Root Certification Authorities -> Import
```

۴. در v2rayN از بخش custom configuration فایل زیر را وارد کنید:

```text
Xray-config/MITM-DomainFronting.json
```

نوع هسته را Xray انتخاب کنید و مراقب باشید پورت پیش‌فرض `10808` با برنامه دیگری تداخل نداشته باشد.

۵. کانفیگ را فعال کنید و سپس مرورگری را که گواهی را در آن trust کرده‌اید تست کنید.

## راه‌اندازی اندروید

برای اندروید بدون root، این روش معمولاً فقط در مرورگرها قابل استفاده است و برنامه‌های مستقل الزاماً از گواهی کاربر پیروی نمی‌کنند.

۱. آخرین نسخه v2rayNG را نصب کنید:

```text
https://github.com/2dust/v2rayNG/releases
```

۲. فایل‌های شخصی `mycert.crt` و `mycert.key` را آماده کنید. بهتر است آن‌ها را خودتان بسازید. اگر از ابزار آنلاین برای ساخت گواهی self-signed استفاده می‌کنید، فایل‌ها را به همین نام‌ها تغییر دهید:

```text
mycert.crt
mycert.key
```

۳. هر دو فایل را در قسمت Asset files برنامه v2rayNG وارد کنید.

۴. فایل `mycert.crt` را به عنوان CA certificate در اندروید نصب کنید. مسیر دقیق در گوشی‌های مختلف کمی فرق دارد، اما معمولاً شبیه این است:

```text
Settings -> Security and privacy -> More security settings -> Install from device storage -> CA Certificate
```

۵. کانفیگ `MITM-DomainFronting.json` را با گزینه import from locally وارد v2rayNG کنید و اجرا کنید. قابلیت TUN در v2rayNG باید فعال باشد و پورت پیش‌فرض `10808` تغییر نکرده باشد.

۶. در Chrome و مرورگرهای Chromium-based تست کنید. برای Firefox Android باید استفاده از CAهای کاربر را جداگانه فعال کنید:

```text
Firefox -> Settings -> About Firefox -> پنج بار روی لوگو بزنید -> Secret Settings -> Use third party CA certificates
```

## ساختار مهم مخزن

- `Xray-config/MITM-DomainFronting.json`: کانفیگ اصلی اجرا.
- `Xray-config/mycert.crt` و `Xray-config/mycert.key`: گواهی و کلید شخصی شما؛ این فایل‌ها local هستند و نباید commit شوند.
- `scripts/gui.py`: مرکز کنترل گرافیکی برای راه‌اندازی، تست، تعمیر و گزارش محلی.
- `scripts/`: ابزارهای validate، preflight، health، DNS، route، browser و release.
- `docs/`: راهنماهای جزئی‌تر درباره گواهی، مرورگر، DNS، پروفایل‌ها، سازگاری پلتفرم، release و عیب‌یابی.
- `.local-state/`: گزارش‌ها و تاریخچه محلی برنامه؛ خروجی پشتیبانی است و نباید بدون بازبینی ارسال شود.

## بررسی و عیب‌یابی محلی

برای اجرای self-test برنامه:

```powershell
py -3 scripts\gui.py --self-test
```

برای audit سریع:

```powershell
py -3 main.py audit
```

چند بررسی مفید برای توسعه‌دهندگان و نگه‌دارندگان:

```powershell
py -3 scripts\validate_config.py Xray-config\MITM-DomainFronting.json
py -3 scripts\preflight.py --config Xray-config\MITM-DomainFronting.json --no-dns --skip-cert --skip-runtime
py -3 scripts\route_intent_sync.py Xray-config\MITM-DomainFronting.json
py -3 scripts\config_src_validate.py --run-steps
py -3 scripts\build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
py -3 scripts\health_policy_tests.py
py -3 scripts\browser_probe_semantics_test.py
py -3 scripts\lab_evidence_run.py --json-out lab-evidence.bundle.json
py -3 scripts\lab_evidence_validate.py lab-evidence.bundle.json
```

## راهنماهای تکمیلی

- راهنمای GUI: `docs/gui.md`
- یکپارچه‌سازی Chromium: `docs/chromium-integration.md`
- چرخه عمر گواهی: `docs/certificate-lifecycle.md`
- عیب‌یابی و preflight: `docs/preflight-and-diagnostics.md`
- پروفایل‌های عملیاتی: `docs/operating-profiles.md`
- DNS و پایداری: `docs/dns-resilience.md`
- سازگاری پلتفرم‌ها: `docs/platform-compatibility.md`
- مهندسی انتشار: `docs/release-engineering.md`

## محدودیت‌ها

- این روش برای همه سرویس‌ها تضمینی نیست.
- تغییرات ECH، DNS، CDN و مرورگر ممکن است نتیجه را عوض کند.
- در اندروید بدون root معمولاً فقط مرورگرها مسیر قابل اتکایی هستند.
- اگر یک برنامه دیگر پورت `10808` را گرفته باشد، باید آن را ببندید یا از پروفایل alternate-port استفاده کنید.
- این پروژه جایگزین رعایت امنیت شخصی، مدیریت درست گواهی و بررسی خروجی‌های محلی نیست.

## حمایت

این پروژه ادامه کاری است که ابتدا در مخزن زیر شروع شد:

```text
https://github.com/patterniha/MMDF
```

و سپس با بحث و پیگیری در Xray-core به مسیر قابل استفاده با کانفیگ Xray رسید:

```text
https://github.com/XTLS/Xray-core/issues/4348
```

اگر این کار برای شما مفید بوده و می‌خواهید حمایت کنید:

</div>

```text
USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424
USDT (TRC20): TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o
Telegram: @patterniha
```
