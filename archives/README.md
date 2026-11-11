# Archives

Архивы версий не хранятся в git-репозитории, потому что GitHub блокирует обычные файлы больше 100 MB.

Загружайте zip-файлы из папки `D:\Work\Mi\Patcher\github-server\archives` в GitHub Release с тегом `archives`.

Базовый URL для программы:
https://github.com/Git72-devst/Patcher/releases/download/archives

После загрузки файлов адреса будут такими:
https://github.com/Git72-devst/Patcher/releases/download/archives/5.8.0.74.zip

Для PATCHER 1.1.4 прикрепите к тому же Release четыре файла:

- `6.0.2.19.zip` — русский перевод;
- `6.0.2.19_en.zip` — английский перевод;
- `6.0.2.30.zip` — русский перевод;
- `6.0.2.30_en.zip` — английский перевод.

Папка подготовки: `D:/Work/Mi/Patcher/github-server/archives`.
Не переименовывайте файлы. Внутренний каталог `Rus/` во всех четырёх архивах —
техническое имя модуля, содержимое каждого соответствует его языку.
Контрольные суммы: [SHA256SUMS-translations-2026-11-11.txt](../SHA256SUMS-translations-2026-11-11.txt).
Перед push метаданных замените оба ZIP 6.0.2.19 и добавьте оба ZIP 6.0.2.30
в Release `archives`. Старые ZIP 6.0.2.19 не соответствуют новым SHA256.
