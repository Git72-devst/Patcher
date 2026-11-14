# Archives

Архивы версий не хранятся в git-репозитории, потому что GitHub блокирует обычные файлы больше 100 MB.

Загружайте zip-файлы из папки `D:\Work\Mi\Patcher\github-server\archives` в GitHub Release с тегом `archives`.

Базовый URL для программы:
https://github.com/Git72-devst/Patcher/releases/download/archives

После загрузки файлов адреса будут такими:
https://github.com/Git72-devst/Patcher/releases/download/archives/5.8.0.74.zip

Для PATCHER 1.1.5 замените в Release `archives` два файла:

- `6.0.2.30.zip` — русский перевод;
- `6.0.2.30_en.zip` — английский перевод.

Папка подготовки: `D:/Work/Mi/Patcher/github-server/archives`.
Не переименовывайте файлы. Внутренний каталог `Rus/` в обоих архивах —
техническое имя модуля, содержимое каждого соответствует его языку.
Контрольные суммы: [SHA256SUMS-translations-2026-11-14.txt](../SHA256SUMS-translations-2026-11-14.txt).
До push метаданных проверьте размеры и SHA256 новых Assets. Желательно
заменять файлы и публиковать каталоги в одном окне обслуживания.
Архивы 6.0.2.19 в этом релизе не менялись.
