# Парсер портала Kaspersky

## Описание

Этот скрипт на Python предназначен для парсинга данных об уязвимостях с сайта [threats.kaspersky.com] и сохранения их в базу данных SQLite. Скрипт также позволяет выполнять запросы для получения информации о уязвимостях по продуктам и топ-5 вендоров с наибольшим количеством уязвимостей, позволяющих подмену пользовательского интерфейса (SUI).

## Функционал

- Создание и настройка базы данных SQLite с необходимыми таблицами.
- Парсинг страниц vendors, products, vulnerabilities и их impacts.
- Вставка данных в базу данных.
- Поиск уязвимостей для конкретного продукта.
- Получение топ-5 вендоров по количеству уязвимостей, связанных с SUI.

## Установка и запуск

1. **Клонируйте репозиторий:**

   ```bash
   git clone [https://github.com/kawa11Tensh1/Parser_kaspersky]
   cd Parser_kaspersky
   ```

2. **Установите необходимые зависимости:**

    ```bash
    pip install requests beautifulsoup4
    ```

3. **Запустите скрипт:**

    ```bash
    python parser.py
    ```

4. **Скрипт выполнит следующие действия:**

- Создаст базу данных SQLite и необходимые таблицы.
- Спарсит страницы с данными о вендорах, продуктах и уязвимостях.
- Сохранит данные в базу данных.
- Выполнит запросы для получения уязвимостей для указанного продукта.
- Определит топ-5 вендоров по количеству уязвимостей SUI и сохранит результат в файл top_vendors.json.

5. **Просмотрите результаты:**

- Файл уязвимостей продукта: vulnerabilities_<product_name>.json
- Файл топ-5 вендоров: top_vendors.json