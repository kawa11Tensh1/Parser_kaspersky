from bs4 import BeautifulSoup
import requests
import sqlite3
import json
import os

def creating_db():
    """
    Создаёт базу данных Kaspersky с таблицами Vulnerabilities, Products, Vendors, Impacts
    """
    connect = sqlite3.connect("Kaspersky.sqlite")
    cursor = connect.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Impacts(
            impact_id INTEGER PRIMARY KEY,
            impact_name TEXT,
            vulnerability_id INTEGER,
            FOREIGN KEY (vulnerability_id) REFERENCES Vulnerabilities(vulnerability_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Vulnerabilities(
            vulnerability_id INTEGER PRIMARY KEY,
            vulnerability_name TEXT,
            product_id INTEGER,
            kaspersky_id INTEGER,
            FOREIGN KEY (product_id) REFERENCES Products(product_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Products(
            product_id INTEGER PRIMARY KEY,
            product_name TEXT,
            vendor_id INTEGER,
            FOREIGN KEY (vendor_id) REFERENCES Vendors(vendor_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Vendors(
            vendor_id INTEGER PRIMARY KEY,
            vendor_name TEXT)
    ''')

    connect.commit()
    connect.close()

def get_product_id(connect, product_name):
    """
    Получает product_id из таблицы Products
    """
    cursor = connect.cursor()

    cursor.execute('''
        SELECT product_id 
        FROM Products 
        WHERE product_name = ?
    ''', (product_name,))

    result = cursor.fetchone()
    if result:
        return result[0]
    return None

def get_vendor_id(connect, vendor_name):
    """
    Получает vendor_id из таблицы Vendors
    """
    cursor = connect.cursor()

    cursor.execute('''
        SELECT vendor_id 
        FROM Vendors 
        WHERE vendor_name = ?
    ''', (vendor_name,))

    result = cursor.fetchone()
    if result:
        return result[0]
    return None

def get_vulnerability_id(connect, kaspersky_id):
    """
    Получает vulnerability_id из таблицы Vulnerabilities
    """
    cursor = connect.cursor()
    cursor.execute('''
        SELECT vulnerability_id 
        FROM Vulnerabilities 
        WHERE kaspersky_id = ?
    ''', (kaspersky_id,))

    result = cursor.fetchone()
    if result:
        return result[0]
    return None



def insert_impact(connect, impact_name, kaspesky_id):
    """
    Вставляет данные в таблицу Impacts, предварительно проверяя,
    существует ли уже запись с таким же impact_name и vulnerability_id.
    """
    vulnerability_id = get_vulnerability_id(connect, kaspesky_id)
    cursor = connect.cursor()

    # Проверка существования записи с таким же impact_name и vulnerability_id
    cursor.execute('''
        SELECT COUNT(*)
        FROM Impacts
        WHERE impact_name = ? AND vulnerability_id = ?
    ''', (impact_name, vulnerability_id))
    
    exists = cursor.fetchone()[0] > 0

    if not exists:
        # Вставка новой записи, если таковой нет
        cursor.execute('''
            INSERT INTO Impacts (impact_name, vulnerability_id)
            VALUES (?, ?)
        ''', (impact_name, vulnerability_id))
        
        connect.commit()

def insert_vulnerability(connect, vulnerability_name, product_name, kaspersky_id):
    """
    Вставляет данные в таблицу Vulnerabilities
    """
    cursor = connect.cursor()

    # Проверяем, существует ли уже такая уязвимость
    cursor.execute('''
        SELECT vulnerability_id 
        FROM Vulnerabilities 
        WHERE kaspersky_id = ?
    ''', (kaspersky_id,))
    
    result = cursor.fetchone()

    if result is None:
        product_id = get_product_id(connect, product_name)

        # Устанавливает product_id = 0, если он равен None
        if product_id is None:
            product_id = 0
        
        cursor.execute('''
        INSERT INTO Vulnerabilities (vulnerability_name, product_id, kaspersky_id)
        VALUES (?, ?, ?)
        ''', (vulnerability_name, product_id, kaspersky_id))

        connect.commit()

def insert_product(connect, product_name, vendor_name):
    """
    Вставляет данные в таблицу Products
    """
    cursor = connect.cursor()

    # Проверяем, существует ли уже такой продукт
    cursor.execute('''
        SELECT product_id 
        FROM Products 
        WHERE product_name = ?
    ''', (product_name,))
    
    result = cursor.fetchone()

    if result is None:
        vendor_id = get_vendor_id(connect, vendor_name)

        # Устанавливает vendor_id = 0, если он равен None
        if vendor_id is None:
            vendor_id = 0

        cursor.execute('''
        INSERT INTO Products (product_name, vendor_id)
        VALUES (?, ?)
        ''', (product_name, vendor_id))

        connect.commit()

def insert_vendor(connect, vendor_name):
    """
    Вставляет данные в таблицу Vendors, если такого vendor_name еще нет
    """
    cursor = connect.cursor()

    # Проверяем, существует ли уже такой vendor_name
    cursor.execute('''
        SELECT vendor_id 
        FROM Vendors 
        WHERE vendor_name = ?
    ''', (vendor_name,))
    
    result = cursor.fetchone()

    if result is None:
        # Если vendor_name не найден, вставляем новый
        cursor.execute('''
            INSERT INTO Vendors (vendor_name)
            VALUES (?)
        ''', (vendor_name,))

        connect.commit()



def parse_vendors_pages(connect, base_url):
    """
    Парсит страницы Vendors и вставляет данные в таблицу Vendors
    """
    page_num = 1  # Начинаем с первой страницы
    while True:
        url = f"{base_url}?paged={page_num}"
        print(f"Parsing vendors on {url}...")

        # Загружаем HTML-контент страницы
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Failed to retrieve the page. Status code: {response.status_code}")
            break
        
        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим все контейнеры с классом 'table__row'
        containers = soup.find_all('div', class_='table__row')

        # Если контейнеры не найдены, значит, страницы больше нет
        if not containers:
            print(f"No more vendors found on page {page_num}. Ending parse.")
            break

        # Извлекаем и вставляем названия в таблицу
        for container in containers:
            title_tag = container.find('div', class_='table__col_title')
            if title_tag and title_tag.a:
                vendor_name = title_tag.a.text.strip()
                insert_vendor(connect, vendor_name)

        page_num += 1

def parse_products_pages(connect, base_url):
    """
    Парсит страницы Products и вставляет данные в таблицу Products
    """
    page_num = 1  # Начинаем с первой страницы
    while True:
        url = f"{base_url}?paged={page_num}"
        print(f"Parsing products on {url}...")

        # Загружаем HTML-контент страницы
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Failed to retrieve the page. Status code: {response.status_code}")
            break

        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим все контейнеры с классом 'table__row'
        containers = soup.find_all('div', class_='table__row')

        # Если контейнеры не найдены, значит, страницы больше нет
        if not containers:
            print(f"No more products found on page {page_num}. Ending parse.")
            break

        # Извлекаем и вставляем названия продуктов в таблицу
        for container in containers:
            product_tag = container.find('div', class_='table__col_title')
            vendor_tag = container.find_all('div', class_='table__col')[1]
            
            if product_tag and product_tag.a:
                product_name = product_tag.a.text.strip()
                if vendor_tag and vendor_tag.a:
                    vendor_name = vendor_tag.a.text.strip()
                    insert_product(connect, product_name, vendor_name)

        page_num += 1

def parse_vulnerabilities_pages(connect, base_url):
    """
    Парсит страницы Vulnerabilities и вставляет данные в таблицу Vulnerabilities
    """
    page_num = 1  # Начинаем с первой страницы
    while True:
        url = f"{base_url}?paged={page_num}"
        print(f"Parsing vulnerabilities on {url}...")

        # Загружаем HTML-контент страницы
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Failed to retrieve the page. Status code: {response.status_code}")
            break

        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим все контейнеры с классом 'table__row'
        containers = soup.find_all('div', class_='table__row')

        # Если контейнеры не найдены, значит, страницы больше нет
        if not containers:
            print(f"No more vulnerabilities found on page {page_num}. Ending parse.")
            break

        # Извлекаем и вставляем данные об уязвимостях в таблицу
        for container in containers:
            kaspersky_id_tag = container.find('div', class_='table__col')
            kaspersky_id = kaspersky_id_tag.a.text.strip() if kaspersky_id_tag and kaspersky_id_tag.a else None
            
            vulnerability_name_tag = container.find('div', class_='table__col_title')
            vulnerability_name = vulnerability_name_tag.a.text.strip() if vulnerability_name_tag and vulnerability_name_tag.a else None

            product_tags = container.find_all('div', class_='table__col')
            if len(product_tags) > 2:
                product_tag = product_tags[2]
                product_name = product_tag.a.text.strip() if product_tag and product_tag.a else None
            else:
                product_name = None

            if not product_name:
                product_name = "Unknown Product"

            if kaspersky_id and vulnerability_name:
                insert_vulnerability(connect, vulnerability_name, product_name, kaspersky_id)

        page_num += 1

def parse_impacts_pages(connect):
    """
    Парсит теги уязвимости со страницы и вставляет их в таблицу Impacts
    """
    cursor = connect.cursor()

    # Извлекаем все kaspersky_id для заданной уязвимости
    cursor.execute('''
        SELECT kaspersky_id FROM Vulnerabilities
    ''')

    results = cursor.fetchall()

    for kaspersky_id in results:
        url = f"https://threats.kaspersky.com/en/vulnerability/{kaspersky_id[0]}/"
        print(f"Parsing Impacts on {url}...")

        # Выполняем запрос к странице уязвимости
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Failed to retrieve the page for kaspersky_id {kaspersky_id}. Status code: {response.status_code}")
            continue

        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим контейнер с тегами
        tags_container = soup.find('div', class_='tags')
        if not tags_container:
            continue

        # Находим все теги внутри контейнера
        tag_elements = tags_container.find_all('div', class_='tags__tag')

        for tag_element in tag_elements:
            # Извлекаем текст до элемента hint
            impact_name = ''
            for element in tag_element.children:
                if element.name == 'div' and 'hint' in element.get('class', []):
                    break
                if element.name is None:
                    impact_name += element.strip()  # Добавляем текст узла
                else:
                    impact_name += element.get_text(strip=True)  # Добавляем текст из тега

            impact_name = impact_name.strip()  # Удаляем лишние пробелы

            # Вставляем тег в таблицу Impacts
            insert_impact(connect, impact_name, kaspersky_id[0])



def find__vulnerabilities(connect, product_name):
    """
    Загружает в файл vulnerabilities_X.json пронумерованный список уязвимостей в продукте X
    """
    cursor = connect.cursor()
    
    # Получаем product_id по имени продукта
    product_id = get_product_id(connect, product_name)
    
    if product_id is None:
        print(f"No product found with name '{product_name}'")
        return

    # Получаем все уязвимости для данного product_id
    cursor.execute('''
        SELECT vulnerability_name 
        FROM Vulnerabilities 
        WHERE product_id = ?
    ''', (product_id,))

    # Формируем компактный словарь уязвимостей
    vulnerabilities = {
        idx: row[0] 
        for idx, row in enumerate(cursor.fetchall(), start=1)
    }
    
    # Формируем имя файла и сохраняем результаты в JSON
    filename = f"vulnerabilities_{product_name}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(vulnerabilities, f, ensure_ascii=False, indent=4)
    
    print(f"Saved vulnerabilities to {filename}")


def top_vendors(connect):
    """
    Возвращает топ-5 вендоров, допустивших наибольшее количество уязвимостей, связанных с подменой пользовательского интерфейса (SUI),
    и сохраняет результат в файл top_vendors.json в компактном формате.
    """
    cursor = connect.cursor()

    # SQL-запрос для получения топ-5 вендоров по количеству уязвимостей SUI
    query = '''
        SELECT v.vendor_name, COUNT(*) AS vulnerability_count
        FROM Vendors v
        JOIN Products p ON v.vendor_id = p.vendor_id
        JOIN Vulnerabilities vl ON p.product_id = vl.product_id
        JOIN Impacts i ON vl.vulnerability_id = i.vulnerability_id
        WHERE i.impact_name LIKE '%SUI%'
        GROUP BY v.vendor_name
        ORDER BY vulnerability_count DESC
        LIMIT 5
    '''

    cursor.execute(query)
    top_vendors = cursor.fetchall()

    # Формируем результат в виде словаря
    top_vendors_dict = {
        row[0]: row[1] 
        for row in top_vendors
    }
    
    # Сохраняем результат в JSON файл
    filename = "top_vendors.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(top_vendors_dict, f, ensure_ascii=False, indent=4)
    
    print(f"Saved top vendors to {filename}")

    # Возвращаем результат
    return top_vendors_dict



def main():
    """
    Запускает скрипт
    """
    connect = sqlite3.connect('Kaspersky.sqlite', check_same_thread=False)
    creating_db()
    #parse_vendors_pages(connect, "https://threats.kaspersky.com/en/vendor/")
    #parse_products_pages(connect, "https://threats.kaspersky.com/en/product/")
    #parse_vulnerabilities_pages(connect, "https://threats.kaspersky.com/en/vulnerability/")
    #parse_impacts_pages(connect)

    # Поиск уязвимостей для конкретного продукта
    find__vulnerabilities(connect, "Microsoft Windows")
    # Получаем топ-5 вендоров и сохраняем в файл
    top_vendors(connect)

    connect.close()

if __name__ == "__main__":
    main()
